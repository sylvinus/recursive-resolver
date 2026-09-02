# Real-world testing protocol

0.1.0 shipped with 210 DNSSEC unit tests, a real-crypto signed-zone fixture,
and a record-level differential harness. All of it passed. It still shipped a
validator that could be made to accept forged data by anyone who owned a signed
domain, and that returned a false `DNSSECValidationError` on ordinary names.

This document is the protocol built in response: what to run, against what
corpus, and what has to hold. Layers 0 to 4 and 6 exist and were run for this
release; layers 5 and 7 are proposals and say so in their headings.

## Why none of the existing testing found it

Each reason is a requirement further down.

1. **The live differential never exercised DNSSEC.** Every named config in
   `diff_harness.py` except `default` sets `dnssec: False`, and `--configs`
   defaults to `no-dnssec`. The validation paths had unit tests, and good ones,
   but nothing compared their verdicts against real DNS.
2. **The verdict was never compared, only the data.** The harness diffs record
   sets. "We say BOGUS, three public validators say AD" is not a record
   difference, so no report could contain it.
3. **One sample per name.** The retrieval failures were non-deterministic: they
   depended on which nameserver the shuffle picked first. A single run has a
   7-in-8 chance of missing a 1-in-8 flap and no way to notice it was luck.
4. **The corpus was chosen for popularity, not for stress.** Tranco and
   CT-derived names are served by well-run infrastructure. The retrieval bugs
   need a zone with a lame server in its NS set, which nobody was selecting for.
5. **No fault injection.** Lame delegations, SERVFAIL, EDNS-hostile middleboxes
   and stripped OPT records all exist, but mostly on the long tail a
   popularity-ranked corpus omits.
6. **Nothing generated hostile input.** This is the big one, and no amount of
   corpus work fixes it. The forgeries needed a signed zone under an attacker's
   control, a decoy RRSIG rdata, or a genuine public record used out of place.
   The honest internet never sends those, so no live differential can find
   them however large it gets. They were found by reading the RFCs against the
   code, and by comparing behaviour against other implementations.

## The pieces

| Script | Layer | What it does |
|---|---|---|
| `scripts/audit.py` | 0 | Invariants checked on every lookup the other layers make |
| `scripts/collect_domains_adversarial.py` | 1 | Probes NS sets and keeps the zones that misbehave |
| `scripts/verdict_harness.py` | 2, 3 | Verdict differential against public validators, plus flap detection |
| `scripts/cassette.py` | 4 | Record real traffic, replay offline under every order and fault |
| `scripts/mutation_check.py` | 6 | Reintroduces each known defect and reports which layer catches it |
| `scripts/diff_harness.py` | 2 | The pre-existing record-level differential |

All of them honour `RR_SRC`, which points the import at a different copy of the
package. That is what lets `mutation_check.py` run the harnesses against a
deliberately broken build without touching the working tree.

## Layer 0: invariants that hold for every lookup

Everything below is a way of generating inputs; this is what makes an input a
*test*. `scripts/audit.py` wraps a live resolver's own
methods, so it observes real calls and cannot drift from them, and records a
per-resolution ledger. Production code carries no test hooks.

| # | Invariant |
|---|---|
| I1 | A DNSSEC verdict requires retrieved material: if any fetch of validation material came back empty-handed, the resolution must end in `DNSSECMaterialUnavailableError`, never a `DNSSECError`. |
| I2 | Every query sent while validating carries EDNS0, so it can carry DO (RFC 4035 §3.2.1). |
| I3 | No zone is judged on one server's word: a failed material fetch must have asked every usable address in the NS set. |
| I4 | Nothing is accepted from a response the resolver itself classified as unusable (no AA, wrong class, out of bailiwick), judged against the resolver's own `require_authoritative` setting. |
| I5 | `DNSSECMaterialUnavailableError` is only raised when a fetch really did return nothing, so it cannot become a way to hide a validation failure. |

I1 alone catches this release's first bug the moment it fires, on any corpus,
without a reference resolver. Write the invariants once; every layer below
reuses them.

## Layer 1: an adversarial corpus

Replace "popular names" with "names selected because they stress a path".
`collect_domains_diverse.py` supplies the candidates (Tranco bands, every IANA
TLD, the Public Suffix List, curated pathological cases);
`collect_domains_adversarial.py` then probes **every nameserver of every zone**
and tags the ones that misbehave:

```bash
python scripts/collect_domains_diverse.py -o corpus.csv --limit 30000
python scripts/collect_domains_adversarial.py --csv corpus.csv -o adversarial.csv
```

| Tag | What it selected for |
|---|---|
| `lame-dnskey` | One server answers DNSKEY with NOERROR and an empty answer while a sibling serves it. The class that broke 0.1.0. |
| `no-aa-dnskey` | A server answers the DNSKEY query without AA: a parent-side server returning a referral. |
| `unreliable-ns`, `servfail-ns`, `formerr-edns`, `all-ns-down` | Servers that time out, fail, or cannot cope with an OPT record. |
| `rrsig-missing` | DNSKEY served with no RRSIG: what a DO-stripping middlebox looks like. |
| `single-ns` | One address for the zone, so there is no sibling to fall back on. |
| `signed` / `unsigned` | Whether the zone serves a signed DNSKEY at all. |

The probe rate-limits itself to one query per address per 250 ms. Pin the
output with its collection date: a corpus that silently drifts is not a
regression test.

Still worth adding: parent-served-child detection (a signed zone whose servers
answer authoritatively for an unsigned child), NSEC vs NSEC3 and algorithm
tagging, and answer-shape tags (large answers, TCP-only, wildcards, empty
non-terminals).

## Layers 2 and 3: verdict differential and flap detection

```bash
python scripts/verdict_harness.py --csv adversarial.csv -o verdicts.csv \
    --types A,MX,SOA,DNSKEY --runs 1 --escalate 8
```

Our `ValidationState` is compared with what public validators say, and each
suspicious name is re-resolved with a fresh resolver until the escalation count
is reached. The references do not expose a verdict, so each is asked twice:
`SERVFAIL` that becomes an answer under CD=1 is bogus, `NOERROR` with AD is
secure, `NOERROR` without AD is insecure.

The panel is first reduced to a verdict of its own. Each reference falls into
one of secure, bogus or insecure, and a group counts only with a two-thirds
majority behind it: with five validators, the odd one running a stale cache, a
negative trust anchor or an algorithm it will not verify cannot decide
anything on its own. A panel with no two-thirds group is `references-disagree`,
reported as a disagreement rather than quietly resolved in our favour.

Rules, each a failure rather than a report line:

| Ours | Required of the references |
|---|---|
| `SECURE` | secure holds the majority. A lone secure among four insecure is a disagreement, not agreement |
| `INSECURE` | secure does not hold the majority, or insecure also does. The dangerous direction is a signature we failed to notice |
| `BOGUS` | all but at most one refuse (SERVFAIL without CD, data with CD) |
| unavailable / failed | flagged when the references all resolved it |

Every resolution runs under the Layer 0 audit, and any name that produces more
than one distinct outcome across its runs is a failure whatever the individual
outcomes look like: a verdict that depends on which server answered first is
not a verdict. This release's original failures were 1-in-8 to 3-in-8, which is
exactly what escalation is sized for.

Still worth adding: a local validating resolver of another implementation as
ground truth (public resolvers only expose AD and SERVFAIL), and running the whole matrix with DNSSEC on *and*
off rather than DNSSEC off in every config but one.

## Layer 4: cassette replay with systematic perturbation

Run for this release: 397 cassettes over 23,320 recorded responses, 19,453
perturbed replays, no failures. Five of the mutations below are caught here
independently of the unit suite - the retrieval-failure family, which is the
class this layer exists for. The other forty-five survive it, and are meant to:
they need input the honest internet does not send.

```bash
python scripts/cassette.py record --csv adversarial.csv -o cassettes.jsonl --types A,MX
python scripts/cassette.py replay  --cassettes cassettes.jsonl   # reproduces offline
python scripts/cassette.py perturb --cassettes cassettes.jsonl   # order x fault matrix
```

`record` resolves each name for real, capturing every response, then **completes
the mesh**: it asks every nameserver that was offered for every question the
resolution asked, not only the one that happened to be picked. That is what
makes ordering replayable. `perturb` then runs, per cassette:

- one replay per server, with that server forced first;
- one replay per (server, fault) pair, faults being `timeout`, `servfail`,
  `formerr` (EDNS queries only), `empty-answer`, `no-aa`, `strip-rrsig` and
  `strip-dnssec`.

What must hold, checked on every replay along with the Layer 0 invariants:

- an **availability** fault must never change the DNSSEC verdict: the
  resolution either reproduces it from a sibling, or reports the material
  unavailable;
- a **signature-removing** fault may additionally produce BOGUS, because data
  that should be signed and is not is what tampering looks like; it must never
  produce a weaker verdict than the baseline;
- an exception that is not a `ResolverError` fails outright, whatever the
  fault and whether or not it reproduces. The README promises none escapes,
  and this is where that promise meets 19,000 adversarial replays.

`record` drops any name whose cassette does not reproduce its own baseline
offline, and says which. Three of 400 did not: zones whose nameservers disagree
with each other, so replaying with a different one first walks into a branch
the recording never entered. Keeping them would mean `replay` failing forever
and `perturb` measuring every scenario against an outcome that was never
recorded.

The retrieval bugs 0.2.0 fixes are the shape this enumerates: each depends on
which server answered first, which is exactly what forcing every order removes.
That is an argument for running it, not a report that it was. The forgeries are
out of its reach, since a cassette records what the internet said and the
internet does not send those.

Still worth adding: two simultaneous faults on distinct servers, truncation and
delay faults, and committing dated cassettes so a replay is a fixed regression
rather than a fresh recording.

## Layer 5, proposed: differential on identical inputs

Not implemented. Feed the same cassette to another implementation through a
fake authoritative server, so
both implementations see byte-identical inputs. This removes internet
nondeterminism from the comparison entirely: a disagreement here is
unambiguously a bug in one of the two, and can be filed as such.

## Layer 6: coverage attribution and mutation

```bash
python scripts/mutation_check.py --cassettes cassettes.jsonl
```

Each known defect is reintroduced into a temporary copy of the package and both
suites are re-run against it, reporting which layer catches it. A mutant that
survives every layer is a hole in the protocol. The catalogue is explicit source
rewrites, so each entry names the defect it reproduces and a rewrite that no
longer applies fails loudly instead of silently passing.

Per-layer coverage attribution is **not implemented**. The intent: a branch in
`resolver.py` or `dnssec.py` reached only by unit tests is a branch whose
real-world behaviour is unknown, and either the corpus gains a name that
reaches it or Layer 4 gains a perturbation that does. Whole-suite coverage is
enforced at 100%, which is a weaker statement than it sounds: it says every
branch runs, not that anything real ever drove it.

## Layer 7, proposed: continuous canary

Not implemented. Nightly, over a rotating 2k-name sample plus the full `disagreeing-ns-set` tag:
Layers 2 and 3 only. Track and alert on:

- verdict disagreements per 10k lookups (release gate: **0**);
- flap rate per 10k lookups (release gate: **0**);
- new `DNSSECMaterialUnavailableError` rate (informational: it is the honest
  reporting of a broken zone, but a jump means something changed here);
- p50/p99 queries per resolution and wall-clock (the fixes add queries; this is
  where that cost shows up).

Keep results as an append-only history so any regression is bisectable, and so
"the internet changed" can be distinguished from "we changed".

## Being a good netizen at this scale

- Rate-limit per authoritative server, not globally; back off on SERVFAIL.
- Prefer cassette replay for anything run more than once a day. Layers 4 and 5
  cost the network nothing.
- Never point the fault-injection layers at real servers; they run on
  cassettes.
- Cache aggressively between layers within a run; the point of Layer 3's cold
  cache is server *ordering*, which can be re-randomised without re-querying if
  the cassette is complete.

Be a good netizen on your own machine too. `--workers` is the whole story: at
64 the harness saturates a two-core box and its uplink, which is fine on a
dedicated runner and antisocial on a laptop you are also using. Measured on
two cores: 64 workers sustained about 8 lookups a second, 4 workers about 2.4,
for a load average of 0.1 instead of a wedged machine. Start at 4 and raise it
only where nothing else is competing:

```bash
python scripts/verdict_harness.py --csv corpus.csv -o verdicts.csv \
    --sample 400 --workers 4 --references 8.8.8.8,1.1.1.1
```

Each name also queries every reference resolver, so the reference list
multiplies the traffic; trim it before you raise the worker count.

## Running it before a release

```bash
make check           # unit suite, lint, types, 100% coverage gate
make test-corpus     # build the adversarial corpus          (network)
make test-verdicts   # verdict differential and flap detection (network)
make test-record     # record cassettes                       (network)
make test-offline    # replay under every order and fault, then mutate
```

`make test-protocol` runs all four in order. Each step's underlying command is
in the Makefile if you need to vary it; `test-verdicts` in particular takes
`--workers` and `--references`, and the defaults are sized for a dedicated
machine.

Gates, all of which must hold:

| Gate | Threshold |
|---|---|
| Layer 0 invariant violations, live and replayed | 0 |
| Verdict disagreements with the public validators | 0 unexplained |
| Names flapping between outcomes | 0 |
| Perturbed replays changing the verdict | 0 |
| Surviving mutants | 0 |
| Statement and branch coverage | 100% |

"0 unexplained" is the one piece of judgement in the list: the internet
supplies genuine oddities, and a disagreement is cleared either by fixing the
resolver or by writing down, in the release notes, why the reference is the one
that is wrong. Nothing is waved through silently.

## The 0.2.0 run

Three things ran, and they found different classes of defect. That is the whole
argument for doing all three.

| Method | Found |
|---|---|
| Live verdict differential against five public validators | 7 defects, all of one family |
| Clause-by-clause reading of the RFCs | 11 defects, four of them forgeries |
| Behavioural comparison against other DNS implementations | 8 defects, plus an advisory sweep that came up clean |

### The live differential

A corpus of 28,550 names over 1,444 TLDs - 12,865 gTLD, 8,143 ccTLD, 2,886
deep and service-label, 1,438 TLD apexes, 400 public-suffix, 213 reverse-tree,
167 IDN - queried across A, MX, TXT, NS, SOA, DNSKEY, DS, SRV, TLSA and CAA and
across eight resolver configurations, with every anomalous name re-resolved six
times to separate a verdict from a coin toss.

It found seven defects, all the same shape: **one bad server in an NS set
condemning a whole zone**. A parent answering a DS query with the SOA alone, a
referral carrying no denial, a server serving an old unsigned copy - each read
as evidence the zone was forged rather than as a server failing to answer.
Because NS sets are shuffled, the verdict flapped, which is exactly why
single-shot testing never caught them and why flap detection did.

The run was executed in chunks against a frozen tree, discarding any chunk that
overlapped an edit. The largest coherent aggregation was 40,500 lookups with
zero flaps, zero invariant violations and two explained disagreements. Later
passes were smaller and targeted: several sweeps of 400-640 lookups across
150-200 TLDs covering answers, denials, NS sets and service labels, all clean.

### What the differential could not find

Nothing it did could have found the four forgeries. A resolver that agrees with
every public DNS resolver on every name on the internet can still
be trivially forgeable, because none of those resolvers will ever send it the
packet that proves it. The forgeries needed a signed zone under the auditor's
control, a decoy RRSIG rdata, or a genuine public record used out of place -
inputs the honest internet does not produce.

### The spec audit

Read RFC 4033/4034/4035 §5, RFC 5011, RFC 5155 §8, RFC 6672, RFC 6840 §4-5,
RFC 8198, RFC 9077 and RFC 9276 §3.2 against the code, clause by clause, then
had three independent auditors do it again with instructions to assume the code
was wrong and the comments lied. Several comments did - one asserted that
exploiting a weakness required the zone's private key when it required two
public records, another described a Secure Entry Point check the code did not
perform.

The four forgeries it found are in the changelog. Two patterns are worth
recording for whoever maintains this next:

**Reading attacker-ordered data.** An RRSIG RRset carries several rdata in
whatever order the sender chose, and only one verified. Three separate checks
read a field off `rrsig[0]` rather than off the signature that validated, and
each was independently exploitable with a decoy. Any decision taken from a
response must come from the part of it that was verified.

**Fixing one instance of a class and not the rest.** The "wildcard at any
ancestor rather than the closest encloser" error appeared in four places:
the NXDOMAIN wildcard denial, NSEC wildcard NODATA, NSEC3 wildcard NODATA, and
the positive wildcard proof. Each was found separately, in three different
review rounds. Three of the defects introduced during this release were
introduced *by* its own fixes.

### The reference comparison

Compared against the major open-source resolver implementations, condition by
condition: their denial proofs, signature validation, iteration state machines
and response sanitisers. Eight further defects,
all in the changelog, and a long list of confirmed-conforming items that is
just as useful: the RRSIG sanity matrix, DNSKEY-to-DS handling, chain descent,
canonical ordering, NSEC3 hashing and base32hex rendering, the KeyTrap caps
(numerically in line: our 8 signature attempts per RRset is the same figure
another implementation settled on), RFC 2181 §5.4.1 trust ranking, bailiwick rules,
and the NXNSAttack and RFC 8020 defences.

One hypothesis was raised and disproved, which is worth knowing: SHA-1 DS
digests do still validate here, because `make_ds` is called with
`validating=True`. Without that argument every SHA-1-DS zone would silently
become insecure.

A separate sweep enumerated every published security advisory for the major
implementations, grouped them by mechanism, and tried each against this code.
No vulnerability. Every resource-exhaustion class is bounded, with numbers:

| Attack | Result |
|---|---|
| tsuNAME cyclic glueless NS | 21 queries, 3 ms, budget exceeded |
| NXNS 50-way glueless fan-out | 21 queries, 4 ms |
| Infinite downward referral with valid glue | 42 queries, 8 ms |
| Cross-zone CNAME chain | 11 queries, loop detected |
| Water torture, 1000 subdomains under an NXDOMAIN parent | 0 upstream queries |
| Ghost domain | delegation TTL clamped to 86400 s, not extendable |

The bulk of those advisories do not apply: C memory-safety bugs and
DNSCrypt/DoQ/DoT/proxy-protocol paths that do not exist in a pure-Python Do53
library.

### What the gentle re-run found

A 600-lookup pass over 300 names at four workers - deliberately small, and
costing a load average of 0.1 rather than saturating the machine - turned up
one verdict flap that the large runs had missed: a signed IDN TLD whose seven
nameservers included one answering from an NSEC3 chain predating the last
re-signing. Six servers proved the denial, one could not, and the verdict
followed whichever the shuffle picked. The two reference resolvers disagreed
with each other on it, which is the signature of this class.

That is the same family as the seven the original differential found, on the
one path that had not been swept yet, and it argues for small frequent runs
over occasional enormous ones: the flap detector needs repetition on the same
name, not breadth. Re-running the identical pass after the fix: zero flaps,
zero disagreements, zero invariant violations.

### What the release run found

15,932 lookups over 3,983 names, four types each, eight resolutions for
anything anomalous. It found one defect the spec audit and the reference
comparison had both missed: ten zones under two TLDs answer NOERROR/NODATA
off the parent whose only proof is an **opt-out** NSEC3 gap, with no wildcard
record and no matching NSEC3. Read strictly, RFC 5155 §8.5 proves nothing
there, and the resolver refused the answer outright. But the Opt-Out bit says
the range holds no *signed* delegation, not that it holds no names: the name
may exist, unsigned, and answer for itself. The proof is absent, not
contradicted, so §9.2 makes it insecure rather than forged. Every reference
validator returned the answer unauthenticated; we were alone in refusing it.

The shape matters more than the count. A deterministic false BOGUS on ten
live zones is the same user-visible failure as the retrieval bug 0.2.0 was
opened for, and it survived a full line-by-line audit of the RFC that
describes it, because reading §8.5 alone gives the wrong answer. Only a live
corpus put the case in front of us.

Re-running the whole pass after the fix: zero verdict flaps, zero
disagreements, zero invariant violations. Ten BOGUS verdicts remain, all of
them the deliberately-broken test zones, all agreed by every reference.

### Disagreements left standing

- **A zone whose NS set mixes signed and unsigned copies.** RFC 4035 §5.5 says
  a validator with other servers to try SHOULD try one before concluding an
  answer is forged. This resolver does not: the retry would have to replace the
  *answer*, handing the caller the RRset from the server that did sign, which
  is a change to the answer path rather than to a verdict. The one zone in the
  corpus that shows it has 3 of its 4 nameservers unreachable, and the public
  validators disagreed with themselves on it within a single run.
- **A CNAME chain load balanced across a signed and an unsigned target.** A
  14-hop chain whose last hop varies per query. The verdict follows the branch
  the query got, correctly - the chain state is the weakest link over every
  hop. One of the five references agreed with us; four got the other branch.

### Known deviations, deliberate

- **RFC 8198** (aggressive use of DNSSEC-validated cache) is a SHOULD and is
  not implemented: NSEC and NSEC3 records are not cached, so negative answers
  are never synthesised. This costs queries; it cannot cost correctness.
- **RFC 9156** QNAME minimisation is not implemented. The major implementations
  do it by default. A privacy gap, not a correctness one.
- **No per-server infrastructure cache.** The references remember round-trip
  times, EDNS capability and recent failures per address; this resolver
  re-probes on every resolution. Costs queries against dead servers.
- **No 0x20 query-name case randomisation** (optional under RFC 5452). The
  randomised query ID and source port with strict response matching meet the
  baseline.
- **Answer records are not address-filtered.** The filter covers nameserver
  addresses; a zone publishing `A 127.0.0.1` for its own name gets that
  returned, as other implementations do. Judging whether an answer is safe to
  connect to is the application's business.
- **A signature window straddling the 2106 serial wrap is refused.** The
  validity check uses RFC 1982 arithmetic as RFC 4034 §3.1.5 specifies, but
  dnspython's own comparison underneath cannot be made to accept a wrapped
  window. No such signature exists, and the horizon is around 2094.

### On the method

Every defect the spec audit found was a MUST in a document already on the
shelf. Every defect the reference comparison found was a check four other
implementations already performed. Neither set was reachable by the live
differential, and the live differential found a family of seven the other two
would have missed, plus the opt-out NODATA above, because only real DNS is
broken in the ways real DNS is broken. A release wants all three, and the
audit wants repeating whenever this code changes.

The mutation catalogue in `scripts/mutation_check.py` now holds 50 entries, one
per defect found across all three methods. Each reintroduces the original bug
into a copy of the package and confirms the suite still fails. That is the only
evidence that the tests written alongside a fix actually test it.

Getting there needed a fix to the harness itself. One mutation preserved the
file's byte length and landed in the same mtime second as the `.pyc` copied
alongside it, so Python reused the stale bytecode: the mutant never executed,
and the report called it caught. The copy now excludes `__pycache__` and
`*.pyc`, so every mutant is compiled from the mutated source. Re-run after the
fix: that mutant executes, and the suite fails on it like the rest. All 50 are
caught, and all 50 now demonstrably ran.
