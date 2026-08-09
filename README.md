# recursive-resolver

[![CI](https://github.com/sylvinus/recursive-resolver/actions/workflows/ci.yml/badge.svg)](https://github.com/sylvinus/recursive-resolver/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recursive-resolver.svg)](https://pypi.org/project/recursive-resolver/)
[![Python](https://img.shields.io/pypi/pyversions/recursive-resolver.svg)](https://pypi.org/project/recursive-resolver/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#testing)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/sylvinus/recursive-resolver/blob/main/LICENSE)

A pure-Python library that performs **true iterative DNS resolution** from the root servers, with **DNSSEC validation**. Unlike a stub resolver that forwards queries to whatever is in `/etc/resolv.conf`, this library starts at the DNS root and follows the delegation chain itself, so you see what the authoritative servers actually say, not what an intermediate cache decided to remember.

Built for high-assurance lookups where the answer matters: **DKIM and DMARC key retrieval**, SPF evaluation, certificate validation, and DNS auditing.

Uses [dnspython](https://www.dnspython.org/) for wire-format parsing, transport and DNSSEC primitives; the iteration algorithm, the security policy and the caching are implemented here.

**When not to use it.** A cold walk from the root costs several round trips, so
this is the wrong tool for ordinary application traffic: for that, keep using
your system resolver or dnspython's stub, both of which sit behind a warm
shared cache. Reach for this library when you need to know what the
authoritative servers actually say and to prove it cryptographically. Note also
that queries go over IPv4 by default, so set `ipv4_only=False` on an IPv6-only
host.

```bash
pip install recursive-resolver
```

## Quick start

```python
from recursive_resolver import RecursiveResolver

resolver = RecursiveResolver()

resolver.resolve("example.com", "A")
# ['104.20.23.154', '172.66.147.243']

answer = resolver.resolve_answer("cloudflare.com", "A")
answer.records        # ['104.16.132.229', '104.16.133.229']
answer.dnssec         # <ValidationState.SECURE: 'secure'>
answer.secure         # True
```

The addresses shown here and in the CLI examples below are a snapshot taken in
August 2026. They are live CDN records and will differ when you run this; only
the shapes and the DNSSEC verdicts are part of the API.

### Multi-chunk TXT records

This is the one API detail worth reading. A TXT record is a sequence of
`<character-string>` chunks of at most 255 octets, so any longer value **arrives
split**. RFC 6376 (DKIM) and RFC 7208 (SPF) both require the chunks to be joined
with no separator; DNS presentation format renders them as `"chunk1" "chunk2"`.
Code that strips the quotes naively corrupts the value. An RSA-2048 DKIM key
does not fit in one chunk, and publishers may split it at any boundary they
like, into two chunks or more — so the invariant to hold on to is
concatenation with no separator. This is the difference between a key that
verifies and one that never does.

```python
answer = resolver.resolve_answer("zendesk1._domainkey.zendesk.com", "TXT")

answer.text_values()   # ✅ ['v=DKIM1;t=s;n=core;k=rsa;p=MIIBIjANBgkq…'] : correct
answer.records         # ⚠️  ['"v=DKIM1;…MII" "BIjANBgkq…"']           : has a seam
answer.rrset[0].strings  # (b'v=DKIM1;…MII', b'BIjANBgkq…')            : raw chunks
```

Use `text_values()` for any TXT-like record, or `resolve_rrset()` when you need
the raw dnspython rdata objects.

## DNSSEC

Validation is **on by default** and chains from the IANA root trust anchors
(KSK-2017 and KSK-2024). Every answer carries its state:

| State | Meaning | Behaviour |
|---|---|---|
| `SECURE` | Signed and validated back to the root | Returned |
| `INSECURE` | Provably unsigned (an ancestor proved no DS exists), or signed only with an algorithm this build cannot verify | Returned |
| `BOGUS` | Claims to be signed but does not validate | **`DNSSECValidationError`** |

Only `BOGUS` is an error: most of the internet is legitimately unsigned, so
rejecting `INSECURE` would reject the majority of domains. A zone signed with
an algorithm this build cannot verify is `INSECURE` rather than `BOGUS`, per
RFC 4035 §5.2: not being able to check a zone is not evidence against it, and
treating it as an attack would take a legitimate domain off the air. If you
need authenticated data and nothing less:

```python
resolver = RecursiveResolver(require_dnssec=True)
resolver.resolve("google.com", "A")      # DNSSECInsecureError: unsigned zone
resolver.resolve("cloudflare.com", "A")  # fine: signed
```

This matters most when the record itself is a credential. A DKIM key, a CAA
policy and an SSHFP fingerprint are all trust decisions delegated to DNS, so
whoever can spoof the response picks the answer. DNSSEC closes that hole **for
signed zones whose answers validate**. It cannot close it for an unsigned zone,
and the default `RecursiveResolver()` returns those answers as `INSECURE`
rather than refusing them — so if a credential's zone must be signed for you to
trust the value, say so with `require_dnssec=True` and handle the error.

DNSSEC needs the `cryptography` package, which ships as part of the default
install. To go without it: `RecursiveResolver(dnssec=False)`.

## Caching

There is a built-in cache, on by default. It holds answers, negatives and
delegations; answers and delegations are controlled separately. That matters
because the reasons to cache each are not the same.

```python
RecursiveResolver(
    cache_enabled=True,                # master switch
    cache_answers=True,                # cache final answer RRsets
    max_delegation_cache_depth="all",  # "tld", "all", "none", or a label depth
    min_ttl=0,                         # 0 honours the wire TTL exactly
)
```

Zone cuts (root -> `com` -> `example.com`) are cached separately from answers.
**Do not turn that off in production.** With `max_delegation_cache_depth="none"`
every upstream cache miss begins with a query to a root server, which at any
real volume is abusive to the root operators and will get you rate-limited.
(Answer and negative hits still short-circuit, so this is not literally every
call — but it is every call that has to go out on the wire.)

**When freshness matters**, such as key rotation or GSLB failover, keep
delegations cached but not answers:

```python
resolver = RecursiveResolver(cache_answers=False)   # fresh answers, cheap path to them
```

To cache only the root -> TLD cuts and re-walk everything below on each query:

```python
resolver = RecursiveResolver(max_delegation_cache_depth=1)
```

Concurrent lookups of the same name are collapsed into a single walk, so a
thread pool hammering one domain does not produce N independent query storms.

## Security

This library is designed to be pointed at names an attacker controls, which is
exactly what happens when you verify DKIM on inbound mail.

- **Nameserver address filtering.** Glue records are attacker-controlled data. An address must be globally routable and none of loopback, link-local, multicast, reserved or private: classification that follows the IANA special-purpose registries rather than a hand-maintained CIDR list. A short explicit list then adds the ranges that classification still calls routable, notably Azure's `168.63.129.16`. So a hostile zone cannot steer the resolver at `127.0.0.1` or at a cloud metadata endpoint. Opt out with `allow_private_addresses=True` only for split-horizon DNS you trust.
- **Query budget.** A shared per-resolution budget bounds total queries (64), failed NS-hostname lookups (5), referrals followed (130) and NS names chased per referral (13, randomly sampled). This is the NXNSAttack / Non-Responsive-Delegation control (CVE-2020-8616, CVE-2020-12662, CVE-2022-3204); without it a hostile zone can provoke tens of thousands of upstream queries from one call.
- **Strict downward progress.** A referral must name a zone *strictly* below the one queried, and the qname must lie at or below it. Sideways and upward referrals are rejected rather than followed in circles.
- **Bailiwick from the query, not the response.** Glue is judged against the zone we asked, never against a zone name the responder supplied.
- **AA required**, answers matched on class as well as type, `NXDOMAIN`-carrying-answers rejected, truncated responses never treated as complete.
- **EDNS payload 1232** (DNS Flag Day 2020), with a downgrade ladder to 512 and then to plain DNS, so a broken-PMTU path does not silently blackhole large responses.
- **KeyTrap hardening** (CVE-2023-50387 / CVE-2023-50868). A zone publishing many DNSKEYs and RRSIGs that collide on key tag can force quadratic signature verification. At most 2 keys and 2 signatures per (tag, algorithm) are tried, at most 8 signatures per RRset, and the whole resolution is bounded to 96 signature verifications and 600 NSEC3 hashes. NSEC3 iteration counts above 100 are refused.
- **IDNA 2008.** IDNA 2003 maps `ß` to `ss`, which would resolve `straße.de` as the entirely different, separately registrable `strasse.de`.

See [SECURITY.md](https://github.com/sylvinus/recursive-resolver/blob/main/SECURITY.md) for the threat model and reporting process.

## CLI

```bash
recursive-resolver example.com                    # A records
recursive-resolver example.com MX                 # a specific type
recursive-resolver --text s1._domainkey.stripe.com TXT   # joined TXT chunks
recursive-resolver --trace example.com            # full delegation trace
recursive-resolver --json example.com MX          # JSON output
recursive-resolver --require-dnssec example.com   # fail unless authenticated
recursive-resolver 8.8.8.8 PTR                    # reverse lookup
python -m recursive_resolver example.com          # as a module
```

`recursive-resolver --help` lists every option.

The DNSSEC verdict goes to **stderr**, using the same wording as `delv`, so
that plain output is never silently unvalidated while stdout stays pipeable:

```console
$ recursive-resolver cloudflare.com A
; fully validated
104.16.132.229
104.16.133.229

$ recursive-resolver google.com A
; unsigned answer
142.251.39.174

$ recursive-resolver cloudflare.com A 2>/dev/null   # just the values
104.16.132.229
104.16.133.229
```

## API

```python
resolver.resolve(name, rdtype)         # -> list[str]      presentation format
resolver.resolve_rrset(name, rdtype)   # -> dns.rrset.RRset  raw rdata
resolver.resolve_answer(name, rdtype)  # -> Answer         records + DNSSEC state
resolver.trace_answer(name, rdtype)    # -> (Answer | None, list[TraceStep])
```

`RecursiveResolver` is thread-safe; share one instance across a thread pool to
get the benefit of the shared cache and query deduplication.

### Exceptions

Every failure is a `ResolverError`. Nothing from dnspython escapes.

| Exception | Raised when |
|---|---|
| `NXDOMAINError` | The name does not exist |
| `NoAnswerError` | The name exists but has no records of that type |
| `CNAMELoopError` | A CNAME loop or over-long chain |
| `ServfailError` | Every nameserver returned an error |
| `ResolutionTimeoutError` | Nameservers timed out, or the deadline elapsed |
| `MaxDepthError` | Delegation depth exceeded |
| `InvalidNameError` | Malformed name (bad label, too long, IDNA failure) |
| `UnsupportedRdtypeError` | Unknown or unqueryable record type |
| `QueryBudgetExceededError` | The work budget was exhausted (likely an attack) |
| `DNSSECValidationError` | Signed data failed validation: **do not use it** |
| `DNSSECInsecureError` | `require_dnssec=True` and the zone is unsigned |

## Configuration

```python
RecursiveResolver(
    timeout=2.0,                  # per-query timeout
    max_resolution_time=15.0,     # hard wall-clock cap per resolve()
    max_depth=20,                 # delegation depth
    max_cname_chain=10,           # CNAME follows
    max_retries=2,                # retries per nameserver (each downgrades EDNS)
    limits=Limits(),              # hardening limits; see below
    edns_payload=1232,
    dnssec=True,
    require_dnssec=False,
    require_authoritative=True,   # demand the AA bit
    ipv4_only=True,
    use_tcp_fallback=True,
    allow_private_addresses=False,
    extra_blocked_networks=None,  # further CIDRs to refuse, added to the built-ins
    idna_codec=None,              # defaults to IDNA 2008 (practical)
    trust_anchors=None,           # defaults to the IANA root anchors
)
```

### Limits

The bounds that stop a hostile zone from making you do unbounded work live in
one object, because they move as a set: raising `max_queries` without raising
`max_referrals` only changes which counter fires first.

```python
from recursive_resolver import Limits, RecursiveResolver

RecursiveResolver(limits=Limits(
    max_queries=64,                  # total upstream queries per resolve()
    max_ns_per_referral=13,          # NS hostnames chased per referral
    max_nx_targets=5,                # NS hostnames allowed to fail (NXNSAttack)
    max_referrals=130,               # referrals followed per resolve()
    max_signature_validations=96,    # RRSIG verifications (KeyTrap)
    max_nsec3_hashes=600,            # NSEC3 hashes (KeyTrap)
))
```

The defaults are the values Unbound and PowerDNS ship. Raise them only
against a measured legitimate name that needs the headroom.

## How it works

1. **Start at the root** (or at the deepest cached delegation) using hardcoded root hints.
2. **Query with RD=0** so servers answer only from their own authority.
3. **Follow referrals downward**, verifying at each step that the delegation descends and stays in bailiwick.
4. **Resolve glueless NS hostnames** when a referral carries no usable glue, under the shared budget.
5. **Validate DNSSEC** at every zone cut: DS against the parent's keys, DNSKEY against the DS, answers against the DNSKEY, and NSEC/NSEC3 proofs for negative answers.
6. **Chase CNAMEs**, using target records already present in the response when the server supplied them.
7. **Cache** answers, negatives (NXDOMAIN by name per RFC 2308/8020) and delegations, with TTLs from the wire and negative TTLs from the SOA.

## Testing

The suite is 520 tests at 100% coverage: 483 unit tests with mocked DNS and 37
integration tests against live DNS, including deliberately-bogus DNSSEC test
domains (`dnssec-failed.org`, `rhybar.cz`, `bogus.nlnetlabs.nl`) that must be
rejected, and real DKIM selectors that must round-trip byte-exactly.

`tests/test_security.py` is a regression test per defect found in the
pre-release audit: SSRF via glue, NXNS amplification, referral ping-pong,
upward-referral crash, truncation acceptance, and the rest.

```bash
make check              # lint, format, types and the offline tests
make check-all          # everything, including live DNS and the coverage gate
make test               # offline tests only
make test-integration   # live-DNS tests only
make coverage-all       # full coverage report (HTML in htmlcov/)
```

### Differential testing against reference resolvers

A separate harness compares this resolver against `dig` (or any reference) over
a deliberately awkward corpus: Tranco sampled across popularity bands, every
IANA TLD including the IDN ones, multi-label public suffixes, underscore
subdomains, and curated pathological cases.

```bash
python scripts/collect_domains_diverse.py -o domains.csv
python scripts/diff_harness.py --csv domains.csv
```

The most recent run: **99.76% agreement over 39,713 comparisons** (3,983 names across
10 record types). Of the 95 remaining differences, 37 are CDN answers that vary
per resolver, 16 are TLD zones publishing a rotating timestamp, 8 are zones
whose own nameservers disagree with each other, and 34 are authoritative servers
unreachable from the test host. No non-`ResolverError` exception escaped the
public API. See [CONTRIBUTING.md](https://github.com/sylvinus/recursive-resolver/blob/main/CONTRIBUTING.md) for how to read the output.

## License

MIT, © 2025-2026 Sylvain Zimmer.

Every runtime dependency is permissive (ISC, Apache-2.0/BSD, MIT-0, BSD-3-Clause);
nothing copyleft is pulled in. [THIRD-PARTY.md](https://github.com/sylvinus/recursive-resolver/blob/main/THIRD-PARTY.md) records the full
dependency licensing, the two files adapted from another MIT project, and the
terms of the data the test-corpus scripts download.

See [CHANGELOG.md](https://github.com/sylvinus/recursive-resolver/blob/main/CHANGELOG.md) for release history and
[CONTRIBUTING.md](https://github.com/sylvinus/recursive-resolver/blob/main/CONTRIBUTING.md) for the development process, the release
process and the policy on AI-assisted contributions.
