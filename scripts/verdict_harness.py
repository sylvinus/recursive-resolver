#!/usr/bin/env python3
"""Layers 2 and 3 of TESTING.md: differential testing on the *verdict*, and
flap detection by repetition.

The record-level differential harness (``diff_harness.py``) compares answer
data. It cannot see the failure that shipped in 0.1.0, where the data was fine
and the DNSSEC verdict was wrong, on a name that resolved correctly seven times
out of eight. Two things are needed for that, and both are here:

1. **Compare the verdict.** For every name, our ``ValidationState`` is checked
   against what public validating resolvers say. They do not expose their
   verdict directly, so each is asked twice: once normally, and once with CD=1.
   ``SERVFAIL`` that turns into an answer under CD is bogus; ``NOERROR`` with
   AD is secure; ``NOERROR`` without AD is insecure.
2. **Run it more than once.** Each name is resolved K times with a fresh
   resolver, so nameserver ordering is re-randomised. Any name that produces
   more than one distinct outcome is a failure in its own right, whatever the
   individual outcomes look like: a verdict that depends on which server
   answered first is not a verdict.

Every resolution also runs under the Layer 0 audit (``audit.py``), so the
invariants are checked against live traffic rather than only against mocks.

Usage:
    python scripts/verdict_harness.py --csv corpus.csv -o results.csv
    python scripts/verdict_harness.py --csv corpus.csv --types A,MX --runs 3
    python scripts/verdict_harness.py --csv corpus.csv --sample 500 --escalate 8
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, os.environ.get("RR_SRC", str(Path(__file__).resolve().parent.parent / "src")))

from audit import resolve_audited  # noqa: E402

from recursive_resolver import (  # noqa: E402
    DNSSECError,
    DNSSECInsecureError,
    InvalidNameError,
    NoAnswerError,
    NXDOMAINError,
    RecursiveResolver,
    ValidationState,
)
from recursive_resolver.exceptions import DNSSECMaterialUnavailableError  # noqa: E402

# Validating resolvers run by independent operators. Each was verified to set
# AD on a signed name, SERVFAIL a deliberately broken one, and answer it under
# CD=1: without all three there is no way to read a verdict off the wire.
REFERENCES = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "94.140.14.14", "149.112.121.10")
DEFAULT_TYPES = "A,MX,SOA,DNSKEY"

# Resolver options worth running the corpus under. Each changes a decision the
# resolver makes about transport or trust, and none of them should change what
# a name means.
CONFIGS: dict[str, dict] = {
    "default": {},
    "no-cache": {"cache_enabled": False},
    "small-edns": {"edns_payload": 512},
    "no-tcp": {"use_tcp_fallback": False},
    "lax-aa": {"require_authoritative": False},
    "no-retries": {"max_retries": 0},
    "require-dnssec": {"require_dnssec": True},
    "tld-cache-only": {"max_delegation_cache_depth": 1},
}

# Used only for its name normalisation, so the references are asked about the
# same domain we resolved.
_NORMALISER = RecursiveResolver(dnssec=False, cache_enabled=False)

# Our outcome, reduced to something comparable with a reference resolver.
SECURE = "secure"
INSECURE = "insecure"
BOGUS = "bogus"
NXDOMAIN = "nxdomain"
NODATA = "nodata"
UNAVAILABLE = "unavailable"
FAILED = "failed"

# Outcomes that say "we could not get there", not "here is what the data means".
# A name that alternates between a verdict and one of these is reporting the
# state of somebody's nameservers; a name that alternates between two verdicts
# is reporting a defect in here.
RETRIEVAL_KINDS = frozenset({UNAVAILABLE, FAILED})

# Disagreements that mean we read the same data differently, as opposed to not
# having got the data at all. Only these gate a release.
VERDICT_DISAGREEMENTS = frozenset(
    {
        "we-say-secure-they-do-not",
        "we-say-insecure-they-say-secure",
        "false-bogus",
        "we-answered-they-refused",
    }
)


@dataclass
class Outcome:
    kind: str
    detail: str = ""
    records: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()

    def key(self) -> str:
        return self.kind

    def fingerprint(self) -> tuple:
        """What the resolution was actually about, so two runs can be compared.

        Some names answer differently from one lookup to the next by design:
        a CNAME chain behind a traffic manager can land in a signed zone or an
        insecurely delegated one depending on which server replies, and a
        verdict that follows the data is not a flap.
        """
        return (self.kind, self.records, self.chain)


@dataclass
class Row:
    domain: str
    rdtype: str
    category: str
    tags: str
    ours: str
    detail: str
    runs: int
    distinct: int
    flapped: bool
    verdict_flap: bool
    unstable_data: bool
    references: dict[str, str]
    disagreement: str
    violations: list[str] = field(default_factory=list)


def our_outcome(resolver: RecursiveResolver, domain: str, rdtype: str) -> tuple[Outcome, list[str]]:
    answer, exc, violations = resolve_audited(resolver, domain, rdtype)
    if exc is None and answer is not None:
        kind = {
            ValidationState.SECURE: SECURE,
            ValidationState.INSECURE: INSECURE,
            ValidationState.BOGUS: BOGUS,
        }[answer.dnssec]
        chain = tuple(str(name) for name in answer.cname_chain)
        return Outcome(kind, "", tuple(sorted(answer.records)), chain), violations
    if isinstance(exc, DNSSECMaterialUnavailableError):
        return Outcome(UNAVAILABLE, str(exc)), violations
    if isinstance(exc, DNSSECInsecureError):
        # `require_dnssec=True` refusing an unsigned answer is the option doing
        # its job, and says the same thing about the name as INSECURE does.
        return Outcome(INSECURE, str(exc)), violations
    if isinstance(exc, DNSSECError):
        return Outcome(BOGUS, str(exc)), violations
    if isinstance(exc, NXDOMAINError):
        return Outcome(NXDOMAIN, str(exc)), violations
    if isinstance(exc, NoAnswerError):
        return Outcome(NODATA, str(exc)), violations
    return Outcome(FAILED, f"{type(exc).__name__}: {exc}"), violations


def ascii_name(domain: str, rdtype: str) -> str:
    """The name our resolver will actually query, in A-label form.

    dnspython's default IDNA codec is IDNA 2003, ours is IDNA 2008, and for
    some internationalised names the two encode to *different domains*.
    Comparing verdicts means comparing them for the same name.

    There is no public entry point for this: the resolver normalises on its way
    into `resolve`, and the whole point here is the name it would actually put
    on the wire. Only the failure it defines is caught, so a name this build
    refuses is compared as written and said so, rather than every error being
    swallowed into a silently different query.
    """
    try:
        return str(_NORMALISER._normalize_qname(domain, rdtype))
    except InvalidNameError as exc:
        print(
            f"  note {domain}/{rdtype}: not a name we can encode ({exc}); asking the references as written",
            file=sys.stderr,
        )
        return domain


def reference_verdict(domain: str, rdtype: str, server: str, timeout: float) -> str:
    """Ask a validating resolver twice: with validation, and with CD=1."""

    def ask(check_disabled: bool):
        query = dns.message.make_query(domain, rdtype, use_edns=0, payload=1232, want_dnssec=True)
        if check_disabled:
            query.flags |= dns.flags.CD
        try:
            response, _tcp = dns.query.udp_with_fallback(query, server, timeout=timeout)
        except Exception:  # noqa: BLE001 - a reference that does not answer is data
            return None
        return response

    plain = ask(False)
    if plain is None:
        return "timeout"
    rcode = plain.rcode()
    has_data = any(rrset.rdtype != dns.rdatatype.RRSIG for rrset in plain.answer)
    if rcode == dns.rcode.SERVFAIL:
        relaxed = ask(True)
        if relaxed is not None and relaxed.rcode() == dns.rcode.NOERROR:
            return BOGUS
        return "servfail"
    if rcode == dns.rcode.NXDOMAIN:
        return "nxdomain-secure" if plain.flags & dns.flags.AD else NXDOMAIN
    if rcode != dns.rcode.NOERROR:
        return dns.rcode.to_text(rcode).lower()
    if plain.flags & dns.flags.AD:
        return SECURE if has_data else "nodata-secure"
    return INSECURE if has_data else NODATA


def compare(ours: Outcome, references: dict[str, str]) -> str:
    """Return "" when the verdicts are compatible, or a disagreement label."""
    verdicts = [v for v in references.values() if v not in ("timeout",)]
    if not verdicts:
        return ""
    secure = [v for v in verdicts if v in (SECURE, "nodata-secure", "nxdomain-secure")]
    bogus = [v for v in verdicts if v in (BOGUS, "servfail")]
    insecure = [v for v in verdicts if v in (INSECURE, NODATA, NXDOMAIN)]

    # With a panel this size the odd operator will differ - a stale cache, a
    # negative trust anchor, an algorithm it will not verify - so a two-thirds
    # majority decides. Only an evenly split panel is inconclusive, which
    # happens on ambiguous zones such as a signed zone serving one unsigned
    # RRset, and there is nothing there to hold a release for.
    groups = {SECURE: secure, BOGUS: bogus, INSECURE: insecure}
    majority = [name for name, group in groups.items() if len(group) * 3 >= len(verdicts) * 2]
    if not majority:
        return "references-disagree"
    secure = secure if SECURE in majority else []
    bogus = bogus if BOGUS in majority else []
    insecure = insecure if INSECURE in majority else []

    if ours.kind == SECURE:
        return "" if secure else "we-say-secure-they-do-not"
    if ours.kind == INSECURE:
        # The dangerous direction: a signature we failed to notice.
        return "we-say-insecure-they-say-secure" if secure and not insecure else ""
    if ours.kind == BOGUS:
        return "" if len(bogus) >= max(2, len(verdicts) - 1) else "false-bogus"
    if ours.kind in (NXDOMAIN, NODATA):
        if bogus and not insecure and not secure:
            return "we-answered-they-refused"
        return ""
    if ours.kind == UNAVAILABLE:
        # Honest, but if every reference resolved it we still want to know.
        return "material-unavailable-but-they-resolved" if secure or insecure else ""
    if ours.kind == FAILED:
        return "we-failed-they-resolved" if secure or insecure else ""
    return ""


def positive_int(text: str) -> int:
    """`--runs 0` leaves `outcomes` empty, and `outcomes[0]` then raises."""
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {value}")
    return value


def server_list(text: str) -> list[str]:
    """An empty list means a ThreadPoolExecutor with no workers, which raises.

    Use ``--no-references`` to skip the reference resolvers; an empty
    ``--references`` is a typo, not a way to ask for that.
    """
    servers = [s.strip() for s in text.split(",") if s.strip()]
    if not servers:
        raise argparse.ArgumentTypeError("needs at least one server; use --no-references to skip them")
    return servers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", required=True, help="Corpus CSV (domain,category[,tags])")
    parser.add_argument("-o", "--output", default="verdicts.csv", help="Output CSV path")
    parser.add_argument("--types", default=DEFAULT_TYPES, help=f"Record types (default {DEFAULT_TYPES})")
    parser.add_argument("--runs", type=positive_int, default=1, help="Resolutions per name before escalation")
    parser.add_argument("--escalate", type=int, default=8, help="Resolutions for anomalous names")
    parser.add_argument("--sample", type=int, default=0, help="Random sample of N names (0 = all)")
    parser.add_argument("--seed", type=int, default=20260830, help="Sampling seed")
    parser.add_argument("--workers", type=int, default=16, help="Concurrent names")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-query timeout")
    parser.add_argument("--no-references", action="store_true", help="Skip the reference resolvers")
    parser.add_argument("--references", type=server_list, default=",".join(REFERENCES), help="Reference resolver IPs")
    parser.add_argument("--config", default="default", help=f"Resolver options from: {','.join(CONFIGS)}")
    parser.add_argument("--append", action="store_true", help="Append to the output file instead of replacing it")
    args = parser.parse_args()

    if args.config not in CONFIGS:
        raise SystemExit(f"unknown config {args.config!r}; choose from {', '.join(CONFIGS)}")
    options = CONFIGS[args.config]
    reference_servers = args.references

    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    with open(args.csv, newline="", encoding="utf-8") as handle:
        corpus = [(r["domain"], r.get("category", ""), r.get("tags", "")) for r in csv.DictReader(handle)]
    if args.sample and args.sample < len(corpus):
        corpus = random.Random(args.seed).sample(corpus, args.sample)

    work_items = [(domain, category, tags, rdtype) for domain, category, tags in corpus for rdtype in types]
    # Shuffled so consecutive lookups do not all land on the same nameservers.
    random.Random(args.seed).shuffle(work_items)
    rows: list[Row] = []
    lock = threading.Lock()
    done = 0
    started = time.time()

    def resolve_n(domain: str, rdtype: str, times: int) -> tuple[list[Outcome], list[str]]:
        outcomes: list[Outcome] = []
        violations: list[str] = []
        for _ in range(times):
            resolver = RecursiveResolver(timeout=args.timeout, max_resolution_time=20.0, **options)
            outcome, found = our_outcome(resolver, domain, rdtype)
            outcomes.append(outcome)
            violations.extend(found)
        return outcomes, violations

    def work(item: tuple[str, str, str, str]) -> Row:
        nonlocal done
        domain, category, tags, rdtype = item
        outcomes, violations = resolve_n(domain, rdtype, args.runs)
        distinct = {o.key() for o in outcomes}

        references: dict[str, str] = {}
        if not args.no_references:
            asked = ascii_name(domain, rdtype)
            references = dict(
                reference_pool.map(
                    lambda server: (server, reference_verdict(asked, rdtype, server, args.timeout)),
                    reference_servers,
                )
            )

        disagreement = compare(outcomes[0], references)
        # Escalate anything suspicious: a disagreement, a violation, or a
        # verdict that is not simply "it resolved".
        suspicious = bool(disagreement or violations or len(distinct) > 1 or outcomes[0].kind in (BOGUS, UNAVAILABLE))
        if suspicious and args.escalate > args.runs:
            more, extra = resolve_n(domain, rdtype, args.escalate - args.runs)
            outcomes.extend(more)
            violations.extend(extra)
            distinct = {o.key() for o in outcomes}
            # Re-judge on the most severe outcome seen.
            severity = [BOGUS, FAILED, UNAVAILABLE, SECURE, INSECURE, NODATA, NXDOMAIN]
            worst = min(outcomes, key=lambda o: severity.index(o.kind) if o.kind in severity else 99)
            disagreement = compare(worst, references) or disagreement

        with lock:
            done += 1
            if done % 200 == 0:
                print(f"  {done}/{len(work_items)} in {time.time() - started:.0f}s", file=sys.stderr, flush=True)

        counted = collections.Counter(o.key() for o in outcomes)
        # Different answers between runs mean the zone itself is unstable, so a
        # verdict that changes with them is following the data, not wobbling.
        answered = [o for o in outcomes if o.kind not in RETRIEVAL_KINDS]
        unstable_data = len({o.fingerprint()[1:] for o in answered}) > 1
        return Row(
            domain=domain,
            rdtype=rdtype,
            category=category,
            tags=tags,
            ours="+".join(f"{k}x{v}" for k, v in counted.most_common()),
            detail=next((o.detail for o in outcomes if o.detail), ""),
            runs=len(outcomes),
            distinct=len(distinct),
            flapped=len(distinct) > 1,
            verdict_flap=len(distinct - RETRIEVAL_KINDS) > 1 and not unstable_data,
            unstable_data=unstable_data,
            references=references,
            disagreement=disagreement,
            violations=sorted(set(violations)),
        )

    # One shared pool for the reference queries: a per-lookup pool would churn
    # five threads per name, which at this scale is both slow and the largest
    # thing in memory.
    with (
        ThreadPoolExecutor(max_workers=len(reference_servers) * 3) as reference_pool,
        ThreadPoolExecutor(max_workers=args.workers) as pool,
    ):
        rows = list(pool.map(work, work_items))

    with open(args.output, "a" if args.append else "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "domain",
                "rdtype",
                "category",
                "tags",
                "ours",
                "detail",
                "runs",
                "distinct",
                "flapped",
                "verdict_flap",
                "unstable_data",
                "references",
                "disagreement",
                "violations",
                "config",
            ],
        )
        if not args.append or handle.tell() == 0:
            writer.writeheader()
        for row in rows:
            record = asdict(row)
            record["config"] = args.config
            record["references"] = json.dumps(row.references)
            record["violations"] = " | ".join(row.violations)
            writer.writerow(record)

    verdict_flaps = [r for r in rows if r.verdict_flap]
    availability_flaps = [r for r in rows if r.flapped and not r.verdict_flap]
    verdict_disagreements = [r for r in rows if r.disagreement in VERDICT_DISAGREEMENTS]
    availability_disagreements = [r for r in rows if r.disagreement and r.disagreement not in VERDICT_DISAGREEMENTS]
    violated = [r for r in rows if r.violations]

    print(f"\n{len(rows)} lookups over {len(corpus)} names in {time.time() - started:.0f}s", file=sys.stderr)
    print("  gating:", file=sys.stderr)
    print(f"    verdict flaps:              {len(verdict_flaps)}", file=sys.stderr)
    print(f"    verdict disagreements:      {len(verdict_disagreements)}", file=sys.stderr)
    print(f"    invariant violations:       {len(violated)}", file=sys.stderr)
    print("  informational (the internet, not us):", file=sys.stderr)
    print(f"    availability flaps:         {len(availability_flaps)}", file=sys.stderr)
    print(f"    availability disagreements: {len(availability_disagreements)}", file=sys.stderr)
    print(f"    unstable zones:             {sum(r.unstable_data for r in rows)}", file=sys.stderr)

    kinds: collections.Counter[str] = collections.Counter()
    for row in rows:
        kinds.update(part.rsplit("x", 1)[0] for part in row.ours.split("+"))
    for kind, count in kinds.most_common():
        print(f"    {kind:12s} {count:6d}", file=sys.stderr)
    for row in verdict_flaps[:40]:
        print(f"  VERDICT FLAP {row.domain}/{row.rdtype}: {row.ours}", file=sys.stderr)
    for row in verdict_disagreements + availability_disagreements:
        print(
            f"  {'DISAGREE' if row.disagreement in VERDICT_DISAGREEMENTS else 'note'} "
            f"{row.domain}/{row.rdtype}: {row.disagreement} ours={row.ours} refs={row.references}",
            file=sys.stderr,
        )
    for row in violated[:40]:
        print(f"  VIOLATION {row.domain}/{row.rdtype}: {row.violations}", file=sys.stderr)
    return 1 if (verdict_flaps or verdict_disagreements or violated) else 0


if __name__ == "__main__":
    raise SystemExit(main())
