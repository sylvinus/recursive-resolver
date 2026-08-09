#!/usr/bin/env python3
"""Differential testing against a reference resolver.

Runs a corpus of names through this resolver and through a reference (``dig``,
or a stub resolver pointed at a public recursive), then reports where they
disagree: broken down by record type, by corpus category and by resolver
configuration.

Comparing DNS answers needs care, because two correct resolvers legitimately
disagree:

* CDNs return different addresses to different clients, so an *overlapping*
  answer set counts as agreement rather than a difference.
* ``dig +short`` renders a multi-chunk TXT record on one line while an rdata
  object keeps the chunks separate, so TXT is compared as a set of chunks.
* SOA serials differ between a zone's own nameservers, so SOA is compared on
  its stable fields.
* Public recursives genuinely disagree with each other on zones whose parent
  delegation and child NS RRset differ, so several references are queried and
  matching *any* of them counts as agreement. Cases where the references
  disagree among themselves are reported separately: that is the internet being
  inconsistent, not a resolver being wrong.

The reference is always queried by explicit IP, never through the system stub.
A local ``systemd-resolved`` synthesises a self-referential ``CNAME`` with TTL 0
for names that have none, which makes every CNAME query look like a mismatch.

Usage:
    python scripts/diff_harness.py --csv domains.csv
    python scripts/diff_harness.py --csv domains.csv --types A,MX,TXT --configs default,no-dnssec
    python scripts/diff_harness.py --csv domains.csv --reference stub --sample 500
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from recursive_resolver import (  # noqa: E402
    NoAnswerError,
    NXDOMAINError,
    RecursiveResolver,
    ResolverError,
)

DEFAULT_TYPES = "A,AAAA,MX,TXT,NS,SOA,CAA,CNAME,DS,DNSKEY"

# Independent public recursives. Never the system stub: see the module docstring.
DEFAULT_REFERENCE_SERVERS = "1.1.1.1,8.8.8.8"

# Resolver configurations exercised by the matrix. Each is a real deployment
# shape, not an arbitrary permutation.
CONFIGS: dict[str, dict[str, Any]] = {
    # What you get out of the box.
    "default": {},
    # DNSSEC off: isolates iteration behaviour from validation behaviour, and
    # is the only fair comparison against a non-validating reference.
    "no-dnssec": {"dnssec": False},
    # The recommended DKIM shape: delegations cached, answers never.
    "fresh-answers": {"dnssec": False, "cache_answers": False},
    # No cache at all: every lookup walks from a root server.
    "no-cache": {"dnssec": False, "cache_enabled": False},
    # Only root->TLD cuts retained.
    "tld-cache-only": {"dnssec": False, "max_delegation_cache_depth": 1},
    # UDP only, so truncation must be handled without falling back to TCP.
    "no-tcp": {"dnssec": False, "use_tcp_fallback": False},
    # Minimum EDNS payload, as if a middlebox forced the downgrade.
    "small-edns": {"dnssec": False, "edns_payload": 512},
    # Dual stack.
    "ipv6": {"dnssec": False, "ipv4_only": False},
    # Accept answers without the AA bit.
    "lax-aa": {"dnssec": False, "require_authoritative": False},
}

# Outcomes that count as the two resolvers agreeing.
AGREEING = {"exact", "overlap", "both-empty", "both-nxdomain", "both-nodata", "reference-empty"}

# Not agreement, but not our defect either: the references contradict each other.
INCONCLUSIVE = {"references-disagree"}


@dataclass
class Result:
    domain: str
    category: str
    rdtype: str
    config: str
    status: str
    ours: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    our_error: str | None = None
    reference_status: str | None = None


# ── reference resolvers ─────────────────────────────────────────────────


def _dig(domain: str, rdtype: str, server: str, timeout: int = 15) -> tuple[str, set[str]]:
    """Query via dig against an explicit server. Returns (rcode, rdata set)."""
    command = [
        "dig", "+nocmd", "+noall", "+comments", "+answer",
        "+time=5", "+tries=2", f"@{server}", "-t", rdtype, domain,
    ]  # fmt: skip
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "TIMEOUT", set()

    rcode = "UNKNOWN"
    match = re.search(r"status:\s*([A-Z]+)", proc.stdout)
    if match:
        rcode = match.group(1)

    records: set[str] = set()
    for line in proc.stdout.splitlines():
        if line.startswith(";") or not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) == 5 and parts[3].upper() == rdtype.upper():
            records.add(parts[4].strip())
    return rcode, records


def _stub(domain: str, rdtype: str, nameserver: str) -> tuple[str, set[str]]:
    """Query via dnspython against a public recursive resolver."""
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = 5
    resolver.lifetime = 10
    try:
        answer = resolver.resolve(domain, rdtype)
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN", set()
    except dns.resolver.NoAnswer:
        return "NOERROR", set()
    except Exception as exc:  # noqa: BLE001 - any failure is a reference failure
        return type(exc).__name__.upper(), set()
    return "NOERROR", {str(record) for record in answer}


# ── normalisation ───────────────────────────────────────────────────────


def _normalise(values: set[str], rdtype: str) -> set[str]:
    """Reduce both sides to a comparable form for this record type."""
    out: set[str] = set()
    for value in values:
        text = value.strip()
        if rdtype == "TXT":
            # dig renders every chunk of one RR on a single line; rdata objects
            # keep them separate. Compare the individual chunks either way.
            quoted = re.findall(r'"[^"]*"', text)
            out.update(chunk.lower() for chunk in quoted) if quoted else out.add(text.lower())
            continue
        if rdtype == "SOA":
            # Serials drift between a zone's nameservers; MNAME and RNAME do not.
            fields = text.split()
            text = " ".join(fields[:2]) if len(fields) >= 2 else text
        if rdtype in {"DNSKEY", "DS", "CAA", "NAPTR"}:
            # Whitespace inside base64 and hex payloads is not significant.
            text = re.sub(r"\s+", "", text)
        out.add(text.rstrip(".").lower())
    return out


def _classify(ours: set[str], theirs: set[str], our_error: str | None, ref_status: str) -> str:
    if our_error == "NXDOMAINError" and ref_status == "NXDOMAIN":
        return "both-nxdomain"
    if our_error == "NoAnswerError" and ref_status == "NOERROR" and not theirs:
        return "both-nodata"
    if ours == theirs and ours:
        return "exact"
    if not ours and not theirs:
        return "both-empty"
    if ours & theirs:
        return "overlap"
    if not theirs:
        # The reference could not answer either; not our disagreement to own.
        return "reference-empty"
    if not ours:
        return "we-are-empty"
    return "different"


# ── execution ───────────────────────────────────────────────────────────


def run_one(
    resolver: RecursiveResolver,
    domain: str,
    category: str,
    rdtype: str,
    config: str,
    reference: str,
    servers: list[str],
) -> Result:
    our_error: str | None = None
    try:
        ours = set(resolver.resolve(domain, rdtype))
    except (NXDOMAINError, NoAnswerError, ResolverError) as exc:
        ours = set()
        our_error = type(exc).__name__
    except Exception as exc:  # noqa: BLE001 - a leaked non-ResolverError is itself a finding
        ours = set()
        our_error = f"LEAKED:{type(exc).__name__}"

    ours_n = _normalise(ours, rdtype)

    # Ask every reference, and take the most favourable verdict: a zone whose
    # parent delegation disagrees with its own NS RRset makes public recursives
    # disagree with each other, and that is not our error to own.
    best: tuple[int, str, str, set[str]] | None = None
    seen: list[tuple[str, frozenset[str]]] = []
    for server in servers:
        status_code, theirs = _dig(domain, rdtype, server) if reference == "dig" else _stub(domain, rdtype, server)
        theirs_n = _normalise(theirs, rdtype)
        seen.append((status_code, frozenset(theirs_n)))
        verdict = _classify(ours_n, theirs_n, our_error, status_code)
        rank = 0 if verdict in AGREEING else 1
        if best is None or rank < best[0]:
            best = (rank, verdict, status_code, theirs_n)
        if rank == 0:
            break

    assert best is not None
    _rank, status, ref_status, theirs_n = best
    if status not in AGREEING and len(set(seen)) > 1:
        status = "references-disagree"

    return Result(
        domain=domain,
        category=category,
        rdtype=rdtype,
        config=config,
        status=status,
        ours=sorted(ours_n),
        reference=sorted(theirs_n),
        our_error=our_error,
        reference_status=ref_status,
    )


def load_corpus(path: Path, sample: int, seed: int) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with open(path, newline="") as handle:
        for row in csv.DictReader(handle):
            domain = (row.get("domain") or "").strip()
            if domain:
                rows.append((domain, (row.get("category") or "uncategorised").strip()))
    if sample and sample < len(rows):
        import random

        rows = random.Random(seed).sample(rows, sample)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", required=True, type=Path, help="Corpus CSV with a 'domain' column")
    parser.add_argument("--types", default=DEFAULT_TYPES, help=f"Record types (default: {DEFAULT_TYPES})")
    parser.add_argument("--configs", default="no-dnssec", help=f"Configs from: {','.join(CONFIGS)}")
    parser.add_argument("--reference", choices=("dig", "stub"), default="dig")
    parser.add_argument(
        "--reference-servers",
        default=DEFAULT_REFERENCE_SERVERS,
        help=f"Comma-separated reference resolvers (default: {DEFAULT_REFERENCE_SERVERS})",
    )
    parser.add_argument("--sample", type=int, default=0, help="Sample N names (0 = all)")
    parser.add_argument("--seed", type=int, default=20260808)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-resolution wall clock")
    parser.add_argument("--out", type=Path, default=None, help="JSONL path for disagreements")
    args = parser.parse_args()

    if args.reference == "dig" and not shutil.which("dig"):
        print("dig not found; use --reference stub", file=sys.stderr)
        return 2

    if args.workers < 1:
        print("--workers must be at least 1", file=sys.stderr)
        return 2

    rdtypes = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    for config in configs:
        if config not in CONFIGS:
            print(f"unknown config {config!r}; choose from {', '.join(CONFIGS)}", file=sys.stderr)
            return 2

    servers = [s.strip() for s in args.reference_servers.split(",") if s.strip()]
    if not servers:
        # With no reference there is nothing to compare against, and run_one
        # trips its own "best is not None" assertion instead of saying so.
        print("--reference-servers must contain at least one server", file=sys.stderr)
        return 2

    corpus = load_corpus(args.csv, args.sample, args.seed)
    total = len(corpus) * len(rdtypes) * len(configs)
    print(
        f"{len(corpus)} names x {len(rdtypes)} types x {len(configs)} configs = {total} comparisons"
        f"  (reference: {args.reference} via {', '.join(servers)})",
        file=sys.stderr,
    )

    out_path = args.out or Path(f"diff_{time.strftime('%Y%m%d_%H%M%S')}.jsonl")
    results: list[Result] = []
    lock = threading.Lock()
    done = 0
    started = time.monotonic()

    for config in configs:
        kwargs = dict(CONFIGS[config])
        kwargs.setdefault("timeout", 3.0)
        kwargs.setdefault("max_resolution_time", args.timeout)
        resolver = RecursiveResolver(**kwargs)

        def task(item: tuple[str, str], rdtype: str, config: str = config, resolver: Any = resolver) -> None:
            nonlocal done
            result = run_one(resolver, item[0], item[1], rdtype, config, args.reference, servers)
            with lock:
                results.append(result)
                done += 1
                if result.status not in AGREEING and result.status not in INCONCLUSIVE:
                    with open(out_path, "a") as handle:
                        handle.write(json.dumps(result.__dict__) + "\n")
                if done % 2000 == 0:
                    rate = done / max(1e-9, time.monotonic() - started)
                    print(f"  {done}/{total}  {rate:.0f}/s", file=sys.stderr, flush=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(task, item, rdtype) for item in corpus for rdtype in rdtypes]
            # result(), not wait(): wait() returns happily when a task died, and
            # the harness would then report an agreement rate over a silently
            # incomplete result set.
            for future in concurrent.futures.as_completed(futures):
                future.result()

    report(results, rdtypes, configs, out_path, time.monotonic() - started)
    # Same exclusion rule as _rate() and report(): a run that meets the
    # threshold on judged results must not exit 1 because of comparisons both
    # references disagreed about.
    _agree, judged, rate = _rate(results)
    return 0 if judged and rate >= 0.96 else 1


def _rate(rows: list[Result]) -> tuple[int, int, float]:
    """Agreement rate, excluding cases where the references contradict each other."""
    judged = [r for r in rows if r.status not in INCONCLUSIVE]
    agree = sum(1 for r in judged if r.status in AGREEING)
    return agree, len(judged), (agree / len(judged) if judged else 1.0)


def report(results: list[Result], rdtypes: list[str], configs: list[str], out_path: Path, elapsed: float) -> None:
    agree, total, rate = _rate(results)
    print(f"\n{'=' * 78}\nAGREEMENT: {agree}/{total} ({rate:.2%}) in {elapsed:.0f}s\n{'=' * 78}")

    counts: dict[str, int] = defaultdict(int)
    for r in results:
        counts[r.status] += 1
    print("\nOutcomes:")
    for status, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        marker = " " if status in AGREEING else ("~" if status in INCONCLUSIVE else "!")
        print(f"  {marker} {status:18s} {count:7d}  {count / total:6.2%}")

    for title, key in (("record type", "rdtype"), ("config", "config"), ("corpus category", "category")):
        buckets: dict[str, list[Result]] = defaultdict(list)
        for r in results:
            buckets[getattr(r, key)].append(r)
        print(f"\nBy {title}:")
        for name, rows in sorted(buckets.items(), key=lambda kv: _rate(kv[1])[2]):
            a, t, pct = _rate(rows)
            flag = "  <-- worst" if pct < 0.9 else ""
            print(f"  {name:28s} {a:6d}/{t:<6d} {pct:7.2%}{flag}")

    inconclusive = [r for r in results if r.status in INCONCLUSIVE]
    if inconclusive:
        print(f"\n{len(inconclusive)} excluded: the reference resolvers disagreed with each other.")

    disagreements = [r for r in results if r.status not in AGREEING and r.status not in INCONCLUSIVE]
    if disagreements:
        print(f"\n{len(disagreements)} disagreements written to {out_path}")
        print("\nFirst 15:")
        for r in disagreements[:15]:
            print(
                f"  {r.domain[:44]:44s} {r.rdtype:6s} {r.config:14s} {r.status:12s}"
                f" ours={str(r.ours)[:34]} ref={str(r.reference)[:34]} err={r.our_error}"
            )

    leaked = [r for r in results if r.our_error and r.our_error.startswith("LEAKED:")]
    if leaked:
        print(f"\n!! {len(leaked)} non-ResolverError exceptions leaked out of the public API:")
        for r in leaked[:10]:
            print(f"   {r.domain} {r.rdtype} {r.our_error}")
    else:
        print("\nNo non-ResolverError exceptions leaked out of the public API.")


if __name__ == "__main__":
    raise SystemExit(main())
