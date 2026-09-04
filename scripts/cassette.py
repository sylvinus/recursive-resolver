#!/usr/bin/env python3
"""Layer 4 of TESTING.md: record real DNS traffic, then replay it under every
server order and every server fault.

Live testing can only observe the internet as it happened to be at that moment,
and the resolver picks a nameserver at random, so a defect that depends on
which server answers first shows up as a coin flip. This records every
nameserver's answer for every query a resolution made, then replays the
resolution offline with the order fixed and with faults injected one at a time.
"Which server answered first" stops being luck and becomes an enumerated
variable.

Three commands:

``record``
    Resolve each name for real, capturing every (server, qname, type) response.
    Then complete the mesh: ask *every* nameserver that was offered for each
    query, not only the one that happened to be picked, so a replay can put any
    of them first. Then close it: replay under each order, record whatever the
    replay could not answer, and repeat, because a different first server makes
    the resolver ask questions the original resolution never had to.
``replay``
    Re-run each recorded resolution offline and check it reproduces.
``perturb``
    Re-run each resolution once per server order and once per (server, fault)
    pair, checking the Layer 0 invariants and the transition rules below.

What must hold under a fault affecting one server:

* An **availability** fault (timeout, SERVFAIL, FORMERR, empty answer, no AA)
  must never change the DNSSEC verdict. The resolution either produces the same
  outcome from a sibling, or fails to retrieve - never a different verdict.
* A **signature-removing** fault may additionally produce BOGUS: an answer that
  should be signed and is not is exactly what tampering looks like. It must
  never produce a *weaker* verdict than the baseline, because that would be a
  silent downgrade.

Usage:
    python scripts/cassette.py record --csv corpus.csv -o cassettes.jsonl --sample 300
    python scripts/cassette.py replay --cassettes cassettes.jsonl
    python scripts/cassette.py perturb --cassettes cassettes.jsonl
"""

from __future__ import annotations

import argparse
import base64
import collections
import csv
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, os.environ.get("RR_SRC", str(Path(__file__).resolve().parent.parent / "src")))

from audit import audited  # noqa: E402

from recursive_resolver import (  # noqa: E402
    DNSSECError,
    RecursiveResolver,
    ResolverError,
)
from recursive_resolver.exceptions import (  # noqa: E402
    DNSSECMaterialUnavailableError,
    DNSSECValidationError,
    NoAnswerError,
    NXDOMAINError,
    QueryBudgetExceededError,
    ResolutionTimeoutError,
    ServfailError,
)
from recursive_resolver.resolver import _RetryableError  # noqa: E402

TIMEOUT = "timeout"
MESH_LIMIT = 6  # addresses probed per (qname, type); keeps root fan-out bounded
CLOSURE_ROUNDS = 6  # passes of "replay, then record what the replay could not answer"
# Each pass reaches one level further, so a CNAME redirected into a zone the
# original resolution never entered needs several: root, TLD, that zone's
# nameservers, then the name itself.

AVAILABILITY_FAULTS = ("timeout", "servfail", "formerr", "empty-answer", "no-aa")
SIGNATURE_FAULTS = ("strip-rrsig", "strip-dnssec")
FAULTS = AVAILABILITY_FAULTS + SIGNATURE_FAULTS

# Outcomes that mean "could not get there from here" rather than a verdict.
RETRIEVAL_FAILURES = (
    DNSSECMaterialUnavailableError,
    ResolutionTimeoutError,
    ServfailError,
    QueryBudgetExceededError,
)


def outcome_of(answer, exc) -> str:
    if exc is None:
        return f"ok/{answer.dnssec.value}"
    if isinstance(exc, DNSSECValidationError):
        return "bogus"
    if isinstance(exc, RETRIEVAL_FAILURES):
        return "unavailable"
    if isinstance(exc, NXDOMAINError):
        return "nxdomain"
    if isinstance(exc, NoAnswerError):
        return "nodata"
    if isinstance(exc, DNSSECError):
        return "bogus"
    if isinstance(exc, ResolverError):
        # A real resolver error this function has no separate bucket for -
        # MaxDepthError, CNAMELoopError and the like. Legitimate, and a fault
        # can legitimately turn one into another.
        return f"error/{type(exc).__name__}"
    # Not a ResolverError at all. README: "Every failure is a `ResolverError`.
    # Nothing from dnspython escapes." This is the layer with 19,000 adversarial
    # replays in it, so it is the place that promise gets tested.
    return f"leaked/{type(exc).__name__}"


def key_of(qname, rdtype, server: str) -> str:
    return f"{qname}|{dns.rdatatype.to_text(rdtype)}|{server}"


def positive_int(text: str) -> int:
    """ThreadPoolExecutor refuses a worker count below one."""
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {value}")
    return value


# ── record ──────────────────────────────────────────────────────────────────


def record_case(domain: str, rdtype: str, timeout: float) -> dict | None:
    resolver = RecursiveResolver(timeout=timeout, max_resolution_time=25.0, cache_enabled=False)
    entries: dict[str, str] = {}
    offers: list[tuple[str, int, list[str]]] = []

    real_send = resolver._send_query
    real_query = resolver._query_once

    def send_query(qname, rdtype_, nameservers, ctx, usable=None):
        offers.append((str(qname), int(rdtype_), resolver.address_filter.filter(nameservers)))
        return real_send(qname, rdtype_, nameservers, ctx, usable=usable)

    def query_once(qname, rdtype_, server, payload, timeout_, ctx):
        response = real_query(qname, rdtype_, server, payload, timeout_, ctx)
        entries.setdefault(key_of(qname, rdtype_, server), base64.b64encode(response.to_wire()).decode("ascii"))
        return response

    resolver._send_query = send_query  # type: ignore[method-assign]
    resolver._query_once = query_once  # type: ignore[method-assign]
    try:
        answer = resolver.resolve_answer(domain, rdtype)
        baseline = outcome_of(answer, None)
        records = sorted(answer.records)
    except ResolverError as exc:
        baseline = outcome_of(None, exc)
        records = []
    except Exception as exc:  # noqa: BLE001 - not a ResolverError, so not an outcome
        # `outcome_of` has a bucket for this and `transition_allowed` refuses
        # it, but neither is reached if the name never becomes a cassette.
        # Dropping it silently makes the corpus smaller and says nothing.
        print(f"  {domain}/{rdtype}: leaked {type(exc).__name__}: {exc}", file=sys.stderr)
        return None

    # Complete the mesh: every server that was offered, for every question, so
    # a replay can put any of them first.
    for qname_text, rdtype_int, servers in offers:
        for server in servers[:MESH_LIMIT]:
            fetch_into(entries, key_of(qname_text, rdtype_int, server), timeout)

    case = {
        "domain": domain,
        "rdtype": rdtype,
        "baseline": baseline,
        "records": records,
        "offers": [[q, t, s[:MESH_LIMIT]] for q, t, s in offers],
        "entries": entries,
    }

    # Close the mesh. Putting a different server first makes the resolver ask
    # questions the original resolution never had to - a server whose NODATA
    # carries no signature sends it looking for a DS that the signed one made
    # unnecessary - and a cassette that cannot answer those would report a
    # perturbation as "unavailable" when the resolver did nothing wrong.
    for _ in range(CLOSURE_ROUNDS):
        gaps: set[str] = set()
        servers = {key.rsplit("|", 1)[1] for key in entries}
        replay(case, missing=gaps)
        for server in sorted(servers):
            replay(case, order=server, missing=gaps)
        if not gaps:
            break
        for key in gaps:
            fetch_into(entries, key, timeout)

    # A cassette that cannot reproduce its own baseline tests nothing: `replay`
    # fails on it forever, and `perturb` would measure every scenario against
    # an outcome the recording never had. Drop it here rather than write a
    # cassette every later layer has to special-case.
    replayed, _violations = replay(case)
    if replayed != baseline:
        print(f"  {domain}/{rdtype}: recorded {baseline}, replayed {replayed}", file=sys.stderr)
        return None
    return case


def fetch_into(entries: dict[str, str], key: str, timeout: float) -> None:
    """Record one (question, server) pair, or mark it as unanswered."""
    if key in entries:
        return
    qname_text, rdtype_text, server = key.split("|")
    query = dns.message.make_query(qname_text, rdtype_text, use_edns=0, payload=1232, want_dnssec=True)
    query.flags &= ~dns.flags.RD
    try:
        response, _tcp = dns.query.udp_with_fallback(query, server, timeout=timeout)
        entries[key] = base64.b64encode(response.to_wire()).decode("ascii")
    except Exception:  # noqa: BLE001 - a server that will not answer is recorded as such
        entries[key] = TIMEOUT


# ── replay ──────────────────────────────────────────────────────────────────


def replay(
    case: dict,
    *,
    order: str | None = None,
    fault: tuple[str, str] | None = None,
    missing: set[str] | None = None,
):
    """Replay one case offline. Returns ``(outcome, violations)``.

    ``missing`` collects the (question, server) pairs the cassette could not
    answer, which is how ``record`` closes the mesh: a different server order
    asks questions the original resolution never had to.
    """
    entries = case["entries"]
    faulty_server, fault_kind = fault if fault else ("", "")

    def query_once(qname, rdtype, server, payload, timeout, ctx):
        key = key_of(qname, rdtype, server)
        raw = entries.get(key, TIMEOUT)
        if raw == TIMEOUT:
            if missing is not None and key not in entries:
                missing.add(key)
            raise _RetryableError("no recorded response")
        response = dns.message.from_wire(base64.b64decode(raw))
        if server == faulty_server:
            response = apply_fault(response, fault_kind, payload)
        return response

    recorded = {key.rsplit("|", 1)[1] for key in entries}

    def order_servers(nameservers):
        servers = resolver.address_filter.filter(nameservers)
        # A server the recording never reached is one the cassette knows
        # nothing about. Leaving it in makes the replay depend on the shuffle
        # again - the very thing this layer exists to remove - so it is set
        # aside unless nothing else is left.
        known = [s for s in servers if s in recorded] or servers
        if order is None or order not in known:
            return known
        return [order] + [s for s in known if s != order]

    resolver = RecursiveResolver(timeout=1.0, max_resolution_time=25.0, cache_enabled=False)
    resolver._query_once = query_once  # type: ignore[method-assign]
    resolver._order_servers = order_servers  # type: ignore[method-assign]

    with audited(resolver) as ledger:
        try:
            answer = resolver.resolve_answer(case["domain"], case["rdtype"])
            return outcome_of(answer, None), ledger.violations(None)
        except Exception as exc:  # noqa: BLE001 - the outcome is what is under test
            return outcome_of(None, exc), ledger.violations(exc)


def apply_fault(response: dns.message.Message, kind: str, payload: int | None) -> dns.message.Message:
    if kind == "timeout":
        raise _RetryableError("injected timeout")
    if kind == "servfail":
        broken = dns.message.Message()
        broken.flags = dns.flags.QR
        broken.set_rcode(dns.rcode.SERVFAIL)
        return broken
    if kind == "formerr":
        if payload is None:
            return response
        broken = dns.message.Message()
        broken.flags = dns.flags.QR
        broken.set_rcode(dns.rcode.FORMERR)
        return broken
    if kind == "empty-answer":
        response.answer = []
        return response
    if kind == "no-aa":
        response.flags &= ~dns.flags.AA
        return response
    if kind == "strip-rrsig":
        response.answer = [r for r in response.answer if r.rdtype != dns.rdatatype.RRSIG]
        response.authority = [r for r in response.authority if r.rdtype != dns.rdatatype.RRSIG]
        return response
    if kind == "strip-dnssec":
        drop = (dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3, dns.rdatatype.DS)
        response.answer = [r for r in response.answer if r.rdtype not in drop]
        response.authority = [r for r in response.authority if r.rdtype not in drop]
        return response
    return response


def transition_allowed(baseline: str, observed: str, fault_kind: str) -> bool:
    """Is this a legitimate consequence of the injected fault?"""
    # Never, whatever else is true. An exception that is not a ResolverError is
    # a broken promise, not an outcome, and reproducing it does not make it one.
    if baseline.startswith("leaked/") or observed.startswith("leaked/"):
        return False
    if observed == baseline:
        return True
    if observed == "unavailable":
        # Losing a server can always cost us the material; it must not cost us
        # the truth.
        return True
    if fault_kind in SIGNATURE_FAULTS and observed == "bogus":
        # Data that should carry signatures and does not is tampering.
        return True
    if baseline.startswith("error/") or observed.startswith("error/"):
        return True
    # NODATA/NXDOMAIN swaps under a fault mean a different server had different
    # contents; the recorded mesh is not always self-consistent across servers.
    return {baseline, observed} <= {"nodata", "nxdomain"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="Record cassettes from live DNS")
    rec.add_argument("--csv", required=True)
    rec.add_argument("-o", "--output", default="cassettes.jsonl")
    rec.add_argument("--types", default="A,MX")
    rec.add_argument("--sample", type=int, default=200)
    rec.add_argument("--seed", type=int, default=20260830)
    rec.add_argument("--workers", type=positive_int, default=12)
    rec.add_argument("--timeout", type=float, default=3.0)

    rep = sub.add_parser("replay", help="Replay cassettes offline")
    rep.add_argument("--cassettes", required=True)

    per = sub.add_parser("perturb", help="Replay under every order and fault")
    per.add_argument("--cassettes", required=True)
    per.add_argument("--max-servers", type=int, default=6, help="Servers to enumerate per case")
    per.add_argument("--workers", type=positive_int, default=4)

    args = parser.parse_args()

    if args.command == "record":
        with open(args.csv, newline="", encoding="utf-8") as handle:
            corpus = [row["domain"] for row in csv.DictReader(handle)]
        if args.sample and args.sample < len(corpus):
            corpus = random.Random(args.seed).sample(corpus, args.sample)
        types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
        items = [(d, t) for d in corpus for t in types]
        started = time.time()
        done = 0
        lock = threading.Lock()

        def work(item):
            nonlocal done
            case = record_case(item[0], item[1], args.timeout)
            with lock:
                done += 1
                if done % 50 == 0:
                    print(f"  recorded {done}/{len(items)} in {time.time() - started:.0f}s", file=sys.stderr)
            return item, case

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            attempted = list(pool.map(work, items))
        cases = [case for _item, case in attempted if case]
        dropped = [item for item, case in attempted if not case]
        with open(args.output, "w", encoding="utf-8") as handle:
            for case in cases:
                handle.write(json.dumps(case) + "\n")
        sizes = sum(len(c["entries"]) for c in cases)
        print(f"\n{len(cases)} cassettes, {sizes} recorded responses, {time.time() - started:.0f}s", file=sys.stderr)
        if dropped:
            names = ", ".join(f"{d}/{t}" for d, t in dropped[:20])
            print(f"  {len(dropped)} not recorded, reasons above: {names}", file=sys.stderr)
        return 0

    cases = [json.loads(line) for line in Path(args.cassettes).read_text(encoding="utf-8").splitlines() if line]

    if args.command == "replay":
        mismatches = []
        for case in cases:
            observed, violations = replay(case)
            if observed != case["baseline"] or violations:
                mismatches.append((case["domain"], case["rdtype"], case["baseline"], observed, violations))
        print(f"{len(cases)} cassettes replayed, {len(mismatches)} did not reproduce", file=sys.stderr)
        for row in mismatches[:40]:
            print(f"  {row[0]}/{row[1]}: recorded {row[2]}, replayed {row[3]} {row[4]}", file=sys.stderr)
        return 1 if mismatches else 0

    # perturb
    failures: list[str] = []
    counts: collections.Counter[str] = collections.Counter()
    started = time.time()
    lock = threading.Lock()

    def scenarios(case: dict):
        servers: list[str] = []
        for _qname, _rdtype, offered in case["offers"]:
            for server in offered:
                if server not in servers:
                    servers.append(server)
        servers = servers[: args.max_servers]
        yield ("order", None, None)
        for server in servers:
            yield ("order", server, None)
        for server in servers:
            for fault in FAULTS:
                yield ("fault", server, fault)

    def run_case(case: dict) -> tuple[int, list[str], str]:
        local: list[str] = []
        ran = 0
        # A cassette that does not reproduce cannot judge a perturbation: every
        # scenario would be measured against an outcome the recording never
        # had. Set the whole cassette aside rather than compare to the wrong
        # baseline. `replay` is the layer that gates reproduction, and reports
        # these by name; here they are counted so the coverage is visible.
        base, base_violations = replay(case)
        if base_violations:
            local.append(f"{case['domain']}/{case['rdtype']} baseline: {base_violations}")
        if base != case["baseline"]:
            return ran, local, f"{case['domain']}/{case['rdtype']}: recorded {case['baseline']}, replayed {base}"
        for kind, server, fault in scenarios(case):
            ran += 1
            if kind == "order":
                observed, violations = replay(case, order=server)
                allowed = transition_allowed(base, observed, "")
                label = f"order={server or 'recorded'}"
            else:
                observed, violations = replay(case, fault=(server, fault))
                allowed = transition_allowed(base, observed, fault)
                label = f"{fault}@{server}"
            with lock:
                counts[observed] += 1
            if not allowed:
                local.append(f"{case['domain']}/{case['rdtype']} [{label}] {base} -> {observed}")
            for violation in violations:
                local.append(f"{case['domain']}/{case['rdtype']} [{label}] {violation}")
        return ran, local, ""

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run_case, cases))
    total = sum(r[0] for r in results)
    skipped = [r[2] for r in results if r[2]]
    for _ran, local, _skip in results:
        failures.extend(local)

    print(f"\n{len(cases)} cassettes, {total} perturbed replays in {time.time() - started:.0f}s", file=sys.stderr)
    for outcome, count in counts.most_common():
        print(f"  {outcome:22s} {count:7d}", file=sys.stderr)
    print(f"  not reproduced, so not perturbed: {len(skipped)}", file=sys.stderr)
    for skip in skipped[:20]:
        print(f"    {skip}", file=sys.stderr)
    print(f"  failures: {len(failures)}", file=sys.stderr)
    for failure in failures[:60]:
        print(f"    {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
