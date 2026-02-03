"""Bulk CSV testing: compare our resolver results against dig."""

from __future__ import annotations

import concurrent.futures
import csv
import json
import os
import random
import re
import subprocess
import threading
import time
from collections import defaultdict

import pytest

from recursive_resolver import RecursiveResolver


def _dig_query(domain: str, rdtype: str) -> set[str]:
    """Query a domain using dig +short and return results as a set."""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, rdtype],
            capture_output=True,
            text=True,
            timeout=15,
        )
        lines = result.stdout.strip().split("\n")
        return {line.strip().rstrip(".").lower() for line in lines if line.strip()}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()


def _normalize_results(results: list[str]) -> set[str]:
    """Normalize resolver results for comparison (strip trailing dots, lowercase)."""
    return {r.strip().rstrip(".").lower() for r in results}


def _normalize_txt(records: set[str]) -> set[str]:
    """Normalize TXT records for comparison.

    dig +short puts all TXT RRs on a single line ('\"a\" \"b\"') while our
    resolver returns each RR separately ('\"a\"', '\"b\"').  Extract every
    individual quoted string so both sides produce the same flat set.
    """
    out: set[str] = set()
    for record in records:
        # Extract all "…" substrings from the record
        quoted = re.findall(r'"[^"]*"', record)
        if quoted:
            for q in quoted:
                out.add(q.lower())
        else:
            # Bare value (no quotes) — keep as-is
            out.add(record.lower())
    return out


def _test_one(domain: str, rdtype: str, resolver: RecursiveResolver) -> dict:
    """Test one domain/rdtype pair. Returns a result dict."""
    try:
        our_results = _normalize_results(resolver.resolve(domain, rdtype))
    except Exception as e:
        our_results = set()
        our_error = type(e).__name__
    else:
        our_error = None

    dig_results = _dig_query(domain, rdtype)
    # Filter out dig error messages (not real results)
    dig_results = {r for r in dig_results if not r.startswith(";;")}

    # TXT records need special normalization: dig concatenates all RRs on one
    # line while our resolver returns them separately.
    if rdtype == "TXT":
        our_results = _normalize_txt(our_results)
        dig_results = _normalize_txt(dig_results)

    if our_results == dig_results:
        status = "exact"
    elif our_results and dig_results and (our_results & dig_results):
        status = "overlap"
    elif our_results and dig_results:
        status = "diff"
    elif not our_results and not dig_results:
        status = "both_empty"
    elif not our_results:
        status = "our_empty"
    else:
        status = "dig_empty"

    return {
        "domain": domain,
        "rdtype": rdtype,
        "status": status,
        "ours": sorted(our_results),
        "dig": sorted(dig_results),
        "our_error": our_error,
    }


def test_csv_bulk(csv_path: str | None, request: pytest.FixtureRequest) -> None:
    """Test domains from a CSV file against dig results.

    The CSV must have a 'domain' column. Record types and sample size are
    controlled via --types and --sample CLI options.
    """
    if csv_path is None:
        pytest.skip("No --csv option provided")

    rdtypes = [t.strip().upper() for t in request.config.getoption("--types").split(",")]
    sample_size = request.config.getoption("--sample")

    resolver = RecursiveResolver(timeout=5.0, ipv4_only=True)

    with open(csv_path) as f:
        reader = csv.DictReader(f)
        domains = [row["domain"].strip() for row in reader if row.get("domain", "").strip()]

    if not domains:
        pytest.skip("CSV file is empty or has no 'domain' column")

    if sample_size > 0 and sample_size < len(domains):
        random.seed(42)  # reproducible sampling
        domains = random.sample(domains, sample_size)

    # Use a unique JSONL file per CSV source (no overwriting between runs)
    csv_basename = os.path.splitext(os.path.basename(csv_path))[0]
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    types_tag = "-".join(rdtypes)
    failures_path = f"csv_test_failures_{csv_basename}_{types_tag}_{timestamp}.jsonl"

    results: list[dict] = []
    lock = threading.Lock()
    done = 0
    failure_count = 0
    total_tasks = len(domains) * len(rdtypes)
    start = time.monotonic()

    print(f"\nTesting {len(domains)} domains × {len(rdtypes)} types ({rdtypes}) = {total_tasks} queries")

    def run_one(domain: str, rdtype: str) -> None:
        nonlocal done, failure_count
        r = _test_one(domain, rdtype, resolver)
        with lock:
            results.append(r)
            done += 1

            # Print and log failures in real-time
            if r["status"] in ("our_empty", "diff"):
                failure_count += 1
                print(
                    f"  FAIL #{failure_count} [{done}/{total_tasks}] "
                    f"{r['domain']}/{r['rdtype']} ({r['status']}): "
                    f"ours={r['ours']} dig={r['dig']} err={r['our_error']}",
                    flush=True,
                )
                with open(failures_path, "a") as f:
                    f.write(json.dumps(r) + "\n")

            if done % 500 == 0:
                elapsed = time.monotonic() - start
                rate = done / elapsed if elapsed > 0 else 0
                print(
                    f"  [{done}/{total_tasks}] {elapsed:.0f}s elapsed, {rate:.0f} tests/s, {failure_count} failures",
                    flush=True,
                )

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = []
        for domain in domains:
            for rdtype in rdtypes:
                futures.append(pool.submit(run_one, domain, rdtype))
        concurrent.futures.wait(futures)

    # Classify results — overall and per-type
    counts: dict[str, int] = {}
    per_type: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    failures: list[dict] = []
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        per_type[r["rdtype"]][r["status"]] += 1
        if r["status"] in ("our_empty", "diff"):
            failures.append(r)

    matches = (
        counts.get("exact", 0) + counts.get("overlap", 0) + counts.get("both_empty", 0) + counts.get("dig_empty", 0)
    )
    match_rate = matches / len(results) if results else 0
    elapsed = time.monotonic() - start

    print(f"\nCSV bulk test: {matches}/{len(results)} matches ({match_rate:.1%}) in {elapsed:.0f}s")
    print(f"Overall: {json.dumps(counts, indent=2)}")

    # Per-type breakdown
    print("\nPer-type breakdown:")
    for rdtype in rdtypes:
        tc = dict(per_type[rdtype])
        type_total = sum(tc.values())
        type_matches = tc.get("exact", 0) + tc.get("overlap", 0) + tc.get("both_empty", 0) + tc.get("dig_empty", 0)
        type_rate = type_matches / type_total if type_total else 0
        print(f"  {rdtype:6s}: {type_matches}/{type_total} ({type_rate:.1%}) — {dict(tc)}")

    if failures:
        print(f"\nTotal failures: {len(failures)}")
        print(f"All failures written to {failures_path}")

    assert match_rate >= 0.96, f"Match rate {match_rate:.1%} is below 96% threshold"
