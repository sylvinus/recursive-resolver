#!/usr/bin/env python3
"""Layer 1 of TESTING.md: pick names because they stress a path, not because
they are popular.

A popularity-ranked corpus is served by well-run infrastructure, so it
exercises the happy path and little else. The failures that matter live in
zones whose nameservers disagree with each other, time out, SERVFAIL, or choke
on EDNS. This probes every nameserver of every candidate zone and keeps the
ones that misbehave, tagging each with the property that got it selected so a
later failure is attributable.

The tags are the ones that map to real defects:

``lame-dnskey``
    At least one server answers the zone's DNSKEY query with NOERROR and an
    empty answer section while a sibling serves the real thing. One of these in
    an NS set was enough to make 0.1.0 report the zone BOGUS.
``no-aa-dnskey``
    A server answers the DNSKEY query without the AA bit: a parent-side server
    returning a referral where an answer was asked for.
``unreliable-ns`` / ``servfail-ns`` / ``formerr-edns``
    A server that times out, fails, or cannot cope with an OPT record while its
    siblings are healthy. Each of these is a chance to conclude something false
    about the zone.
``rrsig-missing``
    A server returns the DNSKEY RRset with no RRSIG over it: what a DO-stripping
    middlebox looks like from here.
``single-ns``
    One address for the whole zone, so there is no sibling to fall back to.
``signed`` / ``unsigned``
    Whether any server served a signed DNSKEY RRset.

Usage:
    python scripts/collect_domains_adversarial.py --csv domains.csv -o adversarial.csv
    python scripts/collect_domains_adversarial.py --csv domains.csv --sample 2000
"""

from __future__ import annotations

import argparse
import collections
import csv
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from recursive_resolver import RecursiveResolver, ResolverError  # noqa: E402

MAX_ADDRESSES = 8
PER_SERVER_INTERVAL = 0.25  # seconds between queries to the same address


class RateLimiter:
    """One query per address per interval: probing is not a licence to flood."""

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: str) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                last = self._last.get(key, 0.0)
                if now - last >= self.interval:
                    self._last[key] = now
                    return
                delay = self.interval - (now - last)
            time.sleep(delay)


@dataclass
class Probe:
    address: str
    rcode: str = "TIMEOUT"
    authoritative: bool = False
    has_dnskey: bool = False
    has_rrsig: bool = False
    edns_only_failure: bool = False


@dataclass
class ZoneReport:
    zone: str
    probes: list[Probe] = field(default_factory=list)

    def tags(self) -> list[str]:
        tags: list[str] = []
        answered = [p for p in self.probes if p.rcode != "TIMEOUT"]
        with_key = [p for p in answered if p.has_dnskey]
        empty = [p for p in answered if p.rcode == "NOERROR" and not p.has_dnskey]

        if not self.probes:
            return ["no-nameservers"]
        if with_key and empty:
            tags.append("lame-dnskey")
        if any(p.has_dnskey and not p.authoritative for p in answered) or any(
            p.rcode == "NOERROR" and not p.authoritative and not p.has_dnskey for p in answered
        ):
            tags.append("no-aa-dnskey")
        if len(answered) < len(self.probes) and answered:
            tags.append("unreliable-ns")
        if not answered:
            tags.append("all-ns-down")
        if any(p.rcode == "SERVFAIL" for p in self.probes):
            tags.append("servfail-ns")
        if any(p.edns_only_failure for p in self.probes):
            tags.append("formerr-edns")
        if any(p.has_dnskey and not p.has_rrsig for p in self.probes):
            tags.append("rrsig-missing")
        if len(self.probes) == 1:
            tags.append("single-ns")
        tags.append("signed" if any(p.has_rrsig for p in self.probes) else "unsigned")
        return tags


def zone_of(resolver: RecursiveResolver, name: str) -> str | None:
    """The closest enclosing zone that answers an NS query."""
    labels = dns.name.from_text(name)
    for _ in range(4):
        try:
            resolver.resolve(str(labels), "NS")
            return str(labels)
        except ResolverError:
            if labels == dns.name.root:
                return None
            labels = labels.parent()
    return None


def addresses_for(resolver: RecursiveResolver, zone: str) -> list[str]:
    try:
        ns_names = resolver.resolve(zone, "NS")
    except ResolverError:
        return []
    out: list[str] = []
    for ns in sorted(ns_names):
        if len(out) >= MAX_ADDRESSES:
            break
        try:
            out.extend(resolver.resolve(ns.rstrip("."), "A"))
        except ResolverError:
            continue
    return list(dict.fromkeys(resolver.address_filter.filter(out)))[:MAX_ADDRESSES]


def probe(zone: str, address: str, limiter: RateLimiter, timeout: float) -> Probe:
    result = Probe(address=address)
    limiter.wait(address)
    query = dns.message.make_query(zone, dns.rdatatype.DNSKEY, use_edns=0, payload=1232, want_dnssec=True)
    query.flags &= ~dns.flags.RD
    try:
        response = dns.query.udp(query, address, timeout=timeout, raise_on_truncation=True)
    except dns.message.Truncated:
        result.rcode = "TRUNCATED"
        return result
    except Exception:  # noqa: BLE001 - any failure is "this server did not answer"
        return result

    result.rcode = dns.rcode.to_text(response.rcode())
    result.authoritative = bool(response.flags & dns.flags.AA)
    zone_name = dns.name.from_text(zone)
    result.has_dnskey = any(
        rrset.rdtype == dns.rdatatype.DNSKEY and rrset.name == zone_name for rrset in response.answer
    )
    result.has_rrsig = any(
        rrset.rdtype == dns.rdatatype.RRSIG and any(rr.type_covered == dns.rdatatype.DNSKEY for rr in rrset)
        for rrset in response.answer
    )

    if response.rcode() in (dns.rcode.FORMERR, dns.rcode.NOTIMP):
        # Confirm it is the OPT record the server dislikes, not the question.
        limiter.wait(address)
        plain = dns.message.make_query(zone, dns.rdatatype.DNSKEY, use_edns=False)
        plain.flags &= ~dns.flags.RD
        try:
            second = dns.query.udp(plain, address, timeout=timeout)
            result.edns_only_failure = second.rcode() == dns.rcode.NOERROR
        except Exception:  # noqa: BLE001
            result.edns_only_failure = False
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", required=True, help="Input corpus CSV (domain,category)")
    parser.add_argument("-o", "--output", default="adversarial.csv", help="Output CSV path")
    parser.add_argument("--sample", type=int, default=0, help="Probe a random sample of N names (0 = all)")
    parser.add_argument("--seed", type=int, default=20260830, help="Sampling seed")
    parser.add_argument("--workers", type=int, default=24, help="Concurrent zone probes")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-query timeout")
    args = parser.parse_args()

    with open(args.csv, newline="", encoding="utf-8") as handle:
        rows = [(row["domain"], row.get("category", "")) for row in csv.DictReader(handle)]
    if args.sample and args.sample < len(rows):
        rows = random.Random(args.seed).sample(rows, args.sample)

    limiter = RateLimiter(PER_SERVER_INTERVAL)
    reports: dict[str, ZoneReport] = {}
    zone_lock = threading.Lock()
    done = 0

    def work(item: tuple[str, str]) -> tuple[str, str, str] | None:
        nonlocal done
        domain, category = item
        resolver = RecursiveResolver(timeout=args.timeout, max_resolution_time=20.0, dnssec=False)
        try:
            zone = zone_of(resolver, domain)
            if zone is None:
                return None
            with zone_lock:
                cached = reports.get(zone)
            if cached is None:
                report = ZoneReport(zone=zone)
                for address in addresses_for(resolver, zone):
                    report.probes.append(probe(zone, address, limiter, args.timeout))
                with zone_lock:
                    reports.setdefault(zone, report)
                    cached = reports[zone]
            return domain, category, " ".join(cached.tags())
        except Exception as exc:  # noqa: BLE001 - a probe failure is data, not a crash
            print(f"  {domain}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return None
        finally:
            done += 1
            if done % 100 == 0:
                print(f"  probed {done}/{len(rows)}", file=sys.stderr, flush=True)

    started = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = [r for r in pool.map(work, rows) if r is not None]

    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["domain", "category", "tags"])
        writer.writerows(sorted(results))

    counts: collections.Counter[str] = collections.Counter()
    for _domain, _category, tags in results:
        counts.update(tags.split())
    print(f"\n{len(results)} names over {len(reports)} zones in {time.time() - started:.0f}s", file=sys.stderr)
    for tag, count in counts.most_common():
        print(f"  {tag:20s} {count:6d}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
