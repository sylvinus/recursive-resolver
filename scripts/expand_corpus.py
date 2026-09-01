#!/usr/bin/env python3
"""Widen a corpus until it looks like the DNS, not like a top-sites list.

`collect_domains_diverse.py` samples popularity bands, every TLD and the Public
Suffix List, which is a good spread but a small one. The failures this project
has actually shipped came from the parts of the namespace a top-sites list
barely touches: ccTLD registries with their own idea of how to answer, empty
non-terminals under service labels, deep names that exist only as ancestors,
and the reverse tree.

So this fans the corpus out along the axes that matter:

**Registry diversity**
    Tranco bucketed by TLD, taking a bounded number from *each* registry rather
    than the head of the list. A ccTLD run by a small registry is where lame
    servers, unusual denial proofs and split-brain NS sets live, and there are
    a couple of hundred of them.

**Depth**
    Service and mail labels (`_dmarc`, `_25._tcp`, `selector1._domainkey`),
    which are the names real applications look up, plus names that exist only
    as ancestors of other names, plus names several labels deep that do not
    exist at all.

**The reverse tree**
    `in-addr.arpa` is signed, delegated in a shape nothing else shares, and
    almost never covered by a corpus of web domains.

Usage:
    python scripts/expand_corpus.py --base base.csv -o extended.csv
    python scripts/expand_corpus.py --base base.csv -o extended.csv --per-registry 60
"""

from __future__ import annotations

import argparse
import collections
import csv
import io
import random
import sys
import zipfile
from urllib.request import Request, urlopen

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
USER_AGENT = "recursive-resolver-corpus/1.0"

# Labels real applications look up, several of which create empty non-terminals
# on the way down.
SERVICE_LABELS = (
    "_dmarc",
    "_domainkey",
    "selector1._domainkey",
    "google._domainkey",
    "_acme-challenge",
    "_mta-sts",
    "_smtp._tls",
    "_25._tcp",
    "_443._tcp",
    "_sip._tcp",
    "_sips._tcp",
    "_xmpp-server._tcp",
    "_autodiscover._tcp",
    "www",
    "mail",
    "smtp",
    "autodiscover",
    "ftp",
    "ns1",
)

# Public addresses spread across registries, for the reverse tree.
REVERSE_SEEDS = (
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
    "193.0.14.129",
    "199.7.83.42",
    "192.36.148.17",
    "128.63.2.53",
    "202.12.27.33",
    "196.216.168.23",
    "200.3.14.10",
    "2.16.0.1",
    "13.107.236.5",
    "151.101.1.140",
    "104.16.132.229",
    "185.199.108.153",
)


def fetch_tranco() -> list[str]:
    print(f"Downloading Tranco from {TRANCO_URL} ...", file=sys.stderr)
    request = Request(TRANCO_URL, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=120) as response:  # noqa: S310 - fixed https URL
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    text = archive.read(archive.namelist()[0]).decode("utf-8", "replace")
    return [row[1].strip().lower() for row in csv.reader(io.StringIO(text)) if len(row) >= 2]


def registry_of(domain: str) -> str:
    return domain.rsplit(".", 1)[-1] if "." in domain else domain


def by_registry(domains: list[str], per_registry: int, rng: random.Random) -> list[tuple[str, str]]:
    """Up to ``per_registry`` names from every TLD, ccTLDs marked as such."""
    buckets: dict[str, list[str]] = collections.defaultdict(list)
    for domain in domains:
        buckets[registry_of(domain)].append(domain)
    out: list[tuple[str, str]] = []
    for tld, names in buckets.items():
        # Two-letter TLDs are the country-code ones, bar a handful of legacy
        # exceptions that behave like gTLDs anyway.
        kind = "cctld" if len(tld) == 2 else ("idn-tld" if tld.startswith("xn--") else "gtld")
        picked = rng.sample(names, min(per_registry, len(names)))
        out.extend((name, f"{kind}-{tld}") for name in picked)
    return out


def derive_depth(apexes: list[str], count: int, rng: random.Random) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for apex in rng.sample(apexes, min(count, len(apexes))):
        label = rng.choice(SERVICE_LABELS)
        kind = "deep-service-underscore" if "_" in label else "deep-service"
        out.append((f"{label}.{apex}", kind))
        if rng.random() < 0.25:
            # The parent of a service label usually exists only as an ancestor.
            out.append((f"{label.split('.')[-1]}.{apex}", "empty-non-terminal-probe"))
        if rng.random() < 0.15:
            out.append((f"{rng.randrange(10**6)}.a.b.{apex}", "deep-nonexistent"))
    return out


def reverse_names(rng: random.Random, extra: int = 200) -> list[tuple[str, str]]:
    out = [(".".join(reversed(ip.split("."))) + ".in-addr.arpa", "reverse-v4") for ip in REVERSE_SEEDS]
    for _ in range(extra):
        octets = [rng.randrange(1, 224), rng.randrange(256), rng.randrange(256), rng.randrange(1, 255)]
        if octets[0] in (10, 127, 169, 172, 192, 100):
            continue
        out.append((".".join(str(o) for o in reversed(octets)) + ".in-addr.arpa", "reverse-v4-random"))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", required=True, help="Corpus CSV to extend (domain,category[,tags])")
    parser.add_argument("-o", "--output", default="extended.csv")
    parser.add_argument("--per-registry", type=int, default=40, help="Names taken from each TLD")
    parser.add_argument("--depth", type=int, default=2500, help="Apexes to layer service labels onto")
    parser.add_argument("--seed", type=int, default=20260830)
    parser.add_argument("--no-tranco", action="store_true")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    with open(args.base, newline="", encoding="utf-8") as handle:
        base = [(row["domain"], row.get("category", ""), row.get("tags", "")) for row in csv.DictReader(handle)]

    collected: list[tuple[str, str]] = [(d, c) for d, c, _t in base]
    apexes = [d for d, c, _t in base if c.startswith("tranco")]

    if not args.no_tranco:
        ranked = fetch_tranco()
        spread = by_registry(ranked, args.per_registry, rng)
        collected.extend(spread)
        apexes.extend(name for name, _kind in spread)
        registries = {kind.split("-", 1)[1] for _name, kind in spread}
        print(f"  registry spread: {len(spread)} names over {len(registries)} TLDs", file=sys.stderr)

    depth = derive_depth(apexes, args.depth, rng)
    collected.extend(depth)
    print(f"  depth: {len(depth)} names", file=sys.stderr)

    reverse = reverse_names(rng)
    collected.extend(reverse)
    print(f"  reverse: {len(reverse)} names", file=sys.stderr)

    tags = {domain: tag for domain, _category, tag in base if tag}
    seen: dict[str, str] = {}
    for domain, category in collected:
        seen.setdefault(domain, category)

    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["domain", "category", "tags"])
        for domain, category in sorted(seen.items()):
            writer.writerow([domain, category, tags.get(domain, "")])

    counts = collections.Counter(category.split("-")[0] for category in seen.values())
    print(f"\n{len(seen)} names", file=sys.stderr)
    for kind, count in counts.most_common(20):
        print(f"  {kind:26s} {count:6d}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
