#!/usr/bin/env python3
"""Build a deliberately awkward corpus for differential testing.

A list of popular apex domains exercises the happy path and little else. This
script assembles names chosen to stress the parts of a resolver that actually
break: unusual delegation shapes, deep names, internationalised labels, signed
and deliberately-bogus zones, wildcards, empty non-terminals and the underscore
labels that mail lookups depend on.

Sources
-------
Tranco
    A research-grade popularity ranking, sampled across bands rather than just
    the head, so the tail (where broken and exotic configurations live) is
    represented.
IANA TLD list
    Every delegated TLD, including the IDN ``xn--`` ones. Querying a TLD apex
    exercises single-label names and referral handling at the top of the tree.
Public Suffix List
    Multi-label suffixes (``co.uk``, ``github.io``, ``s3.amazonaws.com``) whose
    delegation structure is unusual: several zone cuts, sometimes served by the
    same nameservers, sometimes not.
Derived subdomains
    Mail and service labels layered onto popular domains: ``_dmarc``,
    ``_domainkey`` selectors, ``www``, ``autodiscover``, which is where the
    deep, underscore-prefixed names live.
Curated
    Hand-picked pathological cases with a known expected shape.

Usage:
    python scripts/collect_domains_diverse.py -o domains.csv
    python scripts/collect_domains_diverse.py -o domains.csv --limit 20000
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import zipfile
from urllib.error import URLError
from urllib.request import Request, urlopen

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
IANA_TLDS_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

USER_AGENT = "recursive-resolver-corpus/1.0"

# Popularity bands sampled from Tranco. The tail matters most: that is where
# lame delegations, dead glue and odd nameserver software concentrate.
TRANCO_BANDS = (
    (1, 100, 100),
    (100, 1_000, 150),
    (1_000, 10_000, 250),
    (10_000, 100_000, 400),
    (100_000, 1_000_000, 600),
)

# Labels layered onto popular domains. Underscore-prefixed names are the ones
# mail authentication depends on, and they are frequently empty non-terminals.
SUBDOMAIN_LABELS = (
    "www",
    "mail",
    "_dmarc",
    "selector1._domainkey",
    "google._domainkey",
    "autodiscover",
    "api",
    "cdn",
    "_sip._tcp",
    "ftp.internal.dev",
)

# Names with a known-interesting shape, each paired with why it is here.
CURATED: tuple[tuple[str, str], ...] = (
    # Internationalised names: IDNA 2003 and 2008 disagree on these.
    ("bücher.de", "idn-unicode"),
    ("xn--bcher-kva.de", "idn-punycode"),
    ("straße.de", "idn-sharp-s"),
    ("faß.de", "idn-sharp-s"),
    ("münchen.de", "idn-unicode"),
    ("日本.jp", "idn-cjk"),
    ("россия.рф", "idn-cyrillic"),
    ("中国.cn", "idn-cjk"),
    # DNSSEC: signed, and deliberately broken.
    ("cloudflare.com", "dnssec-signed"),
    ("nic.cz", "dnssec-signed-shared-cut"),
    ("ietf.org", "dnssec-signed"),
    ("nlnetlabs.nl", "dnssec-signed"),
    ("internetsociety.org", "dnssec-signed"),
    ("dnssec-tools.org", "dnssec-signed"),
    ("verisign.com", "dnssec-signed"),
    ("ripe.net", "dnssec-signed"),
    ("sigok.verteiltesysteme.net", "dnssec-signed"),
    ("dnssec-failed.org", "dnssec-bogus"),
    ("rhybar.cz", "dnssec-bogus"),
    ("bogus.nlnetlabs.nl", "dnssec-bogus"),
    ("sigfail.verteiltesysteme.net", "dnssec-bogus"),
    # Zone cuts served by the same nameservers as their parent.
    ("bbc.co.uk", "shared-zone-cut"),
    ("amazon.co.uk", "shared-zone-cut"),
    ("gov.uk", "shared-zone-cut"),
    ("ac.uk", "shared-zone-cut"),
    ("com.au", "shared-zone-cut"),
    # CNAME shapes.
    ("www.github.com", "cname"),
    ("www.microsoft.com", "cname-chain"),
    ("selector1._domainkey.microsoft.com", "cname-to-elsewhere"),
    ("zendesk1._domainkey.zendesk.com", "txt-multi-chunk"),
    ("s1._domainkey.stripe.com", "dkim"),
    ("k1._domainkey.mailchimp.com", "dkim"),
    ("20230601._domainkey.gmail.com", "dkim"),
    # Deep names and empty non-terminals.
    ("a.b.c.d.e.f.example.com", "deep-nonexistent"),
    ("_domainkey.zendesk.com", "empty-non-terminal"),
    ("_tcp.example.com", "empty-non-terminal"),
    # Reverse lookups.
    ("8.8.8.8.in-addr.arpa", "reverse-v4"),
    ("1.1.1.1.in-addr.arpa", "reverse-v4"),
    # Apexes with unusual answers.
    ("example.com", "reserved-apex"),
    ("example.org", "reserved-apex"),
    ("localhost", "special-use"),
    ("invalid", "special-use"),
    ("test", "special-use"),
    # Large responses that stress EDNS and truncation.
    ("google.com", "large-txt"),
    ("microsoft.com", "large-txt"),
    ("salesforce.com", "large-txt"),
    # Names that should not exist.
    ("this-domain-should-not-exist-zz99.com", "nxdomain"),
    ("nonexistent.cloudflare.com", "nxdomain-signed-zone"),
    ("nonexistent.nic.cz", "nxdomain-nsec3"),
    ("nonexistent.ietf.org", "wildcard-or-nodata"),
)


def _fetch(url: str, timeout: int = 60) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URLs
        data: bytes = response.read()
    return data


def collect_tranco(rng: random.Random) -> list[tuple[str, str]]:
    """Sample Tranco across popularity bands, not just the head."""
    print(f"Downloading Tranco from {TRANCO_URL} ...", file=sys.stderr)
    archive = zipfile.ZipFile(io.BytesIO(_fetch(TRANCO_URL)))
    text = archive.read(archive.namelist()[0]).decode("utf-8", "replace")

    ranked: list[str] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2:
            ranked.append(row[1].strip().lower())

    out: list[tuple[str, str]] = []
    for low, high, count in TRANCO_BANDS:
        band = ranked[low - 1 : min(high, len(ranked))]
        if not band:
            continue
        picked = rng.sample(band, min(count, len(band)))
        label = f"tranco-{low}-{high}"
        out.extend((domain, label) for domain in picked)
    print(f"  Tranco: {len(out)} domains across {len(TRANCO_BANDS)} bands", file=sys.stderr)
    return out


def collect_tlds() -> list[tuple[str, str]]:
    """Every delegated TLD, including the internationalised ones."""
    print(f"Downloading the IANA TLD list from {IANA_TLDS_URL} ...", file=sys.stderr)
    lines = _fetch(IANA_TLDS_URL).decode("ascii", "replace").splitlines()
    out: list[tuple[str, str]] = []
    for line in lines:
        tld = line.strip().lower()
        if not tld or tld.startswith("#"):
            continue
        out.append((tld, "tld-idn" if tld.startswith("xn--") else "tld"))
    print(f"  TLDs: {len(out)}", file=sys.stderr)
    return out


def collect_public_suffixes(rng: random.Random, count: int = 400) -> list[tuple[str, str]]:
    """Multi-label public suffixes: several zone cuts, unusual delegation shapes."""
    print(f"Downloading the Public Suffix List from {PSL_URL} ...", file=sys.stderr)
    lines = _fetch(PSL_URL).decode("utf-8", "replace").splitlines()
    suffixes: list[str] = []
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("//"):
            continue
        entry = entry.lstrip("*.").lstrip("!")
        # Only multi-label entries are interesting; single labels are TLDs,
        # already covered above.
        if entry.count(".") >= 1 and " " not in entry:
            suffixes.append(entry.lower())
    picked = rng.sample(suffixes, min(count, len(suffixes)))
    print(f"  Public suffixes: {len(picked)} of {len(suffixes)}", file=sys.stderr)
    return [(suffix, "public-suffix") for suffix in picked]


def derive_subdomains(apexes: list[str], rng: random.Random, count: int = 600) -> list[tuple[str, str]]:
    """Layer mail and service labels onto popular domains."""
    out: list[tuple[str, str]] = []
    sample = rng.sample(apexes, min(count, len(apexes)))
    for apex in sample:
        label = rng.choice(SUBDOMAIN_LABELS)
        kind = "subdomain-underscore" if "_" in label else "subdomain"
        out.append((f"{label}.{apex}", kind))
    print(f"  Derived subdomains: {len(out)}", file=sys.stderr)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", default="domains.csv", help="Output CSV path")
    parser.add_argument("--limit", type=int, default=0, help="Cap the total number of names (0 = no cap)")
    parser.add_argument("--seed", type=int, default=20260808, help="Sampling seed, for reproducible corpora")
    parser.add_argument("--no-tranco", action="store_true", help="Skip the Tranco download")
    parser.add_argument("--no-tlds", action="store_true", help="Skip the IANA TLD list")
    parser.add_argument("--no-psl", action="store_true", help="Skip the Public Suffix List")
    args = parser.parse_args()
    if args.limit < 0:
        # Otherwise a negative limit is truthy below and Python's negative
        # slicing quietly drops rows from the *end* of the corpus instead.
        parser.error("--limit must be zero or greater")

    rng = random.Random(args.seed)
    collected: list[tuple[str, str]] = list(CURATED)
    tranco_apexes: list[str] = []

    for enabled, fn in (
        (not args.no_tranco, lambda: collect_tranco(rng)),
        (not args.no_tlds, collect_tlds),
        (not args.no_psl, lambda: collect_public_suffixes(rng)),
    ):
        if not enabled:
            continue
        try:
            rows = fn()
        except (URLError, OSError, zipfile.BadZipFile) as exc:
            print(f"  WARNING: source unavailable ({exc}); continuing without it", file=sys.stderr)
            continue
        collected.extend(rows)
        if rows and rows[0][1].startswith("tranco"):
            tranco_apexes = [domain for domain, _ in rows]

    if tranco_apexes:
        collected.extend(derive_subdomains(tranco_apexes, rng))

    # De-duplicate, keeping the first (most specific) category for each name.
    seen: dict[str, str] = {}
    for domain, category in collected:
        seen.setdefault(domain, category)

    rows = sorted(seen.items())
    rng.shuffle(rows)
    if args.limit > 0:
        rows = rows[: args.limit]

    with open(args.output, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["domain", "category"])
        writer.writerows(rows)

    by_category: dict[str, int] = {}
    for _domain, category in rows:
        by_category[category] = by_category.get(category, 0) + 1

    print(f"\nWrote {len(rows)} names to {args.output}", file=sys.stderr)
    for category, count in sorted(by_category.items(), key=lambda item: -item[1]):
        print(f"  {category:26s} {count:6d}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
