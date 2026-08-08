#!/usr/bin/env python3
"""Strategy 3: public zone and popularity data.

Combines multiple public sources:
- Public Suffix List (all known TLDs/eTLDs)
- Cisco Umbrella top 1M (a popularity list built from resolver traffic)
- Hardcoded "interesting" domains with unusual DNS setups
- DNS infrastructure domains (root servers, TLD nameservers, CDNs)
"""

from __future__ import annotations

import csv
import io
import random
from urllib.error import URLError
from urllib.request import Request, urlopen

OUTPUT = "domains_extra3.csv"

# Domains known for interesting/complex DNS configurations
INTERESTING_DOMAINS = [
    # Multi-level CNAME chains
    "www.github.com",
    "www.heroku.com",
    "www.shopify.com",
    "www.squarespace.com",
    "www.wix.com",
    "www.wordpress.com",
    # Anycast / GeoDNS
    "www.google.com",
    "www.facebook.com",
    "www.amazon.com",
    "www.netflix.com",
    "www.cloudflare.com",
    "www.akamai.com",
    # DNSSEC-signed domains
    "dnssec-failed.org",
    "good.dnssec-or-not.com",
    "internetsociety.org",
    "ietf.org",
    "ripe.net",
    # IDN / punycode
    "münchen.de",
    "中国.cn",
    "日本.jp",
    # Long delegation chains
    "bbc.co.uk",
    "gov.uk",
    "nhs.uk",
    "ac.uk",
    "csiro.au",
    "defence.gov.au",
    # Infrastructure
    "ns1.google.com",
    "dns.google",
    "one.one.one.one",
    "resolver1.opendns.com",
    "dns.quad9.net",
    # Email infrastructure (MX-heavy)
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "protonmail.com",
    "zoho.com",
    "fastmail.com",
    "tutanota.com",
    # CDN endpoints
    "d1234.cloudfront.net",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    # Government / institutional
    "whitehouse.gov",
    "nasa.gov",
    "cern.ch",
    "mit.edu",
    "stanford.edu",
    "ox.ac.uk",
    "cam.ac.uk",
    "elysee.fr",
    "bundeskanzler.de",
    "gov.cn",
    # TLD nameservers themselves
    "a.gtld-servers.net",
    "a.nic.fr",
    "dns1.nic.uk",
    # Large hosting (many NS configurations)
    "aws.amazon.com",
    "cloud.google.com",
    "azure.microsoft.com",
    "pages.github.com",
    "netlify.app",
    "vercel.app",
    # Unusual record types
    "_dmarc.google.com",
    "_spf.google.com",
    "meet.google.com",
    "chat.google.com",
]

# Public suffix list URL
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# Cisco Umbrella top 1M (alternative popularity list)
UMBRELLA_URL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"


def fetch_public_suffixes() -> list[str]:
    """Fetch TLD/eTLD entries from the public suffix list and test them as domains."""
    print("Fetching public suffix list...")
    try:
        req = Request(PSL_URL, headers={"User-Agent": "dns-test/0.1"})
        with urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8")
    except (URLError, TimeoutError) as e:
        print(f"  Failed: {e}")
        return []

    suffixes: list[str] = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("!"):
            continue
        # Remove wildcard prefix
        if line.startswith("*."):
            line = line[2:]
        if "." in line:
            suffixes.append(line)

    # Sample: there are thousands
    random.shuffle(suffixes)
    return suffixes[:500]


def fetch_umbrella_sample() -> list[str]:
    """Fetch a sample from Cisco Umbrella top 1M."""
    import zipfile

    print("Fetching Cisco Umbrella top-1M...")
    try:
        with urlopen(UMBRELLA_URL, timeout=30) as resp:
            data = resp.read()

        zf = zipfile.ZipFile(io.BytesIO(data))
        csv_name = zf.namelist()[0]
        text = zf.read(csv_name).decode("utf-8")

        domains: list[str] = []
        for line in text.strip().split("\n"):
            parts = line.strip().split(",")
            if len(parts) == 2:
                domains.append(parts[1])

        # Sample: top 200, then every 1000th
        sampled = domains[:200]
        sampled.extend(domains[200::1000])
        return sampled
    except Exception as e:
        print(f"  Failed: {e}")
        return []


def main() -> None:
    all_domains: set[str] = set()

    # Source 1: Interesting/hardcoded domains
    all_domains.update(INTERESTING_DOMAINS)
    print(f"Hardcoded interesting domains: {len(INTERESTING_DOMAINS)}")

    # Source 2: Public suffix list
    psl = fetch_public_suffixes()
    all_domains.update(psl)
    print(f"Public suffix samples: {len(psl)} (total: {len(all_domains)})")

    # Source 3: Cisco Umbrella
    umbrella = fetch_umbrella_sample()
    all_domains.update(umbrella)
    print(f"Umbrella samples: {len(umbrella)} (total: {len(all_domains)})")

    # Generate www. variants of top domains for CNAME testing
    www_variants = [f"www.{d}" for d in list(all_domains)[:300] if not d.startswith("www.")]
    all_domains.update(www_variants)
    print(f"After www. variants: {len(all_domains)}")

    sorted_domains = sorted(all_domains)
    with open(OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain"])
        for d in sorted_domains:
            writer.writerow([d])

    print(f"\nWrote {len(sorted_domains)} domains to {OUTPUT}")


if __name__ == "__main__":
    main()
