#!/usr/bin/env python3
"""Strategy 2: Certificate Transparency logs via crt.sh.

Queries crt.sh for recently issued certificates across diverse TLDs.
This produces domains that actually exist and have active HTTPS — good for
testing CNAME chains, CDN delegations, and unusual DNS configurations.
"""

from __future__ import annotations

import csv
import json
import random
import time
from urllib.request import urlopen, Request
from urllib.error import URLError

OUTPUT = "domains_extra2.csv"

# Search terms that produce diverse results across TLDs and configurations
SEARCH_TERMS = [
    # Country TLDs
    "%.de", "%.jp", "%.br", "%.in", "%.au", "%.kr", "%.ru",
    "%.nl", "%.se", "%.ch", "%.za", "%.mx", "%.ar", "%.pl",
    # New gTLDs
    "%.io", "%.dev", "%.app", "%.cloud", "%.xyz", "%.online",
    "%.tech", "%.store", "%.site", "%.blog",
    # Infrastructure / interesting DNS
    "%.gov", "%.edu", "%.mil",
    # CDN / cloud hosted (complex DNS chains)
    "%cdn%", "%api%", "%mail%", "%static%",
]


def query_crtsh(term: str, limit: int = 200) -> list[str]:
    """Query crt.sh for domains matching a pattern."""
    url = f"https://crt.sh/?q={term}&output=json&limit={limit}"
    req = Request(url, headers={"User-Agent": "recursive-resolver-test/0.1"})
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        domains: set[str] = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name = (entry.get("common_name") or "").strip().lower()
            if name and "." in name and not name.startswith("*"):
                domains.add(name)
            # Also check SAN names
            name_value = entry.get("name_value") or ""
            for n in name_value.split("\n"):
                n = n.strip().lower()
                if n and "." in n and not n.startswith("*"):
                    domains.add(n)
        return list(domains)
    except (URLError, json.JSONDecodeError, TimeoutError) as e:
        print(f"  Failed for {term}: {e}")
        return []


def main() -> None:
    all_domains: set[str] = set()

    random.shuffle(SEARCH_TERMS)
    for i, term in enumerate(SEARCH_TERMS):
        print(f"[{i + 1}/{len(SEARCH_TERMS)}] Querying crt.sh for {term}...")
        domains = query_crtsh(term)
        all_domains.update(domains)
        print(f"  Found {len(domains)} domains (total: {len(all_domains)})")
        time.sleep(2)  # Be polite to crt.sh

    # Sort and write
    sorted_domains = sorted(all_domains)
    with open(OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain"])
        for d in sorted_domains:
            writer.writerow([d])

    print(f"\nWrote {len(sorted_domains)} domains to {OUTPUT}")


if __name__ == "__main__":
    main()
