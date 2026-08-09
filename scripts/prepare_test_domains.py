#!/usr/bin/env python3
"""Download a dataset from data.gouv.fr and extract domains for testing.

Downloads a gzipped CSV of French public organizations, extracts domains from
the site_internet column, and optionally enriches with MX/SPF-discovered subdomains.

Usage:
    python scripts/prepare_test_domains.py -o domains.csv
    python scripts/prepare_test_domains.py -o domains.csv --no-enrich
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import gzip
import io
import sys
from urllib.parse import urlparse
from urllib.request import urlopen

DATASET_URL = "https://data.gouv.fr/api/1/datasets/r/551a41a5-4ac7-40df-99cb-930aedb3c3ac"


def download_dataset() -> list[dict[str, str]]:
    """Download and decompress the gzipped CSV dataset."""
    print(f"Downloading dataset from {DATASET_URL}...")
    with urlopen(DATASET_URL) as response:
        raw_data = response.read()

    # Try gzip decompression first
    try:
        decompressed = gzip.decompress(raw_data)
        text = decompressed.decode("utf-8", errors="replace")
    except gzip.BadGzipFile:
        text = raw_data.decode("utf-8", errors="replace")

    # Auto-detect delimiter (this dataset uses semicolons)
    sample = text[:2048]
    delimiter = ";" if sample.count(";") > sample.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    return list(reader)


def _domain_from_url(url: str) -> str | None:
    """Extract a domain from a URL string."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname:
            hostname = hostname.lower().rstrip(".")
            if "." in hostname and not hostname.startswith("."):
                return hostname
    except Exception:
        pass
    return None


def _domain_from_email(email: str) -> str | None:
    """Extract a domain from an email address."""
    if "@" in email:
        domain = email.split("@", 1)[1].strip().lower().rstrip(".")
        if "." in domain and not domain.startswith("."):
            return domain
    return None


def extract_domains(rows: list[dict[str, str]]) -> set[str]:
    """Extract unique domains from site_internet and adresse_messagerie columns."""
    domains: set[str] = set()
    for row in rows:
        # Extract from site_internet (URLs)
        url = row.get("site_internet", "").strip()
        if url:
            domain = _domain_from_url(url)
            if domain:
                domains.add(domain)

        # Extract from adresse_messagerie (email addresses)
        email = row.get("adresse_messagerie", "").strip()
        if email:
            domain = _domain_from_email(email)
            if domain:
                domains.add(domain)

    return domains


def _enrich_one(domain: str, resolver: object) -> list[str]:
    """Enrich a single domain by querying MX and TXT/SPF. Returns discovered domains."""
    found: list[str] = []

    try:
        mx_results = resolver.resolve(domain, "MX")  # type: ignore[union-attr]
        for mx in mx_results:
            parts = mx.split()
            if len(parts) == 2:
                mx_host = parts[1].rstrip(".")
                if "." in mx_host:
                    found.append(mx_host)
    except Exception:
        pass

    try:
        txt_results = resolver.resolve(domain, "TXT")  # type: ignore[union-attr]
        for txt in txt_results:
            txt_str = txt.strip('"')
            if "v=spf1" in txt_str:
                for part in txt_str.split():
                    if part.startswith("include:"):
                        spf_domain = part[len("include:") :].rstrip(".")
                        if "." in spf_domain:
                            found.append(spf_domain)
                    elif part.startswith("redirect="):
                        spf_domain = part[len("redirect=") :].rstrip(".")
                        if "." in spf_domain:
                            found.append(spf_domain)
    except Exception:
        pass

    return found


def enrich_with_mx_spf(domains: set[str], workers: int = 32) -> set[str]:
    """Discover additional domains via MX records and SPF includes/redirects."""
    import concurrent.futures

    try:
        from recursive_resolver import RecursiveResolver
    except ImportError:
        print("Warning: recursive_resolver not installed, skipping enrichment", file=sys.stderr)
        return domains

    resolver = RecursiveResolver(timeout=3.0, ipv4_only=True)
    enriched = set(domains)
    domain_list = sorted(domains)
    total = len(domain_list)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_enrich_one, d, resolver): d for d in domain_list}
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 500 == 0:
                print(f"  Enriching... {done}/{total} domains checked, {len(enriched)} total")
            with contextlib.suppress(Exception):
                enriched.update(future.result())

    return enriched


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare test domains from data.gouv.fr dataset")
    parser.add_argument("-o", "--output", default="domains.csv", help="Output CSV file path")
    parser.add_argument("--no-enrich", action="store_true", help="Skip MX/SPF enrichment")
    args = parser.parse_args()

    rows = download_dataset()
    print(f"Downloaded {len(rows)} rows")

    domains = extract_domains(rows)
    print(f"Extracted {len(domains)} unique domains")

    if not args.no_enrich:
        print("Enriching with MX/SPF subdomains...")
        domains = enrich_with_mx_spf(domains)
        print(f"After enrichment: {len(domains)} domains")

    # Write output
    sorted_domains = sorted(domains)
    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain"])
        for domain in sorted_domains:
            writer.writerow([domain])

    print(f"Wrote {len(sorted_domains)} domains to {args.output}")


if __name__ == "__main__":
    main()
