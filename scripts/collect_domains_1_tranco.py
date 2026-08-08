#!/usr/bin/env python3
"""Strategy 1: Tranco top sites list.

Tranco is a research-oriented top sites ranking that combines multiple lists
(Alexa, Chrome UX, Majestic, Umbrella). Downloads the latest list and samples
domains across the full popularity spectrum: top, middle, and tail.
"""

from __future__ import annotations

import csv
import io
import zipfile
from urllib.request import urlopen

OUTPUT = "domains_extra1.csv"
# Tranco provides a stable, daily-updated top-1M list
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def main() -> None:
    print(f"Downloading Tranco top-1M list from {TRANCO_URL}...")
    with urlopen(TRANCO_URL) as resp:
        data = resp.read()

    print("Extracting...")
    zf = zipfile.ZipFile(io.BytesIO(data))
    csv_name = zf.namelist()[0]
    text = zf.read(csv_name).decode("utf-8")

    all_domains: list[str] = []
    for line in text.strip().split("\n"):
        parts = line.strip().split(",")
        if len(parts) == 2:
            all_domains.append(parts[1])

    print(f"Total domains in list: {len(all_domains)}")

    # Sample: top 500, every 100th from 500-100k, every 500th from 100k-1M
    sampled: list[str] = []
    sampled.extend(all_domains[:500])
    sampled.extend(all_domains[500:100_000:100])
    sampled.extend(all_domains[100_000::500])

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for d in sampled:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    with open(OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain"])
        for d in unique:
            writer.writerow([d])

    print(f"Wrote {len(unique)} domains to {OUTPUT}")


if __name__ == "__main__":
    main()
