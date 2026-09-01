# Third-party notices

`recursive-resolver` is MIT licensed (see [LICENSE](LICENSE)). This file records
everything third-party the project depends on, derives from, or fetches, and the
terms each comes under.

## Runtime dependencies

These are installed alongside the package and ship to every user. All are
permissive and compatible with MIT; none are copyleft.

| Package | Licence | Why it is here |
|---|---|---|
| [dnspython](https://www.dnspython.org/) | ISC | Wire format, transport, DNSSEC primitives |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | Signature verification (via the `dnssec` extra) |
| [cffi](https://cffi.readthedocs.io/) | MIT-0 | Transitive, via `cryptography` |
| [pycparser](https://github.com/eliben/pycparser) | BSD-3-Clause | Transitive, via `cffi` |
| [idna](https://github.com/kjd/idna) | BSD-3-Clause | IDNA 2008 (via the `idna` extra) |

Development dependencies (pytest, ruff, mypy, coverage, build, twine) are not
distributed with the package.

## Derived work

Two files are adapted from [suitenumerique/messages](https://github.com/suitenumerique/messages),
Copyright (c) 2025 Direction Interministérielle du Numérique, Gouvernement
Français, **MIT licensed**. Both carry the notice in their header:

- `scripts/release.sh`: the interactive-gate structure, hermetic
  build-and-upload inside Docker, and the artifact-inspection step are adapted
  from `bin/release-jmap-email.sh`.
- `src/recursive_resolver/addresses.py`: the ordering of the address checks,
  the `is_global` catch-all, and naming the cloud-metadata endpoints explicitly
  are adapted from `core/services/ssrf.py`.

## Reference values, not copied code

`budget.py` and `resolver.py` cite the defaults that other widely-used resolver
implementations use for the same protections
(`max-recursion-queries`, `MAX_TARGET_COUNT`, `max-ns-per-resolve`, and so on).
These are parameter names and numeric values: facts about how those resolvers
behave, recorded so a reader can check our choices against the state of the art.
No code or documentation text is reproduced from any of them.

This distinction matters because several of those projects are copyleft
(PowerDNS Recursor and Knot Resolver are GPL, BIND 9 is MPL-2.0). Nothing
derived from them may be copied into this MIT-licensed package. An earlier draft
of `addresses.py` did embed PowerDNS's curated `dont-query` prefix list; it has
been removed and replaced with classification from Python's `ipaddress` module,
which follows the IANA special-purpose address registries directly.

## Protocol data compiled into the package

- **Root server hints** (`roots.py`): from
  <https://www.internic.net/domain/named.root>. Public protocol data published
  by IANA/ICANN for exactly this purpose; every recursive resolver embeds them.
- **DNSSEC root trust anchors** (`roots.py`): from
  <https://data.iana.org/root-anchors/root-anchors.xml>. Likewise published for
  validators to embed.

## Data fetched by the test corpus scripts

`scripts/collect_domains_diverse.py` and the other `collect_domains_*.py`
scripts download these **at run time**. None of it is vendored into the
repository, and generated corpora are `.gitignore`d, so the project does not
redistribute any of it. If you commit or publish a generated corpus, these terms
become yours to honour:

| Source | Terms |
|---|---|
| [Tranco](https://tranco-list.eu/) | CC BY 4.0; the underlying lists carry their own terms (Majestic CC BY 3.0, CrUX CC BY-SA 4.0). Attribution required, and the authors ask that research cite their paper |
| [Cisco Umbrella top 1M](https://umbrella-static.s3-us-west-1.amazonaws.com/index.html) (`collect_domains_3_zone.py`) | Free for research and analysis; attribution required |
| [Public Suffix List](https://publicsuffix.org/) | MPL-2.0 |
| [IANA TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | Public IANA registry data |
| [data.gouv.fr dataset](https://data.gouv.fr/) (`prepare_test_domains.py`) | Open Licence / Licence Ouverte |
| [crt.sh](https://crt.sh/) (`collect_domains_2_ct.py`) | Public Certificate Transparency log data |

## Reporting a problem

If you believe anything here is attributed incorrectly or licensed
incompatibly, please open an issue, or, if it is sensitive, follow
[SECURITY.md](SECURITY.md).
