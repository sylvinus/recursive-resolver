# recursive-resolver

A pure-Python library that implements **true recursive (iterative) DNS resolution** from root servers. Unlike stub resolvers that forward queries to a local DNS server, this library starts from the DNS root and follows the delegation chain itself. This enables fully cache-less DNS queries, bypassing any intermediate resolver caches.

Uses [dnspython](https://www.dnspython.org/) only for wire-format parsing and UDP/TCP transport — not its built-in `dns.resolver`.

## Installation

```bash
pip install recursive-resolver
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add recursive-resolver
```

## CLI Usage

After installation, the `recursive-resolver` command is available:

```bash
# Resolve A records
recursive-resolver example.com

# Resolve a specific record type
recursive-resolver example.com MX

# Reverse PTR lookup
recursive-resolver 8.8.8.8 PTR

# Show the full DNS delegation trace from root servers
recursive-resolver --trace example.com

# JSON output
recursive-resolver --json example.com MX

# Trace with JSON output
recursive-resolver --trace --json example.com

# Enable debug logging
recursive-resolver -v example.com

# Custom timeout and depth
recursive-resolver --timeout 10 --max-depth 30 example.com
```

You can also run it as a Python module:

```bash
python -m recursive_resolver example.com MX
```

Run `recursive-resolver --help` for all options.

## Quick Start

```python
from recursive_resolver import RecursiveResolver

resolver = RecursiveResolver()

# A records
ips = resolver.resolve("example.com", "A")
print(ips)  # ['93.184.216.34']

# MX records
mx = resolver.resolve("example.com", "MX")
print(mx)  # ['0 .']

# PTR (auto-converts IP to reverse pointer)
ptr = resolver.resolve("1.1.1.1", "PTR")
print(ptr)  # ['one.one.one.one.']
```

## Supported DNS Record Types

A, AAAA, CNAME, MX, TXT, SOA, PTR, NS, SRV, CAA, DNSKEY, DS, NAPTR

## Configuration

```python
resolver = RecursiveResolver(
    timeout=5.0,              # per-query timeout in seconds
    max_resolution_time=30.0, # hard cap on total wall-clock time per resolve() call
    max_depth=20,             # max delegation depth
    max_cname_chain=10,       # max CNAME follows before error
    cache_enabled=True,       # enable DNS response caching
    use_tcp_fallback=True,    # TCP fallback on truncation
    max_retries=2,            # retries per nameserver
    ipv4_only=True,           # only use IPv4 for queries
)
```

## DNS Resolution Trace

```python
trace = resolver.resolve_with_trace("example.com", "A")
for step in trace:
    print(f"{step.server:20s} {step.qname:30s} {step.response_type:10s} {step.detail}")
```

Output:
```
198.41.0.4           example.com.                   referral   NS: a.gtld-servers.net., ...
192.5.6.30           example.com.                   referral   NS: a.iana-servers.net., ...
199.43.135.53        example.com.                   answer
```

## Exceptions

```python
from recursive_resolver import (
    ResolverError,          # Base exception
    NXDOMAINError,          # Domain does not exist (DNS NXDOMAIN)
    NoAnswerError,          # No DNS records of requested type
    MaxDepthError,          # Exceeded max delegation depth
    ResolutionTimeoutError, # All nameservers timed out
    CNAMELoopError,         # CNAME loop detected
    ServfailError,          # All nameservers returned errors
)
```

## How It Works

1. **Start at the root**: The resolver begins with hardcoded root DNS server IP addresses (a.root-servers.net through m.root-servers.net).

2. **Send non-recursive queries**: All queries are sent with `RD=0` (Recursion Desired = off), meaning we're asking the server for what it knows directly, not asking it to recurse on our behalf.

3. **Follow delegations**: When a server doesn't have the final answer, it returns a referral — NS records pointing to DNS nameservers closer to the target. The resolver follows these delegations.

4. **Handle glue records**: Referrals often include "glue" A/AAAA records in the additional section, providing IP addresses for the referred nameservers. When glue is missing, the resolver sub-resolves the NS hostnames.

5. **Chase CNAMEs**: When a CNAME is encountered, DNS resolution restarts from the root for the canonical name (since it may be in a completely different zone).

6. **Cache results**: DNS responses are cached with TTL-based expiry using monotonic time, including negative responses (NXDOMAIN/NODATA).

## Reliability

### Built on dnspython

This library does not implement DNS wire format parsing or UDP/TCP transport from scratch. All low-level DNS operations are handled by [dnspython](https://www.dnspython.org/), one of the most mature and widely-used DNS libraries in the Python ecosystem (first released in 2001). We use it for:

- Building and parsing DNS messages (`dns.message`)
- UDP and TCP transport with timeout handling (`dns.query`)
- Record type and rcode constants (`dns.rdatatype`, `dns.rcode`)

What we implement on top of dnspython is the **iterative resolution algorithm** — the logic that starts at root servers, follows delegations, chases CNAMEs, handles glueless referrals, and enforces bailiwick checking. This is the part that `dns.resolver` (dnspython's built-in stub resolver) delegates to your system's recursive resolver.

### Test suite

The test suite has **97% code coverage** across 92 tests at three levels:

- **81 unit tests** (no network) — resolver logic is tested with mocked DNS responses covering: delegation chains, CNAME following, NXDOMAIN/NODATA, glueless referrals, CNAME loops, max depth, timeout/retry behavior, TCP fallback, EDNS0 fallback, PTR auto-reverse, cache hits, negative caching, bailiwick validation, deadline enforcement, and CLI argument handling.
- **11 integration tests** (real DNS) — live queries against well-known domains verifying A, AAAA, MX, TXT, NS, SOA, PTR, CNAME chains, NXDOMAIN errors, trace output, and cache speedup.
- **Bulk CSV tests** — automated comparison against `dig` on thousands of real domains (see below).

Run the full suite:

```bash
make test               # Unit tests (fast, no network)
make test-integration   # Integration tests (requires network)
make coverage           # Unit tests with coverage report
```

### Large-scale validation against dig

We validated the resolver against `dig` (the reference DNS tool) on over **200,000 queries** across **115,000+ real-world domains** and **7 record types** (A, AAAA, MX, TXT, NS, SOA, CAA). The only differences are CDN round-robin (different valid IPs returned to different resolvers) and a handful of domains with dead nameservers.

#### Reproduce the bulk tests

```bash
# 1. Generate a domain list from data.gouv.fr public dataset
python scripts/prepare_test_domains.py -o domains.csv

# 2. Run against dig with default types (A, MX)
make test-from-csv CSV=domains.csv

# 3. Run with all record types on a sample of 5,000 domains
uv run pytest tests/test_csv.py --csv=domains.csv \
    --types=A,AAAA,MX,TXT,NS,SOA,CAA --sample=5000 -s

# 4. Or bring your own domain list — any CSV with a "domain" column works
echo "domain" > my_domains.csv
echo "example.com" >> my_domains.csv
echo "wikipedia.org" >> my_domains.csv
make test-from-csv CSV=my_domains.csv
```

Failures are written to a timestamped JSONL file for inspection. The test asserts an overall match rate of at least 96%.

## Development

```bash
# Install dependencies
make install

# Run unit tests (no network needed)
make test

# Run integration tests (requires network)
make test-integration

# Coverage report
make coverage

# Lint and format
make lint
make format

# Type check
make typecheck

# Build package
make build

# Bulk test DNS resolution against dig
python scripts/prepare_test_domains.py -o domains.csv
make test-from-csv CSV=domains.csv
```

Run `make help` to see all available targets.

## Releasing

Releases are published to both [PyPI](https://pypi.org/project/recursive-resolver/) and [GitHub Releases](https://github.com/sylvinus/recursive-resolver/releases).

### 1. Bump the version

Update the version string in **both** files:

- `pyproject.toml` → `version = "X.Y.Z"`
- `src/recursive_resolver/__init__.py` → `__version__ = "X.Y.Z"`

### 2. Run pre-release checks

```bash
make release-check
```

This runs lint, format check, type check, unit tests, and verifies the version is consistent between the two files.

### 3. Publish

```bash
# Full release: checks + PyPI + GitHub tag & release
make release

# Or step by step:
make release-build       # Build sdist + wheel into dist/
make release-test-pypi   # Upload to Test PyPI first (optional)
make release-pypi        # Upload to PyPI (production)
make release-github      # Git tag + GitHub release with dist artifacts
```

`make release-test-pypi` lets you verify the package on [test.pypi.org](https://test.pypi.org/project/recursive-resolver/) before the real publish:

```bash
pip install --index-url https://test.pypi.org/simple/ recursive-resolver
```

### Prerequisites

- **PyPI credentials**: Configure a [PyPI API token](https://pypi.org/manage/account/token/) via `UV_PUBLISH_TOKEN` env var, or `~/.pypirc`, or `uv publish --token <token>`.
- **GitHub CLI**: `gh` must be installed and authenticated (`gh auth login`).

Run `make help` to see all available targets.

## License

MIT — Sylvain Zimmer
