# Contributing

## Development setup

```bash
make install          # uv sync
make test             # unit tests (no network)
make test-integration # integration tests (needs network)
make coverage         # coverage report
make lint             # ruff
make format           # ruff format
make typecheck        # mypy
make check            # lint, format, types and the offline tests
```

A Docker shell with `uv`, `make`, `dig` and the dependencies preinstalled:

```bash
make docker-shell
```

## AI-assisted contributions

Using an AI tool to help write a patch is fine. Three conditions apply.

**Merging is best-effort, and nothing more is promised.** A patch that arrives
with a lot of generated code still has to be read, understood and maintained by
someone. Large or unfocused submissions may be closed without a detailed review.
Small, well-scoped changes with tests are far more likely to land.

**The MIT licence still has to hold.** You are submitting the patch under
[LICENSE](LICENSE), so you need to be satisfied that nothing in it was copied
from an incompatible source. Generated code can reproduce training data, and
several of the reference resolvers cited in this project are copyleft. See
[THIRD-PARTY.md](THIRD-PARTY.md) for where the line sits.

**The human author is responsible.** You are the author of anything you submit,
whatever produced the first draft: you are expected to understand it, to stand
behind it in review, and to have run the tests. Do not credit an AI tool as an
author or co-author. `Co-authored-by:` trailers naming Claude, Codex, Copilot or
any other tool will be removed before merge. This is enforced: CI runs
`scripts/check_authors.py` over every commit in a pull request, checking the
author, the committer and any `Co-authored-by:` trailer.

## Licensing

This package is MIT and every runtime dependency is permissive. Before copying
anything in, check [THIRD-PARTY.md](THIRD-PARTY.md) and note that several
widely-used resolver implementations are **copyleft** (GPL or MPL). Their
*behaviour* is fair to cite: parameter names and default values are facts, and
recording them lets a reader check our choices
against the state of the art. Their code, documentation text and curated data
(prefix lists, tables) are not, and must not be pasted in.

If you adapt from a permissively-licensed project, put the copyright notice in
the file header and add a row to `THIRD-PARTY.md`.

## Guidelines

- **Security changes need a regression test.** `tests/test_security.py` is
  organised by the attack each control prevents; add yours there with a comment
  explaining what breaks without it.
- **Do not loosen a defensive check without saying why.** The referral,
  bailiwick, AA, class and address rules each exist because a specific attack or
  real-world failure was observed. `CHANGELOG.md` records which.
- **Keep dnspython exceptions inside the resolver.** Everything raised out of
  the public API must be a `ResolverError`. Bare `except Exception` is not
  acceptable in the query path: it is what previously turned malformed input
  into phantom network timeouts.
- Unit tests must not touch the network. Use the builders in `tests/conftest.py`
  and patch `_send_query`, or `_query_once` when the sweep across a zone's
  nameservers is itself what is being tested.
- **A DNSSEC verdict needs retrieved material.** `DNSSECValidationError` means
  signed data was obtained and failed to verify. Anything that could not be
  fetched, whether a lame server, a SERVFAIL or no answer at all, is a
  `DNSSECMaterialUnavailableError`, which is deliberately not a `DNSSECError`.
- Integration tests go behind the `integration` marker.

## Differential testing

Beyond the unit and integration suites, `scripts/diff_harness.py` compares this
resolver against reference resolvers across a large corpus, broken down by
record type, corpus category and resolver configuration.

It compares record values, not DNSSEC verdicts, and runs each name once. The
layers that cover those, driven by `make test-protocol`, are described in
[TESTING.md](TESTING.md).

```bash
# Build a deliberately awkward corpus (~4k names).
python scripts/collect_domains_diverse.py -o domains.csv

# Compare against dig, all supported types, one configuration.
python scripts/diff_harness.py --csv domains.csv

# Compare configurations against each other on a sample.
python scripts/diff_harness.py --csv domains.csv --sample 250 \
    --types A,MX,TXT,NS --configs default,no-dnssec,no-cache,no-tcp,small-edns,ipv6
```

The corpus is assembled from Tranco sampled across popularity bands (the tail is
where broken configurations live), every IANA TLD including the IDN ones,
multi-label public suffixes, mail and underscore subdomains layered onto popular
domains, and a curated set of pathological cases: signed and deliberately-bogus
zones, IDN homographs, shared zone cuts, empty non-terminals, CNAME chains.

Two things matter when reading the output:

* The reference is queried **by explicit IP**, never through the system stub. A
  local `systemd-resolved` synthesises a self-referential `CNAME` with TTL 0 for
  names that have none, which makes every CNAME query look like a mismatch.
* Several references are queried and matching **any** of them counts as
  agreement. Zones whose parent delegation disagrees with their own NS RRset
  make public recursives disagree with each other; those are reported separately
  rather than counted against either resolver.

`scripts/prepare_test_domains.py` and the `collect_domains_*.py` scripts build
alternative corpora, and `tests/test_csv.py` runs a smaller version under
pytest:

```bash
make test-from-csv CSV=domains.csv
```

By default this covers every supported type that a list of apex domains can
exercise: `A, AAAA, MX, TXT, NS, SOA, CAA, CNAME, DS, DNSKEY`. A type the domain
does not publish yields NODATA on both sides, which is still a meaningful
agreement.

`PTR`, `SRV` and `NAPTR` are excluded from this harness because apex domains
cannot exercise them: PTR needs an IP address and SRV/NAPTR need
`_service._proto` labels. They are covered by the unit and integration suites.

Mismatches are written to a timestamped JSONL file. The test asserts an overall
match rate of at least 96%; the residual differences are CDN round-robin and
domains with genuinely dead nameservers. DNSSEC is disabled for this comparison
because `dig +short` does not validate either.

## Releasing

1. **Bump the version** in both `pyproject.toml` and
   `src/recursive_resolver/__init__.py`, and add a `CHANGELOG.md` entry.
2. **Run `scripts/release.sh`.**

```bash
./scripts/release.sh
```

The script is interactive and every step is a y/N gate, so you can read what it
found before continuing. It:

1. checks the tree is clean, the two version strings agree, the changelog has an
   entry and the tag does not already exist;
2. runs `make check-all`;
3. builds the sdist and wheel **inside Docker**, so the host never needs `pip`,
   `build` or `twine`, and runs `twine check`;
4. inspects the artifacts against what this package promises: `py.typed`
   present, no tests or scripts in the wheel, LICENSE bundled, and the
   `dnspython` floor at or above the 2.8.0 security floor with the `dnssec` and
   `idna` extras. It reads these out of the built wheel's `METADATA`, not out
   of `pyproject.toml`, so a build that lost them is caught;
5. uploads to TestPyPI, then installs from there in a throwaway container and
   **actually resolves a name**, checking that a signed zone validates and that
   a multi-chunk DKIM key joins without a separator;
6. uploads to PyPI;
7. prints the `git tag`, `git push` and `gh release create` commands, with the
   changelog section already extracted to `dist/RELEASE_NOTES_<version>.md`.
   It does not run them: tagging rewrites history and a release is public, so
   both stay a deliberate act by whoever is running the release.

The GitHub release carries the release notes, the sdist and wheel, and a
`SHA256SUMS` manifest. Those are the same files twine uploaded moments earlier
-- nothing rebuilds in between -- so they are byte-identical to PyPI's copy by
construction. PyPI remains the channel `pip` installs from; the attached copy
is an archival one, and it is what survives a release being *deleted* on PyPI,
which unlike yanking stops the files being downloadable at all. `SHA256SUMS`
makes the two copies comparable: PyPI publishes a sha256 per file at
`https://pypi.org/pypi/recursive-resolver/<version>/json`, so anyone can check
that they match without trusting either host.

Run the printed commands promptly. Python builds are not byte-reproducible, so
rebuilding `dist/` before running them would attach artifacts that differ from
the ones on PyPI even though the source is identical.

`SKIP_GATES=1` skips step 2 on a retry; `SKIP_TESTPYPI=1` goes straight to PyPI.

### Prerequisites

Docker, git, and, for the last step only, an authenticated `gh` CLI. You will
be prompted for the TestPyPI and PyPI API tokens; they are read into the
container's environment and never written to disk.

### Root hints and trust anchors

`src/recursive_resolver/roots.py` contains hardcoded root server addresses and
DNSSEC trust anchors. Re-check them against the upstream sources when preparing
a release:

- Root hints: <https://www.internic.net/domain/named.root>
- Trust anchors: <https://data.iana.org/root-anchors/root-anchors.xml>

Only anchors that are currently valid belong in the file: retired ones (such as
KSK-2010, tag 19036) must be removed, not kept "just in case".
