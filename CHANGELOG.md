# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-15

A security release, with breaking API changes. Three defects in DNSSEC
validation let an attacker able to answer for a signed zone, on-path or by
spoofing, have forged data accepted: twice as authenticated, once by
downgrading the zone to unsigned. None needs a key of the zone; each reuses a
genuine, public record or field out of place. Upgrade before relying on a
`SECURE` verdict, or on a signed zone being treated as signed, from 0.2.0.

### Security

- An unsigned CNAME beside a genuine signed DNAME decided where the
  redirection went, and the answer came back `SECURE` whatever its target.
  The CNAME is now always synthesised from the DNAME (RFC 6672 §3.4) and the
  server's is ignored.
- A wildcard's NSEC record, replayed under another owner name, proved NODATA
  (`_dmarc.example.` has no TXT) or NXDOMAIN as authenticated: its signature
  verifies under any name below the wildcard's parent. A denial record now
  counts only with a signature made for its own owner name.
- An RRSIG signer field naming any unsigned delegation in a signed zone sent
  the chain-of-trust walk there, and that zone's genuine "no DS" proof was
  applied to the name being judged: forged referrals, NXDOMAIN and NODATA
  came back `INSECURE` instead of `BOGUS`, and the forged delegation was
  cached. The signer must now contain the name being judged.
- A DS set listing a supported and an unsupported algorithm could be
  downgraded to unsigned by a forged DNSKEY answer keeping only the
  unsupported key. Whether a zone is verifiable is now read off the signed DS
  RRset (RFC 4035 §5.2), and a SHA-1 DS is ignored beside a stronger one
  (RFC 4509 §3).
- Validated DNSKEY and DS records were cached for their wire TTL, up to a day,
  with a 60 second floor, past the expiry of their signatures. They are now
  capped like any authenticated data (RFC 4035 §5.3.3), so a rollover or an
  emergency revocation takes effect.
- An unauthenticated NXDOMAIN hid every name below it (RFC 8020) for up to an
  hour: one broken server or spoofed packet for `_domainkey.example.` hid
  every DKIM selector. Only an authenticated NXDOMAIN covers its subtree now,
  as in Unbound.
- A packet from any address reaching the resolver's ephemeral port aborted
  the query in flight. It is now ignored, as wrong-ID packets already were.
- CNAME and DNAME redirections were accepted without the AA bit.
- A TCP response with TC set was used as complete.
- The child apex's own NSEC3 could prove its parent publishes no DS; the NSEC
  path already refused this.
- A lame zone, whose servers all refuse or fail, drew 44 to 64 queries per
  lookup to its own servers: its in-zone NS names were re-resolved through
  the same servers, recursively, and SERVFAIL sweeps were quadratic in the
  number of servers. It now costs about one query per server, and reports
  `ServfailError` instead of a budget error.
- dnspython 2.9.2 or later is required. Earlier releases are affected by
  CVE-2026-114605 (CPU exhaustion on crafted name compression, reachable from
  any nameserver a lookup reaches) and CVE-2026-128089. See SECURITY.md.

### Fixed

- Every name in `root-servers.net` failed with
  `DNSSECMaterialUnavailableError`. The root servers serve that zone but not
  `net`, and the chain of trust was only ever asked of them. A referral they
  send to the zone whose keys or DS proof is needed is now followed.
- Glueless NS names are resolved two at a time, as far as needed, rather than
  all thirteen in both address families before the first query, and an
  address family the host cannot reach is given up for the rest of the
  resolution without being charged. With `ipv4_only=False` on a host without
  IPv6, `www.gov.uk`, `login.microsoftonline.com` and `aws.amazon.com` ran out
  of query budget; in the default mode `www.gov.uk` cost 44 queries and now
  costs 24.
- With validation on, servers that cannot do EDNS were unreachable even for
  unsigned zones. Plain DNS is now the last rung of the downgrade ladder
  wherever the chain of trust is not secure.
- An NXDOMAIN is confirmed by one sibling server, not two, and a response
  with no signature in a signed zone is retried on one sibling, not on all of
  them. Sibling retries no longer count against `max_depth`.
- `Answer.cname_chain` repeated names and differed between a cold and a warm
  lookup. It now lists each redirected name once, in order.
- Cached CNAMEs are followed for any record type, so a warm lookup of a name
  behind a CNAME costs no upstream query.
- A server failure or DNSSEC failure is remembered for 5 seconds (RFC 9520).
- DS answers sent in referral form, with the DS and its RRSIG in AUTHORITY,
  validate instead of reading as unsigned.
- Algorithms dnspython refuses to validate (RSAMD5, DSA) are unverifiable, so
  such zones are `INSECURE` per RFC 8624 rather than `BOGUS`. Hosts whose
  crypto policy refuses SHA-1 signatures (the RHEL 9 family) treat
  algorithms 5 and 7 the same way.
- `dnssec=True` with a `cryptography` too old for dnspython's DNSSEC support
  failed every lookup as an attack. It is now refused at construction with
  `DNSSECUnavailableError`.
- The whole-call deadline is a hard cap: a TCP retry gets what is left of it,
  and a caller that waited out its time on an identical concurrent lookup no
  longer starts a full resolution of its own.
- A negative answer with no SOA is not cached (RFC 2308 §5).
- No reachable nameserver is a `ServfailError`, not a timeout, and
  `ServfailError` says what failed rather than always "SERVFAIL".
- `--trace` reports the exception a failed resolution ended with, and marks
  the step whose response failed validation `bogus`; `-v` logs every query.
- `--text` escapes control characters and bytes that are not UTF-8 instead of
  writing them to the terminal, where they could crash a strict encoding.
- Rejected glue is logged at DEBUG: the zone chooses it, so at WARNING a
  hostile zone could write a log line per referral.
- Exceptions survive pickling, so they cross process pools and task queues.
- `"example.com "` is stripped rather than resolved with a trailing `\032`,
  and `"@"` is refused rather than resolved as the root.

### Changed

- Python 3.10 is no longer supported: dnspython 2.9 requires 3.11. The
  `dnssec` extra requires `cryptography>=50`, as dnspython 2.9 does.
- `RecursiveResolver`, `DNSCache` and `Limits` take keyword arguments only,
  and out-of-range values (`timeout`, `max_depth`, `max_retries`, the limits)
  raise `ValueError`.
- A resolver built with `dnssec=False` reports `ValidationState.DISABLED`
  rather than `INSECURE`, which claimed a zone had been checked.
- `Answer.dnssec` has no default.
- `trace_answer()` returns a `Trace`, a list of `TraceStep` with an `error`
  attribute; code that unpacks it as a list keeps working.
- `RRSIG` cannot be queried with validation on: it has no signature of its
  own, so the answer was always `BOGUS`.
- `QueryBudgetExceededError` for the signature and NSEC3 limits has `qname`
  `None` rather than the placeholder `"<dnssec>"`.
- GitHub Actions in CI are pinned by commit, and the release script pins
  `build`, `twine` and Hatchling and refuses to run on a dirty tree. The sdist
  now ships `TESTING.md` and the `Dockerfile`.

### Added

- `resolve()`, `resolve_answer()`, `resolve_rrset()` and `trace_answer()`
  accept a `dns.name.Name` and a `dns.rdatatype.RdataType` as well as text.
- `ResolverError.query_name` and `query_type`: the query passed to
  `resolve()`, where `qname` can be a CNAME target or a nameserver hostname.
- `Trace`, exported from the package.
- Python 3.15 in the CI matrix.
- Nineteen entries in the mutation catalogue, covering the fixes above that
  it can express, for 71 in all.

## [0.2.0] - 2026-09-03

A security release. Four defects in DNSSEC validation allowed forged data to be
accepted as authenticated; the most direct required only that the attacker own
a signed domain of their own. Upgrade before relying on a `SECURE` verdict from
0.1.0. `TESTING.md` describes how they were found.

### Security

- An RRSIG's signer was never required to contain the RRset it covers
  (RFC 4035 §5.3.1), so any signed zone could sign for any name.
- A wildcard at any ancestor was accepted where only the one at the closest
  encloser can have answered (RFC 4035 §5.3.4/§5.4). Three variants: forged
  NXDOMAIN, forged NODATA against a nested wildcard, and a replayed wildcard
  RRset authenticated under a name a closer wildcard governs.
- Denials served from the parent side of a zone cut were accepted as proof
  about the child, and a child's own SOA-bearing record could deny its DS
  (RFC 6840 §4.1, RFC 4035 §5.2). Likewise a parent-side NSEC3 as the closest
  encloser (RFC 5155 §8.3).
- An opt-out NSEC3 proved NODATA for any type; it only ever proves a missing
  DS (RFC 5155 §8.5, §8.6), and even then unauthenticated (§9.2).
- The DNSKEY RRset was authenticated against every published key rather than
  the one the parent's DS matched (RFC 4035 §5.2), so a compromised
  zone-signing key was enough to introduce a new one.
- A DNSKEY with the REVOKE bit was still used to verify signatures
  (RFC 5011 §2.1).
- Three checks read a field from the first RRSIG rdata rather than the
  signature that verified, which an attacker orders. Each was exploitable with
  a decoy.
- An authenticated RRset could be cached past its signature's expiry
  (RFC 4035 §5.3.3), for up to 24 hours; a proven denial for up to an hour.
- An NXDOMAIN or NODATA resting on an opt-out cover was reported
  authenticated, and `require_dnssec=True` did not apply to negative answers
  at all, cached or fresh.
- NSEC3 records with reserved flag bits were read as Opt-Out (RFC 5155 §8.2).

### Fixed

- One unreachable or out-of-sync nameserver no longer condemns a zone. DNSKEY
  and DS fetches, bare referrals, failed denials and answers carrying no
  signature at all now sweep the NS set (RFC 4035 §5.5); a stale cached
  delegation re-resolves its NS names. The last of those is a nameserver
  serving a stale *unsigned* copy of a signed zone: every type it answers
  reads as forged and its DNSKEY NODATA proves nothing, so landing on it made
  the whole zone intermittently BOGUS. One of `nic.bj`'s four nameservers is
  such a copy.
- A single spoofed UDP packet no longer retires a healthy nameserver
  (RFC 5452 §9).
- DNAME is implemented: CNAME synthesis when the server omits it, and the
  redirection inherits the DNAME's verdict rather than reading the unsigned
  synthesized CNAME as a stripped signature (RFC 6672 §3.3, §3.4, §8).
- `ANY` is refused rather than answered as NODATA and cached as a denial.
- An NS set that points sideways or upwards is an error, not a denial.
- The SOA marking a negative answer must be class IN and belong to the zone
  queried.
- Glue is cached under its own TTL, not the NS set's.
- `AAAA` is queried for glueless NS targets when IPv6 is enabled.
- A CNAME chain reports the minimum TTL over its hops.
- Empty non-terminals and wildcard-synthesised NODATA are no longer BOGUS
  (RFC 4035 §3.1.3.4.1, §5.4; RFC 5155 §8.7), nor is a NODATA whose only proof
  is an opt-out gap. The bit says the range holds no *signed* delegation, not
  that it holds no names, so the answer is returned unauthenticated rather than
  refused (RFC 5155 §8.6, §9.2). Ten zones in a 4000-name corpus needed this.
- RRSIG validity uses RFC 1982 serial arithmetic, allows configurable slack on
  inception (`clock_skew`, 60s) for signers whose clock runs ahead, and is
  checked before any cryptography.
- The IPv6 transition prefixes (6to4, Teredo, NAT64, IPv4-compatible) are
  refused as nameserver addresses by name. Each carries an IPv4 address
  inside it, and CVE-2024-4032 moved where the standard library draws that
  line, so the control no longer depends on the interpreter's patch level.
- `edns_payload` outside 16 bits, and a cache `min_ttl` above its `max_ttl`,
  are rejected at construction rather than misbehaving later.
- `--json` with `--no-dnssec` reports `"dnssec": "disabled"`. It said
  `"insecure"`, which claims a zone was checked and found unsigned.
- A resolution that runs out of budget while resolving a referral's
  nameservers reports a timeout, not a server failure.

### Changed

- A high NSEC3 iteration count downgrades to insecure rather than failing,
  matching the major implementations (RFC 9276 §3.2 permits either).
- `min_ttl` no longer floors authenticated answers or delegations, whose TTL
  is already capped by their signature.

### Added

- `DNSSECMaterialUnavailableError`, raised when a DNSKEY or DS could not be
  retrieved. Deliberately not a `DNSSECError`, so "refuse to use this data"
  handling stays correct while retrieval failures fall through to retries.
- `TESTING.md` and the harnesses it describes, including a mutation catalogue
  of 52 reintroduced defects that confirms the suite still catches each one.

## [0.1.0] - 2026-08-09

First public release.
