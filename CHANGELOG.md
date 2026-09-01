# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-01

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
  and DS fetches, bare referrals and failed denials all sweep the NS set
  (RFC 4035 §5.5); a stale cached delegation re-resolves its NS names.
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
  of 50 reintroduced defects that confirms the suite still catches each one.

## [0.1.0] - 2026-08-09

First public release.
