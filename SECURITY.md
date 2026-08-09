# Security Policy

## Reporting a vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/sylvinus/recursive-resolver/security/advisories/new). Please do not open a public issue for an unpatched vulnerability.

We will triage them with best effort.

## Threat model

This library is designed to be pointed at domain names chosen by an attacker. That is the normal case for its intended use: verifying DKIM signatures on inbound mail means resolving names controlled by whoever sent the message.

**Assumed hostile:** the queried domain's zone contents, its NS records, its glue records, its referrals, its response flags, and the timing and size of its responses.

**Assumed trustworthy:** the root hints and the IANA root trust anchors compiled into this package, and the local network path (this library does not defend against a full on-path attacker; use `require_dnssec=True` if you need cryptographic assurance).

### What is defended against

| Attack | Control |
|---|---|
| **DNS-driven SSRF**: glue pointing at `127.0.0.1`, RFC1918, or `169.254.169.254` to probe internal networks or a cloud metadata endpoint | Every candidate nameserver address must be globally routable and none of loopback, link-local, multicast, reserved or private, per the IANA special-purpose registries as tracked by Python's `ipaddress`. A short explicit list adds ranges that classification still calls routable: Azure's `168.63.129.16`, 6to4 relay anycast, ORCHIDv2 and deprecated site-local. IPv4-mapped IPv6 is unwrapped first so it cannot bypass the v4 rules |
| **NXNSAttack / Non-Responsive Delegation amplification** (CVE-2020-8616, CVE-2020-12662, CVE-2022-3204): a zone that answers every query with a glueless referral to many fresh NS names, using the resolver as a DDoS amplifier | A budget shared across the whole resolution and all sub-resolutions: 64 queries, 5 failed NS targets, 130 referrals, 13 NS names per referral (randomly sampled, not a prefix) |
| **Referral loops and lame delegation** | A referral must name a zone strictly below the zone queried; sideways and upward referrals are rejected |
| **Cache poisoning via out-of-bailiwick glue** | Bailiwick is evaluated against the zone we queried, never against a zone name supplied in the response |
| **Answer injection** | Answers are matched on owner name, type *and* class, must carry the AA bit, and `NXDOMAIN` responses carrying answer records are rejected |
| **Off-path spoofing** | dnspython validates the source address, query ID and question section; DNSSEC validation provides cryptographic assurance where the zone is signed |
| **EDNS downgrade by a spoofed packet** | Unmatched or unparseable responses do not trigger an EDNS downgrade or retire a nameserver |
| **IP fragmentation attacks** | EDNS payload defaults to 1232 (DNS Flag Day 2020) rather than 4096 |
| **Truncation-based data loss** | A truncated response is never treated as complete, on any code path |
| **Random-subdomain (water torture) floods** | NXDOMAIN is cached by name and suppresses everything below it (RFC 8020) |
| **IDN homograph confusion** | IDNA 2008 is used, so `straße.de` is not silently resolved as `strasse.de` |
| **KeyTrap** (CVE-2023-50387, CVE-2023-50868): colliding key tags forcing quadratic signature verification | At most 2 keys and 2 signatures per (tag, algorithm), 8 signatures per RRset, 8 DS records per zone; per-resolution budget of 96 signature verifications and 600 NSEC3 hashes |
| **NSEC3 CPU exhaustion** | NSEC3 iteration counts above 100 are rejected (RFC 9276 requires zones to publish 0) |
| **Unbounded resolution time** | A hard wall-clock deadline applies to the whole call, including all sub-resolutions |

### What is not defended against

- **A full on-path attacker**, unless the target zone is DNSSEC-signed and you use `require_dnssec=True`. An unsigned zone offers no cryptographic assurance at all: that is a property of DNS, not of this library.
- **Traffic analysis.** QNAME minimisation (RFC 9156) is not implemented, so the full query name is visible to root and TLD servers.
- **Resource exhaustion from your own call volume.** The budget bounds a single `resolve()`; rate-limiting your callers is your responsibility.
- **Malicious `allow_private_addresses=True`.** That flag disables the SSRF control by design. Only enable it for split-horizon DNS you fully control.

## Supported versions

Security fixes are applied to the latest released version. Given the pre-1.0 status, please upgrade to the newest release before reporting.

## Dependency policy

The only runtime dependency is `dnspython` (ISC licence), with its `dnssec` extra pulling in `cryptography` and its `idna` extra pulling in `idna`.

The floor is `dnspython>=2.8.0`. Versions below 2.6.1 are affected by [CVE-2023-29483](https://nvd.nist.gov/vuln/detail/CVE-2023-29483) ("TuDoor"), and 2.6.0 additionally regressed truncation handling in a way that breaks UDP→TCP failover.
