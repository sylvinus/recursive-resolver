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
| **DNS-driven SSRF**: glue pointing at `127.0.0.1`, RFC1918, or `169.254.169.254` to probe internal networks or a cloud metadata endpoint | Every candidate nameserver address must be globally routable and none of loopback, link-local, multicast, reserved or private, per the IANA special-purpose registries as tracked by Python's `ipaddress`. A short explicit list adds ranges classification does not refuse, or did not always refuse: Azure's `168.63.129.16`, 6to4 relay anycast, ORCHIDv2, deprecated site-local, and the IPv6 transition prefixes that carry an IPv4 address inside them (6to4, Teredo, NAT64, IPv4-compatible). CVE-2024-4032 changed how the standard library classifies several of those prefixes; the others a current stdlib already refuses, and are listed as explicit policy so the control behaves the same on every supported Python. IPv4-mapped IPv6 is unwrapped first so it cannot bypass the v4 rules |
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
| **NSEC3 CPU exhaustion** | NSEC3 iteration counts above 100 are not computed. The proof is downgraded to insecure rather than refused, which is what the major implementations do (RFC 9276 §3.2 permits either) |
| **Signature forgery by a zone that owns one** | An RRSIG counts only if the zone it names as signer contains the RRset it covers (RFC 4035 §5.3.1), and only a key the parent's DS matched authenticates the DNSKEY RRset (§5.2). A revoked key is never used (RFC 5011 §2.1) |
| **Forged denial of existence** | A denial must come from the zone holding the name, not the parent side of its cut (RFC 6840 §4.1, RFC 5155 §8.3); only the wildcard at the closest encloser can have answered; an opt-out cover proves a missing DS and nothing else |
| **Decisions taken from attacker-ordered data** | An RRSIG RRset may carry several rdata, only one of which verified. Every check reads the signature that validated; the signing zone comes from the keyring, never the wire |
| **Authenticated data outliving its signature** | A validated RRset's cache TTL is capped by the time left on its RRSIG (RFC 4035 §5.3.3) |
| **One broken nameserver condemning a zone** | Validation material and unproven denials are re-sought from the zone's other nameservers before any BOGUS verdict (RFC 4035 §5.5), with no relaxation of what is then checked |
| **Unbounded resolution time** | A hard wall-clock deadline applies to the whole call, including all sub-resolutions |

### What is not defended against

- **A full on-path attacker**, unless the target zone is DNSSEC-signed and you use `require_dnssec=True`. An unsigned zone offers no cryptographic assurance at all: that is a property of DNS, not of this library.
- **Traffic analysis.** QNAME minimisation (RFC 9156) is not implemented, so the full query name is visible to root and TLD servers.
- **Resource exhaustion from your own call volume.** The budget bounds a single `resolve()`; rate-limiting your callers is your responsibility.
- **DNS rebinding.** The address filter applies to nameserver addresses, not to answers: a zone may legitimately publish `A 127.0.0.1` for its own name, and this library returns it, as other implementations do. Filter the addresses you get back before connecting to them.
- **An unsigned answer from a zone whose other nameservers serve it signed.** RFC 4035 §5.5 says to try another server before concluding an answer is forged. Denials do this; answers do not, because the retry would have to replace the returned RRset. Such a zone yields an intermittent `DNSSECValidationError`.
- **Malicious `allow_private_addresses=True`.** That flag disables the SSRF control by design. Only enable it for split-horizon DNS you fully control.

## Supported versions

Security fixes are applied to the latest released version. Given the pre-1.0 status, please upgrade to the newest release before reporting.

## Dependency policy

The only runtime dependency is `dnspython` (ISC licence), with its `dnssec` extra pulling in `cryptography` and its `idna` extra pulling in `idna`.

The floor is `dnspython>=2.8.0`. Versions below 2.6.1 are affected by [CVE-2023-29483](https://nvd.nist.gov/vuln/detail/CVE-2023-29483) ("TuDoor"), and 2.6.0 additionally regressed truncation handling in a way that breaks UDP→TCP failover.
