#!/usr/bin/env python3
"""Layer 6 of TESTING.md: check that the suites actually bite.

A green test run proves nothing on its own: the tests that pass today would
also have passed against 0.1.0, which is how the DNSSEC failures shipped. This
reintroduces each known defect into a *copy* of the package, one at a time, and
reports which layer catches it. A mutant that survives every layer is a hole in
the protocol, not a curiosity.

The catalogue is explicit source rewrites rather than a generic mutation tool,
for two reasons: each entry documents the real defect it reproduces, and a
rewrite that no longer applies is reported loudly, so the catalogue cannot
quietly rot as the code moves.

Nothing here touches the working tree: the package is copied to a temporary
directory and the harnesses are pointed at it with ``RR_SRC``.

Usage:
    python scripts/mutation_check.py --cassettes cassettes.jsonl
    python scripts/mutation_check.py --cassettes cassettes.jsonl --only lame-dnskey
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (label, description, [(old, new), ...]) - each entry is a defect that really
# existed, or a plausible weakening of the control that replaced it.
MUTATIONS: list[tuple[str, str, list[tuple[str, str]]]] = [
    (
        "lame-dnskey",
        "0.1.0: an empty DNSKEY answer condemns the zone instead of sweeping on",
        [
            (
                """        response, _server = self._send_query(
            zone,
            dns.rdatatype.DNSKEY,
            nameservers,
            ctx,
            usable=self._noting_rejects(self._usable_dnskey(zone), rejected),
        )
        if response is None:
            raise DNSSECMaterialUnavailableError(str(zone), "DNSKEY")

        dnskey_rrset = self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY)
        if dnskey_rrset is None:  # pragma: no cover - the predicate rules this out
            raise DNSSECMaterialUnavailableError(str(zone), "DNSKEY")""",
                """        response, _server = self._send_query(zone, dns.rdatatype.DNSKEY, nameservers, ctx)
        if response is None:
            raise ResolutionTimeoutError(str(zone), "DNSKEY")

        dnskey_rrset = self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY)
        if dnskey_rrset is None:
            return ZoneKeys(zone, None, ValidationState.BOGUS)""",
            )
        ],
    ),
    (
        "no-do-bit",
        "0.1.0: the last sweep of the EDNS ladder drops the OPT record",
        [("        return min(512, self.edns_payload) if dnssec else None", "        return None")],
    ),
    (
        "edns-incapable-retried",
        "0.1.0: an EDNS-incapable server is re-queried without DO while validating",
        [
            (
                """                    if validating:
                        abandoned.add(server)
                        ctx.answered_with_error.add(server)
                        if last_resort is None:
                            last_resort = (response, server)
                    else:
                        no_edns.add(server)""",
                "                    no_edns.add(server)",
            ),
            (
                "                if server in no_edns and not validating:",
                "                if server in no_edns:",
            ),
        ],
    ),
    (
        "mangled-response-retried-without-do",
        "weakening: a server whose response does not parse is re-queried without DO while validating",
        [
            (
                "                    if payload is not None and not validating:",
                "                    if payload is not None:",
            ),
            (
                "                if server in no_edns and not validating:",
                "                if server in no_edns:",
            ),
        ],
    ),
    (
        "edns-incapable-carried-into-a-signed-zone",
        "weakening: a server found EDNS-incapable below an unsigned cut is asked without DO in a signed zone",
        [
            (
                "                if server in no_edns and not validating:",
                "                if server in no_edns:",
            )
        ],
    ),
    (
        "ds-fetch-no-sweep",
        "0.1.0: the DS fetch believes the first server that answers",
        [
            (
                """        response, _server = self._send_query(
            next_zone,
            dns.rdatatype.DS,
            nameservers,
            ctx,
            usable=self._noting_rejects(self._usable_ds(next_zone), rejected),
        )""",
                "        response, _server = self._send_query(next_zone, dns.rdatatype.DS, nameservers, ctx)",
            )
        ],
    ),
    (
        "insecure-child-bogus",
        "0.1.0: an unsigned answer from a signed parent is BOGUS without checking the delegation",
        [
            (
                """        if name == zone or not name.is_subdomain(zone):
            return False""",
                """        if name == zone or not name.is_subdomain(zone):
            return False
        return False""",
            )
        ],
    ),
    (
        "optout-wildcard-secure",
        "0.2.0-rc: an opt-out NSEC3 is accepted as proof for a wildcard expansion",
        [
            (
                """        if any(not n[0].flags & NSEC3_OPT_OUT for n in covering):
            return ValidationState.SECURE
        return ValidationState.INSECURE""",
                "        return ValidationState.SECURE",
            )
        ],
    ),
    (
        "aa-not-required",
        "weakening: accept a DNSKEY answer from a server that is not authoritative",
        [
            (
                """            if self.require_authoritative and not response.flags & dns.flags.AA:
                return False
            if self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY) is None:""",
                """            if self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY) is None:""",
            )
        ],
    ),
    (
        "ent-nodata-bogus",
        "0.1.0: an empty non-terminal in an NSEC zone is BOGUS instead of NODATA",
        [
            (
                """            following: dns.name.Name = nsec[0].next
            if following != qname and following.is_subdomain(qname) and self._nsec_covers(nsec.name, following, qname):
                return ValidationState.SECURE""",
                "            continue",
            )
        ],
    ),
    (
        "wildcard-nodata-bogus",
        "0.2.0-rc: a NODATA synthesised from a wildcard is BOGUS (NSEC3 form)",
        [
            (
                """        if next_closer_covers:
            wildcard = dns.name.Name((b"*",) + closest.labels)
            for nsec3 in nsec3s:
                if self._nsec3_owner(wildcard, nsec3.name, params, budget) != nsec3.name:
                    continue
                types = _types_in_bitmap(nsec3[0])
                if rdtype not in types and dns.rdatatype.CNAME not in types:
                    if any(not n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
                        return ValidationState.SECURE
                    break""",
                "        pass",
            )
        ],
    ),
    (
        "wildcard-nodata-bogus-nsec",
        "0.2.0-rc: the same, in an NSEC zone",
        [
            (
                """        deniers = [n for n in nsecs if self._may_deny_below(n, qname, signer)]
        for covering in deniers:""",
                """        deniers = []
        for covering in deniers:""",
            )
        ],
    ),
    (
        "optout-no-ds-at-the-child-only",
        "0.2.0-rc: the no-DS opt-out proof looks for a cover of the delegation itself",
        [
            (
                """        closest = self._closest_encloser_nsec3(child, nsec3s, params, budget)
        if closest is None:
            return False
        next_closer = self._next_closer(child, closest)
        if next_closer is None:
            return False
        for nsec3 in nsec3s:
            if nsec3[0].flags & NSEC3_OPT_OUT and self._nsec3_covers(next_closer, nsec3, params, budget):
                return True""",
                """        for nsec3 in nsec3s:
            if nsec3[0].flags & NSEC3_OPT_OUT and self._nsec3_covers(child, nsec3, nsec3[0], budget):
                return True""",
            )
        ],
    ),
    (
        "authenticated-ttl-not-capped",
        "spec audit: cached authenticated data outlives its signature (RFC 4035 5.3.3)",
        [
            (
                """    return min(
        int(rrset.ttl),
        int(rrsig_rrset.ttl),
        int(signature.original_ttl),
        max(0, int(signature.expiration) - int(time.time())),
    )""",
                "    return int(rrset.ttl)",
            )
        ],
    ),
    (
        "spoofed-packet-retires-a-server",
        "hardening: one wrong-ID datagram abandons a healthy nameserver (RFC 5452 9)",
        [
            (
                "                    ignore_errors=True,\n",
                "",
            )
        ],
    ),
    (
        "require-dnssec-skips-denials",
        "policy: require_dnssec accepts an unauthenticated 'no such name'",
        [
            (
                """        if self.require_dnssec and state is not ValidationState.SECURE:
            raise DNSSECInsecureError(str(qname), rdtype_text)""",
                "        return None",
            )
        ],
    ),
    (
        "wildcard-trigger-reads-the-first-rrsig",
        "spec audit: the RFC 4035 5.3.4 wildcard proof keys off rrsig[0], not the one that verified",
        [
            (
                "        if not rrset.name.is_wild() and signature.labels < len(rrset.name.labels) - 1:",
                "        if not rrset.name.is_wild() and rrsig[0].labels < len(rrset.name.labels) - 1:",
            )
        ],
    ),
    (
        "cached-denials-skip-require-dnssec",
        "policy: a cached denial is served without the strict-mode check",
        [
            (
                """            self._require_proven_denial(
                ValidationState.SECURE if nx.secure else ValidationState.INSECURE,
                qname,
                dns.rdatatype.to_text(rdtype),
            )
""",
                "",
            )
        ],
    ),
    (
        "cross-zone-signer-accepted",
        "spec audit: any zone may sign for any name (RFC 4035 5.3.1) - full DNSSEC bypass",
        [
            (
                """            if not rrset.name.is_subdomain(rrsig.signer):
                logger.debug("RRSIG for %s claims signer %s, which does not contain it", rrset.name, rrsig.signer)
                continue
""",
                "",
            )
        ],
    ),
    (
        "failed-denial-not-retried",
        "RFC 4035 5.5: one out-of-sync server condemns a zone's denials",
        [
            (
                """        fresh, _server = self._send_query(
            qname, rdtype, nameservers, ctx, usable=self._usable_denial(qname, rdtype, keyring, ctx, negative)
        )
        if fresh is not None:""",
                """        fresh = None
        if fresh is not None:""",
            )
        ],
    ),
    (
        "any-silently-becomes-nodata",
        "reference gap: an ANY query is accepted, matches nothing, and caches a denial",
        [
            (
                '            raise UnsupportedRdtypeError(rdtype, "ANY cannot be queried; ask for specific types")',
                "            return value",
            )
        ],
    ),
    (
        "dname-not-followed",
        "reference gap: RFC 6672 CNAME synthesis is not performed",
        [
            (
                """        dname_rrset = self._find_dname(response, qname, current_zone)
        if dname_rrset is not None:
            if self.require_authoritative and not authoritative:""",
                """        dname_rrset = None
        if dname_rrset is not None:
            if self.require_authoritative and not authoritative:""",
            )
        ],
    ),
    (
        "synthesized-cname-demands-a-signature",
        "reference gap: the unsigned CNAME a DNAME implies is read as a stripped signature",
        [
            (
                """            return self._validate_answer(
                response, dname_rrset, qname, dns.rdatatype.DNAME, ctx, zone, nameservers, state, ds
            )
""",
                "            pass\n",
            )
        ],
    ),
    (
        "sideways-ns-set-read-as-nodata",
        "reference gap: an NS set that does not delegate onward is cached as a denial",
        [
            (
                "        if ns_sets and not any("
                "self._delegates_towards(rrset.name, qname, current_zone) for rrset in ns_sets):\n"
                '            return {"type": "error", "rcode": rcode, '
                '"detail": "NS set that does not delegate below this zone"}\n',
                "",
            )
        ],
    ),
    (
        "negative-soa-from-any-zone",
        "reference gap: an SOA from above the zone marks a negative answer and sets its TTL",
        [
            (
                """            and qname.is_subdomain(rrset.name)
            and rrset.name.is_subdomain(current_zone)""",
                "            and qname.is_subdomain(rrset.name)",
            )
        ],
    ),
    (
        "glue-outlives-its-own-ttl",
        "reference gap: cached addresses expire with the NS set, not with the glue",
        [
            (
                """        if glue_ttls:
            ttl = min(ttl, *glue_ttls)
""",
                "",
            )
        ],
    ),
    (
        "glueless-ns-is-ipv4-only",
        "reference gap: AAAA is never queried for a glueless NS target",
        [
            (
                "        wanted = [dns.rdatatype.A] if self.ipv4_only else [dns.rdatatype.A, dns.rdatatype.AAAA]",
                "        wanted = [dns.rdatatype.A]",
            )
        ],
    ),
    (
        "high-nsec3-iterations-are-bogus",
        "reference gap: a legacy iteration count is refused where the ecosystem downgrades",
        [
            (
                """        if self.nsec3_beyond_our_limits(authority, parent_keys, budget):
            return ValidationState.INSECURE, None
""",
                "",
            )
        ],
    ),
    (
        "positive-wildcard-ignores-the-labels-count",
        "reference gap: the NSEC wildcard proof accepts any covering record, not the encloser's",
        [
            (
                """            if self._closest_encloser_nsec(qname, nsec) == closest:
                return ValidationState.SECURE""",
                "            return ValidationState.SECURE",
            )
        ],
    ),
    (
        "child-may-deny-its-own-ds",
        "reference gap: a SOA-bearing record denies a DS (RFC 4035 5.2)",
        [
            (
                "                if rdtype == dns.rdatatype.DS and dns.rdatatype.SOA in types "
                "and qname != dns.name.root:\n                    continue\n",
                "",
            )
        ],
    ),
    (
        "no-clock-skew-on-inception",
        "reference gap: no slack for a signer whose clock runs ahead",
        [
            (
                "            if not _serial_le(int(rrsig.inception), (stamp + self.clock_skew) & 0xFFFFFFFF):",
                "            if not _serial_le(int(rrsig.inception), stamp):",
            )
        ],
    ),
    (
        "expired-signatures-still-cost-crypto",
        "hardening: the validity window is checked after the crypto, not before",
        [
            (
                """            if not _serial_le(stamp, int(rrsig.expiration)):
                logger.debug("RRSIG for %s has expired", rrset.name)
                continue
""",
                "",
            )
        ],
    ),
    (
        "cached-delegation-ns-names-dropped",
        "reference gap: a dead cached delegation is not re-resolved from its NS names",
        [
            (
                "        pending_ns_names = [n for n in cached_ns_names if not n.is_subdomain(current_zone)]",
                "        pending_ns_names: list[dns.name.Name] = []",
            )
        ],
    ),
    (
        "nested-wildcard-nodata-at-any-ancestor",
        "spec audit: wildcard NODATA takes any ancestor's wildcard, not the closest encloser's",
        [
            (
                """            wildcard = dns.name.Name((b"*",) + self._closest_encloser_nsec(qname, covering).labels)
            for nsec in deniers:
                if nsec.name != wildcard:""",
                """            for nsec in deniers:
                if not (nsec.name.is_wild() and qname.is_subdomain(nsec.name.parent())):""",
            )
        ],
    ),
    (
        "opt-out-wildcard-cover-called-secure",
        "spec audit: only the next-closer cover is checked for opt-out, not the wildcard's",
        [
            (
                """        for covers in (covering, wildcard_covering):
            if not any(not n[0].flags & NSEC3_OPT_OUT for n in covers):
                return ValidationState.INSECURE
        return ValidationState.SECURE""",
                """        if any(not n[0].flags & NSEC3_OPT_OUT for n in covering):
            return ValidationState.SECURE
        return ValidationState.INSECURE""",
            )
        ],
    ),
    (
        "wildcard-denial-at-any-ancestor",
        "spec audit: NXDOMAIN accepted by denying a wildcard above the closest encloser",
        [
            (
                """            wildcard = dns.name.Name((b"*",) + self._closest_encloser_nsec(qname, nsec).labels)
            if any(self._nsec_covers(n.name, n[0].next, wildcard) for n in nsecs):
                return True""",
                """            for i in range(1, len(qname.labels)):
                wildcard = dns.name.Name((b"*",) + qname.labels[i:])
                if any(self._nsec_covers(n.name, n[0].next, wildcard) for n in nsecs):
                    return True""",
            )
        ],
    ),
    (
        "closest-encloser-from-the-parent-side",
        "spec audit: a delegation or DNAME record is accepted as closest encloser (RFC 5155 8.3)",
        [
            (
                """                types = _types_in_bitmap(nsec3[0])
                if dns.rdatatype.DNAME in types:
                    return None
                if dns.rdatatype.NS in types and dns.rdatatype.SOA not in types:
                    return None
                return current""",
                "                return current",
            )
        ],
    ),
    (
        "matching-nsec3-ignores-the-bitmap",
        "weakening: a matching NSEC3 denies the type without consulting its bitmap (RFC 5155 8.5)",
        [
            (
                """            if rdtype not in types and dns.rdatatype.CNAME not in types:
                return ValidationState.SECURE

        # Everything below needs the closest encloser""",
                """            return ValidationState.SECURE

        # Everything below needs the closest encloser""",
            )
        ],
    ),
    (
        "opt-out-nxdomain-called-secure",
        "spec audit: an NXDOMAIN proven only by an opt-out cover is reported authenticated",
        [
            (
                """        if any(not n[0].flags & NSEC3_OPT_OUT for n in covering):
            return ValidationState.SECURE
        return ValidationState.INSECURE""",
                "        return ValidationState.SECURE",
            )
        ],
    ),
    (
        "ds-denied-by-the-parent-side-record-refused",
        "spec audit: RFC 6840 4.1 exempts DS, so refusing it breaks every DS lookup",
        [
            (
                "                if rdtype != dns.rdatatype.DS and self._parent_side(nsec, qname, signer):",
                "                if self._parent_side(nsec, qname, signer):",
            )
        ],
    ),
    (
        "any-key-may-sign-the-dnskey-rrset",
        "spec audit: the DNSKEY RRset is checked against every published key, not the DS-matched one",
        [
            (
                "self.validated_rrsig(dnskey_rrset, rrsig_rrset, {zone: entry_points}, budget=budget)",
                "self.validated_rrsig(dnskey_rrset, rrsig_rrset, {zone: dnskey_rrset}, budget=budget)",
            )
        ],
    ),
    (
        "revoked-keys-still-validate",
        "spec audit: a DNSKEY with the REVOKE bit is still used to verify signatures (RFC 5011 2.1)",
        [
            (
                """            if revoked:
                logger.debug("Ignoring revoked DNSKEY for %s", name)
                continue
""",
                "",
            )
        ],
    ),
    (
        "parent-side-denial-accepted",
        "spec audit: an ancestor delegation record denies things below the cut (RFC 6840 4.1)",
        [
            (
                """        types = _types_in_bitmap(nsec[0])
        if dns.rdatatype.NS not in types or dns.rdatatype.SOA in types:
            return False
        return zone is not None and len(zone) < len(owner)""",
                "        return False",
            )
        ],
    ),
    (
        "dname-denial-accepted",
        "spec audit: a DNAME record denies subdomains it rewrites (RFC 6840 4.1)",
        [
            (
                """        if dns.rdatatype.DNAME in _types_in_bitmap(nsec[0]):
            return False
""",
                "",
            )
        ],
    ),
    (
        "nsec3-reserved-flags-accepted",
        "spec audit: NSEC3 records with reserved flag bits are used (RFC 5155 8.2)",
        [
            (
                """            if rdtype == dns.rdatatype.NSEC3 and rrset[0].flags & ~NSEC3_OPT_OUT:
                logger.debug("Ignoring NSEC3 at %s with reserved flags %#x", rrset.name, rrset[0].flags)
                continue
""",
                "",
            )
        ],
    ),
    (
        "ent-in-the-chain-walk-condemned",
        "0.2.0-rc: an intermediate label that is not a cut breaks the chain walk",
        [
            (
                """        if state is ValidationState.BOGUS and self._validator.prove_no_delegation(
            next_zone, records, keyring, budget=ctx.budget
        ):
            return state, None, False
""",
                "",
            )
        ],
    ),
    (
        "no-delegation-proof-ignores-the-bitmap",
        "weakening: any matching NSEC counts as proof that a label is not a cut",
        [
            (
                """            if nsec.name == name:
                types = _types_in_bitmap(nsec[0])
                if dns.rdatatype.NS not in types and dns.rdatatype.DS not in types:
                    return True
                continue
            if not self._may_deny_below(nsec, name, signer):
                continue""",
                """            if nsec.name == name:
                return True
            if not self._may_deny_below(nsec, name, signer):
                continue""",
            )
        ],
    ),
    (
        "referral-to-a-higher-cut-accepted",
        "0.2.0-rc: 'ask further down' is taken as an answer about the delegation",
        [
            (
                """            if any(
                rrset.rdtype == dns.rdatatype.NS and rrset.name != zone and zone.is_subdomain(rrset.name)
                for rrset in records
            ):
                return False
""",
                "",
            )
        ],
    ),
    (
        "opt-out-nodata-called-bogus",
        "0.2.0-rc: a NODATA whose only proof is an opt-out gap is refused outright",
        [
            (
                """        if any(n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
            return ValidationState.INSECURE""",
                """        if rdtype == dns.rdatatype.DS and any(
            n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers
        ):
            return ValidationState.INSECURE""",
            )
        ],
    ),
    (
        "opt-out-ds-nodata-authenticated",
        "0.2.0-rc: an opt-out cover is reported as an authenticated absent DS",
        [
            (
                """        if any(n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
            return ValidationState.INSECURE
        return ValidationState.BOGUS""",
                """        if any(n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
            return ValidationState.SECURE
        return ValidationState.BOGUS""",
            )
        ],
    ),
    (
        "opt-out-wildcard-nodata-authenticated",
        "0.2.0-rc: a wildcard NODATA whose next closer is only opt-out covered is authenticated",
        [
            (
                """                    if any(not n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
                        return ValidationState.SECURE
                    break""",
                """                    return ValidationState.SECURE""",
            )
        ],
    ),
    (
        "bare-referral-condemned",
        "0.2.0-rc: a referral carrying no DS and no denial is BOGUS rather than walked",
        [
            (
                "        if not self._usable_ds(child_zone)(response):",
                "        if False:",
            )
        ],
    ),
    (
        "stale-unsigned-server-condemns-the-zone",
        "0.1.0: one nameserver serving an unsigned copy makes the whole zone bogus",
        [
            (
                """        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return False
        if kind not in ("answer", "cname", "nodata", "nxdomain"):
            return False""",
                """        return False""",
            )
        ],
    ),
    (
        "an-unsigned-referral-is-swept-past",
        "the same control over-firing: a delegation NS RRset is unsigned by design",
        [('        if kind not in ("answer", "cname", "nodata", "nxdomain"):', "        if False:")],
    ),
    (
        "dname-target-from-the-wire",
        "0.2.0 review: an unsigned CNAME beside a signed DNAME picks the target, and validates",
        [
            (
                """        if dname_rrset is not None:
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "DNAME without AA bit"}""",
                "        wire_cname = self._find_answer_rrset(response, qname, dns.rdatatype.CNAME)\n"
                """        if dname_rrset is not None and wire_cname is None:
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "DNAME without AA bit"}""",
            ),
            (
                """                    "dname_rrset": None,
                    "ttl": cname_rrset.ttl,""",
                """                    "dname_rrset": self._find_dname(response, qname, current_zone),
                    "ttl": cname_rrset.ttl,""",
            ),
        ],
    ),
    (
        "renamed-wildcard-nsec-denies",
        "0.2.0 review: a wildcard's NSEC replayed under another owner proves NODATA and NXDOMAIN",
        [
            (
                "self.validate_rrset(rrset, rrsig, keys, budget=budget, exact_owner=True)",
                "self.validate_rrset(rrset, rrsig, keys, budget=budget)",
            )
        ],
    ),
    (
        "signer-field-followed-sideways",
        "0.2.0 review: an RRSIG naming an unsigned sibling zone downgrades a signed zone",
        [
            (
                "                if name.is_subdomain(signer):\n                    return signer",
                "                return signer",
            )
        ],
    ),
    (
        "unverifiable-judged-from-the-keys",
        "0.2.0 review: a forged DNSKEY RRset keeping only the unsupported key reads as unsigned",
        [
            (
                "ds for ds in candidate_ds if _digest_supported(ds.digest_type) and algorithm_supported(ds.algorithm)",
                "ds for ds in candidate_ds if _digest_supported(ds.digest_type)",
            ),
            (
                """            return ValidationState.BOGUS, None

        # The DNSKEY RRset must be signed by a key the DS matched""",
                """            return ValidationState.BOGUS, None
        if not any(algorithm_supported(key.algorithm) for key in matched):
            return ValidationState.INSECURE, None

        # The DNSKEY RRset must be signed by a key the DS matched""",
            ),
        ],
    ),
    (
        "sha1-ds-beside-sha256",
        "0.2.0 review: a SHA-1 DS is accepted where a SHA-256 one exists (RFC 4509 3)",
        [
            (
                "            usable_ds = [ds for ds in usable_ds if ds.digest_type != dns.dnssec.DSDigest.SHA1]",
                "            pass",
            )
        ],
    ),
    (
        "keys-cached-for-the-wire-ttl",
        "0.2.0 review: DNSKEYs outlive their signature by up to a day",
        [
            (
                "self._store_keys(keys, authenticated_ttl(dnskey_rrset, rrsig, signature))",
                "self._store_keys(keys, dnskey_rrset.ttl)",
            )
        ],
    ),
    (
        "ds-cached-for-the-wire-ttl",
        "0.2.0 review: a validated DS outlives its signature",
        [("                rdataset.add(rr, ttl=ttl)", "                rdataset.add(rr, ttl=ds_rrset.ttl)")],
    ),
    (
        "in-zone-ns-names-re-resolved",
        "0.2.0 review: a lame zone's in-zone NS names are resolved through the same lame servers",
        [
            (
                "pending_ns_names = [n for n in ns_names if not n.is_subdomain(child_zone)]\n",
                "pending_ns_names = [n for n in ns_names if not n.is_subdomain(child_zone)] or ns_names\n",
            ),
            (
                "                    glue = self._resolve_ns_names(pending_ns_names, ctx, depth + 1)",
                "                    glue = self._resolve_ns_names(pending_ns_names or ns_names, ctx, depth + 1)",
            ),
        ],
    ),
    (
        "servfail-sweep-quadratic",
        "0.2.0 review: servers held back with SERVFAIL are dropped one per pass",
        [("                failed = {server, *ctx.answered_with_error}", "                failed = {server}")],
    ),
    (
        "every-ns-name-resolved-up-front",
        "0.2.0 review: all thirteen NS names, in both families, are resolved before the first query",
        [("_NS_NAMES_AHEAD = 2", "_NS_NAMES_AHEAD = 99")],
    ),
    (
        "unreachable-family-retried",
        "0.2.0 review: on a v4-only host every IPv6 server costs a query",
        [("                        ctx.unreachable_families.add(_family(server))\n", "")],
    ),
    (
        "plain-dns-never-below-an-unsigned-cut",
        "0.2.0 review: with validation on, an EDNS-incapable server is unreachable even for unsigned zones",
        [("        validating = ctx.dnssec and not ctx.chain_insecure", "        validating = ctx.dnssec")],
    ),
    (
        "cname-without-aa",
        "0.2.0 review: a CNAME is followed without the AA bit",
        [
            (
                "                if self.require_authoritative and not authoritative:\n"
                '                    return {"type": "error", "rcode": rcode, "detail": "CNAME without AA bit"}\n',
                "",
            )
        ],
    ),
    (
        "third-party-packet-aborts-the-query",
        "0.2.0 review: a datagram from any other address ends the query",
        [("                    ignore_unexpected=True,", "                    ignore_unexpected=False,")],
    ),
    (
        "truncated-tcp-accepted",
        "0.2.0 review: a TCP response with TC set is used as complete",
        [("                if response.flags & dns.flags.TC:", "                if False:")],
    ),
    (
        "nsec3-child-apex-denies-ds",
        "0.2.0 review: the child apex's own NSEC3 proves its parent has no DS",
        [
            (
                """                # The child apex's own record, as in the NSEC branch above.
                if dns.rdatatype.SOA in types and child != dns.name.root:
                    continue
""",
                "",
            )
        ],
    ),
    (
        "algorithms-dnspython-refuses-are-supported",
        "0.2.0 review: a DSA-only zone is BOGUS instead of unverifiable (RFC 8624)",
        [("    if not dns.dnssec.default_policy.ok_to_validate(probe):\n        return False\n", "")],
    ),
    (
        "grandparent-servers-asked-for-the-parent",
        "0.3.0 protocol run: every name in root-servers.net is material-unavailable",
        [("        for response in rejected:\n", "        for response in []:\n")],
    ),
    (
        "grandparent-servers-asked-for-the-ds",
        "0.3.0 protocol run: with the parent's keys cached, root-servers.net is unavailable",
        [
            (
                "                    servers = self._referred_servers(rejected, zone, bailiwick)\n"
                "                    if not servers:\n"
                "                        raise\n"
                "                    bailiwick = zone\n"
                "                    step",
                "                    raise\n                    step",
            )
        ],
    ),
]


def apply_mutation(target: Path, edits: list[tuple[str, str]]) -> None:
    """Apply every edit exactly once, across both files.

    Every edit has to land. Applying some and reporting success would run the
    suites against a half-mutated build, which proves nothing about the defect
    the entry names: an edit that no longer matches is a stale catalogue entry
    and has to be said out loud.
    """
    for old, _new in edits:
        # An empty search string matches anything, so the rewrite would land at
        # offset 0 and break the file: caught by every layer, and a test of
        # nothing.
        if not old:
            raise SystemExit("mutation has an empty search string")

    # Indices, not the (old, new) pairs themselves: two identical edits are two
    # rewrites to make, and comparing by value would strike both off the list
    # the first time one of them matched.
    pending = set(range(len(edits)))
    for name in ("resolver.py", "dnssec.py"):
        path = target / "recursive_resolver" / name
        text = path.read_text(encoding="utf-8")
        applied = set()
        for index in sorted(pending):
            old, new = edits[index]
            if old in text:
                text = text.replace(old, new, 1)
                applied.add(index)
        if applied:
            path.write_text(text, encoding="utf-8")
            pending -= applied

    if pending:
        raise SystemExit(f"mutation no longer applies: {edits[min(pending)][0][:60]!r}")


# pytest exits 0 when everything passed and 1 when a test failed. Anything else
# is the harness itself going wrong - a usage mistake, an interpreter that will
# not start - and reading it as "the mutant was caught" turns a broken run into
# a clean report. A collection error is not told apart this way: under -x it
# exits 1. The unmutated run in `main` is what catches that.
PYTEST_EXIT_CODES = frozenset({0, 1})

# The same rule for the cassette harness: 0 reproduced, 1 did not. It exits 2
# for anything else, so a truncated cassette file or a JSONDecodeError is a
# loud failure here instead of one more mutant reported as caught.
CASSETTE_EXIT_CODES = frozenset({0, 1})


def copy_package(target: Path) -> None:
    """Copy the package and its tests, and nothing else of the repository."""
    # Leave __pycache__ behind. A mutation that happens to preserve the file's
    # byte length can otherwise land within the same mtime granularity as the
    # copied .pyc, and Python reuses the stale bytecode: the mutant silently
    # never runs.
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(REPO / "src" / "recursive_resolver", target / "recursive_resolver", ignore=ignore)
    shutil.copytree(REPO / "tests", target / "tests", ignore=ignore)


def unit_command(python: str, target: Path) -> list[str]:
    """The unit suite, as run against a copy made by :func:`copy_package`."""
    return [
        python,
        "-m",
        "pytest",
        str(target / "tests"),
        "-q",
        "-x",
        "--tb=no",
        "-p",
        "no:cacheprovider",
        # Live DNS fails for reasons no mutant caused.
        "-m",
        "not integration",
        # These two test the repository around the package, which is not
        # copied. With -x a module that cannot be imported exits 1, the same
        # as a failed test.
        "--ignore",
        str(target / "tests/test_check_authors.py"),
        "--ignore",
        str(target / "tests/test_protocol_harness.py"),
    ]


def run(cmd: list[str], env_src: Path, cwd: Path, expected: frozenset[int] | None = None) -> bool:
    """True when the command passes (i.e. the mutant survived this layer)."""
    import os

    env = dict(os.environ, RR_SRC=str(env_src), PYTHONPATH=str(env_src))
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(cwd))
    if expected is not None and result.returncode not in expected:
        raise SystemExit(
            f"{cmd[0]} exited {result.returncode}, which is neither pass nor fail:\n{result.stdout[-2000:]}"
        )
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cassettes", help="Cassette file for the Layer 4 check")
    parser.add_argument("--only", help="Run a single mutation by label")
    parser.add_argument("--python", default=sys.executable, help="Interpreter to run the suites with")
    args = parser.parse_args()

    mutations = [m for m in MUTATIONS if not args.only or m[0] == args.only]
    if not mutations:
        raise SystemExit(f"no mutation named {args.only!r}")

    # An unreadable cassette file makes every perturb run fail, which reads as
    # "every mutant caught by the cassettes" - the most flattering possible
    # result, produced by the harness being broken.
    cassettes = ""
    if args.cassettes:
        path = Path(args.cassettes)
        if not path.is_file():
            raise SystemExit(f"cassette file not found: {args.cassettes}")
        try:
            path.open("rb").close()
        except OSError as exc:
            raise SystemExit(f"cannot read {args.cassettes}: {exc}") from None
        # `run` starts the child with cwd=REPO, so a path relative to wherever
        # this was invoked from would not resolve there.
        cassettes = str(path.resolve())

    cassette_cmd = [args.python, str(REPO / "scripts/cassette.py"), "perturb", "--cassettes", cassettes]

    # A layer that fails on the package as it stands fails on every mutant
    # too, and each of them reads as caught.
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        copy_package(target)
        if not run(unit_command(args.python, target), target, target, expected=PYTEST_EXIT_CODES):
            raise SystemExit("the unit suite fails on an unmutated copy of the package")
        if args.cassettes and not run(cassette_cmd, target, REPO, expected=CASSETTE_EXIT_CODES):
            raise SystemExit("the cassettes fail on an unmutated copy of the package")

    survivors: list[str] = []
    print(f"{'mutation':<44}{'unit suite':<14}{'cassettes':<14}caught by")
    for label, description, edits in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            copy_package(target)
            apply_mutation(target, edits)

            unit_ok = run(unit_command(args.python, target), target, target, expected=PYTEST_EXIT_CODES)
            cassette_ok = True
            if args.cassettes:
                cassette_ok = run(cassette_cmd, target, REPO, expected=CASSETTE_EXIT_CODES)

            caught = [name for name, ok in (("unit", unit_ok), ("cassettes", cassette_ok)) if not ok]
            if not caught:
                survivors.append(f"{label}: {description}")
            print(
                f"{label:<44}{'survived' if unit_ok else 'caught':<14}"
                f"{('survived' if cassette_ok else 'caught') if args.cassettes else 'skipped':<14}"
                f"{','.join(caught) or 'NOTHING'}"
            )

    if survivors:
        print("\nSurviving mutants - the protocol has a hole here:")
        for survivor in survivors:
            print(f"  {survivor}")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
