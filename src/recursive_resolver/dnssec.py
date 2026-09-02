"""DNSSEC validation: chain of trust, RRSIG verification and denial of existence.

The validator walks down from the IANA root trust anchors
(:data:`~recursive_resolver.roots.ROOT_TRUST_ANCHORS`).  At every zone cut it
establishes one of three states, following RFC 4035:

``SECURE``
    The zone's DNSKEY chains back to the root anchor and the data is signed.
``INSECURE``
    Some ancestor proved, with an NSEC/NSEC3 record, that no DS exists: the
    zone is legitimately unsigned. This is the common case: most domains are
    not signed.
``BOGUS``
    The zone claims to be signed but the signatures, the delegation chain or
    the denial-of-existence proof do not validate. The data must not be used.

Only ``BOGUS`` is an error. Treating ``INSECURE`` as an error would reject the
majority of the internet, so that is opt-in via ``require_dnssec=True``.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.NSEC3 import b32_normal_to_hex

from .roots import ROOT_TRUST_ANCHORS

logger = logging.getLogger(__name__)

# DNSKEY flag bits (RFC 4034 §2.1.1, RFC 5011 §7).
FLAG_ZONE_KEY = 0x0100
FLAG_REVOKE = 0x0080

# NSEC3 flags (RFC 5155 §3.1.2).
NSEC3_OPT_OUT = 0x01

# Slack allowed on a signature's inception, in seconds. A zone that re-signs
# continuously publishes records whose inception is a moment in the future as
# far as a validator with a slightly slow clock is concerned, and without any
# tolerance those records are intermittently BOGUS. Other implementations allow
# between a minute and several; this is the conservative end of that range.
CLOCK_SKEW = 60


def _serial_le(first: int, second: int) -> bool:
    """RFC 1982 serial comparison: is ``first`` at or before ``second``?"""
    return ((second - first) & 0xFFFFFFFF) < 0x80000000


# Reject absurd NSEC3 iteration counts outright rather than burning CPU on
# them. RFC 9276 requires zones to publish 0; .com/.net/.org already do, and
# common ccTLDs stay in single digits, so 100 rejects only abuse.
MAX_NSEC3_ITERATIONS = 100

# KeyTrap (CVE-2023-50387) hardening. The attack publishes many DNSKEYs and
# many RRSIGs that collide on key tag and algorithm, so a validator that tries
# every signature against every candidate key performs quadratic work for one
# answer. PowerDNS caps both at 2 per (tag, algorithm).
MAX_KEYS_PER_TAG = 2
MAX_RRSIGS_PER_TAG = 2
MAX_RRSIGS_PER_RRSET = 8
MAX_DS_PER_ZONE = 8


class ValidationState(Enum):
    """The DNSSEC status of a response."""

    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"


def algorithm_supported(algorithm: int) -> bool:
    """True if signatures made with this DNSSEC algorithm can be verified here.

    Which algorithms work depends on the installed dnspython and cryptography,
    so this is a property of the build rather than a fixed list. A zone signed
    only with an algorithm we lack is unverifiable, which RFC 4035 §5.2 says to
    treat as unsigned rather than as an attack.
    """
    try:
        dns.dnssec.get_algorithm_cls(algorithm)
    except Exception:
        return False
    return True


def cryptography_available() -> bool:
    """True if the optional `cryptography` dependency is importable."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def _types_in_bitmap(rdata: Any) -> set[int]:
    """Return the set of rdatatypes present in an NSEC/NSEC3 type bitmap."""
    types: set[int] = set()
    for window, bitmap in rdata.windows:
        for i, byte in enumerate(bitmap):
            for j in range(8):
                if byte & (0x80 >> j):
                    types.add(window * 256 + i * 8 + j)
    return types


def find_rrsig(rrsets: list[dns.rrset.RRset], name: dns.name.Name, covered: int) -> dns.rrset.RRset | None:
    """Find the RRSIG RRset covering rdatatype ``covered`` at owner ``name``."""
    for rrset in rrsets:
        if rrset.rdtype != dns.rdatatype.RRSIG or rrset.name != name:
            continue
        if any(rr.type_covered == covered for rr in rrset):
            return rrset
    return None


def _rrset_of(rrsets: list[dns.rrset.RRset], name: dns.name.Name, rdtype: int) -> dns.rrset.RRset | None:
    for rrset in rrsets:
        if rrset.name == name and rrset.rdtype == rdtype and rrset.rdclass == dns.rdataclass.IN:
            return rrset
    return None


def _trim_keyring(keys: dict[dns.name.Name, Any]) -> dict[dns.name.Name, Any]:
    """Keep at most MAX_KEYS_PER_TAG usable keys per (key tag, algorithm).

    Colliding key tags are the core of KeyTrap: without this a single answer can
    force one signature check per published key.

    Keys with the REVOKE bit are dropped here rather than filtered at each call
    site, because this is the one place every signature check passes through. A
    revoked key is one whose owner has publicly withdrawn it, typically because
    it was compromised, and RFC 5011 §2.1 says it must not be used for any
    purpose afterwards. Its private key still produces signatures that verify,
    so a validator that ignores the bit keeps trusting exactly the key an
    attacker holds - which is the situation revocation exists to end. This
    resolver does not track trust anchors automatically, so it has no need of
    the one exception the RFC allows (validating the revocation itself) and
    simply never uses such a key.
    """
    trimmed: dict[dns.name.Name, Any] = {}
    for name, keyset in keys.items():
        if keyset is None:
            continue
        seen: dict[tuple[int, int], int] = {}
        kept = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for key in keyset:
            try:
                tag = dns.dnssec.key_id(key)
                revoked = bool(key.flags & FLAG_REVOKE)
            except Exception:
                # Not a usable DNSKEY at all; nothing here can be trusted.
                continue
            if revoked:
                logger.debug("Ignoring revoked DNSKEY for %s", name)
                continue
            slot = (tag, int(key.algorithm))
            if seen.get(slot, 0) >= MAX_KEYS_PER_TAG:
                continue
            seen[slot] = seen.get(slot, 0) + 1
            kept.add(key)
        kept.ttl = getattr(keyset, "ttl", 0)
        trimmed[name] = kept
    return trimmed


def _trim_rrsigs(rrsig_rrset: dns.rrset.RRset) -> list[Any]:
    """Keep a bounded, tag-diverse subset of the RRSIGs to try."""
    seen: dict[tuple[int, int], int] = {}
    out: list[Any] = []
    for rrsig in rrsig_rrset:
        slot = (int(rrsig.key_tag), int(rrsig.algorithm))
        if seen.get(slot, 0) >= MAX_RRSIGS_PER_TAG:
            continue
        seen[slot] = seen.get(slot, 0) + 1
        out.append(rrsig)
        if len(out) >= MAX_RRSIGS_PER_RRSET:
            break
    return out


@dataclass
class ZoneKeys:
    """Validated DNSKEY material for one zone."""

    zone: dns.name.Name
    dnskey_rrset: dns.rrset.RRset | None
    state: ValidationState
    expiry: float = field(default=0.0)

    def as_keyring(self) -> dict[dns.name.Name, Any]:
        return {self.zone: self.dnskey_rrset}


class DNSSECValidator:
    """Validates DNSSEC signatures and denial-of-existence proofs.

    Args:
        trust_anchors: DS records for the root, in presentation format.
            Must be non-empty: an empty anchor set can never validate anything,
            so it is rejected rather than silently treated as "use the
            defaults".
        max_nsec3_iterations: Reject NSEC3 records above this iteration count.
        clock_skew: Seconds of slack allowed on an RRSIG's inception, for
            signers whose clock runs ahead of ours (60 by default). Applies to
            inception only: expiration is checked against the real time, so
            slack can never keep an expired signature alive.

    Raises:
        ValueError: If ``trust_anchors`` is empty.
    """

    def __init__(
        self,
        trust_anchors: tuple[str, ...] = ROOT_TRUST_ANCHORS,
        max_nsec3_iterations: int = MAX_NSEC3_ITERATIONS,
        clock_skew: int = CLOCK_SKEW,
    ) -> None:
        if not trust_anchors:
            raise ValueError("trust_anchors must not be empty; omit it to use the IANA root anchors")
        self.max_nsec3_iterations = max_nsec3_iterations
        self.clock_skew = clock_skew
        self._root_ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        for anchor in trust_anchors:
            self._root_ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, anchor), ttl=86400)

    # ── signature validation ────────────────────────────────────────────

    def validate_rrset(
        self,
        rrset: dns.rrset.RRset,
        rrsig_rrset: dns.rrset.RRset | None,
        keys: dict[dns.name.Name, Any],
        now: float | None = None,
        budget: Any = None,
    ) -> bool:
        """Verify ``rrset`` against its RRSIG using ``keys``."""
        return self.validated_rrsig(rrset, rrsig_rrset, keys, now=now, budget=budget) is not None

    def validated_rrsig(
        self,
        rrset: dns.rrset.RRset,
        rrsig_rrset: dns.rrset.RRset | None,
        keys: dict[dns.name.Name, Any],
        now: float | None = None,
        budget: Any = None,
    ) -> Any | None:
        """The RRSIG rdata that authenticates ``rrset``, or None.

        Signatures are tried one at a time, against a tag-trimmed keyring, and
        each attempt is charged to the budget. Letting dnspython loop over the
        full cross-product internally would leave the KeyTrap work unbounded.

        The winning signature is returned rather than a bare yes, because how
        long the data may be cached depends on *which* signature vouched for it
        (RFC 4035 §5.3.3).
        """
        if rrsig_rrset is None:
            return None
        trimmed_keys = _trim_keyring(keys)
        if not trimmed_keys:
            return None
        wall = time.time() if now is None else now
        for rrsig in _trim_rrsigs(rrsig_rrset):
            # RFC 4034 §3.1.5 defines inception and expiration as serial
            # numbers, so they are compared per RFC 1982 rather than as plain
            # integers, and the inception is allowed a little slack for a
            # signer whose clock runs ahead of ours.
            #
            # A window that straddles the 2106 serial wrap is still refused:
            # dnspython's own plain comparison below cannot be talked into
            # accepting one, and there is no such signature in the world yet.
            stamp = int(wall) & 0xFFFFFFFF
            if not _serial_le(int(rrsig.inception), (stamp + self.clock_skew) & 0xFFFFFFFF):
                logger.debug("RRSIG for %s is not yet valid, beyond the skew allowance", rrset.name)
                continue
            if not _serial_le(stamp, int(rrsig.expiration)):
                logger.debug("RRSIG for %s has expired", rrset.name)
                continue
            # RFC 4035 §5.3.1: "The RRSIG RR's Signer's Name field MUST be the
            # name of the zone that contains the RRset." Nothing below checks
            # this - dnspython compares the labels count and looks the signer
            # up in the keyring, but never relates the signer to the owner - so
            # without it any zone can sign for any name. Owning one signed zone
            # would be enough to authenticate forged data for every domain:
            # sign the victim's RRset with your own key, name your own zone as
            # the signer, and a validator that chases the signer to fetch keys
            # fetches yours and verifies against them.
            if not rrset.name.is_subdomain(rrsig.signer):
                logger.debug("RRSIG for %s claims signer %s, which does not contain it", rrset.name, rrsig.signer)
                continue
            if budget is not None:
                budget.spend_signature_validation()
            inside = max(int(rrsig.inception), min(stamp, int(rrsig.expiration)))
            try:
                dns.dnssec.validate_rrsig(rrset, rrsig, trimmed_keys, now=inside)
            except Exception as exc:
                logger.debug("RRSIG (tag %s) failed for %s: %s", rrsig.key_tag, rrset.name, exc)
                continue
            return rrsig
        return None

    def validate_dnskey(
        self,
        zone: dns.name.Name,
        dnskey_rrset: dns.rrset.RRset,
        rrsig_rrset: dns.rrset.RRset | None,
        ds_rdataset: dns.rdataset.Rdataset,
        budget: Any = None,
    ) -> ValidationState:
        """Verify a zone's DNSKEY RRset against the DS records held by its parent.

        At least one DS must match a key with the ZONE flag set, and that key
        must have signed the DNSKEY RRset itself (RFC 4035 §5.2). The Secure
        Entry Point bit is deliberately not required: it is advisory, every
        reference implementation ignores it for this purpose, and a zone whose
        KSK does not set it is unusual rather than wrong.

        Returns:
            SECURE when that holds. INSECURE when the DS RRset names only
            digest types or signing algorithms this build cannot compute:
            RFC 4035 §5.2 and RFC 6840 §5.2 say a child we have no way to
            check must be treated as unsigned, not as forged. BOGUS otherwise.
        """
        matched: list[Any] = []
        # Digest computations we completed, versus ones we could not perform.
        # Only "we could never compute one" means unverifiable; a zone that
        # publishes no usable key at all is broken, not merely unsupported.
        compared = 0
        undigestable = 0
        # Bound the DS x DNSKEY digest cross-product (KeyTrap).
        candidate_ds = list(ds_rdataset)[:MAX_DS_PER_ZONE]
        for key in dnskey_rrset:
            if not key.flags & FLAG_ZONE_KEY:
                continue
            for ds in candidate_ds:
                try:
                    computed = dns.dnssec.make_ds(zone, key, ds.digest_type, validating=True)
                except Exception as exc:
                    logger.debug("Cannot compute DS for %s (digest type %s): %s", zone, ds.digest_type, exc)
                    undigestable += 1
                    continue
                compared += 1
                if computed == ds:
                    matched.append(key)
                    break

        if not matched:
            if undigestable and not compared:
                logger.debug("No usable DS digest type for %s; treating the zone as unsigned", zone)
                return ValidationState.INSECURE
            logger.debug("No DS record matches any DNSKEY for %s", zone)
            return ValidationState.BOGUS

        # A key we matched but whose signatures we cannot verify leaves us in
        # the same position: unable to check the zone, so unable to call it
        # forged.
        if not any(algorithm_supported(key.algorithm) for key in matched):
            logger.debug("DS for %s names only unsupported algorithms; treating the zone as unsigned", zone)
            return ValidationState.INSECURE

        # The DNSKEY RRset must be signed by a key the DS matched, and only by
        # such a key. RFC 4035 §5.2 requires that "the corresponding private
        # key has signed the child zone's apex DNSKEY RRset"; verifying against
        # the whole published set instead lets any key in it stand in for the
        # one the parent blessed. That would make the DS worth nothing:
        # whoever compromises a zone-signing key - shorter-lived, rotated more
        # often, and never the key the registry protects - could publish a
        # DNSKEY RRset containing a key of their own, sign it with the key they
        # hold, and have the whole zone validate, while the real KSK sat
        # untouched in the same RRset satisfying the DS match.
        entry_points = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for key in matched:
            entry_points.add(key)
        entry_points.ttl = dnskey_rrset.ttl
        if self.validate_rrset(dnskey_rrset, rrsig_rrset, {zone: entry_points}, budget=budget):
            return ValidationState.SECURE
        return ValidationState.BOGUS

    def validate_root_dnskey(
        self, dnskey_rrset: dns.rrset.RRset, rrsig_rrset: dns.rrset.RRset | None, budget: Any = None
    ) -> bool:
        """Verify the root DNSKEY RRset against the built-in trust anchors.

        The root is the anchor, so there is no "treat as unsigned" option here:
        anything short of a full match is a failure.
        """
        state = self.validate_dnskey(dns.name.root, dnskey_rrset, rrsig_rrset, self._root_ds, budget=budget)
        return state is ValidationState.SECURE

    def validate_ds(
        self,
        child: dns.name.Name,
        authority: list[dns.rrset.RRset],
        parent_keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> tuple[ValidationState, dns.rdataset.Rdataset | None]:
        """Establish whether ``child`` is a signed delegation.

        Returns ``(SECURE, ds_rdataset)`` when a validated DS exists,
        ``(INSECURE, None)`` when the parent proves no DS exists, and
        ``(BOGUS, None)`` when neither can be established.
        """
        ds_rrset = _rrset_of(authority, child, dns.rdatatype.DS)
        if ds_rrset is not None:
            rrsig = find_rrsig(authority, child, dns.rdatatype.DS)
            if not self.validate_rrset(ds_rrset, rrsig, parent_keys, budget=budget):
                return ValidationState.BOGUS, None
            rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
            for rr in ds_rrset:
                rdataset.add(rr, ttl=ds_rrset.ttl)
            return ValidationState.SECURE, rdataset

        # No DS: the parent must prove its absence, or the delegation is bogus.
        if self.prove_no_ds(child, authority, parent_keys, budget=budget):
            return ValidationState.INSECURE, None
        if self.nsec3_beyond_our_limits(authority, parent_keys, budget):
            return ValidationState.INSECURE, None
        return ValidationState.BOGUS, None

    # ── denial of existence ─────────────────────────────────────────────

    def _validated_nsec_rrsets(
        self, authority: list[dns.rrset.RRset], keys: dict[dns.name.Name, Any], rdtype: int, budget: Any = None
    ) -> list[dns.rrset.RRset]:
        """Return the NSEC (or NSEC3) RRsets in ``authority`` whose RRSIGs validate.

        NSEC3 records with anything but Opt-Out in the Flags field are dropped
        unread (RFC 5155 §8.2). The reserved bits have no defined meaning, so a
        record that sets one is asserting something this validator cannot
        interpret, and guessing at it is how a future flag gets silently
        ignored rather than noticed.
        """
        out: list[dns.rrset.RRset] = []
        for rrset in authority:
            if rrset.rdtype != rdtype or rrset.rdclass != dns.rdataclass.IN:
                continue
            if rdtype == dns.rdatatype.NSEC3 and rrset[0].flags & ~NSEC3_OPT_OUT:
                logger.debug("Ignoring NSEC3 at %s with reserved flags %#x", rrset.name, rrset[0].flags)
                continue
            rrsig = find_rrsig(authority, rrset.name, rdtype)
            if self.validate_rrset(rrset, rrsig, keys, budget=budget):
                out.append(rrset)
        return out

    @staticmethod
    def _signing_zone(keys: dict[dns.name.Name, Any]) -> dns.name.Name | None:
        """The zone these proofs are being validated against.

        Read from the keyring, never from the RRSIG on the wire. A signature
        verifies only against the key its signer field names, and every keyring
        here holds exactly one zone, so this *is* the signer of anything that
        validated. Reading the wire field instead is exploitable: an RRSIG
        RRset can carry several rdata, only one of which verified, and an
        attacker who prepends a second one naming a different zone changes
        what a naive `rrsig[0].signer` reports while the record still
        validates on the genuine signature behind it.
        """
        return next(iter(keys), None)

    def _parent_side(
        self,
        nsec: dns.rrset.RRset,
        owner: dns.name.Name,
        zone: dns.name.Name | None,
    ) -> bool:
        """Is this an "ancestor delegation" record (RFC 6840 §4.1)?

        NS set, SOA clear, and signed by a zone shorter than the name it is
        about: that is a record served from the *parent* side of a zone cut.
        The parent holds only the child's NS and DS, so its type bitmap lists
        only those - and reading that bitmap as "the child has no A record"
        denies data the parent was never authoritative for. Anyone able to get
        a parent-side record into an answer could otherwise deny any name in
        the child zone, which is why RFC 6840 §4.1 forbids using one to prove
        the nonexistence of anything at or below the cut except a DS.

        ``owner`` is passed separately because for NSEC3 the record's own name
        is a hash; the name it is about is the one that hashed to it.
        """
        types = _types_in_bitmap(nsec[0])
        if dns.rdatatype.NS not in types or dns.rdatatype.SOA in types:
            return False
        return zone is not None and len(zone) < len(owner)

    def _may_deny_below(
        self,
        nsec: dns.rrset.RRset,
        target: dns.name.Name,
        zone: dns.name.Name | None,
    ) -> bool:
        """May this NSEC be used to deny ``target``, which lies below its owner?

        Two records must not be (RFC 6840 §4.1): one from the parent side of a
        zone cut, which says nothing about the zone below it, and one with the
        DNAME bit, which rewrites every name below its owner and so describes
        none of them.
        """
        if target == nsec.name or not target.is_subdomain(nsec.name):
            return True
        if dns.rdatatype.DNAME in _types_in_bitmap(nsec[0]):
            return False
        return not self._parent_side(nsec, nsec.name, zone)

    @staticmethod
    def _nsec_covers(owner: dns.name.Name, next_name: dns.name.Name, target: dns.name.Name) -> bool:
        """True if ``target`` falls strictly between ``owner`` and ``next_name``."""
        if owner == next_name:
            # A single-NSEC zone covers everything except the owner itself.
            return bool(target != owner)
        if owner < next_name:
            return bool(owner < target < next_name)
        # The last NSEC in the zone wraps around to the apex.
        return bool(target > owner or target < next_name)

    def nsec3_beyond_our_limits(
        self,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> bool:
        """True when this response's NSEC3 parameters are more than we will compute.

        RFC 9276 §3.2 leaves the choice open - "Validating resolvers MAY return
        an insecure response ... MAY also return a SERVFAIL" - and the major
        implementations all take the first option. Refusing outright
        makes a validly signed zone with a legacy iteration count unresolvable
        here while everyone else still answers for it, so the caller returns
        the data unauthenticated instead of calling the zone forged.

        The signature is verified first regardless, as RFC 5155 §10.3 requires,
        so the iteration count itself cannot have been tampered with.
        """
        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        return any(n[0].iterations > self.max_nsec3_iterations for n in nsec3s)

    def prove_no_ds(
        self,
        child: dns.name.Name,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> bool:
        """Prove that no DS record exists for ``child`` (an insecure delegation)."""
        # NSEC: a record matching the child whose bitmap has NS but not DS. A
        # record bearing SOA is the child's own apex record and cannot speak for
        # the parent's DS (RFC 4035 §5.2); the same guard as in `prove_nodata`.
        for nsec in self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget):
            if nsec.name != child:
                continue
            types = _types_in_bitmap(nsec[0])
            if dns.rdatatype.SOA in types and child != dns.name.root:
                continue
            if dns.rdatatype.DS not in types and dns.rdatatype.NS in types:
                return True

        # NSEC3: either a matching record without the DS bit, or an opt-out
        # NSEC3 covering the child (RFC 5155 §8.9).
        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        for nsec3 in nsec3s:
            params = nsec3[0]
            if params.iterations > self.max_nsec3_iterations:
                logger.debug("NSEC3 iteration count %d exceeds cap", params.iterations)
                return False
            hashed = self._nsec3_owner(child, nsec3.name, params, budget)
            if hashed is None:
                continue
            if hashed == nsec3.name:
                types = _types_in_bitmap(params)
                if dns.rdatatype.DS not in types and dns.rdatatype.NS in types:
                    return True

        # Opt-out: no NSEC3 matches the delegation, so the proof is the closest
        # provable encloser plus an opt-out NSEC3 covering the next closer name
        # (RFC 5155 §8.6). Usually the encloser is the child's own parent and
        # the next closer is the child itself, but where a whole subtree sits
        # inside an opt-out span the encloser is further up: a delegation two
        # or more labels below an unsigned cut is denied by the cover for its
        # topmost missing ancestor, not for the delegation name.
        if not nsec3s:
            return False
        params = nsec3s[0][0]
        closest = self._closest_encloser_nsec3(child, nsec3s, params, budget)
        if closest is None:
            return False
        next_closer = self._next_closer(child, closest)
        if next_closer is None:
            return False
        for nsec3 in nsec3s:
            if nsec3[0].flags & NSEC3_OPT_OUT and self._nsec3_covers(next_closer, nsec3, params, budget):
                return True
        return False

    def prove_no_delegation(
        self,
        name: dns.name.Name,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> bool:
        """Prove that ``name`` is not a zone cut, so it can hold no DS.

        Walking a chain of trust asks for a DS at every label between the zone
        in force and the target, and most of those labels are not delegation
        points. The parent answers such a query with a denial that no ``no DS``
        proof matches - there is no delegation to deny - and the caller needs
        to tell that apart from a chain that is actually broken.

        Two shapes say it. A name with an NSEC or NSEC3 of its own whose bitmap
        carries neither NS nor DS exists but is not delegated: an empty
        non-terminal in an NSEC3 zone, or a name holding only, say, TXT. A name
        covered by an NSEC owns no NSEC at all, which in an NSEC zone is what
        an empty non-terminal looks like (RFC 4035 §3.1.3.4.1).

        Both are signed statements from the parent, so neither can be forged
        into existence by an off-path attacker, and neither is used to conclude
        anything about the target: the walk simply carries on to the next
        label with the same zone and the same keys.
        """
        signer = self._signing_zone(keys)
        for nsec in self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget):
            if nsec.name == name:
                types = _types_in_bitmap(nsec[0])
                if dns.rdatatype.NS not in types and dns.rdatatype.DS not in types:
                    return True
                continue
            if not self._may_deny_below(nsec, name, signer):
                continue
            if self._nsec_covers(nsec.name, nsec[0].next, name):
                return True

        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return False
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return False
        for nsec3 in nsec3s:
            if self._nsec3_owner(name, nsec3.name, params, budget) != nsec3.name:
                continue
            types = _types_in_bitmap(nsec3[0])
            if dns.rdatatype.NS not in types and dns.rdatatype.DS not in types:
                return True
        return False

    def _nsec3_owner(
        self, name: dns.name.Name, nsec3_owner: dns.name.Name, params: Any, budget: Any = None
    ) -> dns.name.Name | None:
        """Hash ``name`` with ``params`` and return the resulting NSEC3 owner name."""
        if budget is not None:
            budget.spend_nsec3_hash()
        try:
            digest = dns.dnssec.nsec3_hash(name, params.salt, params.iterations, params.algorithm)
        except Exception as exc:
            logger.debug("NSEC3 hashing failed for %s: %s", name, exc)
            return None
        zone = nsec3_owner.parent() if len(nsec3_owner) > 1 else dns.name.root
        try:
            return dns.name.from_text(digest, origin=zone)
        except dns.exception.DNSException:  # pragma: no cover - digest is always a valid label
            return None

    def _nsec3_covers(self, name: dns.name.Name, nsec3: dns.rrset.RRset, params: Any, budget: Any = None) -> bool:
        """True if the NSEC3 record covers (but does not match) ``name``'s hash.

        ``params`` supplies the zone-wide hashing parameters (salt, iterations,
        algorithm). The next-hashed-owner interval, however, belongs to *this*
        record: reading it from ``params`` would compare against a different
        record's range and get the answer wrong whenever a proof spans several
        NSEC3 records, which is the normal case for NXDOMAIN and opt-out.
        """
        hashed = self._nsec3_owner(name, nsec3.name, params, budget)
        if hashed is None:
            return False
        try:
            # The next-hashed-owner is stored as raw bytes; render it in the
            # same base32hex alphabet dnspython uses for the owner name.
            encoded = base64.b32encode(nsec3[0].next).translate(b32_normal_to_hex).decode("ascii")
            zone = nsec3.name.parent() if len(nsec3.name) > 1 else dns.name.root
            next_label = dns.name.from_text(encoded, origin=zone)
        except (dns.exception.DNSException, ValueError, TypeError) as exc:
            logger.debug("Cannot decode NSEC3 next-hashed-owner: %s", exc)
            return False
        return self._nsec_covers(nsec3.name, next_label, hashed)

    def prove_nxdomain(
        self,
        qname: dns.name.Name,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> ValidationState:
        """Prove that ``qname`` does not exist at all.

        Returns:
            SECURE when the name error is proven, BOGUS when nothing proves it,
            and INSECURE when either cover an RFC 5155 §8.4 proof needs - the
            next closer name's or the wildcard's - is **opt-out** only. Opt-out
            asserts that a range contains no signed delegations, not that it
            contains no names (RFC 5155 §6), so a name inside it may exist as an
            unsigned delegation and the name error is not proven. This is not a hypothetical: in an opt-out TLD every
            unsigned domain sits in such a range, and the records needed are
            public and correctly signed, so treating the result as authenticated
            would let anyone forge an authenticated "does not exist" for them.
            The public DNS resolvers all clear AD on these answers.
        """
        signer = self._signing_zone(keys)
        nsecs = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget)
        if nsecs:
            # A record from the parent side of a cut, or one carrying a DNAME,
            # describes nothing below its owner (RFC 6840 §4.1).
            deniers = [n for n in nsecs if self._may_deny_below(n, qname, signer)]
            if not any(self._nsec_covers(n.name, n[0].next, qname) for n in deniers):
                return ValidationState.BOGUS
            # A wildcard could still synthesise the name, so its absence must
            # also be proven (RFC 4035 §5.4). NSEC has no opt-out, so a proof
            # here is a whole one.
            if self._wildcard_denied_nsec(qname, deniers):
                return ValidationState.SECURE
            return ValidationState.BOGUS

        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return ValidationState.BOGUS
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return ValidationState.BOGUS
        closest = self._closest_encloser_nsec3(qname, nsec3s, params, budget)
        if closest is None:
            return ValidationState.BOGUS
        # The next closer name must be covered, and so must the wildcard at
        # the closest encloser (RFC 5155 §8.4).
        next_closer = self._next_closer(qname, closest)
        if next_closer is None:
            return ValidationState.BOGUS
        covering = [n for n in nsec3s if self._nsec3_covers(next_closer, n, params, budget)]
        if not covering:
            return ValidationState.BOGUS
        wildcard = dns.name.Name((b"*",) + closest.labels)
        wildcard_covering = [n for n in nsec3s if self._nsec3_covers(wildcard, n, params, budget)]
        if not wildcard_covering:
            return ValidationState.BOGUS
        # Both covers have to be real ones. Either resting on opt-out leaves a
        # name the proof needs absent free to exist as an unsigned delegation.
        for covers in (covering, wildcard_covering):
            if not any(not n[0].flags & NSEC3_OPT_OUT for n in covers):
                return ValidationState.INSECURE
        return ValidationState.SECURE

    def prove_wildcard(
        self,
        qname: dns.name.Name,
        labels: int,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> ValidationState:
        """Prove a wildcard-expanded answer was legitimate (RFC 4035 §5.3.4).

        An RRSIG whose ``labels`` count is smaller than the owner name's label
        count says the data was synthesised from a wildcard. The signature
        alone does not make that answer trustworthy: it verifies against the
        reconstructed ``*.<closest encloser>`` name, so the *same* signature
        verifies for every name the wildcard could cover. Without the extra
        proof below, anyone able to replay a zone's genuine wildcard record
        under a different owner name gets it validated, overriding whatever
        explicit data that name really holds.

        What must still be shown is that ``qname`` itself does not exist. Had
        it existed, the server was obliged to answer from the exact name, so a
        wildcard answer for a name that does exist is a substitution.

        Returns:
            SECURE when the expansion is proven; BOGUS when nothing denies the
            queried name; INSECURE when the only denial is an opt-out NSEC3.
            An opt-out record does not assert that the names in its range do
            not exist - only that none of them is a *signed* delegation (RFC
            5155 §6) - so it cannot rule out a closer match, and the expansion
            cannot be authenticated. The public DNS resolvers return such
            answers unauthenticated rather than refusing them.

        Args:
            qname: The name that was queried.
            labels: The RRSIG ``labels`` field, which fixes the closest
                encloser and therefore which wildcard was used.
        """
        # The Labels count fixes which wildcard signed this data, and therefore
        # which encloser it belongs to.
        extra = len(qname.labels) - 1 - labels
        if extra < 1:
            return ValidationState.BOGUS
        closest = dns.name.Name(qname.labels[extra:])

        # NSEC: some record must cover qname itself, i.e. assert that nothing
        # exists between its two neighbours where qname would sort. NSEC has no
        # opt-out, so a cover here is a real proof.
        #
        # It must also agree with the Labels count about where the closest
        # encloser is. A zone holding nested wildcards - `*.example` and
        # `*.b.example` - signs each with a different Labels value, so without
        # this the higher wildcard's genuine record and RRSIG can be replayed
        # as the answer for a name the lower one really covers, and the
        # substitution comes back authenticated.
        signer = self._signing_zone(keys)
        nsecs = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget)
        for nsec in nsecs:
            if not self._may_deny_below(nsec, qname, signer):
                continue
            if not self._nsec_covers(nsec.name, nsec[0].next, qname):
                continue
            if self._closest_encloser_nsec(qname, nsec) == closest:
                return ValidationState.SECURE

        # NSEC3: the name one label below the closest encloser (the "next
        # closer") must be covered.
        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return ValidationState.BOGUS
        next_closer = self._next_closer(qname, closest)
        if next_closer is None:  # pragma: no cover - extra >= 1 guarantees a next closer
            return ValidationState.BOGUS
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return ValidationState.BOGUS

        covering = [n for n in nsec3s if self._nsec3_covers(next_closer, n, params, budget)]
        if not covering:
            return ValidationState.BOGUS
        if any(not n[0].flags & NSEC3_OPT_OUT for n in covering):
            return ValidationState.SECURE
        return ValidationState.INSECURE

    @staticmethod
    def _common_ancestor(first: dns.name.Name, second: dns.name.Name) -> dns.name.Name:
        """The longest name that is a suffix of both, compared case-insensitively."""
        depth = 0
        for left, right in zip(reversed(first.labels), reversed(second.labels), strict=False):
            if left.lower() != right.lower():
                break
            depth += 1
        return dns.name.Name(first.labels[len(first.labels) - depth :])

    def _closest_encloser_nsec(self, qname: dns.name.Name, nsec: dns.rrset.RRset) -> dns.name.Name:
        """The closest encloser of ``qname``, per an NSEC that covers it.

        The record's owner and its next name both exist, and ``qname`` sorts
        between them, so the deepest ancestor of ``qname`` that can exist is
        the deeper of the two names it shares a suffix with. Only the wildcard
        at *that* name could have synthesised ``qname``; a wildcard higher up
        says nothing about it, because the closer encloser would have matched
        first (RFC 4592 §3.3.1).
        """
        return max(
            (self._common_ancestor(qname, nsec.name), self._common_ancestor(qname, nsec[0].next)),
            key=lambda name: len(name.labels),
        )

    def _wildcard_denied_nsec(self, qname: dns.name.Name, nsecs: list[dns.rrset.RRset]) -> bool:
        """Check that no wildcard could have synthesised ``qname`` (RFC 4035 §5.4).

        Exactly one wildcard could have: the one at the closest encloser, the
        deepest ancestor of ``qname`` that exists. Accepting a denial of the
        wildcard at *any* ancestor instead is not a mere completeness gap - it
        is forgeable from public data. Where a zone holds `*.example.` and is
        asked for `a.b.example.`, the server must answer from the wildcard, but
        two genuine, signed, publicly fetchable NSEC records - one covering
        `a.b.example.`, one covering the non-existent `*.b.example.` - would
        together read as a proven NXDOMAIN and suppress the wildcard's data.
        Often the same record does both.

        The closest encloser follows from the covering NSEC itself. Its owner
        and its next name both exist, and ``qname`` sorts between them, so the
        deepest ancestor of ``qname`` that can exist is the deeper of the two
        names it shares a suffix with.
        """
        for nsec in nsecs:
            if not self._nsec_covers(nsec.name, nsec[0].next, qname):
                continue
            wildcard = dns.name.Name((b"*",) + self._closest_encloser_nsec(qname, nsec).labels)
            if any(self._nsec_covers(n.name, n[0].next, wildcard) for n in nsecs):
                return True
        return False

    def _closest_encloser_nsec3(
        self, qname: dns.name.Name, nsec3s: list[dns.rrset.RRset], params: Any, budget: Any = None
    ) -> dns.name.Name | None:
        """Find the deepest ancestor of ``qname`` with a matching NSEC3 record.

        RFC 5155 §8.3 requires more than a match: "the validator MUST check
        that the NSEC3 RR that has the closest encloser as the original owner
        name is from the proper zone. The DNAME type bit must not be set and
        the NS type bit may only be set if the SOA type bit is set."

        A record failing that came from the parent side of a cut, or from a
        name whose subtree is rewritten by a DNAME, and describes nothing
        inside the zone below it. Accepting one lets a parent's public,
        correctly signed delegation record stand as the closest encloser for a
        name in the signed child, and every proof built on it then denies data
        the child really serves. The deepest match is the closest encloser or
        there is none - falling back to a shallower ancestor would build a
        proof about a different name.
        """
        current = qname
        while True:
            for nsec3 in nsec3s:
                if self._nsec3_owner(current, nsec3.name, params, budget) != nsec3.name:
                    continue
                types = _types_in_bitmap(nsec3[0])
                if dns.rdatatype.DNAME in types:
                    return None
                if dns.rdatatype.NS in types and dns.rdatatype.SOA not in types:
                    return None
                return current
            if current == dns.name.root:
                return None
            try:
                current = current.parent()
            except dns.name.NoParent:  # pragma: no cover - guarded above
                return None

    @staticmethod
    def _next_closer(qname: dns.name.Name, closest: dns.name.Name) -> dns.name.Name | None:
        """The name one label longer than ``closest`` on the path to ``qname``."""
        extra = len(qname.labels) - len(closest.labels)
        if extra < 1:
            return None
        return dns.name.Name(qname.labels[extra - 1 :])

    def prove_nodata(
        self,
        qname: dns.name.Name,
        rdtype: int,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> ValidationState:
        """Prove that ``qname`` exists but has no records of type ``rdtype``.

        Returns:
            SECURE when the denial is proven, BOGUS when nothing proves it, and
            INSECURE where the proof rests on an **opt-out** NSEC3. Opt-out says
            a range holds no signed delegations, not that it holds no names, so
            a name inside one may exist and the denial is returned without being
            authenticated: the DS of an unsigned delegation (RFC 5155 §8.6), and
            a wildcard NODATA whose next closer name only an opt-out record
            covers.
        """
        signer = self._signing_zone(keys)
        nsecs = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget)
        for nsec in nsecs:
            if nsec.name == qname:
                # A parent-side record lists the delegation's types, not the
                # child's, so it cannot deny a type in the child (RFC 6840
                # §4.1) - "all RRs at that (original) owner name other than DS
                # RRs". The DS is the exception, and it is the one type that
                # lives on the parent side, so a direct DS query is
                # answered by exactly this record.
                if rdtype != dns.rdatatype.DS and self._parent_side(nsec, qname, signer):
                    continue
                types = _types_in_bitmap(nsec[0])
                # The DS exemption above lets a parent-side record answer a DS
                # query. It must not let a *child*-side one: a record bearing
                # SOA is the child apex's own, the DS lives in the parent, and
                # the child is in no position to say whether its parent
                # published one (RFC 4035 §5.2).
                if rdtype == dns.rdatatype.DS and dns.rdatatype.SOA in types and qname != dns.name.root:
                    continue
                if rdtype not in types and dns.rdatatype.CNAME not in types:
                    return ValidationState.SECURE
                continue
            if not self._may_deny_below(nsec, qname, signer):
                continue
            # An empty non-terminal has no NSEC of its own: it holds no records
            # while a name below it does, so the zone's NSEC chain jumps
            # straight over it. The NSEC that covers the name and whose *next*
            # name lies below it proves exactly that, and therefore that the
            # name has no records of any type (RFC 4035 §3.1.3.4.1).
            #
            # A name that did have records would own an NSEC, and the record
            # before it would point at the name itself rather than past it, so
            # this cannot be used to deny a name that exists.
            following: dns.name.Name = nsec[0].next
            if following != qname and following.is_subdomain(qname) and self._nsec_covers(nsec.name, following, qname):
                return ValidationState.SECURE

        # Wildcard NODATA: the queried name does not exist, but a wildcard
        # above it does and holds no record of the queried type, so the server
        # answers NODATA rather than NXDOMAIN (RFC 4035 §5.4). The proof is a
        # cover for the name plus an NSEC owned by the wildcard itself whose
        # bitmap lacks the type.
        deniers = [n for n in nsecs if self._may_deny_below(n, qname, signer)]
        for covering in deniers:
            if not self._nsec_covers(covering.name, covering[0].next, qname):
                continue
            # The wildcard that answered is the one at the closest encloser,
            # and only that one. A zone can hold nested wildcards - say
            # `*.deep.example` with an MX and `*.example` without - and taking
            # any ancestor's wildcard would let the higher one deny a type the
            # closer one really serves.
            wildcard = dns.name.Name((b"*",) + self._closest_encloser_nsec(qname, covering).labels)
            for nsec in deniers:
                if nsec.name != wildcard:
                    continue
                types = _types_in_bitmap(nsec[0])
                if rdtype not in types and dns.rdatatype.CNAME not in types:
                    return ValidationState.SECURE

        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return ValidationState.BOGUS
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return ValidationState.BOGUS
        for nsec3 in nsec3s:
            if self._nsec3_owner(qname, nsec3.name, params, budget) != nsec3.name:
                continue
            if rdtype != dns.rdatatype.DS and self._parent_side(nsec3, qname, signer):
                continue
            types = _types_in_bitmap(nsec3[0])
            if rdtype == dns.rdatatype.DS and dns.rdatatype.SOA in types and qname != dns.name.root:
                continue
            if rdtype not in types and dns.rdatatype.CNAME not in types:
                return ValidationState.SECURE

        # Everything below needs the closest encloser, and a next closer name
        # under it.
        closest = self._closest_encloser_nsec3(qname, nsec3s, params, budget)
        if closest is None:
            return ValidationState.BOGUS
        next_closer = self._next_closer(qname, closest)
        if next_closer is None:
            return ValidationState.BOGUS

        # Wildcard NODATA: the queried name does not exist, but a wildcard at
        # its closest encloser does and holds no record of the queried type
        # (RFC 5155 §8.7). The proof is the closest encloser, a cover for the
        # next closer name, and an NSEC3 matching `*.<closest encloser>` whose
        # bitmap lacks the type. Zones that answer NODATA off a wildcard are
        # common: this is how a name with only an A wildcard denies TXT.
        next_closer_covers = [n for n in nsec3s if self._nsec3_covers(next_closer, n, params, budget)]
        if next_closer_covers:
            wildcard = dns.name.Name((b"*",) + closest.labels)
            for nsec3 in nsec3s:
                if self._nsec3_owner(wildcard, nsec3.name, params, budget) != nsec3.name:
                    continue
                types = _types_in_bitmap(nsec3[0])
                if rdtype not in types and dns.rdatatype.CNAME not in types:
                    if any(not n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
                        return ValidationState.SECURE
                    break

        # Opt-out. RFC 5155 §8.6 lets an opt-out cover deny the DS of an
        # unsigned delegation, and §8.5 wants a *matching* NSEC3 for any other
        # type - which a name inside an opt-out span does not have. The bit
        # asserts only that the range holds no *signed* delegation, so a name
        # in it may exist, unsigned, and answer for itself: nothing here proves
        # the denial, and nothing here contradicts it either. Returned
        # unauthenticated rather than refused (§9.2). Refusing is what a whole
        # family of TLD subzones looked like in the wild: a NOERROR/NODATA off
        # the parent whose only proof is an opt-out gap.
        if any(n[0].flags & NSEC3_OPT_OUT for n in next_closer_covers):
            return ValidationState.INSECURE
        return ValidationState.BOGUS
