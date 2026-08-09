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

# DNSKEY flag bits (RFC 4034 §2.1.1).
FLAG_ZONE_KEY = 0x0100
FLAG_SECURE_ENTRY_POINT = 0x0001

# NSEC3 flags (RFC 5155 §3.1.2).
NSEC3_OPT_OUT = 0x01

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
    """Keep at most MAX_KEYS_PER_TAG keys per (key tag, algorithm).

    Colliding key tags are the core of KeyTrap: without this a single answer can
    force one signature check per published key.
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
            except Exception:  # pragma: no cover - malformed key
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

    Raises:
        ValueError: If ``trust_anchors`` is empty.
    """

    def __init__(
        self,
        trust_anchors: tuple[str, ...] = ROOT_TRUST_ANCHORS,
        max_nsec3_iterations: int = MAX_NSEC3_ITERATIONS,
    ) -> None:
        if not trust_anchors:
            raise ValueError("trust_anchors must not be empty; pass None to use the IANA root anchors")
        self.max_nsec3_iterations = max_nsec3_iterations
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
        """Verify ``rrset`` against its RRSIG using ``keys``.

        Signatures are tried one at a time, against a tag-trimmed keyring, and
        each attempt is charged to the budget. Letting dnspython loop over the
        full cross-product internally would leave the KeyTrap work unbounded.
        """
        if rrsig_rrset is None:
            return False
        trimmed_keys = _trim_keyring(keys)
        if not trimmed_keys:
            return False
        for rrsig in _trim_rrsigs(rrsig_rrset):
            if budget is not None:
                budget.spend_signature_validation()
            try:
                dns.dnssec.validate_rrsig(rrset, rrsig, trimmed_keys, now=now)
            except Exception as exc:
                logger.debug("RRSIG (tag %s) failed for %s: %s", rrsig.key_tag, rrset.name, exc)
                continue
            return True
        return False

    def validate_dnskey(
        self,
        zone: dns.name.Name,
        dnskey_rrset: dns.rrset.RRset,
        rrsig_rrset: dns.rrset.RRset | None,
        ds_rdataset: dns.rdataset.Rdataset,
        budget: Any = None,
    ) -> ValidationState:
        """Verify a zone's DNSKEY RRset against the DS records held by its parent.

        At least one DS must match a Secure Entry Point key, and that key must
        have signed the DNSKEY RRset itself (RFC 4035 §5.2).

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

        # The DNSKEY RRset must be self-signed by one of the DS-matched keys.
        keyring = {zone: dnskey_rrset}
        if self.validate_rrset(dnskey_rrset, rrsig_rrset, keyring, budget=budget):
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
        return ValidationState.BOGUS, None

    # ── denial of existence ─────────────────────────────────────────────

    def _validated_nsec_rrsets(
        self, authority: list[dns.rrset.RRset], keys: dict[dns.name.Name, Any], rdtype: int, budget: Any = None
    ) -> list[dns.rrset.RRset]:
        """Return the NSEC (or NSEC3) RRsets in ``authority`` whose RRSIGs validate."""
        out: list[dns.rrset.RRset] = []
        for rrset in authority:
            if rrset.rdtype != rdtype or rrset.rdclass != dns.rdataclass.IN:
                continue
            rrsig = find_rrsig(authority, rrset.name, rdtype)
            if self.validate_rrset(rrset, rrsig, keys, budget=budget):
                out.append(rrset)
        return out

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

    def prove_no_ds(
        self,
        child: dns.name.Name,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> bool:
        """Prove that no DS record exists for ``child`` (an insecure delegation)."""
        # NSEC: a record matching the child whose bitmap has NS but not DS.
        for nsec in self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget):
            if nsec.name != child:
                continue
            types = _types_in_bitmap(nsec[0])
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

        # Opt-out: an NSEC3 covering the child's hash, with the opt-out flag.
        for nsec3 in nsec3s:
            params = nsec3[0]
            if not params.flags & NSEC3_OPT_OUT:
                continue
            if self._nsec3_covers(child, nsec3, params, budget):
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
    ) -> bool:
        """Prove that ``qname`` does not exist at all."""
        nsecs = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget)
        if nsecs:
            name_denied = any(self._nsec_covers(n.name, n[0].next, qname) for n in nsecs)
            if not name_denied:
                return False
            # A wildcard could still synthesise the name, so its absence must
            # also be proven (RFC 4035 §5.4).
            return self._wildcard_denied_nsec(qname, nsecs)

        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return False
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return False
        closest = self._closest_encloser_nsec3(qname, nsec3s, params, budget)
        if closest is None:
            return False
        # The next closer name must be covered, and so must the wildcard at
        # the closest encloser.
        next_closer = self._next_closer(qname, closest)
        if next_closer is None:
            return False
        if not any(self._nsec3_covers(next_closer, n, params, budget) for n in nsec3s):
            return False
        # A wildcard at the closest encloser would have synthesised the name,
        # so its non-existence must be covered too (RFC 5155 §8.4).
        wildcard = dns.name.Name((b"*",) + closest.labels)
        return any(self._nsec3_covers(wildcard, n, params, budget) for n in nsec3s)

    def prove_wildcard(
        self,
        qname: dns.name.Name,
        labels: int,
        authority: list[dns.rrset.RRset],
        keys: dict[dns.name.Name, Any],
        budget: Any = None,
    ) -> bool:
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

        Args:
            qname: The name that was queried.
            labels: The RRSIG ``labels`` field, which fixes the closest
                encloser and therefore which wildcard was used.
        """
        # NSEC: some record must cover qname itself, i.e. assert that nothing
        # exists between its two neighbours where qname would sort.
        nsecs = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget)
        if any(self._nsec_covers(n.name, n[0].next, qname) for n in nsecs):
            return True

        # NSEC3: the closest encloser follows from the labels count, and the
        # name one label below it (the "next closer") must be covered.
        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return False
        extra = len(qname.labels) - 1 - labels
        if extra < 1:
            return False
        closest = dns.name.Name(qname.labels[extra:])
        next_closer = self._next_closer(qname, closest)
        if next_closer is None:  # pragma: no cover - extra >= 1 guarantees a next closer
            return False
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return False
        return any(self._nsec3_covers(next_closer, n, params, budget) for n in nsec3s)

    def _wildcard_denied_nsec(self, qname: dns.name.Name, nsecs: list[dns.rrset.RRset]) -> bool:
        """Check that no wildcard could have synthesised ``qname``.

        Known limitation: rather than deriving the closest encloser, this
        accepts a covering NSEC for a wildcard at any ancestor of ``qname``,
        which is weaker than RFC 4035 §5.4 strictly requires. Exploiting the
        difference needs valid RRSIGs from the zone's own key: i.e. control of
        the zone, so it is a completeness gap, not a third-party attack.
        """
        for i in range(1, len(qname.labels)):
            wildcard = dns.name.Name((b"*",) + qname.labels[i:])
            for nsec in nsecs:
                if self._nsec_covers(nsec.name, nsec[0].next, wildcard):
                    return True
        return False

    def _closest_encloser_nsec3(
        self, qname: dns.name.Name, nsec3s: list[dns.rrset.RRset], params: Any, budget: Any = None
    ) -> dns.name.Name | None:
        """Find the deepest ancestor of ``qname`` with a matching NSEC3 record."""
        current = qname
        while True:
            for nsec3 in nsec3s:
                if self._nsec3_owner(current, nsec3.name, params, budget) == nsec3.name:
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
    ) -> bool:
        """Prove that ``qname`` exists but has no records of type ``rdtype``."""
        for nsec in self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC, budget):
            if nsec.name != qname:
                continue
            types = _types_in_bitmap(nsec[0])
            if rdtype not in types and dns.rdatatype.CNAME not in types:
                return True

        nsec3s = self._validated_nsec_rrsets(authority, keys, dns.rdatatype.NSEC3, budget)
        if not nsec3s:
            return False
        params = nsec3s[0][0]
        if params.iterations > self.max_nsec3_iterations:
            return False
        for nsec3 in nsec3s:
            if self._nsec3_owner(qname, nsec3.name, params, budget) != nsec3.name:
                continue
            types = _types_in_bitmap(nsec3[0])
            if rdtype not in types and dns.rdatatype.CNAME not in types:
                return True

        # Opt-out NODATA for an unsigned delegation below an NSEC3 zone. When
        # `closest` is a proper ancestor of `qname` a next-closer name always
        # exists, so the two conditions collapse into one.
        closest = self._closest_encloser_nsec3(qname, nsec3s, params, budget)
        next_closer = self._next_closer(qname, closest) if closest is not None else None
        if next_closer is not None:
            for nsec3 in nsec3s:
                if nsec3[0].flags & NSEC3_OPT_OUT and self._nsec3_covers(next_closer, nsec3, params, budget):
                    return True
        return False
