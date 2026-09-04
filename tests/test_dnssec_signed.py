"""DNSSEC validation against a real, locally-signed zone.

Everything here uses genuine keys, signatures and DS digests generated in
process, so the success paths are covered deterministically and without a
network, including cases live DNS does not reliably provide.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from conftest import make_response
from signed_zone import EXPIRATION, SignedZone, rrset_of

from recursive_resolver import (
    DNSSECInsecureError,
    DNSSECMaterialUnavailableError,
    DNSSECValidationError,
    NoAnswerError,
    NXDOMAINError,
    RecursiveResolver,
    ValidationState,
)
from recursive_resolver.budget import QueryBudget
from recursive_resolver.cache import DNSCache
from recursive_resolver.dnssec import DNSSECValidator, ZoneKeys

EXAMPLE = dns.name.from_text("example.test.")


def _zone_keys(zone: SignedZone) -> ZoneKeys:
    """The validated-key record the resolver would have built for this zone."""
    return ZoneKeys(zone.name, zone.dnskey_rrset, ValidationState.SECURE)


@pytest.fixture(scope="module")
def zone() -> SignedZone:
    return SignedZone.create("example.test.")


@pytest.fixture(scope="module")
def parent() -> SignedZone:
    return SignedZone.create("test.")


class TestAuthenticatedTTLIsCappedBySignatureValidity:
    """RFC 4035 §5.3.3: authenticated data must not outlive its signature.

    The TTL must be no greater than the minimum of the RRset's TTL, the RRSIG's
    TTL, the RRSIG's Original TTL, and the time left before the signature
    expires. The last term is the one that matters: a record with a day-long
    TTL signed with a short-lived RRSIG would otherwise be served as
    authenticated long after anything vouched for it.
    """

    @staticmethod
    def _signed_for(zone: SignedZone, rrset: dns.rrset.RRset, seconds: int) -> dns.rrset.RRset:
        now = int(time.time())
        rrsig = dns.dnssec.sign(
            rrset, zone.private_key, zone.name, zone.dnskey, inception=now - 10, expiration=now + seconds
        )
        out = dns.rrset.RRset(rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        out.add(rrsig)
        out.ttl = rrset.ttl
        return out

    def test_the_cap_follows_the_signature_that_actually_verified(self, zone: SignedZone) -> None:
        data = rrset_of("example.test.", "A", "192.0.2.1", ttl=86400)
        sig = self._signed_for(zone, data, 30)
        signature = DNSSECValidator().validated_rrsig(data, sig, zone.keyring())
        assert signature is not None
        cap = min(data.ttl, sig.ttl, int(signature.original_ttl), int(signature.expiration) - int(time.time()))
        assert cap <= 30, "a day-long TTL survived a 30-second signature"

    def test_a_long_lived_signature_does_not_shorten_the_ttl(self, zone: SignedZone) -> None:
        data = rrset_of("example.test.", "A", "192.0.2.1", ttl=300)
        signature = DNSSECValidator().validated_rrsig(data, zone.sign(data), zone.keyring())
        assert signature is not None
        cap = min(data.ttl, int(signature.original_ttl), int(signature.expiration) - int(time.time()))
        assert cap == 300

    def test_the_cache_floor_does_not_lift_an_authenticated_ttl(self) -> None:
        """`min_ttl` keeps a warm cache warm; it must not outlive a signature."""
        cache = DNSCache(min_ttl=3600)
        data = rrset_of("example.test.", "A", "192.0.2.1", ttl=86400)
        cache.put_answer("example.test.", "A", data, 30, secure=True)
        entry = cache.get_answer("example.test.", "A")
        assert entry is not None
        assert entry.expiry - time.monotonic() <= 31

    def test_the_cache_floor_still_applies_to_unauthenticated_data(self) -> None:
        cache = DNSCache(min_ttl=3600)
        data = rrset_of("example.test.", "A", "192.0.2.1", ttl=10)
        cache.put_answer("example.test.", "A", data, 10, secure=False)
        entry = cache.get_answer("example.test.", "A")
        assert entry is not None
        assert entry.expiry - time.monotonic() > 3000


class TestTheValidatedSignatureIsWhatCounts:
    """Every decision must come from the RRSIG that verified, not the first one.

    An RRSIG RRset can carry several rdata, in an order the attacker chooses,
    and only one of them verified. Reading a field off `rrsig[0]` therefore
    reads attacker-controlled data. Two separate checks here used to do that.
    """

    @staticmethod
    def _with_decoy(genuine: dns.rrset.RRset, owner: dns.name.Name, labels: str) -> dns.rrset.RRset:
        """`genuine`, preceded by a copy whose Labels field has been rewritten."""
        text = genuine[0].to_text().split()
        text[2] = labels
        out = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        out.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, " ".join(text)))
        for rr in genuine:
            out.add(rr)
        out.ttl = genuine.ttl
        return out

    def test_a_decoy_rrsig_does_not_hide_a_wildcard_expansion(self, zone: SignedZone) -> None:
        """RFC 4035 §5.3.4 keys off "the covering RRSIG RR" - the one that verified.

        A wildcard's signature verifies for every name the wildcard could
        cover, so a replayed wildcard record needs a proof that no closer match
        exists. A decoy claiming a larger Labels count would otherwise make the
        answer look ordinary and skip that proof.
        """
        wild = rrset_of("*.example.test.", "A", "6.6.6.6")
        genuine = zone.sign(wild)
        replayed = rrset_of("evil.example.test.", "A", "6.6.6.6")
        validator = DNSSECValidator()

        # The replay verifies: that is the property the proof exists to contain.
        assert validator.validate_rrset(replayed, genuine, zone.keyring()) is True

        tampered = self._with_decoy(genuine, replayed.name, "3")
        assert tampered[0].labels == 3, "the decoy must sort first"
        signature = validator.validated_rrsig(replayed, tampered, zone.keyring())
        assert signature is not None
        assert signature.labels == 2, "the signature that verified is the wildcard's"
        owner_labels = len(replayed.name.labels) - 1
        assert signature.labels < owner_labels, "so a wildcard proof is required"
        assert not tampered[0].labels < owner_labels, "while the decoy would have skipped it"

    def test_the_resolver_still_demands_the_proof_end_to_end(self, zone: SignedZone) -> None:
        wild = rrset_of("*.example.test.", "A", "6.6.6.6")
        genuine = zone.sign(wild)
        replayed = rrset_of("evil.example.test.", "A", "6.6.6.6")
        tampered = self._with_decoy(genuine, replayed.name, "3")

        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        ctx = resolver._new_context()
        response = make_response()
        response.answer = [replayed, tampered]
        response.authority = []
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_zone_keys(zone)),
            pytest.raises(DNSSECValidationError, match="wildcard-expanded"),
        ):
            resolver._validate_answer(
                response,
                replayed,
                replayed.name,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                None,
            )


class TestTheSignerMustContainTheOwner:
    """RFC 4035 §5.3.1: the signer must be the zone that contains the RRset.

    Nothing else in the stack enforces this. dnspython checks the RRSIG's label
    count and looks the signer up in the keyring, but never relates the signer
    to the owner name, so without this check any zone can sign for any name.
    Owning a single signed zone would be enough to authenticate forged data for
    every domain on the internet.
    """

    def test_a_zone_cannot_sign_for_a_name_it_does_not_contain(self) -> None:
        attacker = SignedZone.create("evil.example.")
        forged = rrset_of("www.victim.test.", "A", "6.6.6.6")
        # A genuine signature, made by a key the attacker really owns.
        assert DNSSECValidator().validate_rrset(forged, attacker.sign(forged), attacker.keyring()) is False

    def test_a_zone_can_still_sign_for_names_it_does_contain(self) -> None:
        zone = SignedZone.create("evil.example.")
        own = rrset_of("www.evil.example.", "A", "1.2.3.4")
        assert DNSSECValidator().validate_rrset(own, zone.sign(own), zone.keyring()) is True

    def test_the_apex_signs_for_itself(self) -> None:
        zone = SignedZone.create("example.test.")
        apex = rrset_of("example.test.", "A", "192.0.2.1")
        assert DNSSECValidator().validate_rrset(apex, zone.sign(apex), zone.keyring()) is True

    def test_a_parent_signs_the_ds_of_its_child(self) -> None:
        """The DS lives in the parent but is owned by the child's name."""
        parent = SignedZone.create("test.")
        child = SignedZone.create("example.test.")
        ds = parent.ds_rrset(child)
        assert DNSSECValidator().validate_rrset(ds, parent.sign(ds), parent.keyring()) is True

    def test_the_resolver_rejects_a_cross_zone_forgery_end_to_end(self) -> None:
        """The whole attack, through the public API, with require_dnssec on.

        A root, a zone the attacker controls and can get keys served for,
        and one spoofed packet carrying the victim's name signed by that zone.
        """
        root = SignedZone.create(".")
        attacker = SignedZone.create("evil.")
        qname = dns.name.from_text("www.victim.")
        forged = rrset_of("www.victim.", "A", "6.6.6.6")

        def reply(answer):
            message = make_response()
            message.answer = list(answer)
            message.authority = []
            return message

        def send(qname_, rdtype, nameservers, ctx, usable=None):
            if rdtype == dns.rdatatype.DNSKEY:
                z = root if qname_ == dns.name.root else attacker
                return reply([z.dnskey_rrset, z.signed_dnskey()]), "198.41.0.4"
            if rdtype == dns.rdatatype.DS:
                ds = root.ds_rrset(attacker)
                return reply([ds, root.sign(ds)]), "198.41.0.4"
            return reply([forged, attacker.sign(forged)]), "198.41.0.4"

        resolver = RecursiveResolver(
            dnssec=True, require_dnssec=True, cache_enabled=False, trust_anchors=(root.anchor_text(),)
        )
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(DNSSECValidationError):
            resolver.resolve_answer(str(qname), "A")


class TestTheDSMatchedKeyMustSign:
    """RFC 4035 §5.2: the key the DS matched must have signed the DNSKEY RRset.

    The DS is the only link the parent provides. If any key in the published
    RRset can supply the self-signature instead, then compromising a
    zone-signing key - shorter-lived, rotated more often, and not the key a
    registry protects - is enough to publish a new key and have the whole zone
    validate, with the real KSK sitting untouched in the same RRset satisfying
    the DS match.
    """

    @staticmethod
    def _published(*zones: SignedZone) -> dns.rrset.RRset:
        rrset = dns.rrset.RRset(zones[0].name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for z in zones:
            rrset.add(z.dnskey)
        rrset.ttl = 3600
        return rrset

    @staticmethod
    def _signed_by(signer: SignedZone, rrset: dns.rrset.RRset) -> dns.rrset.RRset:
        """The RRSIG ``signer`` would make over ``rrset``, using its own key."""
        return SignedZone(
            name=signer.name, private_key=signer.private_key, dnskey=signer.dnskey, dnskey_rrset=rrset
        ).sign(rrset)

    def test_a_dnskey_rrset_signed_only_by_a_non_ds_key_is_bogus(self, parent: SignedZone) -> None:
        ksk = SignedZone.create("example.test.")
        zsk = SignedZone.create("example.test.")
        intruder = SignedZone.create("example.test.")
        published = self._published(ksk, zsk, intruder)
        state = DNSSECValidator().validate_dnskey(
            ksk.name, published, self._signed_by(zsk, published), parent.ds_rdataset(ksk)
        )
        assert state is ValidationState.BOGUS

    def test_the_same_rrset_signed_by_the_ds_matched_key_is_secure(self, parent: SignedZone) -> None:
        """Only the signer changes, so that is what the verdict turns on."""
        ksk = SignedZone.create("example.test.")
        zsk = SignedZone.create("example.test.")
        published = self._published(ksk, zsk)
        state = DNSSECValidator().validate_dnskey(
            ksk.name, published, self._signed_by(ksk, published), parent.ds_rdataset(ksk)
        )
        assert state is ValidationState.SECURE

    def test_any_one_of_several_ds_matched_keys_may_sign(self, parent: SignedZone) -> None:
        """Two DS, two entry points: either signature is a valid path.

        RFC 6840 §5.11 - a validator should accept any single valid path, not
        insist that every advertised one works.
        """
        first = SignedZone.create("example.test.")
        second = SignedZone.create("example.test.")
        published = self._published(first, second)
        ds = parent.ds_rdataset(first)
        for rr in parent.ds_rdataset(second):
            ds.add(rr, ttl=3600)
        state = DNSSECValidator().validate_dnskey(first.name, published, self._signed_by(second, published), ds)
        assert state is ValidationState.SECURE


class TestRevokedKeys:
    """RFC 5011 §2.1: a revoked key must not be used for anything.

    Revocation is how the owner of a compromised key withdraws it. The private
    key still works, so every signature it makes still verifies; the only thing
    standing between an attacker holding that key and a validator trusting it
    is the REVOKE bit. These use real keys and real signatures, so a validator
    that ignores the bit passes them all.
    """

    def test_a_revoked_key_does_not_validate_data(self, zone: SignedZone) -> None:
        revoked = zone.revoked()
        data = rrset_of("example.test.", "A", "192.0.2.1")
        # The signature is genuine: the same private key made it.
        assert DNSSECValidator().validate_rrset(data, revoked.sign(data), revoked.keyring()) is False

    def test_the_same_key_before_revocation_does_validate(self, zone: SignedZone) -> None:
        """The bit is what changes the answer, not the key material."""
        data = rrset_of("example.test.", "A", "192.0.2.1")
        assert DNSSECValidator().validate_rrset(data, zone.sign(data), zone.keyring()) is True

    def test_a_revoked_key_is_not_a_secure_entry_point(self, zone: SignedZone, parent: SignedZone) -> None:
        """Even where the parent publishes a DS matching the revoked form."""
        revoked = zone.revoked()
        state = DNSSECValidator().validate_dnskey(
            revoked.name, revoked.dnskey_rrset, revoked.signed_dnskey(), parent.ds_rdataset(revoked)
        )
        assert state is ValidationState.BOGUS

    def test_a_revoked_key_cannot_anchor_the_root(self, zone: SignedZone) -> None:
        revoked = zone.revoked()
        validator = DNSSECValidator(trust_anchors=(revoked.anchor_text(),))
        assert validator.validate_root_dnskey(revoked.dnskey_rrset, revoked.signed_dnskey()) is False

    def test_a_live_sibling_key_still_works_alongside_a_revoked_one(self, parent: SignedZone) -> None:
        """Revoking one key must not take the rest of the DNSKEY RRset with it."""
        live = SignedZone.create("example.test.")
        revoked = SignedZone.create("example.test.").revoked()
        published = dns.rrset.RRset(live.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        published.add(live.dnskey)
        published.add(revoked.dnskey)
        published.ttl = 3600
        data = rrset_of("example.test.", "A", "192.0.2.1")
        keyring = {live.name: published}
        assert DNSSECValidator().validate_rrset(data, live.sign(data), keyring) is True
        assert DNSSECValidator().validate_rrset(data, revoked.sign(data), keyring) is False


class TestSignatureValidation:
    def test_a_genuine_signature_validates(self, zone: SignedZone) -> None:
        data = rrset_of("example.test.", "A", "192.0.2.1")
        assert DNSSECValidator().validate_rrset(data, zone.sign(data), zone.keyring()) is True

    def test_a_signature_over_different_data_does_not_validate(self, zone: SignedZone) -> None:
        signed = rrset_of("example.test.", "A", "192.0.2.1")
        tampered = rrset_of("example.test.", "A", "198.51.100.66")
        assert DNSSECValidator().validate_rrset(tampered, zone.sign(signed), zone.keyring()) is False

    def test_a_foreign_key_does_not_validate(self, zone: SignedZone, parent: SignedZone) -> None:
        data = rrset_of("example.test.", "A", "192.0.2.1")
        assert DNSSECValidator().validate_rrset(data, zone.sign(data), parent.keyring()) is False

    def test_validation_is_charged_to_the_budget(self, zone: SignedZone) -> None:
        data = rrset_of("example.test.", "A", "192.0.2.1")
        budget = QueryBudget()
        DNSSECValidator().validate_rrset(data, zone.sign(data), zone.keyring(), budget=budget)
        assert budget.signature_validations == 1


class TestChainOfTrust:
    def test_a_dnskey_matching_its_ds_validates(self, zone: SignedZone, parent: SignedZone) -> None:
        validator = DNSSECValidator()
        assert (
            validator.validate_dnskey(zone.name, zone.dnskey_rrset, zone.signed_dnskey(), parent.ds_rdataset(zone))
            is ValidationState.SECURE
        )

    def test_a_dnskey_not_matching_the_ds_is_rejected(self, zone: SignedZone, parent: SignedZone) -> None:
        """A comparable DS that simply does not match is forgery, not an unknown algorithm."""
        other = SignedZone.create("example.test.")
        validator = DNSSECValidator()
        assert (
            validator.validate_dnskey(zone.name, zone.dnskey_rrset, zone.signed_dnskey(), parent.ds_rdataset(other))
            is ValidationState.BOGUS
        )

    def test_an_unsigned_dnskey_rrset_is_rejected(self, zone: SignedZone, parent: SignedZone) -> None:
        """The DS must match a key that actually signed the DNSKEY RRset."""
        validator = DNSSECValidator()
        assert (
            validator.validate_dnskey(zone.name, zone.dnskey_rrset, None, parent.ds_rdataset(zone))
            is ValidationState.BOGUS
        )

    def test_the_root_anchor_path(self) -> None:
        """validate_root_dnskey, against a locally-generated root anchor."""
        root_zone = SignedZone.create(".")
        validator = DNSSECValidator(trust_anchors=(root_zone.anchor_text(),))
        assert validator.validate_root_dnskey(root_zone.dnskey_rrset, root_zone.signed_dnskey()) is True

    def test_a_root_dnskey_not_matching_the_anchor_is_rejected(self) -> None:
        real_root = SignedZone.create(".")
        impostor = SignedZone.create(".")
        validator = DNSSECValidator(trust_anchors=(real_root.anchor_text(),))
        assert validator.validate_root_dnskey(impostor.dnskey_rrset, impostor.signed_dnskey()) is False

    def test_a_signed_ds_yields_a_secure_delegation(self, zone: SignedZone, parent: SignedZone) -> None:
        ds = parent.ds_rrset(zone)
        authority = [ds, parent.sign(ds)]
        state, rdataset = DNSSECValidator().validate_ds(zone.name, authority, parent.keyring())
        assert state is ValidationState.SECURE
        assert rdataset is not None and len(rdataset) == 1

    def test_an_unsigned_ds_is_bogus(self, zone: SignedZone, parent: SignedZone) -> None:
        state, rdataset = DNSSECValidator().validate_ds(zone.name, [parent.ds_rrset(zone)], parent.keyring())
        assert state is ValidationState.BOGUS
        assert rdataset is None

    def test_a_signed_nsec_proving_no_ds_yields_an_insecure_delegation(self, parent: SignedZone) -> None:
        """The ordinary unsigned-child case: NS present, DS absent."""
        nsec = rrset_of("example.test.", "NSEC", "next.test. NS RRSIG NSEC")
        state, rdataset = DNSSECValidator().validate_ds(EXAMPLE, [nsec, parent.sign(nsec)], parent.keyring())
        assert state is ValidationState.INSECURE
        assert rdataset is None


class TestSignedDenialOfExistence:
    def test_signed_nsec_proves_nodata(self, zone: SignedZone) -> None:
        nsec = rrset_of("example.test.", "NSEC", "next.test. A RRSIG NSEC")
        authority = [nsec, zone.sign(nsec)]
        assert (
            DNSSECValidator().prove_nodata(EXAMPLE, dns.rdatatype.MX, authority, zone.keyring())
            is ValidationState.SECURE
        )

    def test_an_unsigned_nsec_proves_nothing(self, zone: SignedZone) -> None:
        nsec = rrset_of("example.test.", "NSEC", "next.test. A RRSIG NSEC")
        assert (
            DNSSECValidator().prove_nodata(EXAMPLE, dns.rdatatype.MX, [nsec], zone.keyring()) is ValidationState.BOGUS
        )

    def test_signed_nsec_proves_nxdomain(self, zone: SignedZone) -> None:
        covering = rrset_of("a.example.test.", "NSEC", "c.example.test. A RRSIG NSEC")
        wildcard = rrset_of("!.example.test.", "NSEC", "+.example.test. A RRSIG NSEC")
        authority = [covering, zone.sign(covering), wildcard, zone.sign(wildcard)]
        target = dns.name.from_text("b.example.test.")
        assert DNSSECValidator().prove_nxdomain(target, authority, zone.keyring()) is ValidationState.SECURE

    def test_an_empty_non_terminal_is_proven_by_the_nsec_that_jumps_over_it(self, zone: SignedZone) -> None:
        """The name holds no records while a name below it does, so the zone's
        NSEC chain steps straight over it and no NSEC matches it.

        The record before it points *below* it, which is what proves it is an
        empty non-terminal and therefore has no records of any type (RFC 4035
        §3.1.3.4.1). Without this, every ENT in an NSEC-signed zone - and there
        are many, including whole TLDs - is reported BOGUS.
        """
        nsec = rrset_of("po.example.test.", "NSEC", "a.pp.example.test. A RRSIG NSEC")
        authority = [nsec, zone.sign(nsec)]
        qname = dns.name.from_text("pp.example.test.")
        assert (
            DNSSECValidator().prove_nodata(qname, dns.rdatatype.A, authority, zone.keyring()) is ValidationState.SECURE
        )

    def test_a_covering_nsec_that_does_not_descend_proves_no_nodata(self, zone: SignedZone) -> None:
        """The name is denied, not shown to be empty: that is NXDOMAIN, not NODATA."""
        nsec = rrset_of("po.example.test.", "NSEC", "pq.example.test. A RRSIG NSEC")
        authority = [nsec, zone.sign(nsec)]
        qname = dns.name.from_text("pp.example.test.")
        assert (
            DNSSECValidator().prove_nodata(qname, dns.rdatatype.A, authority, zone.keyring()) is ValidationState.BOGUS
        )

    def test_an_nsec_pointing_at_the_name_itself_proves_nothing(self, zone: SignedZone) -> None:
        """A name with records owns an NSEC, and its predecessor points at it.

        Accepting that as an empty-non-terminal proof would deny the records of
        every name in the zone.
        """
        nsec = rrset_of("po.example.test.", "NSEC", "pp.example.test. A RRSIG NSEC")
        authority = [nsec, zone.sign(nsec)]
        qname = dns.name.from_text("pp.example.test.")
        assert (
            DNSSECValidator().prove_nodata(qname, dns.rdatatype.A, authority, zone.keyring()) is ValidationState.BOGUS
        )

    def test_signed_nsec_proving_no_ds(self, zone: SignedZone) -> None:
        nsec = rrset_of("child.example.test.", "NSEC", "next.example.test. NS RRSIG NSEC")
        authority = [nsec, zone.sign(nsec)]
        child = dns.name.from_text("child.example.test.")
        assert DNSSECValidator().prove_no_ds(child, authority, zone.keyring()) is True


class TestResolverAgainstASignedZone:
    """Drive the resolver end to end over a locally-signed delegation chain."""

    @staticmethod
    def _resolver(root: SignedZone) -> RecursiveResolver:
        """A resolver anchored on the locally-generated root instead of IANA's."""
        return RecursiveResolver(
            cache_enabled=True,
            max_resolution_time=5,
            trust_anchors=(root.anchor_text(),),
        )

    def test_a_fully_signed_chain_validates_secure(self) -> None:
        root = SignedZone.create(".")
        tld = SignedZone.create("test.")
        leaf = SignedZone.create("example.test.")

        answer = rrset_of("example.test.", "A", "192.0.2.10")
        root_ds = root.ds_rrset(tld)
        tld_ds = tld.ds_rrset(leaf)

        # Responses are held in a dict keyed by (qname, rdtype), which keeps the
        # mock readable as the chain grows.
        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        def referral(zone_name: str, ds_rrset, signer: SignedZone):
            response = make_response(
                authority=[(zone_name, 3600, "NS", [f"ns.{zone_name}"])],
                additional=[(f"ns.{zone_name}", 3600, "A", ["9.9.9.9"])],
                aa=False,
            )
            response.authority.append(ds_rrset)
            response.authority.append(signer.sign(ds_rrset))
            return response

        answer_response = make_response()
        answer_response.answer.append(answer)
        answer_response.answer.append(leaf.sign(answer))

        table = {
            (dns.name.root, dns.rdatatype.DNSKEY): dnskey_response(root),
            (tld.name, dns.rdatatype.DNSKEY): dnskey_response(tld),
            (leaf.name, dns.rdatatype.DNSKEY): dnskey_response(leaf),
        }
        state = {"step": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            key = (qname, rdtype)
            if key in table:
                return table[key], "9.9.9.9"
            state["step"] += 1
            if state["step"] == 1:
                return referral("test.", root_ds, root), "198.41.0.4"
            if state["step"] == 2:
                return referral("example.test.", tld_ds, tld), "9.9.9.9"
            return answer_response, "9.9.9.9"

        resolver = self._resolver(root)
        with patch.object(resolver, "_send_query", side_effect=send):
            result = resolver.resolve_answer("example.test.", "A")

        assert result.records == ["192.0.2.10"]
        assert result.dnssec is ValidationState.SECURE
        assert result.secure is True
        # The validated keys must have been cached for reuse.
        assert resolver._cached_keys(leaf.name) is not None

    def test_a_tampered_answer_in_a_signed_chain_is_rejected(self) -> None:
        root = SignedZone.create(".")
        leaf = SignedZone.create("test.")
        genuine = rrset_of("test.", "A", "192.0.2.10")
        forged = rrset_of("test.", "A", "198.51.100.66")

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        ds = root.ds_rrset(leaf)
        referral = make_response(
            authority=[("test.", 3600, "NS", ["ns.test."])],
            additional=[("ns.test.", 3600, "A", ["9.9.9.9"])],
            aa=False,
        )
        referral.authority.append(ds)
        referral.authority.append(root.sign(ds))

        # The attacker swaps the data but keeps the genuine signature.
        tampered = make_response()
        tampered.answer.append(forged)
        tampered.answer.append(leaf.sign(genuine))

        table = {
            (dns.name.root, dns.rdatatype.DNSKEY): dnskey_response(root),
            (leaf.name, dns.rdatatype.DNSKEY): dnskey_response(leaf),
        }
        state = {"step": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if (qname, rdtype) in table:
                return table[(qname, rdtype)], "9.9.9.9"
            state["step"] += 1
            return (referral, "198.41.0.4") if state["step"] == 1 else (tampered, "9.9.9.9")

        resolver = self._resolver(root)
        with (
            patch.object(resolver, "_send_query", side_effect=send),
            pytest.raises(DNSSECValidationError, match="RRSIG did not verify"),
        ):
            resolver.resolve("test.", "A")

    def test_require_dnssec_rejects_an_unsigned_answer(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=False, require_dnssec=True)
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
        chain = [
            (
                make_response(
                    authority=[("com.", 3600, "NS", ["a.gtld.net."])],
                    additional=[("a.gtld.net.", 3600, "A", ["192.5.6.30"])],
                    aa=False,
                ),
                "198.41.0.4",
            ),
            (
                make_response(
                    authority=[("example.com.", 3600, "NS", ["ns.example.com."])],
                    additional=[("ns.example.com.", 3600, "A", ["9.9.9.9"])],
                    aa=False,
                ),
                "192.5.6.30",
            ),
            (response, "9.9.9.9"),
        ]
        step = {"i": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            i = step["i"]
            step["i"] += 1
            return chain[i] if i < len(chain) else (None, "")

        with (
            patch.object(resolver, "_send_query", side_effect=send),
            pytest.raises(DNSSECInsecureError),
        ):
            resolver.resolve("example.com", "A")


class TestWildcardExpansion:
    """RFC 4035 §5.3.4: a wildcard answer needs a proof that nothing closer exists.

    An RRSIG whose ``labels`` count is below the owner's verifies against the
    reconstructed ``*.<closest encloser>``, so the same signature verifies for
    every name the wildcard could cover. Without the extra proof, a genuine
    wildcard record replayed under another owner name validates, overriding
    whatever explicit data that name really holds.
    """

    @staticmethod
    def _zone_with_wildcard():
        zone = SignedZone.create("example.test.")
        wild = rrset_of("*.example.test.", "A", "192.0.2.99")
        return zone, wild, zone.sign(wild)

    @staticmethod
    def _covering_nsec(zone: SignedZone):
        """One NSEC from the apex to z., covering both the qname and the wildcard."""
        nsec = rrset_of("example.test.", "NSEC", "z.example.test. A RRSIG NSEC")
        return [nsec, zone.sign(nsec)]

    def test_the_signature_alone_verifies_for_a_foreign_owner(self) -> None:
        """The premise: crypto cannot distinguish these, which is why proof is needed."""
        zone, _, wild_sig = self._zone_with_wildcard()
        forged = rrset_of("secure.example.test.", "A", "192.0.2.99")
        assert DNSSECValidator().validate_rrset(forged, wild_sig, zone.keyring()) is True

    def test_a_wildcard_answer_with_a_covering_proof_is_accepted(self) -> None:
        zone, _, wild_sig = self._zone_with_wildcard()
        qname = dns.name.from_text("anything.example.test.")
        assert (
            DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, self._covering_nsec(zone), zone.keyring())
            is ValidationState.SECURE
        )

    def test_a_wildcard_answer_with_no_proof_at_all_is_refused(self) -> None:
        zone, _, wild_sig = self._zone_with_wildcard()
        qname = dns.name.from_text("anything.example.test.")
        assert DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, [], zone.keyring()) is ValidationState.BOGUS

    def test_an_unsigned_proof_proves_nothing(self) -> None:
        zone, _, wild_sig = self._zone_with_wildcard()
        nsec = rrset_of("example.test.", "NSEC", "z.example.test. A RRSIG NSEC")
        qname = dns.name.from_text("anything.example.test.")
        assert (
            DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, [nsec], zone.keyring()) is ValidationState.BOGUS
        )

    def test_a_proof_that_does_not_cover_the_name_is_refused(self) -> None:
        """An NSEC from a different part of the zone must not satisfy the check."""
        zone, _, wild_sig = self._zone_with_wildcard()
        nsec = rrset_of("aa.example.test.", "NSEC", "ab.example.test. A RRSIG NSEC")
        qname = dns.name.from_text("zz.example.test.")
        assert (
            DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, [nsec, zone.sign(nsec)], zone.keyring())
            is ValidationState.BOGUS
        )

    @staticmethod
    def _wildcard_chain(*, proof: bool, opt_out: bool = False):
        """A signed zone answering `victim.test.` from its `*.test.` wildcard.

        With ``proof=False`` this is the attack: the wildcard's data and
        signature are presented under a name that really has its own, different
        record, and no denial proof accompanies them. On the wire the RRSIG
        owner must match the RRset it covers, so the owner is rewritten too; the
        rdata (labels=2) is untouched, and that is what still verifies.

        With ``opt_out=True`` the denial is a single opt-out NSEC3 covering
        everything, which is what the signed TLD zone that turned this up
        really serves.
        """
        root = SignedZone.create(".")
        leaf = SignedZone.create("test.")
        wild = rrset_of("*.test.", "A", "192.0.2.99")
        wild_sig = leaf.sign(wild)
        answer = rrset_of("victim.test.", "A", "192.0.2.99")
        answer_sig = dns.rrset.RRset(dns.name.from_text("victim.test."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        answer_sig.add(wild_sig[0])
        answer_sig.ttl = wild_sig.ttl

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        ds = root.ds_rrset(leaf)
        delegation = make_response(
            authority=[("test.", 3600, "NS", ["ns.test."])],
            additional=[("ns.test.", 3600, "A", ["9.9.9.9"])],
            aa=False,
        )
        delegation.authority.append(ds)
        delegation.authority.append(root.sign(ds))

        answer_response = make_response()
        answer_response.answer.append(answer)
        answer_response.answer.append(answer_sig)
        if opt_out:
            # Covers every hash, but with the opt-out flag: it denies signed
            # delegations, not existence, so it cannot rule out a closer match.
            nsec3 = rrset_of(
                "00000000000000000000000000000000.test.",
                "NSEC3",
                "1 1 0 - ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ A RRSIG",
            )
            answer_response.authority.append(nsec3)
            answer_response.authority.append(leaf.sign(nsec3))
        elif proof:
            # Covers `victim.test.`, so no closer match could have existed.
            nsec = rrset_of("test.", "NSEC", "z.test. A RRSIG NSEC")
            answer_response.authority.append(nsec)
            answer_response.authority.append(leaf.sign(nsec))

        table = {
            (dns.name.root, dns.rdatatype.DNSKEY): dnskey_response(root),
            (leaf.name, dns.rdatatype.DNSKEY): dnskey_response(leaf),
        }
        state = {"step": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if (qname, rdtype) in table:
                return table[(qname, rdtype)], "9.9.9.9"
            state["step"] += 1
            if state["step"] == 1:
                return delegation, "198.41.0.4"
            return answer_response, "9.9.9.9"

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),))
        return resolver, send

    def test_a_proven_wildcard_answer_validates_secure(self) -> None:
        """A legitimate wildcard answer carrying its proof must still work."""
        resolver, send = self._wildcard_chain(proof=True)
        with patch.object(resolver, "_send_query", side_effect=send):
            result = resolver.resolve_answer("victim.test.", "A")
        assert result.records == ["192.0.2.99"]
        assert result.dnssec is ValidationState.SECURE

    def test_the_resolver_refuses_an_unproven_wildcard_answer(self) -> None:
        """End to end: a replayed wildcard signature must not validate as SECURE."""
        resolver, send = self._wildcard_chain(proof=False)
        with (
            patch.object(resolver, "_send_query", side_effect=send),
            pytest.raises(DNSSECValidationError, match="wildcard"),
        ):
            resolver.resolve("victim.test.", "A")

    def test_an_opt_out_proof_leaves_the_wildcard_answer_unauthenticated(self) -> None:
        """Found in the wild while testing 0.2.0, in a signed TLD zone.

        The zone denies the queried name with a single opt-out NSEC3. Opt-out
        says nothing about names that are not signed delegations, so the
        expansion cannot be authenticated: the data is returned, INSECURE, as
        four independent public validators all return it. Calling it SECURE
        would let a replayed wildcard RRset override the real contents of any
        name inside an opt-out span.
        """
        resolver, send = self._wildcard_chain(proof=False, opt_out=True)
        with patch.object(resolver, "_send_query", side_effect=send):
            result = resolver.resolve_answer("victim.test.", "A")
        assert result.records == ["192.0.2.99"]
        assert result.dnssec is ValidationState.INSECURE

    def test_require_dnssec_refuses_an_opt_out_wildcard_answer(self) -> None:
        resolver, send = self._wildcard_chain(proof=False, opt_out=True)
        resolver.require_dnssec = True
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(DNSSECInsecureError):
            resolver.resolve("victim.test.", "A")


class TestSignedDenialThroughTheResolveLoop:
    """The denial proof must be demanded by the resolve loop, not just testable.

    `_verify_denial` is well covered on its own, but nothing drove a signed
    negative answer through `resolve()`, so the wiring that connects the two
    was unguarded: deleting the call broke no test.
    """

    @staticmethod
    def _chain(negative_response):
        root = SignedZone.create(".")
        leaf = SignedZone.create("test.")
        ds = root.ds_rrset(leaf)

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        delegation = make_response(
            authority=[("test.", 3600, "NS", ["ns.test."])],
            additional=[("ns.test.", 3600, "A", ["9.9.9.9"])],
            aa=False,
        )
        delegation.authority.append(ds)
        delegation.authority.append(root.sign(ds))

        table = {
            (dns.name.root, dns.rdatatype.DNSKEY): dnskey_response(root),
            (leaf.name, dns.rdatatype.DNSKEY): dnskey_response(leaf),
        }
        state = {"step": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if (qname, rdtype) in table:
                return table[(qname, rdtype)], "9.9.9.9"
            state["step"] += 1
            if state["step"] == 1:
                return delegation, "198.41.0.4"
            return negative_response(leaf), "9.9.9.9"

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),))
        return resolver, send

    @staticmethod
    def _nxdomain(leaf: SignedZone, *, proof: bool, expiration: int | None = None):
        response = make_response(
            authority=[("test.", 300, "SOA", ["ns.test. a.test. 1 3600 900 604800 300"])],
            rcode=dns.rcode.NXDOMAIN,
        )
        expiry = EXPIRATION if expiration is None else expiration
        response.authority.append(leaf.sign(response.authority[0], expiration=expiry))
        if proof:
            # One NSEC from the apex covers both the missing name and the
            # wildcard that could otherwise have synthesised it.
            nsec = rrset_of("test.", "NSEC", "z.test. A RRSIG NSEC")
            response.authority.append(nsec)
            response.authority.append(leaf.sign(nsec, expiration=expiry))
        return response

    @staticmethod
    def _nodata(leaf: SignedZone, *, proof: bool):
        response = make_response(
            authority=[("test.", 300, "SOA", ["ns.test. a.test. 1 3600 900 604800 300"])],
        )
        response.authority.append(leaf.sign(response.authority[0]))
        if proof:
            nsec = rrset_of("missing.test.", "NSEC", "z.test. A RRSIG NSEC")
            response.authority.append(nsec)
            response.authority.append(leaf.sign(nsec))
        return response

    def test_a_proven_nxdomain_is_accepted(self) -> None:
        resolver, send = self._chain(lambda leaf: self._nxdomain(leaf, proof=True))
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NXDOMAINError):
            resolver.resolve("missing.test.", "A")

    def test_an_unproven_nxdomain_in_a_signed_zone_is_refused(self) -> None:
        resolver, send = self._chain(lambda leaf: self._nxdomain(leaf, proof=False))
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(DNSSECValidationError):
            resolver.resolve("missing.test.", "A")

    def test_a_proven_nxdomain_is_not_cached_past_its_signature(self) -> None:
        """RFC 4035 §5.3.3: the denial stops being authenticated when the proof does.

        The SOA asks for 300s of negative caching, but the RRSIGs expire in 30,
        so 30 is what the entry gets.
        """
        cache = DNSCache()
        resolver, send = self._chain(lambda leaf: self._nxdomain(leaf, proof=True, expiration=int(time.time()) + 30))
        resolver.cache = cache
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NXDOMAINError):
            resolver.resolve("missing.test.", "A")
        entry = cache.get_nxdomain("missing.test.")
        assert entry is not None and entry.secure
        assert 0 < entry.expiry - time.monotonic() <= 30

    def test_a_long_lived_proof_leaves_the_soa_ttl_alone(self) -> None:
        """The cap only ever shortens: a 30-day signature does not extend 300s."""
        cache = DNSCache()
        resolver, send = self._chain(lambda leaf: self._nxdomain(leaf, proof=True))
        resolver.cache = cache
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NXDOMAINError):
            resolver.resolve("missing.test.", "A")
        entry = cache.get_nxdomain("missing.test.")
        assert entry is not None
        assert 290 < entry.expiry - time.monotonic() <= 300

    def test_an_unproven_nodata_in_a_signed_zone_is_refused(self) -> None:
        resolver, send = self._chain(lambda leaf: self._nodata(leaf, proof=False))
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(DNSSECValidationError):
            resolver.resolve("missing.test.", "MX")


class TestUnverifiableZoneResolvesAsUnsigned:
    """RFC 4035 §5.2 end to end, on every path that consults a zone's keys.

    A zone signed only with an algorithm this build cannot verify must resolve
    exactly like an unsigned zone: an answer, marked INSECURE. Reporting BOGUS
    would take a legitimately signed domain off the air for our users.
    """

    @staticmethod
    def _chain(final_response_for):
        """Root -> test. -> answer, with `test.` signed but unverifiable."""
        root = SignedZone.create(".")
        leaf = SignedZone.create("test.")
        ds = root.ds_rrset(leaf)

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        delegation = make_response(
            authority=[("test.", 3600, "NS", ["ns.test."])],
            additional=[("ns.test.", 3600, "A", ["9.9.9.9"])],
            aa=False,
        )
        delegation.authority.append(ds)
        delegation.authority.append(root.sign(ds))

        table = {
            (dns.name.root, dns.rdatatype.DNSKEY): dnskey_response(root),
            (leaf.name, dns.rdatatype.DNSKEY): dnskey_response(leaf),
        }
        state = {"step": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if (qname, rdtype) in table:
                return table[(qname, rdtype)], "9.9.9.9"
            state["step"] += 1
            if state["step"] == 1:
                return delegation, "198.41.0.4"
            return final_response_for(leaf), "9.9.9.9"

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),))
        return resolver, send, leaf

    @staticmethod
    def _unverifiable(resolver: RecursiveResolver, leaf: SignedZone):
        """Make only the leaf zone's keys unverifiable; the root stays sound."""
        real = resolver._validator.validate_dnskey

        def stub(zone, dnskey_rrset, rrsig_rrset, ds_rdataset, budget=None):
            if zone == leaf.name:
                return ValidationState.INSECURE
            return real(zone, dnskey_rrset, rrsig_rrset, ds_rdataset, budget=budget)

        return patch.object(resolver._validator, "validate_dnskey", side_effect=stub)

    def test_a_positive_answer_is_insecure(self) -> None:
        def answer(leaf: SignedZone):
            response = make_response()
            rrset = rrset_of("test.", "A", "192.0.2.10")
            response.answer.append(rrset)
            response.answer.append(leaf.sign(rrset))
            return response

        resolver, send, leaf = self._chain(answer)
        with patch.object(resolver, "_send_query", side_effect=send), self._unverifiable(resolver, leaf):
            result = resolver.resolve_answer("test.", "A")
        assert result.records == ["192.0.2.10"]
        assert result.dnssec is ValidationState.INSECURE

    def test_an_nxdomain_is_accepted_without_a_proof(self) -> None:
        """We cannot check the denial either, so it must not be called forged."""

        def nxdomain(leaf: SignedZone):
            response = make_response(
                authority=[("test.", 300, "SOA", ["ns.test. a.test. 1 3600 900 604800 300"])],
                rcode=dns.rcode.NXDOMAIN,
            )
            response.authority.append(leaf.sign(response.authority[0]))
            return response

        resolver, send, leaf = self._chain(nxdomain)
        with (
            patch.object(resolver, "_send_query", side_effect=send),
            self._unverifiable(resolver, leaf),
            pytest.raises(NXDOMAINError),
        ):
            resolver.resolve("missing.test.", "A")

    def test_require_dnssec_still_refuses_it(self) -> None:
        """Insecure is not secure: a caller demanding authentication gets none."""

        def answer(leaf: SignedZone):
            response = make_response()
            rrset = rrset_of("test.", "A", "192.0.2.10")
            response.answer.append(rrset)
            response.answer.append(leaf.sign(rrset))
            return response

        resolver, send, leaf = self._chain(answer)
        resolver.require_dnssec = True
        with (
            patch.object(resolver, "_send_query", side_effect=send),
            self._unverifiable(resolver, leaf),
            pytest.raises(DNSSECInsecureError),
        ):
            resolver.resolve("test.", "A")


class TestLameServersDoNotProduceDNSSECVerdicts:
    """One lame nameserver in a zone's NS set must not condemn the zone.

    Measured against live DNS before the fix: 4 of 25 ordinary domains flapped
    between an answer and "DNSSEC validation failed", depending only on which
    server the shuffle happened to pick first. Each had a server in its NS set
    that answers DNSKEY with NOERROR, no answer section and the delegation in
    AUTHORITY - a parent-side server, or a plain lame one. Being unable to
    retrieve validation material is a resolution failure, never evidence of
    tampering.

    Driven at `_query_once` rather than `_send_query`, so the sweep across
    servers is the thing under test.
    """

    LAME = "9.9.9.9"
    GOOD = "9.9.9.10"

    def _world(self, *, lame: set[str], mode: str = "empty"):
        root = SignedZone.create(".")
        child = SignedZone.create("test.")
        ds = root.ds_rrset(child)

        referral = make_response(
            authority=[("test.", 3600, "NS", ["ns1.test.", "ns2.test."])],
            additional=[("ns1.test.", 3600, "A", [self.LAME]), ("ns2.test.", 3600, "A", [self.GOOD])],
            aa=False,
        )
        referral.authority.append(ds)
        referral.authority.append(root.sign(ds))

        answer = make_response()
        data = rrset_of("example.test.", "A", "198.51.100.9")
        answer.answer.append(data)
        answer.answer.append(child.sign(data))

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        def lame_response():
            """NOERROR, empty ANSWER, delegation in AUTHORITY."""
            response = make_response(authority=[("test.", 3600, "NS", ["ns1.test.", "ns2.test."])], aa=False)
            response.authority.append(ds)
            response.authority.append(root.sign(ds))
            return response

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            if server not in (self.LAME, self.GOOD):
                if rdtype == dns.rdatatype.DNSKEY and qname == dns.name.root:
                    return dnskey_response(root)
                return referral
            if rdtype == dns.rdatatype.DNSKEY and qname == child.name:
                if server in lame:
                    return lame_response() if mode == "empty" else make_response(rcode=dns.rcode.SERVFAIL, aa=False)
                return dnskey_response(child)
            return answer

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),), cache_enabled=False)
        return resolver, query_once

    def test_a_lame_first_server_does_not_make_the_zone_bogus(self) -> None:
        resolver, query_once = self._world(lame={self.LAME})
        with (
            patch.object(resolver, "_order_servers", side_effect=lambda servers: list(servers)),
            patch.object(resolver, "_query_once", side_effect=query_once),
        ):
            result = resolver.resolve_answer("example.test.", "A")
        assert result.records == ["198.51.100.9"]
        assert result.dnssec is ValidationState.SECURE

    def test_every_server_lame_is_a_retrieval_failure(self) -> None:
        """Not a DNSSECError: that distinction is what consumers branch on."""
        resolver, query_once = self._world(lame={self.LAME, self.GOOD})
        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver.resolve("example.test.", "A")

    def test_servfail_on_dnskey_is_a_retrieval_failure(self) -> None:
        resolver, query_once = self._world(lame={self.LAME, self.GOOD}, mode="servfail")
        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver.resolve("example.test.", "A")

    def test_a_lame_server_on_the_ds_fetch_does_not_break_the_chain(self) -> None:
        """The same sweep is needed wherever validation material is fetched.

        A server authoritative for both `test.` and `sub.test.` answers from
        the child, so the resolver has to fetch `sub.test./DS` itself; one lame
        server there used to surface as "broken chain of trust".
        """
        root = SignedZone.create(".")
        child = SignedZone.create("test.")
        grandchild = SignedZone.create("sub.test.")

        ds = root.ds_rrset(child)
        referral = make_response(
            authority=[("test.", 3600, "NS", ["ns1.test.", "ns2.test."])],
            additional=[("ns1.test.", 3600, "A", [self.LAME]), ("ns2.test.", 3600, "A", [self.GOOD])],
            aa=False,
        )
        referral.authority.append(ds)
        referral.authority.append(root.sign(ds))

        answer = make_response()
        data = rrset_of("example.sub.test.", "A", "198.51.100.9")
        answer.answer.append(data)
        answer.answer.append(grandchild.sign(data))

        sub_ds = child.ds_rrset(grandchild)
        ds_answer = make_response()
        ds_answer.answer.append(sub_ds)
        ds_answer.answer.append(child.sign(sub_ds))

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            if server not in (self.LAME, self.GOOD):
                if rdtype == dns.rdatatype.DNSKEY and qname == dns.name.root:
                    return dnskey_response(root)
                return referral
            if rdtype == dns.rdatatype.DNSKEY:
                return dnskey_response(child if qname == child.name else grandchild)
            if rdtype == dns.rdatatype.DS and qname == grandchild.name:
                if server == self.LAME:
                    return make_response(authority=[("sub.test.", 3600, "NS", ["ns1.test."])], aa=False)
                return ds_answer
            return answer

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),), cache_enabled=False)
        with (
            patch.object(resolver, "_order_servers", side_effect=lambda servers: list(servers)),
            patch.object(resolver, "_query_once", side_effect=query_once),
        ):
            result = resolver.resolve_answer("example.sub.test.", "A")
        assert result.records == ["198.51.100.9"]
        assert result.dnssec is ValidationState.SECURE


class TestParentServedInsecureChild:
    """A signed parent answering for its own insecurely delegated child.

    A signed second-level zone can be authoritative for a child that has no
    DS, and answer the child's records itself, unsigned and with AA set. There
    is no RRSIG, so no signer to align on: without walking the delegation the
    resolver has no way to tell "insecure child" from "signatures stripped",
    and used to call every such answer BOGUS. The public validators all return
    the answer, unauthenticated.
    """

    SERVER = "9.9.9.10"

    def _world(self, final_response, *, bitmap: str = "NS RRSIG NSEC"):
        """Root -> signed `test.` -> an unsigned answer for `example.sub.test.`.

        ``bitmap`` is what `test.` says about `sub.test.`: with NS in it the
        name is a delegation and the missing DS makes it insecure; without NS
        it is an ordinary name in the signed zone and nothing excuses the
        missing signature.
        """
        root = SignedZone.create(".")
        child = SignedZone.create("test.")
        ds = root.ds_rrset(child)

        referral = make_response(
            authority=[("test.", 3600, "NS", ["ns1.test."])],
            additional=[("ns1.test.", 3600, "A", [self.SERVER])],
            aa=False,
        )
        referral.authority.append(ds)
        referral.authority.append(root.sign(ds))

        nsec = rrset_of("sub.test.", "NSEC", f"z.test. {bitmap}")
        no_ds = make_response()
        no_ds.authority.append(nsec)
        no_ds.authority.append(child.sign(nsec))

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            if server != self.SERVER:
                if rdtype == dns.rdatatype.DNSKEY and qname == dns.name.root:
                    return dnskey_response(root)
                return referral
            if rdtype == dns.rdatatype.DNSKEY:
                return dnskey_response(child)
            if rdtype == dns.rdatatype.DS:
                return no_ds
            return final_response

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),), cache_enabled=False)
        return resolver, query_once

    def test_an_unsigned_answer_for_an_insecure_child_is_insecure(self) -> None:
        answer = make_response()
        answer.answer.append(rrset_of("example.sub.test.", "A", "198.51.100.9"))
        resolver, query_once = self._world(answer)
        with patch.object(resolver, "_query_once", side_effect=query_once):
            result = resolver.resolve_answer("example.sub.test.", "A")
        assert result.records == ["198.51.100.9"]
        assert result.dnssec is ValidationState.INSECURE

    def test_an_unsigned_negative_answer_for_an_insecure_child_is_accepted(self) -> None:
        nodata = make_response(
            authority=[("sub.test.", 300, "SOA", ["ns1.test. hm.test. 1 3600 900 604800 300"])],
        )
        resolver, query_once = self._world(nodata)
        with patch.object(resolver, "_query_once", side_effect=query_once), pytest.raises(NoAnswerError):
            resolver.resolve("example.sub.test.", "A")

    def test_a_stripped_signature_inside_the_signed_zone_is_still_bogus(self) -> None:
        """The downgrade must not become a way to launder tampering.

        Same unsigned answer, but the zone proves the name is not a delegation:
        no NS in the NSEC bitmap, so nothing licenses treating it as insecure.
        """
        answer = make_response()
        answer.answer.append(rrset_of("example.sub.test.", "A", "198.51.100.9"))
        resolver, query_once = self._world(answer, bitmap="A RRSIG NSEC")
        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(DNSSECValidationError, match="no RRSIG"),
        ):
            resolver.resolve("example.sub.test.", "A")


class TestAStaleUnsignedServerDoesNotCondemnTheZone:
    """RFC 4035 §5.5: try another server before concluding an answer is Bogus.

    The same rule `_verify_denial` applies to a proof that does not validate,
    one level up. Found on `nic.bj`, whose four nameservers include one
    serving a stale *unsigned* copy of the zone: it answers authoritatively
    with no RRSIG for any type, and NODATA for DNSKEY. Landing on it made
    every type in the zone read as forged and the DNSKEY NODATA unprovable,
    while every other validating resolver simply asked a sibling.

    Driven at `_query_once` so the real sweep across the NS set runs, and the
    stale server is the one the sweep has to get past rather than one the test
    arranged to be skipped.
    """

    STALE = "9.9.9.10"
    GOOD = "9.9.9.11"

    def _world(self, stale_response, good_response):
        root = SignedZone.create(".")
        child = SignedZone.create("test.")
        ds = root.ds_rrset(child)

        referral = make_response(
            authority=[("test.", 3600, "NS", ["ns1.test.", "ns2.test."])],
            additional=[("ns1.test.", 3600, "A", [self.STALE]), ("ns2.test.", 3600, "A", [self.GOOD])],
            aa=False,
        )
        referral.authority.append(ds)
        referral.authority.append(root.sign(ds))

        def dnskey_response(zone: SignedZone):
            response = make_response()
            response.answer.append(zone.dnskey_rrset)
            response.answer.append(zone.signed_dnskey())
            return response

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            if server not in (self.STALE, self.GOOD):
                if rdtype == dns.rdatatype.DNSKEY and qname == dns.name.root:
                    return dnskey_response(root)
                return referral
            if server == self.STALE:
                return stale_response
            if rdtype == dns.rdatatype.DNSKEY and qname == child.name:
                return dnskey_response(child)
            return good_response(child)

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),), cache_enabled=False)
        return resolver, query_once

    @staticmethod
    def _unsigned_answer() -> dns.message.Message:
        response = make_response()
        response.answer.append(rrset_of("test.", "A", "198.51.100.9"))
        return response

    @staticmethod
    def _signed_answer(child: SignedZone) -> dns.message.Message:
        answer = rrset_of("test.", "A", "192.0.2.10")
        response = make_response()
        response.answer.append(answer)
        response.answer.append(child.sign(answer))
        return response

    def test_an_unsigned_answer_from_one_server_is_retried_elsewhere(self) -> None:
        # The sweep shuffles the NS set, so this runs both orders.
        for _ in range(8):
            resolver, query_once = self._world(self._unsigned_answer(), self._signed_answer)
            with patch.object(resolver, "_query_once", side_effect=query_once):
                result = resolver.resolve_answer("test.", "A")
            assert result.records == ["192.0.2.10"], "took the stale server's unsigned answer"
            assert result.dnssec is ValidationState.SECURE

    def test_an_unsigned_nodata_from_one_server_is_retried_elsewhere(self) -> None:
        """The `nic.bj/DNSKEY` case: a NODATA the stale copy cannot prove.

        Sweeping only on a failed *proof* does not reach this: the sibling
        holds real DNSKEY records, so it never sends a denial for the
        denial-sweep predicate to accept, and the zone came out "unproven
        nodata in a signed zone" with the records sitting on the next server.
        """
        stale = make_response(authority=[("test.", 300, "SOA", ["ns1.test. hm.test. 1 3600 900 604800 300"])])
        for _ in range(8):
            resolver, query_once = self._world(stale, self._signed_answer)
            with patch.object(resolver, "_query_once", side_effect=query_once):
                result = resolver.resolve_answer("test.", "DNSKEY")
            assert result.dnssec is ValidationState.SECURE
            assert result.records, "no DNSKEY came back"

    def test_a_zone_every_server_serves_unsigned_is_still_bogus(self) -> None:
        """Sweeping must not turn a zone with no signatures anywhere into a pass."""
        resolver, query_once = self._world(self._unsigned_answer(), lambda _child: self._unsigned_answer())
        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(DNSSECValidationError, match="no RRSIG"),
        ):
            resolver.resolve("test.", "A")

    def test_a_referral_is_not_swept_past_for_want_of_a_signature(self) -> None:
        """The delegation NS RRset is unsigned by design (RFC 4035 §2.2).

        Treating an unsigned referral as a stale copy would sweep the whole
        parent NS set on every delegation in a signed zone and then fail.
        """
        resolver, _ = self._world(self._unsigned_answer(), self._signed_answer)
        ctx = resolver._new_context()
        bare = make_response(authority=[("sub.test.", 3600, "NS", ["ns1.sub.test."])], aa=False)
        assert resolver._serves_an_unsigned_copy(bare, "referral", ValidationState.SECURE, ctx) is False, (
            "a referral was mistaken for a stale unsigned copy"
        )

    def test_an_insecure_chain_is_left_alone(self) -> None:
        """Nothing to sweep for when the chain never claimed the zone was signed."""
        resolver, _ = self._world(self._unsigned_answer(), self._signed_answer)
        ctx = resolver._new_context()
        assert (
            resolver._serves_an_unsigned_copy(self._unsigned_answer(), "answer", ValidationState.INSECURE, ctx) is False
        )


class TestClockSkewOnInception:
    """A signer whose clock runs ahead of ours must not produce BOGUS.

    Zones that re-sign continuously publish records whose inception is a
    moment in the future as far as a slightly-slow validator is concerned.
    With no tolerance the freshest records in such a zone are intermittently
    unresolvable. PowerDNS and Unbound both allow slack; this is the
    conservative end of what they do.
    """

    @staticmethod
    def _signed_from(zone: SignedZone, rrset: dns.rrset.RRset, offset: int) -> dns.rrset.RRset:
        """Sign ``rrset`` with an inception ``offset`` seconds from now."""
        now = int(time.time())
        rrsig = dns.dnssec.sign(
            rrset,
            zone.private_key,
            zone.name,
            zone.dnskey,
            inception=now + offset,
            expiration=now + 30 * 86400,
        )
        out = dns.rrset.RRset(rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        out.add(rrsig)
        out.ttl = rrset.ttl
        return out

    def test_an_inception_just_inside_the_skew_allowance_validates(self, zone: SignedZone) -> None:
        from recursive_resolver.dnssec import CLOCK_SKEW

        data = rrset_of("example.test.", "A", "192.0.2.1")
        sig = self._signed_from(zone, data, CLOCK_SKEW - 5)
        assert DNSSECValidator().validate_rrset(data, sig, zone.keyring()) is True

    def test_an_inception_beyond_the_allowance_does_not(self, zone: SignedZone) -> None:
        from recursive_resolver.dnssec import CLOCK_SKEW

        data = rrset_of("example.test.", "A", "192.0.2.1")
        sig = self._signed_from(zone, data, CLOCK_SKEW + 3600)
        assert DNSSECValidator().validate_rrset(data, sig, zone.keyring()) is False

    def test_an_expired_signature_is_still_refused(self, zone: SignedZone) -> None:
        """The slack applies to inception only; expiry stays strict."""
        now = int(time.time())
        data = rrset_of("example.test.", "A", "192.0.2.1")
        rrsig = dns.dnssec.sign(
            data,
            zone.private_key,
            zone.name,
            zone.dnskey,
            inception=now - 30 * 86400,
            expiration=now - 3600,
        )
        sig = dns.rrset.RRset(data.name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        sig.add(rrsig)
        sig.ttl = data.ttl
        assert DNSSECValidator().validate_rrset(data, sig, zone.keyring()) is False

    def test_the_skew_is_configurable(self, zone: SignedZone) -> None:
        data = rrset_of("example.test.", "A", "192.0.2.1")
        sig = self._signed_from(zone, data, 600)
        assert DNSSECValidator(clock_skew=0).validate_rrset(data, sig, zone.keyring()) is False
        assert DNSSECValidator(clock_skew=1200).validate_rrset(data, sig, zone.keyring()) is True


class TestSignedDNAME:
    """RFC 6672 §8: "A validating resolver MUST understand DNAME".

    The synthesized CNAME must not be signed (§3.3) - the DNAME's own
    signature is what authenticates the redirection, and the CNAME follows
    from it by construction. A validator that demands an RRSIG on the CNAME
    calls every DNAME in a signed zone forged.
    """

    QNAME = dns.name.from_text("foo.sub.example.test.")

    @staticmethod
    def _dname(zone: SignedZone):
        return rrset_of("sub.example.test.", "DNAME", "target.example.test.")

    def _validate(self, resolver, zone, answer):
        response = make_response()
        response.answer = list(answer)
        response.authority = []
        ctx = resolver._new_context()
        classification = resolver._classify_response(response, self.QNAME, dns.rdatatype.A, zone.name)
        assert classification["type"] == "cname"
        with patch.object(resolver, "_get_zone_keys", return_value=_zone_keys(zone)):
            return resolver._validate_answer(
                response,
                classification["cname_rrset"],
                self.QNAME,
                dns.rdatatype.CNAME,
                ctx,
                zone.name,
                ["9.9.9.9"],
                ValidationState.SECURE,
                None,
                classification.get("dname_rrset"),
            )

    def test_a_signed_dname_authenticates_the_redirection(self, zone: SignedZone) -> None:
        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        dname = self._dname(zone)
        state, _ttl = self._validate(resolver, zone, [dname, zone.sign(dname)])
        assert state is ValidationState.SECURE

    def test_the_servers_unsigned_synthesized_cname_does_not_spoil_it(self, zone: SignedZone) -> None:
        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        dname = self._dname(zone)
        synthesized = rrset_of(str(self.QNAME), "CNAME", "foo.target.example.test.")
        state, _ttl = self._validate(resolver, zone, [dname, zone.sign(dname), synthesized])
        assert state is ValidationState.SECURE

    def test_an_unsigned_dname_in_a_signed_zone_never_validates(self, zone: SignedZone) -> None:
        """Stripping the DNAME's signature must not be survivable.

        Which error comes out depends on what the delegation check can reach -
        an unsigned subtree is INSECURE, a signed one BOGUS, an unreachable
        parent "material unavailable" - but SECURE is never among them.
        """
        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        with pytest.raises((DNSSECValidationError, DNSSECMaterialUnavailableError)):
            self._validate(resolver, zone, [self._dname(zone)])

    def test_a_dname_signed_by_another_zone_is_bogus(self, zone: SignedZone) -> None:
        other = SignedZone.create("elsewhere.test.")
        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        dname = self._dname(zone)
        with pytest.raises(DNSSECValidationError):
            self._validate(resolver, zone, [dname, other.sign(dname)])


class TestQueryingAWildcardNameDirectly:
    """RFC 4592 §2.2.1: the wildcard name can be asked for by name.

    The answer is an exact match, not an expansion, and carries no denial
    records. Its RRSIG always covers one label fewer than the owner has, so a
    naive expansion test reads every such answer as synthesised and demands a
    proof that cannot exist.
    """

    def test_the_wildcard_owner_validates_without_a_denial(self, zone: SignedZone) -> None:
        wild = rrset_of("*.example.test.", "A", "192.0.2.7")
        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        ctx = resolver._new_context()
        response = make_response()
        response.answer = [wild, zone.sign(wild)]
        response.authority = []
        with patch.object(resolver, "_get_zone_keys", return_value=_zone_keys(zone)):
            state, _ttl = resolver._validate_answer(
                response,
                wild,
                wild.name,
                dns.rdatatype.A,
                ctx,
                zone.name,
                ["9.9.9.9"],
                ValidationState.SECURE,
                None,
            )
        assert state is ValidationState.SECURE

    def test_a_name_the_wildcard_expanded_to_still_needs_its_proof(self, zone: SignedZone) -> None:
        """Only the literal owner is exempt; expansion is unchanged."""
        wild = rrset_of("*.example.test.", "A", "192.0.2.7")
        expanded = rrset_of("host.example.test.", "A", "192.0.2.7")
        # What a server sends for an expansion: the answer owned by the queried
        # name, carrying the wildcard's signature, whose Labels count is one
        # short of the owner.
        signature = dns.rrset.RRset(expanded.name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        for rr in zone.sign(wild):
            signature.add(rr)
        signature.ttl = 300
        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        ctx = resolver._new_context()
        response = make_response()
        response.answer = [expanded, signature]
        response.authority = []
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_zone_keys(zone)),
            pytest.raises(DNSSECValidationError, match="wildcard-expanded"),
        ):
            resolver._validate_answer(
                response,
                expanded,
                expanded.name,
                dns.rdatatype.A,
                ctx,
                zone.name,
                ["9.9.9.9"],
                ValidationState.SECURE,
                None,
            )
