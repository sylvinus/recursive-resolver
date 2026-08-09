"""DNSSEC validation against a real, locally-signed zone.

Everything here uses genuine keys, signatures and DS digests generated in
process, so the success paths are covered deterministically and without a
network, including cases live DNS does not reliably provide.
"""

from __future__ import annotations

from unittest.mock import patch

import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from conftest import make_response
from signed_zone import SignedZone, rrset_of

from recursive_resolver import (
    DNSSECInsecureError,
    DNSSECValidationError,
    NXDOMAINError,
    RecursiveResolver,
    ValidationState,
)
from recursive_resolver.budget import QueryBudget
from recursive_resolver.dnssec import DNSSECValidator

EXAMPLE = dns.name.from_text("example.test.")


@pytest.fixture(scope="module")
def zone() -> SignedZone:
    return SignedZone.create("example.test.")


@pytest.fixture(scope="module")
def parent() -> SignedZone:
    return SignedZone.create("test.")


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
        assert DNSSECValidator().prove_nodata(EXAMPLE, dns.rdatatype.MX, authority, zone.keyring()) is True

    def test_an_unsigned_nsec_proves_nothing(self, zone: SignedZone) -> None:
        nsec = rrset_of("example.test.", "NSEC", "next.test. A RRSIG NSEC")
        assert DNSSECValidator().prove_nodata(EXAMPLE, dns.rdatatype.MX, [nsec], zone.keyring()) is False

    def test_signed_nsec_proves_nxdomain(self, zone: SignedZone) -> None:
        covering = rrset_of("a.example.test.", "NSEC", "c.example.test. A RRSIG NSEC")
        wildcard = rrset_of("!.example.test.", "NSEC", "+.example.test. A RRSIG NSEC")
        authority = [covering, zone.sign(covering), wildcard, zone.sign(wildcard)]
        target = dns.name.from_text("b.example.test.")
        assert DNSSECValidator().prove_nxdomain(target, authority, zone.keyring()) is True

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

        def send(qname, rdtype, nameservers, ctx):
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

        def send(qname, rdtype, nameservers, ctx):
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

        def send(qname, rdtype, nameservers, ctx):
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
        assert DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, self._covering_nsec(zone), zone.keyring())

    def test_a_wildcard_answer_with_no_proof_at_all_is_refused(self) -> None:
        zone, _, wild_sig = self._zone_with_wildcard()
        qname = dns.name.from_text("anything.example.test.")
        assert not DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, [], zone.keyring())

    def test_an_unsigned_proof_proves_nothing(self) -> None:
        zone, _, wild_sig = self._zone_with_wildcard()
        nsec = rrset_of("example.test.", "NSEC", "z.example.test. A RRSIG NSEC")
        qname = dns.name.from_text("anything.example.test.")
        assert not DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, [nsec], zone.keyring())

    def test_a_proof_that_does_not_cover_the_name_is_refused(self) -> None:
        """An NSEC from a different part of the zone must not satisfy the check."""
        zone, _, wild_sig = self._zone_with_wildcard()
        nsec = rrset_of("aa.example.test.", "NSEC", "ab.example.test. A RRSIG NSEC")
        qname = dns.name.from_text("zz.example.test.")
        assert not DNSSECValidator().prove_wildcard(qname, wild_sig[0].labels, [nsec, zone.sign(nsec)], zone.keyring())

    @staticmethod
    def _wildcard_chain(*, proof: bool):
        """A signed zone answering `victim.test.` from its `*.test.` wildcard.

        With ``proof=False`` this is the attack: the wildcard's data and
        signature are presented under a name that really has its own, different
        record, and no denial proof accompanies them. On the wire the RRSIG
        owner must match the RRset it covers, so the owner is rewritten too; the
        rdata (labels=2) is untouched, and that is what still verifies.
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
        if proof:
            # Covers `victim.test.`, so no closer match could have existed.
            nsec = rrset_of("test.", "NSEC", "z.test. A RRSIG NSEC")
            answer_response.authority.append(nsec)
            answer_response.authority.append(leaf.sign(nsec))

        table = {
            (dns.name.root, dns.rdatatype.DNSKEY): dnskey_response(root),
            (leaf.name, dns.rdatatype.DNSKEY): dnskey_response(leaf),
        }
        state = {"step": 0}

        def send(qname, rdtype, nameservers, ctx):
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

        def send(qname, rdtype, nameservers, ctx):
            if (qname, rdtype) in table:
                return table[(qname, rdtype)], "9.9.9.9"
            state["step"] += 1
            if state["step"] == 1:
                return delegation, "198.41.0.4"
            return negative_response(leaf), "9.9.9.9"

        resolver = RecursiveResolver(max_resolution_time=5, trust_anchors=(root.anchor_text(),))
        return resolver, send

    @staticmethod
    def _nxdomain(leaf: SignedZone, *, proof: bool):
        response = make_response(
            authority=[("test.", 300, "SOA", ["ns.test. a.test. 1 3600 900 604800 300"])],
            rcode=dns.rcode.NXDOMAIN,
        )
        response.authority.append(leaf.sign(response.authority[0]))
        if proof:
            # One NSEC from the apex covers both the missing name and the
            # wildcard that could otherwise have synthesised it.
            nsec = rrset_of("test.", "NSEC", "z.test. A RRSIG NSEC")
            response.authority.append(nsec)
            response.authority.append(leaf.sign(nsec))
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

        def send(qname, rdtype, nameservers, ctx):
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
