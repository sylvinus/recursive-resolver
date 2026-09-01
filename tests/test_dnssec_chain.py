"""The resolver's DNSSEC chain-of-trust plumbing.

Each branch here decides whether data is trusted, so each is driven explicitly.
"""

from __future__ import annotations

from unittest.mock import patch

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import pytest
from conftest import make_response

from recursive_resolver import (
    DNSSECInsecureError,
    DNSSECMaterialUnavailableError,
    DNSSECValidationError,
    RecursiveResolver,
    ValidationState,
)
from recursive_resolver.dnssec import ZoneKeys

ROOT = dns.name.root
COM = dns.name.from_text("com.")
EXAMPLE = dns.name.from_text("example.com.")
DEEP = dns.name.from_text("a.b.example.com.")


def _ds_rdataset() -> dns.rdataset.Rdataset:
    """A syntactically valid DS rdataset that matches no real key."""
    rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
    rdataset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 2 " + "ab" * 32), ttl=300)
    return rdataset


SENTINEL_DS = _ds_rdataset()


def _dnssec_resolver(**kwargs) -> RecursiveResolver:
    kwargs.setdefault("cache_enabled", False)
    return RecursiveResolver(dnssec=True, **kwargs)


def _keys(zone: dns.name.Name, state: ValidationState = ValidationState.SECURE) -> ZoneKeys:
    rrset = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    rrset.ttl = 300
    return ZoneKeys(zone, rrset if state is ValidationState.SECURE else None, state)


def _signed_dnskey_response() -> dns.message.Message:
    """A DNSKEY answer carrying an RRSIG, so it is material worth judging.

    The signature is nonsense, which is the point for the callers below: what
    is being exercised is what happens *after* retrieval succeeds.
    """
    return make_response(
        answer=[
            ("example.com.", 300, "DNSKEY", ["257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"]),
            ("example.com.", 300, "RRSIG", ["DNSKEY 8 2 300 20990101000000 20200101000000 1 example.com. AAAA"]),
        ]
    )


class TestZoneKeyFetch:
    def test_no_response_is_a_resolution_failure(self) -> None:
        """Not BOGUS: see TestIndeterminateVsBogus for the reasoning."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_every_server_answering_emptily_is_a_resolution_failure(self) -> None:
        """A server answering emptily is a fact about the server, not the zone.

        Every one of them must be asked before anything is concluded, and what
        is concluded is "could not retrieve", not "forged".
        """
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        asked: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx_):
            asked.append(server)
            return make_response(aa=False)

        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9", "1.1.1.1"], ctx)
        assert set(asked) == {"9.9.9.9", "1.1.1.1"}

    def test_a_lame_server_does_not_stop_the_sweep(self) -> None:
        """The zone's real DNSKEY is one sibling away; it must be found."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()

        def query_once(qname, rdtype, server, payload, timeout, ctx_):
            return make_response(aa=False) if server == "9.9.9.9" else _signed_dnskey_response()

        with (
            patch.object(resolver, "_order_servers", side_effect=lambda s: list(s)),
            patch.object(resolver, "_query_once", side_effect=query_once),
            patch.object(resolver._validator, "validate_dnskey", return_value=ValidationState.SECURE),
        ):
            keys = resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9", "1.1.1.1"], ctx)
        assert keys.state is ValidationState.SECURE

    def test_no_ds_for_a_non_root_zone_is_bogus(self) -> None:
        """Without a DS there is nothing to anchor the zone's keys to."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_send_query", return_value=(_signed_dnskey_response(), "9.9.9.9")):
            keys = resolver._get_zone_keys(EXAMPLE, None, ["9.9.9.9"], ctx)
        assert keys.state is ValidationState.BOGUS

    def test_cached_keys_short_circuit_the_query(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        resolver._store_keys(_keys(EXAMPLE), 3600)
        with patch.object(resolver, "_send_query") as send:
            keys = resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)
        send.assert_not_called()
        assert keys.state is ValidationState.SECURE


class TestDescendChain:
    def test_no_descent_needed(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        zone, ds, state = resolver._descend_chain(COM, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert (zone, ds, state) == (COM, SENTINEL_DS, ValidationState.SECURE)

    def test_target_outside_the_current_zone_is_a_no_op(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        other = dns.name.from_text("example.org.")
        zone, _ds, state = resolver._descend_chain(other, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert zone == COM and state is ValidationState.SECURE

    def test_unusable_parent_keys_abort(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_get_zone_keys", return_value=_keys(COM, ValidationState.BOGUS)):
            _zone, ds, state = resolver._descend_chain(EXAMPLE, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert state is ValidationState.BOGUS and ds is None

    def test_unfetchable_ds_is_a_resolution_failure(self) -> None:
        """Not BOGUS: see TestIndeterminateVsBogus for the reasoning."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._descend_chain(EXAMPLE, COM, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_insecure_intermediate_stops_the_descent(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(make_response(), "9.9.9.9")),
            patch.object(resolver._validator, "validate_ds", return_value=(ValidationState.INSECURE, None)),
        ):
            zone, ds, state = resolver._descend_chain(EXAMPLE, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert (zone, ds, state) == (EXAMPLE, None, ValidationState.INSECURE)

    def test_a_label_that_is_not_a_cut_is_skipped(self) -> None:
        """`_dmarc.example.com` and `3.200.in-addr.arpa` are not delegations.

        The parent denies the DS with a proof that matches no delegation, and
        the walk has to carry on with the same zone rather than call the chain
        broken.
        """
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        middle = dns.name.from_text("b.example.com.")
        asked: list[str] = []

        def validate_ds(zone, records, keyring, budget=None):
            asked.append(str(zone))
            if zone == middle:
                return ValidationState.BOGUS, None
            return ValidationState.SECURE, SENTINEL_DS

        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(make_response(), "9.9.9.9")),
            patch.object(resolver._validator, "validate_ds", side_effect=validate_ds),
            patch.object(
                resolver._validator, "prove_no_delegation", side_effect=lambda n, r, k, budget=None: n == middle
            ),
        ):
            zone, _ds, state = resolver._descend_chain(DEEP, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert (zone, state) == (DEEP, ValidationState.SECURE)
        assert asked == ["example.com.", "b.example.com.", "a.b.example.com."]

    def test_a_broken_intermediate_that_is_a_cut_still_stops_the_descent(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(make_response(), "9.9.9.9")),
            patch.object(resolver._validator, "validate_ds", return_value=(ValidationState.BOGUS, None)),
            patch.object(resolver._validator, "prove_no_delegation", return_value=False),
        ):
            zone, ds, state = resolver._descend_chain(DEEP, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert (zone, ds, state) == (EXAMPLE, None, ValidationState.BOGUS)

    def test_multi_label_descent_walks_one_label_at_a_time(self) -> None:
        """uk. -> co.uk. -> bbc.co.uk. when one server serves several zones."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        visited: list[str] = []

        def send(zone, rdtype, nameservers, ctx_, usable=None):
            visited.append(str(zone))
            return make_response(), "9.9.9.9"

        with (
            patch.object(resolver, "_get_zone_keys", side_effect=lambda z, d, n, c: _keys(z)),
            patch.object(resolver, "_send_query", side_effect=send),
            patch.object(resolver._validator, "validate_ds", return_value=(ValidationState.SECURE, SENTINEL_DS)),
        ):
            zone, _ds, state = resolver._descend_chain(DEEP, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert zone == DEEP and state is ValidationState.SECURE
        assert visited == ["example.com.", "b.example.com.", "a.b.example.com."]


def _referral_with_a_denial(child: dns.name.Name = EXAMPLE) -> dns.message.Message:
    """A referral of the shape a signed parent sends: NS plus an NSEC3.

    ``_advance_dnssec`` walks the delegations when the referral carries
    neither, so tests aimed at anything else start from this one. The NS is
    owned by ``child`` because a referral to a cut above the queried name is
    not an answer about it.
    """
    return make_response(
        authority=[
            (str(child), 300, "NS", ["ns.child.example."]),
            ("0" * 32 + ".com.", 300, "NSEC3", ["1 1 0 - " + "V" * 32 + " NS"]),
        ],
        aa=False,
    )


def _bare_referral() -> dns.message.Message:
    """A delegation with no DS and no denial of one: says nothing about DNSSEC."""
    return make_response(authority=[("example.com.", 300, "NS", ["ns.child.example."])], aa=False)


class TestAdvanceDNSSEC:
    def test_insecure_parent_stays_insecure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        state, ds = resolver._advance_dnssec(
            make_response(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.INSECURE, None, ctx
        )
        assert (state, ds) == (ValidationState.INSECURE, None)

    def test_alignment_to_an_insecure_zone(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_authority_signer", return_value=EXAMPLE),
            patch.object(resolver, "_descend_chain", return_value=(EXAMPLE, None, ValidationState.INSECURE)),
        ):
            state, ds = resolver._advance_dnssec(
                _referral_with_a_denial(DEEP), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )
        assert (state, ds) == (ValidationState.INSECURE, None)

    def test_alignment_to_a_bogus_zone_raises(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_authority_signer", return_value=EXAMPLE),
            patch.object(resolver, "_descend_chain", return_value=(EXAMPLE, None, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="broken chain"),
        ):
            resolver._advance_dnssec(
                _referral_with_a_denial(DEEP), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )

    def test_child_equal_to_the_aligned_parent_is_already_proven(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_authority_signer", return_value=EXAMPLE),
            patch.object(resolver, "_descend_chain", return_value=(EXAMPLE, SENTINEL_DS, ValidationState.SECURE)),
        ):
            state, ds = resolver._advance_dnssec(
                _referral_with_a_denial(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )
        assert (state, ds) == (ValidationState.SECURE, SENTINEL_DS)

    def test_unusable_parent_keys_raise(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="cannot establish DNSKEY"),
        ):
            resolver._advance_dnssec(
                _referral_with_a_denial(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )

    def test_bogus_ds_raises(self) -> None:
        """The proof was there and did not hold up: that is a real BOGUS."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver._validator, "validate_ds", return_value=(ValidationState.BOGUS, None)),
            pytest.raises(DNSSECValidationError, match="neither signed nor provably unsigned"),
        ):
            resolver._advance_dnssec(
                _referral_with_a_denial(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )

    def test_a_referral_without_a_denial_walks_the_delegations(self) -> None:
        """Some servers in a signed parent's NS set send a bare delegation.

        There is no proof to judge and no signature to align on, so the cuts
        between parent and child are walked instead, and what that walk finds
        is what settles the delegation.
        """
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_descend_chain", return_value=(EXAMPLE, None, ValidationState.INSECURE)) as descend,
            patch.object(resolver, "_get_zone_keys") as keys,
            patch.object(resolver._validator, "validate_ds") as validate,
        ):
            state, ds = resolver._advance_dnssec(
                _bare_referral(), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, SENTINEL_DS, ctx
            )
        assert (state, ds) == (ValidationState.INSECURE, None)
        assert descend.call_args.args[:3] == (DEEP, COM, SENTINEL_DS)
        # Nothing was judged against the parent's keys: there was no proof.
        keys.assert_not_called()
        validate.assert_not_called()

    def test_a_bare_referral_whose_walk_reaches_the_child_is_secure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_descend_chain", return_value=(DEEP, SENTINEL_DS, ValidationState.SECURE)):
            state, ds = resolver._advance_dnssec(
                _bare_referral(), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )
        assert (state, ds) == (ValidationState.SECURE, SENTINEL_DS)

    def test_a_bare_referral_whose_walk_goes_bogus_raises(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_descend_chain", return_value=(EXAMPLE, None, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="neither signed nor provably unsigned"),
        ):
            resolver._advance_dnssec(_bare_referral(), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx)

    def test_a_referral_without_a_denial_and_no_ds_anywhere_is_unavailable(self) -> None:
        """The walk asks each NS set in turn; none of them answered."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(None, None)),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._advance_dnssec(_bare_referral(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx)

    def test_authority_signer_extraction(self) -> None:
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "NSEC3PARAM", ["1 0 10 AABBCCDD"]),
                ("example.com.", 300, "RRSIG", ["DS 8 2 300 20990101000000 20200101000000 1 com. AAAA"]),
            ],
            aa=False,
        )
        assert resolver._authority_signer(response) == COM

    def test_authority_signer_absent(self) -> None:
        assert _dnssec_resolver()._authority_signer(make_response()) is None

    def test_authority_signer_ignores_unrelated_rrsigs(self) -> None:
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[("example.com.", 300, "RRSIG", ["A 8 2 300 20990101000000 20200101000000 1 com. AAAA"])],
            aa=False,
        )
        assert resolver._authority_signer(response) is None


class TestAnswerValidation:
    @staticmethod
    def _answer_with_sig() -> tuple[dns.rrset.RRset, object]:
        response = make_response(
            answer=[
                ("example.com.", 300, "A", ["1.2.3.4"]),
                ("example.com.", 300, "RRSIG", ["A 8 2 300 20990101000000 20200101000000 1 example.com. AAAA"]),
            ]
        )
        rrset = response.answer[0]
        return rrset, response

    def test_insecure_chain_skips_validation(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        rrset, response = self._answer_with_sig()
        state, _ttl = resolver._validate_answer(
            response, rrset, EXAMPLE, dns.rdatatype.A, ctx, EXAMPLE, ["9.9.9.9"], ValidationState.INSECURE, None
        )
        assert state is ValidationState.INSECURE

    def test_missing_rrsig_in_a_signed_zone_is_bogus(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
        with pytest.raises(DNSSECValidationError, match="carries no RRSIG"):
            resolver._validate_answer(
                response,
                response.answer[0],
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
            )

    def test_alignment_to_insecure_returns_insecure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        rrset, response = self._answer_with_sig()
        with patch.object(resolver, "_align_zone", return_value=(EXAMPLE, None, ValidationState.INSECURE)):
            state, _ttl = resolver._validate_answer(
                response, rrset, EXAMPLE, dns.rdatatype.A, ctx, COM, ["9.9.9.9"], ValidationState.SECURE, None
            )
        assert state is ValidationState.INSECURE

    def test_alignment_to_bogus_raises(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        rrset, response = self._answer_with_sig()
        with (
            patch.object(resolver, "_align_zone", return_value=(EXAMPLE, None, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="broken chain"),
        ):
            resolver._validate_answer(
                response, rrset, EXAMPLE, dns.rdatatype.A, ctx, COM, ["9.9.9.9"], ValidationState.SECURE, None
            )

    def test_unusable_keys_raise(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        rrset, response = self._answer_with_sig()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="no valid DNSKEY"),
        ):
            resolver._validate_answer(
                response,
                rrset,
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
            )


class TestDenialValidation:
    def test_insecure_chain_skips_the_proof(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        resolver._verify_denial(
            make_response(),
            EXAMPLE,
            dns.rdatatype.A,
            ctx,
            EXAMPLE,
            ["9.9.9.9"],
            ValidationState.INSECURE,
            None,
            negative="nxdomain",
        )

    def test_alignment_to_insecure_skips_the_proof(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_align_zone", return_value=(EXAMPLE, None, ValidationState.INSECURE)):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                COM,
                ["9.9.9.9"],
                ValidationState.SECURE,
                None,
                negative="nxdomain",
            )

    def test_alignment_to_bogus_raises(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_align_zone", return_value=(EXAMPLE, None, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="broken chain"),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                COM,
                ["9.9.9.9"],
                ValidationState.SECURE,
                None,
                negative="nxdomain",
            )

    @pytest.mark.parametrize("negative", ["nxdomain", "nodata"])
    def test_unproven_denial_is_bogus(self, negative: str) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            pytest.raises(DNSSECValidationError, match=f"unproven {negative}"),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative=negative,
            )

    def test_unusable_keys_raise(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="no valid DNSKEY"),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nodata",
            )

    @pytest.mark.parametrize("negative", ["nxdomain", "nodata"])
    def test_a_valid_proof_is_accepted(self, negative: str) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        prover = "prove_nxdomain" if negative == "nxdomain" else "prove_nodata"
        proven = ValidationState.SECURE if negative == "nxdomain" else True
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, prover, return_value=proven),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative=negative,
            )


class TestIndeterminateVsBogus:
    """Being unable to fetch validation material is not evidence of tampering.

    Reporting an unreachable nameserver as BOGUS would make every transient
    network fault look like an attack, and would make DNSSEC verdicts
    non-deterministic under load, which is exactly what a differential run
    against live DNS exposed.
    """

    def test_unfetchable_dnskey_is_not_bogus(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_unfetchable_ds_is_not_bogus(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._descend_chain(EXAMPLE, COM, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_the_unavailable_error_is_not_a_dnssec_verdict(self) -> None:
        """Consumers branch on DNSSECError to mean "refuse to use this data"."""
        from recursive_resolver import DNSSECError, ResolverError

        assert issubclass(DNSSECMaterialUnavailableError, ResolverError)
        assert not issubclass(DNSSECMaterialUnavailableError, DNSSECError)

    def test_a_retrievable_but_invalid_dnskey_is_still_bogus(self) -> None:
        """The distinction is retrieval failure versus verification failure.

        Here the signed DNSKEY RRset arrives in full and simply does not match
        the DS, which is the one thing BOGUS is for.
        """
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_send_query", return_value=(_signed_dnskey_response(), "9.9.9.9")):
            keys = resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert keys.state is ValidationState.BOGUS

    def test_a_dnskey_arriving_without_its_rrsig_is_not_bogus(self) -> None:
        """An OPT-stripping middlebox produces exactly this; the zone is fine."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        unsigned = make_response(answer=[("example.com.", 300, "DNSKEY", ["257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"])])
        with (
            patch.object(resolver, "_query_once", return_value=unsigned),
            pytest.raises(DNSSECMaterialUnavailableError),
        ):
            resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)


class TestUnverifiableZoneKeysPropagateAsInsecure:
    """A zone whose keys we cannot verify is unsigned, not forged.

    RFC 4035 §5.2. Every place that consults a zone's keys has to carry the
    distinction, otherwise a legitimately signed domain using an algorithm this
    build lacks would be rejected outright rather than merely unauthenticated.
    """

    def test_the_descent_stops_and_reports_insecure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_get_zone_keys", return_value=_keys(COM, ValidationState.INSECURE)):
            zone, ds, state = resolver._descend_chain(EXAMPLE, COM, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert state is ValidationState.INSECURE
        assert ds is None
        assert zone == COM

    def test_a_ds_lookup_under_unverifiable_parent_keys_is_insecure(self) -> None:
        """Contrast with test_unusable_parent_keys_raise, which is BOGUS."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM, ValidationState.INSECURE)),
            patch.object(resolver, "_descend_chain", return_value=(COM, SENTINEL_DS, ValidationState.SECURE)),
        ):
            state, ds = resolver._advance_dnssec(
                _referral_with_a_denial(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )
        assert state is ValidationState.INSECURE
        assert ds is None


class TestUnsupportedSigningAlgorithm:
    """A DS that matches a key whose algorithm we cannot verify.

    The digest computes and matches, so nothing looks wrong, but we still have
    no way to check a single signature the zone makes.
    """

    def test_a_matched_key_with_an_unverifiable_algorithm_is_insecure(self) -> None:
        from recursive_resolver.dnssec import DNSSECValidator, algorithm_supported

        # Algorithm 12 (ECCGOST) is withdrawn and unimplemented here, but its
        # DS digest is still computable, so the DS genuinely matches.
        assert algorithm_supported(12) is False
        zone = dns.name.from_text("gost.test.")
        keys = dns.rrset.RRset(zone, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 12 " + "A" * 64)
        keys.add(key)
        keys.ttl = 300

        ds_rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds_rdataset.add(dns.dnssec.make_ds(zone, key, "SHA256"), ttl=300)

        assert DNSSECValidator().validate_dnskey(zone, keys, None, ds_rdataset) is ValidationState.INSECURE


class TestMaterialPredicates:
    """What counts as an answer to "give me this zone's validation material".

    These decide whether the sweep moves on to the next nameserver, so each
    rejection reason is driven explicitly: a predicate that quietly accepts a
    useless response puts the old false-BOGUS behaviour straight back.
    """

    def test_an_error_rcode_is_not_a_dnskey_answer(self) -> None:
        resolver = _dnssec_resolver()
        assert not resolver._usable_dnskey(EXAMPLE)(make_response(rcode=dns.rcode.SERVFAIL, aa=False))

    def test_an_authoritative_answer_without_the_dnskey_is_not_one_either(self) -> None:
        resolver = _dnssec_resolver()
        assert not resolver._usable_dnskey(EXAMPLE)(make_response())

    def test_a_signed_dnskey_answer_is_accepted(self) -> None:
        resolver = _dnssec_resolver()
        assert resolver._usable_dnskey(EXAMPLE)(_signed_dnskey_response())

    def test_an_error_rcode_is_not_a_ds_answer(self) -> None:
        resolver = _dnssec_resolver()
        assert not resolver._usable_ds(EXAMPLE)(make_response(rcode=dns.rcode.REFUSED, aa=False))

    def test_a_referral_carrying_the_ds_is_accepted_without_aa(self) -> None:
        """A parent may answer a DS query with a referral; the DS is signed either way."""
        resolver = _dnssec_resolver()
        response = make_response(aa=False)
        response.authority.append(_ds_rrset_at(EXAMPLE))
        assert resolver._usable_ds(EXAMPLE)(response)

    def test_a_bare_nodata_from_a_non_authoritative_server_is_refused(self) -> None:
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 2 3 4 5"])], aa=False
        )
        assert not resolver._usable_ds(EXAMPLE)(response)

    def test_an_authoritative_soa_without_a_denial_is_refused(self) -> None:
        """The DS is only ever asked of a signed parent, which signs its denials.

        A server sending the SOA alone cannot settle the delegation, so the
        sweep has to move on rather than hand the validator half a proof.
        """
        resolver = _dnssec_resolver()
        response = make_response(authority=[("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 2 3 4 5"])])
        assert not resolver._usable_ds(EXAMPLE)(response)

    def test_an_authoritative_soa_with_an_nsec_denial_is_accepted(self) -> None:
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 2 3 4 5"]),
                ("example.com.", 300, "NSEC", ["a.example.com. NS SOA RRSIG NSEC DNSKEY"]),
            ]
        )
        assert resolver._usable_ds(EXAMPLE)(response)

    def test_an_authoritative_soa_with_an_nsec3_denial_is_accepted(self) -> None:
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 2 3 4 5"]),
                ("0" * 32 + ".example.com.", 300, "NSEC3", ["1 1 0 - " + "V" * 32 + " NS"]),
            ]
        )
        assert resolver._usable_ds(EXAMPLE)(response)

    def test_a_referral_to_a_cut_above_the_queried_name_is_refused(self) -> None:
        """ "Ask further down" is not an answer, however well signed it is.

        The NSEC belongs to the higher cut and denies nothing about the name
        that was asked for, so the sweep has to reach a server authoritative
        for the right zone instead of judging the delegation on this.
        """
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "NS", ["ns.example.com."]),
                ("example.com.", 300, "NSEC", ["a.example.com. NS RRSIG NSEC"]),
            ],
            aa=False,
        )
        assert not resolver._usable_ds(DEEP)(response)
        # The same records do settle the cut they actually belong to.
        assert resolver._usable_ds(EXAMPLE)(response)

    def test_a_referral_carrying_the_denial_is_accepted_without_aa(self) -> None:
        """The standard "no DS" answer from several ccTLDs: a referral plus NSEC3.

        AA is clear because the parent is handing the query on, but the NSEC3
        is signed by the parent and re-checked by the validator either way.
        """
        resolver = _dnssec_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "NS", ["ns.child.example."]),
                ("0" * 32 + ".example.com.", 300, "NSEC3", ["1 1 0 - " + "V" * 32 + " NS"]),
            ],
            aa=False,
        )
        assert resolver._usable_ds(EXAMPLE)(response)


def _ds_rrset_at(name: dns.name.Name) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DS)
    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 2 " + "ab" * 32))
    rrset.ttl = 300
    return rrset


class TestDenialUnderUnverifiableKeys:
    def test_insecure_zone_keys_skip_the_denial_proof(self) -> None:
        """A zone we cannot verify is unsigned, so there is no proof to demand.

        The signer is present, so the delegation walk does not apply and the
        keys themselves are what settles it.
        """
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_authority_signer", return_value=EXAMPLE),
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE, ValidationState.INSECURE)),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nxdomain",
            )


class TestRequireDNSSECCoversDenials:
    """`require_dnssec` must hold "no such name" to the standard of an answer.

    A negative answer leaves through an exception rather than an `Answer`, so
    the check on the returned value never sees it. Being told a name has no CAA
    or no MX record, on unauthenticated evidence, is exactly what the strict
    mode exists to refuse.
    """

    def test_an_unproven_denial_is_refused_when_dnssec_is_required(self) -> None:
        resolver = _dnssec_resolver(require_dnssec=True)
        with pytest.raises(DNSSECInsecureError):
            resolver._require_proven_denial(ValidationState.INSECURE, EXAMPLE, "A")

    def test_a_proven_denial_passes(self) -> None:
        resolver = _dnssec_resolver(require_dnssec=True)
        resolver._require_proven_denial(ValidationState.SECURE, EXAMPLE, "A")

    def test_without_the_flag_an_unproven_denial_is_allowed(self) -> None:
        resolver = _dnssec_resolver()
        resolver._require_proven_denial(ValidationState.INSECURE, EXAMPLE, "A")

    def test_a_denial_in_an_insecure_zone_reports_insecure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        state, _ttl = resolver._verify_denial(
            make_response(),
            EXAMPLE,
            dns.rdatatype.A,
            ctx,
            COM,
            ["9.9.9.9"],
            ValidationState.INSECURE,
            None,
            negative="nxdomain",
        )
        assert state is ValidationState.INSECURE

    def test_an_opt_out_nxdomain_is_returned_but_not_authenticated(self) -> None:
        """The whole point of the tri-state reaching the caller."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "prove_nxdomain", return_value=ValidationState.INSECURE),
        ):
            state, _ttl = resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nxdomain",
            )
        assert state is ValidationState.INSECURE


class TestUnverifiableNSEC3ParametersDowngrade:
    """A denial or wildcard proof we cannot compute is unauthenticated, not forged."""

    def test_a_denial_with_parameters_beyond_the_cap_is_insecure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "nsec3_beyond_our_limits", return_value=True),
            patch.object(resolver._validator, "prove_nxdomain") as prove,
        ):
            state, _ttl = resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nxdomain",
            )
        assert state is ValidationState.INSECURE
        prove.assert_not_called()

    def test_a_wildcard_answer_we_cannot_prove_is_insecure(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        rrset = dns.rrset.from_text("a.b.example.com.", 300, "IN", "A", "1.2.3.4")
        response = make_response()
        response.answer = [
            rrset,
            dns.rrset.from_text(
                "a.b.example.com.",
                300,
                "IN",
                "RRSIG",
                "A 8 2 300 20990101000000 20200101000000 1 example.com. AAAA",
            ),
        ]
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "validated_rrsig", return_value=response.answer[1][0]),
            patch.object(resolver._validator, "prove_wildcard", return_value=ValidationState.BOGUS),
            patch.object(resolver._validator, "nsec3_beyond_our_limits", return_value=True),
        ):
            state, _ttl = resolver._validate_answer(
                response,
                rrset,
                rrset.name,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
            )
        assert state is ValidationState.INSECURE


class TestADenialThatDoesNotProveIsRetriedElsewhere:
    """RFC 4035 §5.5: try another server before concluding an answer is forged.

    One server out of sync with the rest of its NS set - serving an NSEC3
    chain from before the last re-signing, say - would otherwise make the zone
    intermittently unresolvable on the say-so of the one machine that is wrong.
    Found in the wild on a signed TLD whose seven nameservers included one
    stale one.
    """

    def _resolver_with_keys(self):
        resolver = _dnssec_resolver()
        return resolver, resolver._new_context()

    def test_a_failed_proof_sweeps_to_another_server(self) -> None:
        resolver, ctx = self._resolver_with_keys()
        proofs = iter([ValidationState.BOGUS, ValidationState.SECURE])
        asked: list[str] = []

        def prove(*args, **kwargs):
            return next(proofs, ValidationState.SECURE)

        def send(qname, rdtype, nameservers, ctx_, usable=None):
            asked.append("resent")
            return make_response(), "1.1.1.1"

        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "prove_nxdomain", side_effect=prove),
            patch.object(resolver, "_send_query", side_effect=send),
        ):
            state, _ttl = resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nxdomain",
            )
        assert state is ValidationState.SECURE
        assert asked == ["resent"], "the second server was never asked"

    def test_a_zone_where_no_server_can_prove_it_is_still_bogus(self) -> None:
        """Sweeping must not turn a broken zone into a pass."""
        resolver, ctx = self._resolver_with_keys()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "prove_nxdomain", return_value=ValidationState.BOGUS),
            patch.object(resolver, "_send_query", return_value=(None, None)),
            pytest.raises(DNSSECValidationError, match="unproven nxdomain"),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nxdomain",
            )

    def test_a_fresh_response_that_also_fails_is_bogus(self) -> None:
        resolver, ctx = self._resolver_with_keys()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "prove_nodata", return_value=ValidationState.BOGUS),
            patch.object(resolver, "_send_query", return_value=(make_response(), "1.1.1.1")),
            pytest.raises(DNSSECValidationError, match="unproven nodata"),
        ):
            resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nodata",
            )

    def test_the_sweep_predicate_rejects_an_error_rcode(self) -> None:
        resolver, ctx = self._resolver_with_keys()
        check = resolver._usable_denial(EXAMPLE, dns.rdatatype.A, {}, ctx, "nodata")
        assert check(make_response(rcode=dns.rcode.SERVFAIL, aa=False)) is False

    def test_the_sweep_predicate_accepts_a_denial_that_proves(self) -> None:
        resolver, ctx = self._resolver_with_keys()
        with patch.object(resolver._validator, "prove_nodata", return_value=ValidationState.SECURE):
            check = resolver._usable_denial(EXAMPLE, dns.rdatatype.A, {}, ctx, "nodata")
            assert check(make_response()) is True

    def test_the_sweep_predicate_rejects_a_non_authoritative_denial(self) -> None:
        """The sweep must not accept what `_classify_response` would have refused.

        A cache or a parent-side server can hand back a proof-shaped answer with
        AA clear; taking it here would let the sweep launder it into a verdict.
        """
        resolver, ctx = self._resolver_with_keys()
        assert resolver.require_authoritative
        with patch.object(resolver._validator, "prove_nodata", return_value=ValidationState.SECURE):
            check = resolver._usable_denial(EXAMPLE, dns.rdatatype.A, {}, ctx, "nodata")
            assert check(make_response(aa=False)) is False
            assert check(make_response()) is True

    def test_the_sweep_predicate_allows_it_when_authority_is_not_required(self) -> None:
        resolver, ctx = self._resolver_with_keys()
        resolver.require_authoritative = False
        with patch.object(resolver._validator, "prove_nodata", return_value=ValidationState.SECURE):
            check = resolver._usable_denial(EXAMPLE, dns.rdatatype.A, {}, ctx, "nodata")
            assert check(make_response(aa=False)) is True

    def test_an_opt_out_nxdomain_is_accepted_without_sweeping(self) -> None:
        """INSECURE is an outcome, not a failure, so it must not trigger a retry."""
        resolver, ctx = self._resolver_with_keys()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, "prove_nxdomain", return_value=ValidationState.INSECURE),
            patch.object(resolver, "_send_query", side_effect=AssertionError("should not resend")),
        ):
            state, _ttl = resolver._verify_denial(
                make_response(),
                EXAMPLE,
                dns.rdatatype.A,
                ctx,
                EXAMPLE,
                ["9.9.9.9"],
                ValidationState.SECURE,
                SENTINEL_DS,
                negative="nxdomain",
            )
        assert state is ValidationState.INSECURE
