"""The resolver's DNSSEC chain-of-trust plumbing.

Each branch here decides whether data is trusted, so each is driven explicitly.
"""

from __future__ import annotations

from unittest.mock import patch

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import pytest
from conftest import make_response

from recursive_resolver import DNSSECValidationError, RecursiveResolver, ValidationState
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


class TestZoneKeyFetch:
    def test_no_response_is_a_resolution_failure(self) -> None:
        """Not BOGUS: see TestIndeterminateVsBogus for the reasoning."""
        from recursive_resolver import ResolutionTimeoutError

        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_response_without_a_dnskey_is_bogus(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_send_query", return_value=(make_response(), "9.9.9.9")):
            keys = resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert keys.state is ValidationState.BOGUS

    def test_no_ds_for_a_non_root_zone_is_bogus(self) -> None:
        """Without a DS there is nothing to anchor the zone's keys to."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        response = make_response(answer=[("example.com.", 300, "DNSKEY", ["257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"])])
        with patch.object(resolver, "_send_query", return_value=(response, "9.9.9.9")):
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
        from recursive_resolver import ResolutionTimeoutError

        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(ResolutionTimeoutError),
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

    def test_multi_label_descent_walks_one_label_at_a_time(self) -> None:
        """uk. -> co.uk. -> bbc.co.uk. when one server serves several zones."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        visited: list[str] = []

        def send(zone, rdtype, nameservers, ctx_):
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
                make_response(), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
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
            resolver._advance_dnssec(make_response(), DEEP, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx)

    def test_child_equal_to_the_aligned_parent_is_already_proven(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_authority_signer", return_value=EXAMPLE),
            patch.object(resolver, "_descend_chain", return_value=(EXAMPLE, SENTINEL_DS, ValidationState.SECURE)),
        ):
            state, ds = resolver._advance_dnssec(
                make_response(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
            )
        assert (state, ds) == (ValidationState.SECURE, SENTINEL_DS)

    def test_unusable_parent_keys_raise(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM, ValidationState.BOGUS)),
            pytest.raises(DNSSECValidationError, match="cannot establish DNSKEY"),
        ):
            resolver._advance_dnssec(make_response(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx)

    def test_bogus_ds_raises(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver._validator, "validate_ds", return_value=(ValidationState.BOGUS, None)),
            pytest.raises(DNSSECValidationError, match="neither signed nor provably unsigned"),
        ):
            resolver._advance_dnssec(make_response(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx)

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
        state = resolver._validate_answer(
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
            state = resolver._validate_answer(
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
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(EXAMPLE)),
            patch.object(resolver._validator, prover, return_value=True),
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

    def test_unfetchable_dnskey_is_a_timeout_not_bogus(self) -> None:
        from recursive_resolver import ResolutionTimeoutError

        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_unfetchable_ds_is_a_timeout_not_bogus(self) -> None:
        from recursive_resolver import ResolutionTimeoutError

        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with (
            patch.object(resolver, "_get_zone_keys", return_value=_keys(COM)),
            patch.object(resolver, "_send_query", return_value=(None, "")),
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver._descend_chain(EXAMPLE, COM, SENTINEL_DS, ["9.9.9.9"], ctx)

    def test_a_retrievable_but_invalid_dnskey_is_still_bogus(self) -> None:
        """The distinction is retrieval failure versus verification failure."""
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        response = make_response(answer=[("example.com.", 300, "DNSKEY", ["257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"])])
        with patch.object(resolver, "_send_query", return_value=(response, "9.9.9.9")):
            keys = resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert keys.state is ValidationState.BOGUS

    def test_a_missing_dnskey_rrset_is_still_bogus(self) -> None:
        resolver = _dnssec_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_send_query", return_value=(make_response(), "9.9.9.9")):
            keys = resolver._get_zone_keys(EXAMPLE, SENTINEL_DS, ["9.9.9.9"], ctx)
        assert keys.state is ValidationState.BOGUS


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
                make_response(), EXAMPLE, COM, ["9.9.9.9"], ValidationState.SECURE, None, ctx
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
