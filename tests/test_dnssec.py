"""Unit tests for the DNSSEC validator (no network)."""

from __future__ import annotations

import base64
import time
from unittest.mock import patch

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import pytest
from dns.rdtypes.ANY.NSEC3 import b32_normal_to_hex

from recursive_resolver import ValidationState
from recursive_resolver.dnssec import (
    MAX_NSEC3_ITERATIONS,
    NSEC3_OPT_OUT,
    DNSSECValidator,
    _types_in_bitmap,
    cryptography_available,
    find_rrsig,
)
from recursive_resolver.roots import ROOT_TRUST_ANCHORS


def rrset(name: str, rdtype: str, *rdatas: str, ttl: int = 300) -> dns.rrset.RRset:
    rdt = dns.rdatatype.from_text(rdtype)
    out = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, rdt)
    for rd in rdatas:
        out.add(dns.rdata.from_text(dns.rdataclass.IN, rdt, rd))
    out.ttl = ttl
    return out


class TestTrustAnchors:
    def test_only_current_anchors_are_shipped(self) -> None:
        """KSK-2010 (tag 19036) was retired in 2019 and must not be trusted."""
        tags = {int(a.split()[0]) for a in ROOT_TRUST_ANCHORS}
        assert tags == {20326, 38696}

    def test_anchors_parse_as_ds_records(self) -> None:
        for anchor in ROOT_TRUST_ANCHORS:
            rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, anchor)
            assert rd.algorithm == 8
            assert rd.digest_type == 2

    def test_validator_loads_anchors(self) -> None:
        validator = DNSSECValidator()
        assert len(validator._root_ds) == 2

    def test_an_empty_anchor_set_is_rejected(self) -> None:
        """() is a caller error, not a synonym for "use the IANA defaults"."""
        with pytest.raises(ValueError, match="must not be empty"):
            DNSSECValidator(trust_anchors=())


class TestTypeBitmap:
    def test_decodes_nsec_bitmap(self) -> None:
        nsec = rrset("example.com.", "NSEC", "next.example.com. A MX RRSIG NSEC")
        types = _types_in_bitmap(nsec[0])
        assert dns.rdatatype.A in types
        assert dns.rdatatype.MX in types
        assert dns.rdatatype.NSEC in types
        assert dns.rdatatype.AAAA not in types

    def test_decodes_high_window_types(self) -> None:
        nsec = rrset("example.com.", "NSEC", "next.example.com. A TYPE300")
        types = _types_in_bitmap(nsec[0])
        assert 300 in types


class TestNSECCovering:
    def test_covers_name_between_owner_and_next(self) -> None:
        v = DNSSECValidator()
        owner = dns.name.from_text("a.example.com.")
        nxt = dns.name.from_text("c.example.com.")
        assert v._nsec_covers(owner, nxt, dns.name.from_text("b.example.com."))

    def test_does_not_cover_outside_the_interval(self) -> None:
        v = DNSSECValidator()
        owner = dns.name.from_text("a.example.com.")
        nxt = dns.name.from_text("c.example.com.")
        assert not v._nsec_covers(owner, nxt, dns.name.from_text("z.example.com."))

    def test_does_not_cover_the_owner_itself(self) -> None:
        v = DNSSECValidator()
        owner = dns.name.from_text("a.example.com.")
        nxt = dns.name.from_text("c.example.com.")
        assert not v._nsec_covers(owner, nxt, owner)

    def test_wraparound_at_the_end_of_the_zone(self) -> None:
        """The last NSEC wraps back to the apex."""
        v = DNSSECValidator()
        owner = dns.name.from_text("z.example.com.")
        nxt = dns.name.from_text("example.com.")
        assert v._nsec_covers(owner, nxt, dns.name.from_text("zz.example.com."))


class TestDenialOfExistence:
    def test_nodata_proven_by_matching_nsec(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "next.example.com. A RRSIG NSEC")
        # Bypass signature checking by stubbing the validated-NSEC extractor.
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.MX, [], {}) is ValidationState.SECURE

    def test_nodata_not_proven_when_the_type_is_present(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "next.example.com. A MX RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    def test_nodata_not_proven_when_a_cname_exists(self) -> None:
        """A CNAME at the name means the answer should have been a CNAME."""
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "next.example.com. CNAME RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    def test_no_ds_proven_by_nsec_without_the_ds_bit(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("child.example.com.", "NSEC", "next.example.com. NS RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert v.prove_no_ds(dns.name.from_text("child.example.com."), [], {})

    def test_no_ds_rejected_when_the_ds_bit_is_set(self) -> None:
        """A DS bit means the zone IS signed; claiming otherwise is a downgrade."""
        v = DNSSECValidator()
        nsec = rrset("child.example.com.", "NSEC", "next.example.com. NS DS RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert not v.prove_no_ds(dns.name.from_text("child.example.com."), [], {})

    def test_nxdomain_needs_a_wildcard_denial_too(self) -> None:
        """Covering the name alone is not enough; a wildcard could synthesise it."""
        v = DNSSECValidator()
        covering = rrset("a.example.com.", "NSEC", "c.example.com. A RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [covering] if rdtype == dns.rdatatype.NSEC else []
        )
        # b.example.com is covered, but *.example.com is not denied.
        assert v.prove_nxdomain(dns.name.from_text("b.example.com."), [], {}) is ValidationState.BOGUS

    def test_nxdomain_proven_with_both_denials(self) -> None:
        v = DNSSECValidator()
        covering = rrset("a.example.com.", "NSEC", "c.example.com. A RRSIG NSEC")
        wildcard = rrset("!.example.com.", "NSEC", "+.example.com. A RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [covering, wildcard] if rdtype == dns.rdatatype.NSEC else []
        )
        assert v.prove_nxdomain(dns.name.from_text("b.example.com."), [], {}) is ValidationState.SECURE

    def test_unsigned_authority_proves_nothing(self) -> None:
        v = DNSSECValidator()
        assert v.prove_nxdomain(dns.name.from_text("b.example.com."), [], {}) is ValidationState.BOGUS
        assert v.prove_nodata(dns.name.from_text("b.example.com."), dns.rdatatype.A, [], {}) is ValidationState.BOGUS
        assert not v.prove_no_ds(dns.name.from_text("b.example.com."), [], {})


class TestNSEC3:
    @staticmethod
    def _nsec3(zone: str, owner_hash: str, next_hash_b32: str, types: str, flags: int = 0, iterations: int = 10):
        return rrset(f"{owner_hash}.{zone}", "NSEC3", f"1 {flags} {iterations} AABBCCDD {next_hash_b32} {types}")

    def test_iteration_cap_rejects_absurd_values(self) -> None:
        v = DNSSECValidator()
        nsec3 = self._nsec3("example.com.", "AAAA", "ZZZZ", "NS", iterations=MAX_NSEC3_ITERATIONS + 1)
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec3] if rdtype == dns.rdatatype.NSEC3 else []
        )
        assert not v.prove_no_ds(dns.name.from_text("child.example.com."), [], {})

    def test_opt_out_flag_is_recognised(self) -> None:
        nsec3 = self._nsec3("example.com.", "AAAA", "ZZZZ", "NS", flags=NSEC3_OPT_OUT)
        assert nsec3[0].flags & NSEC3_OPT_OUT

    def test_next_hash_round_trips_through_base32hex(self) -> None:
        """The decoder must match dnspython's own presentation encoding."""
        nsec3 = self._nsec3("example.com.", "AAAA", "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S", "A RRSIG")
        params = nsec3[0]
        encoded = base64.b32encode(params.next).translate(b32_normal_to_hex).decode("ascii")
        assert encoded.lower() == params.to_text().split()[4].lower()


class TestFindRRSIG:
    def test_finds_the_covering_rrsig(self) -> None:
        sig = rrset(
            "example.com.",
            "RRSIG",
            "A 8 2 300 20990101000000 20200101000000 12345 example.com. AAAA",
        )
        assert find_rrsig([sig], dns.name.from_text("example.com."), dns.rdatatype.A) is sig

    def test_ignores_rrsigs_covering_other_types(self) -> None:
        sig = rrset(
            "example.com.",
            "RRSIG",
            "MX 8 2 300 20990101000000 20200101000000 12345 example.com. AAAA",
        )
        assert find_rrsig([sig], dns.name.from_text("example.com."), dns.rdatatype.A) is None

    def test_ignores_rrsigs_at_other_names(self) -> None:
        sig = rrset(
            "other.com.",
            "RRSIG",
            "A 8 2 300 20990101000000 20200101000000 12345 other.com. AAAA",
        )
        assert find_rrsig([sig], dns.name.from_text("example.com."), dns.rdatatype.A) is None


class TestValidatorBasics:
    def test_missing_rrsig_never_validates(self) -> None:
        v = DNSSECValidator()
        assert v.validate_rrset(rrset("example.com.", "A", "1.2.3.4"), None, {}) is False

    def test_garbage_signature_is_rejected(self) -> None:
        v = DNSSECValidator()
        data = rrset("example.com.", "A", "1.2.3.4")
        sig = rrset(
            "example.com.",
            "RRSIG",
            "A 8 2 300 20990101000000 20200101000000 12345 example.com. AAAA",
        )
        assert v.validate_rrset(data, sig, {dns.name.from_text("example.com."): data}) is False

    def test_validation_states(self) -> None:
        assert {s.value for s in ValidationState} == {"secure", "insecure", "bogus"}

    def test_cryptography_is_available_in_the_test_env(self) -> None:
        assert cryptography_available() is True


class TestDSValidation:
    def test_missing_ds_without_proof_is_bogus(self) -> None:
        v = DNSSECValidator()
        state, ds = v.validate_ds(dns.name.from_text("child.example.com."), [], {})
        assert state is ValidationState.BOGUS
        assert ds is None

    def test_unverifiable_ds_is_bogus(self) -> None:
        v = DNSSECValidator()
        ds = rrset("child.example.com.", "DS", "12345 8 2 " + "AB" * 32)
        state, out = v.validate_ds(dns.name.from_text("child.example.com."), [ds], {})
        assert state is ValidationState.BOGUS
        assert out is None


@pytest.mark.skipif(not cryptography_available(), reason="cryptography not installed")
class TestDNSKEYValidation:
    def test_dnskey_not_matching_any_ds_is_rejected(self) -> None:
        v = DNSSECValidator()
        # A syntactically valid but unrelated key.
        key = rrset(
            "example.com.",
            "DNSKEY",
            "257 3 8 "
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7S"
            "WXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3"
            "rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilB"
            "mSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
        )
        ds_set = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds_set.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "65000 8 2 " + "AB" * 32), ttl=300)
        assert v.validate_dnskey(dns.name.from_text("example.com."), key, None, ds_set) is ValidationState.BOGUS


class TestKeyTrapHardening:
    """CVE-2023-50387 / CVE-2023-50868: bound the crypto work one answer can cost."""

    @staticmethod
    def _dnskey_rrset(count: int) -> dns.rrset.RRset:
        """A DNSKEY RRset with `count` distinct keys (many sharing a tag in practice)."""
        out = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        base = (
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN"
            "7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8"
            "efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLY"
            "A4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
        )
        for i in range(count):
            flags = 256 if i % 2 else 257
            out.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, f"{flags} 3 8 {base}"))
        out.ttl = 300
        return out

    def test_keyring_is_trimmed_per_tag(self) -> None:
        """However many colliding keys a zone publishes, only a few are tried."""
        from recursive_resolver.dnssec import MAX_KEYS_PER_TAG, _trim_keyring

        keys = self._dnskey_rrset(40)
        trimmed = _trim_keyring({dns.name.from_text("evil.test."): keys})
        counts: dict[tuple[int, int], int] = {}
        for key in next(iter(trimmed.values())):
            slot = (dns.dnssec.key_id(key), int(key.algorithm))
            counts[slot] = counts.get(slot, 0) + 1
        assert counts, "trimming must not drop every key"
        assert max(counts.values()) <= MAX_KEYS_PER_TAG

    def test_rrsigs_are_trimmed(self) -> None:
        from recursive_resolver.dnssec import MAX_RRSIGS_PER_RRSET, MAX_RRSIGS_PER_TAG, _trim_rrsigs

        sigs = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        for tag in range(40):
            for _ in range(3):
                sigs.add(
                    dns.rdata.from_text(
                        dns.rdataclass.IN,
                        dns.rdatatype.RRSIG,
                        f"A 8 2 300 20990101000000 20200101000000 {tag} evil.test. AAAA",
                    )
                )
        kept = _trim_rrsigs(sigs)
        assert len(kept) <= MAX_RRSIGS_PER_RRSET
        per_tag: dict[tuple[int, int], int] = {}
        for sig in kept:
            slot = (int(sig.key_tag), int(sig.algorithm))
            per_tag[slot] = per_tag.get(slot, 0) + 1
        assert max(per_tag.values()) <= MAX_RRSIGS_PER_TAG

    @staticmethod
    def _sigs(count: int, *, window: str) -> dns.rrset.RRset:
        """``count`` RRSIGs with distinct key tags, in or out of validity.

        The window matters: an out-of-window signature is refused before any
        crypto is attempted, so it never reaches the budget.
        """
        now = int(time.time())
        if window == "valid":
            expiration, inception = now + 30 * 86400, now - 3600
        else:
            expiration, inception = now - 7200, now - 30 * 86400
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(expiration))
        start = time.strftime("%Y%m%d%H%M%S", time.gmtime(inception))
        sigs = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        for tag in range(count):
            sigs.add(
                dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    f"A 8 2 300 {stamp} {start} {tag} evil.test. AAAA",
                )
            )
        return sigs

    def test_signature_validations_are_charged_to_the_budget(self) -> None:
        from recursive_resolver.budget import QueryBudget
        from recursive_resolver.dnssec import MAX_RRSIGS_PER_RRSET

        v = DNSSECValidator()
        data = rrset("evil.test.", "A", "1.2.3.4")
        budget = QueryBudget()
        keys = {dns.name.from_text("evil.test."): self._dnskey_rrset(40)}
        assert v.validate_rrset(data, self._sigs(50, window="valid"), keys, budget=budget) is False
        assert 0 < budget.signature_validations <= MAX_RRSIGS_PER_RRSET

    def test_expired_signatures_cost_no_crypto_at_all(self) -> None:
        """The cheap check comes first, so a flood of stale RRSIGs is free."""
        from recursive_resolver.budget import QueryBudget

        v = DNSSECValidator()
        data = rrset("evil.test.", "A", "1.2.3.4")
        budget = QueryBudget()
        keys = {dns.name.from_text("evil.test."): self._dnskey_rrset(40)}
        assert v.validate_rrset(data, self._sigs(50, window="expired"), keys, budget=budget) is False
        assert budget.signature_validations == 0

    def test_budget_exhaustion_raises(self) -> None:
        from recursive_resolver.budget import QueryBudget
        from recursive_resolver.exceptions import QueryBudgetExceededError

        budget = QueryBudget(max_signature_validations=3)
        for _ in range(3):
            budget.spend_signature_validation()
        with pytest.raises(QueryBudgetExceededError):
            budget.spend_signature_validation()

    def test_nsec3_hashes_are_charged_to_the_budget(self) -> None:
        from recursive_resolver.budget import QueryBudget
        from recursive_resolver.exceptions import QueryBudgetExceededError

        budget = QueryBudget(max_nsec3_hashes=2)
        v = DNSSECValidator()
        owner = dns.name.from_text("AAAA.example.com.")
        nsec3 = rrset("AAAA.example.com.", "NSEC3", "1 0 10 AABBCCDD 2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S A")
        for _ in range(2):
            v._nsec3_owner(dns.name.from_text("x.example.com."), owner, nsec3[0], budget)
        with pytest.raises(QueryBudgetExceededError):
            v._nsec3_owner(dns.name.from_text("y.example.com."), owner, nsec3[0], budget)

    def test_nsec3_iteration_cap_matches_rfc9276_practice(self) -> None:
        from recursive_resolver.dnssec import MAX_NSEC3_ITERATIONS

        assert MAX_NSEC3_ITERATIONS <= 100

    def test_ds_cross_product_is_bounded(self) -> None:
        """A zone publishing hundreds of DS records cannot force unbounded digests."""
        from recursive_resolver.dnssec import MAX_DS_PER_ZONE

        v = DNSSECValidator()
        ds_set = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        for tag in range(500):
            ds_set.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, f"{tag} 8 2 " + "AB" * 32), ttl=300)

        digests = 0
        real_make_ds = dns.dnssec.make_ds

        def counting(*args, **kwargs):
            nonlocal digests
            digests += 1
            return real_make_ds(*args, **kwargs)

        keys = self._dnskey_rrset(2)
        try:
            dns.dnssec.make_ds = counting
            v.validate_dnskey(dns.name.from_text("evil.test."), keys, None, ds_set)
        finally:
            dns.dnssec.make_ds = real_make_ds
        assert digests <= len(keys) * MAX_DS_PER_ZONE


def _nsec3(zone: str, owner_hash: str, next_b32: str, types: str, flags: int = 0, iterations: int = 10):
    return rrset(f"{owner_hash}.{zone}", "NSEC3", f"1 {flags} {iterations} AABBCCDD {next_b32} {types}")


B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"


def _successor(digest: str) -> str:
    """The immediately following base32hex hash of the same length."""
    chars = list(digest)
    for i in range(len(chars) - 1, -1, -1):
        idx = B32HEX.index(chars[i])
        if idx + 1 < len(B32HEX):
            chars[i] = B32HEX[idx + 1]
            return "".join(chars)
        chars[i] = B32HEX[0]
    return "".join(chars)


def _predecessor(digest: str) -> str:
    """The immediately preceding base32hex hash of the same length."""
    chars = list(digest)
    for i in range(len(chars) - 1, -1, -1):
        idx = B32HEX.index(chars[i])
        if idx > 0:
            chars[i] = B32HEX[idx - 1]
            return "".join(chars)
        chars[i] = B32HEX[-1]
    return "".join(chars)


def _stub_nsec(v, nsecs=(), nsec3s=()):
    """Bypass signature checking so denial logic can be tested in isolation."""
    v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
        list(nsecs) if rdtype == dns.rdatatype.NSEC else list(nsec3s)
    )


class TestValidatorEdgeCases:
    def test_cryptography_unavailable_is_reported(self) -> None:
        import builtins

        from recursive_resolver.dnssec import cryptography_available

        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "cryptography":
                raise ImportError("blocked")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", blocked):
            assert cryptography_available() is False

    def test_trim_keyring_skips_empty_keysets(self) -> None:
        from recursive_resolver.dnssec import _trim_keyring

        assert _trim_keyring({dns.name.from_text("a.test."): None}) == {}

    def test_trim_keyring_skips_unhashable_keys(self) -> None:
        from recursive_resolver.dnssec import _trim_keyring

        keys = TestKeyTrapHardening._dnskey_rrset(2)
        with patch("dns.dnssec.key_id", side_effect=ValueError("bad key")):
            trimmed = _trim_keyring({dns.name.from_text("evil.test."): keys})
        assert len(next(iter(trimmed.values()))) == 0

    def test_validate_rrset_with_no_usable_keys(self) -> None:
        v = DNSSECValidator()
        data = rrset("example.com.", "A", "1.2.3.4")
        sig = rrset("example.com.", "RRSIG", "A 8 2 300 20990101000000 20200101000000 12345 example.com. AAAA")
        assert v.validate_rrset(data, sig, {}) is False

    def test_dnskey_without_the_zone_flag_is_ignored(self) -> None:
        v = DNSSECValidator()
        keys = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        # flags=0 means "not a zone key"
        keys.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, "0 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"))
        keys.ttl = 300
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 2 " + "AB" * 32), ttl=300)
        assert v.validate_dnskey(dns.name.from_text("evil.test."), keys, None, ds) is ValidationState.BOGUS

    def test_a_ds_we_cannot_digest_leaves_the_zone_insecure(self) -> None:
        """RFC 4035 §5.2: a child we have no way to check is unsigned, not forged.

        Reporting BOGUS here would reject a legitimately signed zone outright
        just because this build lacks its digest algorithm.
        """
        v = DNSSECValidator()
        keys = TestKeyTrapHardening._dnskey_rrset(1)
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 2 " + "AB" * 32), ttl=300)
        with patch("dns.dnssec.make_ds", side_effect=ValueError("unsupported digest")):
            assert v.validate_dnskey(dns.name.from_text("evil.test."), keys, None, ds) is ValidationState.INSECURE

    def test_single_nsec_zone_covers_everything_but_its_owner(self) -> None:
        v = DNSSECValidator()
        owner = dns.name.from_text("example.com.")
        assert v._nsec_covers(owner, owner, dns.name.from_text("x.example.com.")) is True
        assert v._nsec_covers(owner, owner, owner) is False

    def test_nsec3_hash_failure_is_handled(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "NS")
        with patch("dns.dnssec.nsec3_hash", side_effect=ValueError("bad salt")):
            assert v._nsec3_owner(dns.name.from_text("x.example.com."), n3.name, n3[0]) is None
            assert v._nsec3_covers(dns.name.from_text("x.example.com."), n3, n3[0]) is False

    def test_undecodable_next_hash_is_handled(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "NS")
        with patch("base64.b32encode", side_effect=TypeError("bad bytes")):
            assert v._nsec3_covers(dns.name.from_text("x.example.com."), n3, n3[0]) is False


class TestNoDSProofBranches:
    def test_the_childs_own_apex_nsec_cannot_deny_its_ds(self) -> None:
        """The DS lives in the parent, so a record bearing SOA is the wrong side.

        RFC 4035 §5.2. Without the guard a child could declare itself unsigned
        and drop out of the chain of trust on its own say-so.
        """
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        apex = rrset("child.example.com.", "NSEC", "z.child.example.com. NS SOA RRSIG NSEC")
        _stub_nsec(v, nsecs=[apex])
        assert v.prove_no_ds(child, [], {}) is False

    def test_the_root_is_exempt_from_the_soa_guard(self) -> None:
        """The root has no parent, so its own record is the only one there is."""
        v = DNSSECValidator()
        apex = rrset(".", "NSEC", "a. NS SOA RRSIG NSEC")
        _stub_nsec(v, nsecs=[apex])
        assert v.prove_no_ds(dns.name.root, [], {}) is True

    def test_nsec3_matching_record_without_ds_bit(self) -> None:
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "NS RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_ds(child, [], {}) is True

    def test_nsec3_matching_record_with_ds_bit_is_rejected(self) -> None:
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "NS DS RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_ds(child, [], {}) is False

    def test_nsec3_non_matching_record_is_skipped(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "00000000000000000000000000000000", "11111111111111111111111111111111", "NS")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_ds(dns.name.from_text("child.example.com."), [], {}) is False

    def test_nsec3_opt_out_covering_record_proves_no_ds(self) -> None:
        """Opt-out zones cover the next closer name rather than matching it."""
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        apex_hash = dns.dnssec.nsec3_hash(dns.name.from_text("example.com."), "AABBCCDD", 10, 1)
        lo = "0" * 32
        hi = "V" * 32
        assert lo < digest < hi
        encloser = _nsec3("example.com.", apex_hash, _successor(apex_hash), "NS SOA RRSIG DNSKEY")
        covering = _nsec3("example.com.", lo, hi, "NS", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=[encloser, covering])
        assert v.prove_no_ds(child, [], {}) is True

    def test_nsec3_opt_out_covers_a_delegation_below_an_unsigned_cut(self) -> None:
        """A whole subtree inside an opt-out span: the cover is for `sub`.

        The delegation is two labels below the encloser, so the next closer
        name is its parent, not the delegation itself.
        """
        v = DNSSECValidator()
        child = dns.name.from_text("deep.sub.example.com.")
        next_closer = dns.name.from_text("sub.example.com.")
        nc_hash = dns.dnssec.nsec3_hash(next_closer, "AABBCCDD", 10, 1)
        apex_hash = dns.dnssec.nsec3_hash(dns.name.from_text("example.com."), "AABBCCDD", 10, 1)
        # The range brackets the next closer name alone, so a proof that looked
        # for a cover of the delegation itself would not find one.
        lo, hi = _predecessor(nc_hash), _successor(nc_hash)
        assert not lo < dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1) < hi
        encloser = _nsec3("example.com.", apex_hash, _successor(apex_hash), "NS SOA RRSIG DNSKEY")
        covering = _nsec3("example.com.", lo, hi, "NS", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=[encloser, covering])
        assert v.prove_no_ds(child, [], {}) is True

    def test_nsec3_opt_out_without_a_closest_encloser_proves_nothing(self) -> None:
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        lo, hi = "0" * 32, "V" * 32
        assert lo < digest < hi
        covering = _nsec3("example.com.", lo, hi, "NS", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=[covering])
        assert v.prove_no_ds(child, [], {}) is False

    def test_a_matching_record_that_asserts_a_ds_leaves_nothing_to_fall_back_on(self) -> None:
        """The child *is* its own closest encloser, so there is no next closer.

        The bitmap says a DS exists, so the matching branch cannot prove its
        absence, and the opt-out branch has no name below the encloser to look
        for a cover of.
        """
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "NS SOA DS RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_ds(child, [], {}) is False

    def test_opt_out_records_that_cover_nothing_prove_nothing(self) -> None:
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        apex_hash = dns.dnssec.nsec3_hash(dns.name.from_text("example.com."), "AABBCCDD", 10, 1)
        elsewhere = dns.dnssec.nsec3_hash(dns.name.from_text("nowhere.example.com."), "AABBCCDD", 10, 1)
        encloser = _nsec3("example.com.", apex_hash, _successor(apex_hash), "NS SOA RRSIG DNSKEY")
        # Opt-out, but its range brackets an unrelated name.
        covering = _nsec3("example.com.", _predecessor(elsewhere), _successor(elsewhere), "NS", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=[encloser, covering])
        assert v.prove_no_ds(child, [], {}) is False

    def test_nsec3_covering_record_without_opt_out_proves_nothing(self) -> None:
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        apex_hash = dns.dnssec.nsec3_hash(dns.name.from_text("example.com."), "AABBCCDD", 10, 1)
        lo, hi = "0" * 32, "V" * 32
        assert lo < digest < hi
        encloser = _nsec3("example.com.", apex_hash, _successor(apex_hash), "NS SOA RRSIG DNSKEY")
        covering = _nsec3("example.com.", lo, hi, "NS")
        _stub_nsec(v, nsec3s=[encloser, covering])
        assert v.prove_no_ds(child, [], {}) is False

    def test_nsec_owner_mismatch_is_skipped(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("other.example.com.", "NSEC", "next.example.com. NS RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_ds(dns.name.from_text("child.example.com."), [], {}) is False


class TestNXDOMAINProofBranches:
    def test_nsec_not_covering_the_name(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("x.example.com.", "NSEC", "y.example.com. A RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_nxdomain(dns.name.from_text("zz.example.com."), [], {}) is ValidationState.BOGUS

    def test_nsec3_iteration_cap(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "A", iterations=MAX_NSEC3_ITERATIONS + 1)
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nxdomain(dns.name.from_text("x.example.com."), [], {}) is ValidationState.BOGUS

    def test_nsec3_without_a_closest_encloser(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "00000000000000000000000000000000", "11111111111111111111111111111111", "A")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nxdomain(dns.name.from_text("x.example.com."), [], {}) is ValidationState.BOGUS

    def test_nsec3_closest_encloser_without_a_covered_next_closer(self) -> None:
        v = DNSSECValidator()
        apex = dns.name.from_text("example.com.")
        qname = dns.name.from_text("x.example.com.")
        apex_hash = dns.dnssec.nsec3_hash(apex, "AABBCCDD", 10, 1)
        qname_hash = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        # An interval spanning only the apex hash and its immediate successor:
        # it matches the closest encloser but covers no other name.
        n3 = _nsec3("example.com.", apex_hash, _successor(apex_hash), "A")
        assert not (apex_hash < qname_hash < _successor(apex_hash))
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nxdomain(qname, [], {}) is ValidationState.BOGUS

    def test_next_closer_of_an_equal_name_is_none(self) -> None:
        v = DNSSECValidator()
        apex = dns.name.from_text("example.com.")
        assert v._next_closer(apex, apex) is None

    def test_closest_encloser_search_terminates_at_the_root(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "00000000000000000000000000000000", "11111111111111111111111111111111", "A")
        assert v._closest_encloser_nsec3(dns.name.from_text("a.b.c."), [n3], n3[0]) is None


class TestNODATAProofBranches:
    def test_nsec_owner_mismatch_is_skipped(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("other.example.com.", "NSEC", "next.example.com. A RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    def test_nsec3_matching_record_without_the_type(self) -> None:
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is ValidationState.SECURE

    def test_nsec3_matching_record_with_the_type_present(self) -> None:
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A MX RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    def test_nsec3_iteration_cap(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "A", iterations=MAX_NSEC3_ITERATIONS + 1)
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    @staticmethod
    def _opt_out_chain():
        """An opt-out cover for the next closer, plus a matching closest encloser."""
        apex_hash = dns.dnssec.nsec3_hash(dns.name.from_text("example.com."), "AABBCCDD", 10, 1)
        nc_hash = dns.dnssec.nsec3_hash(dns.name.from_text("sub.example.com."), "AABBCCDD", 10, 1)
        lo, hi = "0" * 32, "V" * 32
        assert lo < nc_hash < hi
        return [
            _nsec3("example.com.", apex_hash, "Z" * 32, "A SOA RRSIG"),
            _nsec3("example.com.", lo, hi, "NS", flags=NSEC3_OPT_OUT),
        ]

    def test_nsec3_opt_out_covers_the_ds_of_an_unsigned_delegation(self) -> None:
        """RFC 5155 §8.6: an opt-out cover denies a DS, and only a DS.

        Unauthenticated, though: opt-out says the range holds no *signed*
        delegation, so the absent DS is insecure rather than proven (§9.2).
        """
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._opt_out_chain())
        qname = dns.name.from_text("deep.sub.example.com.")
        assert v.prove_nodata(qname, dns.rdatatype.DS, [], {}) is ValidationState.INSECURE

    def test_an_opt_out_record_covering_nothing_denies_no_ds_either(self) -> None:
        v = DNSSECValidator()
        apex_hash = dns.dnssec.nsec3_hash(dns.name.from_text("example.com."), "AABBCCDD", 10, 1)
        elsewhere = dns.dnssec.nsec3_hash(dns.name.from_text("nowhere.example.com."), "AABBCCDD", 10, 1)
        _stub_nsec(
            v,
            nsec3s=[
                _nsec3("example.com.", apex_hash, _successor(apex_hash), "A SOA RRSIG"),
                _nsec3("example.com.", _predecessor(elsewhere), _successor(elsewhere), "NS", flags=NSEC3_OPT_OUT),
            ],
        )
        qname = dns.name.from_text("deep.sub.example.com.")
        assert v.prove_nodata(qname, dns.rdatatype.DS, [], {}) is ValidationState.BOGUS

    def test_nsec3_opt_out_does_not_authenticate_any_other_type(self) -> None:
        """§8.5 wants a matching NSEC3; opt-out asserts nothing about names.

        A range with the bit set says only that it holds no *signed*
        delegations. The queried name may well exist inside it, unsigned, and
        hold exactly the records being denied. So the denial is not proven -
        but it is not contradicted either, and BOGUS is an accusation of
        forgery the record does not support. Insecure, and the answer stands.
        """
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._opt_out_chain())
        qname = dns.name.from_text("deep.sub.example.com.")
        for rdtype in (dns.rdatatype.MX, dns.rdatatype.A, dns.rdatatype.TLSA):
            assert v.prove_nodata(qname, rdtype, [], {}) is ValidationState.INSECURE

    def test_a_name_that_exists_is_still_denied_nothing_by_opt_out(self) -> None:
        """The escape hatch is a *gap*, so a name with its own NSEC3 cannot use it.

        Without this the rule above would read as "opt-out anywhere in the zone
        excuses any missing proof", which would let a matching NSEC3 that lists
        the type be talked past.
        """
        v = DNSSECValidator()
        qname = dns.name.from_text("deep.sub.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        chain = self._opt_out_chain()
        chain.append(_nsec3("example.com.", digest, _successor(digest), "A MX RRSIG"))
        _stub_nsec(v, nsec3s=chain)
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is ValidationState.BOGUS


def _signed(name: str, rdtype: str, signer: str) -> dns.rrset.RRset:
    """An RRSIG at ``name`` covering ``rdtype``, claiming to come from ``signer``."""
    return rrset(name, "RRSIG", f"{rdtype} 8 2 300 20990101000000 20200101000000 1 {signer} AAAA")


def _keyring(zone: str) -> dict:
    """A keyring naming the zone a proof is being validated against.

    Which zone signed a record is read from here, not from the RRSIG on the
    wire, so tests that turn on the signer have to say it here too.
    """
    return {dns.name.from_text(zone): None}


class TestAncestorDelegationRecords:
    """RFC 6840 §4.1: a parent-side record denies nothing below the cut.

    The parent of a delegation holds the child's NS and DS and nothing else,
    so its NSEC bitmap lists only those. Read as a statement about the child
    it denies every type the child actually serves, which is a denial anyone
    able to place a parent-side record in an answer could exploit.
    """

    @staticmethod
    def _delegation_nsec() -> list:
        """`example.com` delegated by `com`: NS set, SOA clear, signer above."""
        return [
            rrset("example.com.", "NSEC", "z.com. NS RRSIG NSEC"),
            _signed("example.com.", "NSEC", "com."),
        ]

    def test_a_parent_side_nsec_cannot_deny_a_type_at_the_cut(self) -> None:
        v = DNSSECValidator()
        records = self._delegation_nsec()
        _stub_nsec(v, nsecs=[records[0]])
        assert (
            v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.A, records, _keyring("com."))
            is ValidationState.BOGUS
        )

    def test_the_childs_own_nsec_still_denies_it(self) -> None:
        """Same bitmap, but signed at the apex, so it is the child speaking."""
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "z.example.com. NS SOA RRSIG NSEC")
        records = [nsec, _signed("example.com.", "NSEC", "example.com.")]
        _stub_nsec(v, nsecs=[nsec])
        assert (
            v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.A, records, _keyring("example.com."))
            is ValidationState.SECURE
        )

    def test_a_parent_side_nsec_cannot_deny_a_name_below_the_cut(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "z.com. NS RRSIG NSEC")
        records = [nsec, _signed("example.com.", "NSEC", "com.")]
        _stub_nsec(v, nsecs=[nsec])
        target = dns.name.from_text("host.example.com.")
        # The range does cover the name; the record is simply not allowed to say so.
        assert v._nsec_covers(nsec.name, nsec[0].next, target) is True
        assert v.prove_nxdomain(target, records, _keyring("com.")) is ValidationState.BOGUS

    def test_a_parent_side_nsec_cannot_authenticate_a_wildcard_below_the_cut(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "z.com. NS RRSIG NSEC")
        records = [nsec, _signed("example.com.", "NSEC", "com.")]
        _stub_nsec(v, nsecs=[nsec])
        state = v.prove_wildcard(dns.name.from_text("host.example.com."), 2, records, _keyring("com."))
        assert state is ValidationState.BOGUS

    def test_a_dname_nsec_cannot_deny_a_subdomain(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "z.com. DNAME RRSIG NSEC")
        records = [nsec, _signed("example.com.", "NSEC", "example.com.")]
        _stub_nsec(v, nsecs=[nsec])
        # Signed by the zone itself, so only the DNAME bit disqualifies it.
        assert (
            v.prove_nxdomain(dns.name.from_text("host.example.com."), records, _keyring("example.com."))
            is ValidationState.BOGUS
        )

    def test_a_parent_side_nsec3_cannot_deny_a_type_at_the_cut(self) -> None:
        v = DNSSECValidator()
        name = dns.name.from_text("example.com.")
        digest = dns.dnssec.nsec3_hash(name, "AABBCCDD", 10, 1)
        n3 = _nsec3("com.", digest, _successor(digest), "NS RRSIG")
        records = [n3, _signed(f"{digest}.com.", "NSEC3", "com.")]
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(name, dns.rdatatype.A, records, _keyring("com.")) is ValidationState.BOGUS

    def test_a_ds_at_the_cut_is_the_documented_exception(self) -> None:
        """RFC 6840 §4.1 exempts "DS RRs" at the delegation's own name.

        The DS is the one type that lives on the parent side, so a
        direct DS query is answered by exactly this record. Refusing it would
        make every DS lookup on an insecure delegation in an NSEC zone fail.
        """
        v = DNSSECValidator()
        records = self._delegation_nsec()
        _stub_nsec(v, nsecs=[records[0]])
        child = dns.name.from_text("example.com.")
        assert v.prove_nodata(child, dns.rdatatype.DS, records, _keyring("com.")) is ValidationState.SECURE
        # Every other type at that name is still refused.
        assert v.prove_nodata(child, dns.rdatatype.A, records, _keyring("com.")) is ValidationState.BOGUS

    def test_a_parent_side_nsec_cannot_prove_a_label_below_it_is_not_a_cut(self) -> None:
        """The chain walk must not skip a label on a parent-side record's say-so.

        Skipping means "the zone in force is unchanged", so a record that knows
        nothing about the zone below the cut must not be what decides it.
        """
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "z.com. NS RRSIG NSEC")
        records = [nsec, _signed("example.com.", "NSEC", "com.")]
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_delegation(dns.name.from_text("sub.example.com."), records, _keyring("com.")) is False

    def test_the_sweep_carries_on_past_a_parent_side_record(self) -> None:
        """Skipping one record must not abandon the rest of the proof."""
        v = DNSSECValidator()
        parent_side = rrset("example.com.", "NSEC", "z.com. NS RRSIG NSEC")
        usable = rrset("a.example.com.", "NSEC", "z.example.com. A RRSIG NSEC")
        records = [
            parent_side,
            _signed("example.com.", "NSEC", "com."),
            usable,
            _signed("a.example.com.", "NSEC", "example.com."),
        ]
        _stub_nsec(v, nsecs=[parent_side, usable])
        assert v.prove_no_delegation(dns.name.from_text("m.example.com."), records, _keyring("com.")) is True

    def test_a_parent_side_nsec_cannot_prove_an_empty_non_terminal_below_it(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "a.b.example.com. NS RRSIG NSEC")
        records = [nsec, _signed("example.com.", "NSEC", "com.")]
        _stub_nsec(v, nsecs=[nsec])
        assert (
            v.prove_nodata(dns.name.from_text("b.example.com."), dns.rdatatype.A, records, _keyring("com."))
            is ValidationState.BOGUS
        )

    def test_an_unsigned_record_is_not_treated_as_parent_side(self) -> None:
        """With no RRSIG there is no signer to compare, so the rule cannot apply.

        Such a record never reaches these functions in production - it would
        have failed signature validation first - but the guard must not throw.
        """
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "z.com. NS RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.A, [nsec], {}) is ValidationState.SECURE


class TestNSEC3ReservedFlags:
    """RFC 5155 §8.2: only Opt-Out is defined; anything else must be ignored."""

    def test_a_reserved_flag_bit_makes_the_record_unusable(self) -> None:
        v = DNSSECValidator()
        name = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(name, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "A RRSIG", flags=0x02)
        with patch.object(DNSSECValidator, "validate_rrset", return_value=True):
            assert v.prove_nodata(name, dns.rdatatype.MX, [n3], {}) is ValidationState.BOGUS

    def test_opt_out_alone_is_still_accepted(self) -> None:
        v = DNSSECValidator()
        name = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(name, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "A RRSIG", flags=NSEC3_OPT_OUT)
        with patch.object(DNSSECValidator, "validate_rrset", return_value=True):
            assert v.prove_nodata(name, dns.rdatatype.MX, [n3], {}) is ValidationState.SECURE


class TestWildcardDenialUsesTheClosestEncloser:
    """RFC 4035 §5.4: exactly one wildcard could have synthesised the name.

    Denying the wildcard at any ancestor instead is forgeable from public data:
    where a zone holds `*.example.` and is asked for `a.b.example.`, it must
    answer from the wildcard, but a genuine NSEC covering the non-existent
    `*.b.example.` would otherwise read as a proof that nothing exists there.
    """

    def test_a_wildcard_at_a_deeper_ancestor_does_not_prove_nxdomain(self) -> None:
        v = DNSSECValidator()
        # example. < *.example. < *.b.example. < a.b.example. < c.example.
        # so this one record covers both the queried name and *.b.example.
        nsec = rrset("*.example.", "NSEC", "c.example. A RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        qname = dns.name.from_text("a.b.example.")
        assert v._nsec_covers(nsec.name, nsec[0].next, qname) is True
        # `*.example.` owns this NSEC, so it exists and would have answered.
        assert v.prove_nxdomain(qname, [nsec], {}) is ValidationState.BOGUS

    def test_denying_the_wildcard_at_the_closest_encloser_does_prove_it(self) -> None:
        v = DNSSECValidator()
        # The closest encloser of `nx.example.` is `example.`, and the NSEC at
        # the apex covers `*.example.`, so no wildcard could have matched.
        covering = rrset("a.example.", "NSEC", "z.example. A RRSIG NSEC")
        apex = rrset("example.", "NSEC", "a.example. SOA NS RRSIG NSEC")
        _stub_nsec(v, nsecs=[covering, apex])
        assert v.prove_nxdomain(dns.name.from_text("nx.example."), [covering, apex], {}) is ValidationState.SECURE

    def test_records_that_do_not_cover_the_name_are_skipped(self) -> None:
        """The covering record is what fixes the closest encloser, so the
        others must be passed over rather than used to derive one."""
        v = DNSSECValidator()
        unrelated = rrset("q.other.", "NSEC", "r.other. A RRSIG NSEC")
        covering = rrset("a.example.", "NSEC", "z.example. A RRSIG NSEC")
        apex = rrset("example.", "NSEC", "a.example. SOA NS RRSIG NSEC")
        _stub_nsec(v, nsecs=[unrelated, covering, apex])
        assert (
            v.prove_nxdomain(dns.name.from_text("nx.example."), [unrelated, covering, apex], {})
            is ValidationState.SECURE
        )

    def test_the_closest_encloser_comes_from_the_covering_record(self) -> None:
        v = DNSSECValidator()
        qname = dns.name.from_text("x.deep.example.")
        nsec = rrset("a.deep.example.", "NSEC", "z.deep.example. A RRSIG NSEC")
        assert v._common_ancestor(qname, nsec.name) == dns.name.from_text("deep.example.")
        assert v._common_ancestor(qname, nsec[0].next) == dns.name.from_text("deep.example.")

    def test_common_ancestor_is_case_insensitive(self) -> None:
        v = DNSSECValidator()
        assert v._common_ancestor(
            dns.name.from_text("a.EXAMPLE."), dns.name.from_text("b.example.")
        ) == dns.name.from_text("example.")

    def test_unrelated_names_share_only_the_root(self) -> None:
        v = DNSSECValidator()
        assert v._common_ancestor(dns.name.from_text("a.foo."), dns.name.from_text("b.bar.")) == dns.name.root


class TestNestedWildcards:
    """Only the wildcard at the closest encloser answered (RFC 4592 §3.3.1).

    A zone can hold nested wildcards. Taking any ancestor's lets the higher,
    sparser one deny a type the closer one really serves - a forged "no MX" or
    "no TLSA" built from two genuine, public, correctly signed records.
    """

    QNAME = dns.name.from_text("foo.deep.example.")

    @staticmethod
    def _zone(closer_types: str):
        return [
            rrset("*.example.", "NSEC", "a.example. A RRSIG NSEC"),
            rrset("a.deep.example.", "NSEC", "z.deep.example. A RRSIG NSEC"),
            rrset("*.deep.example.", "NSEC", f"a.deep.example. {closer_types}"),
        ]

    def test_a_higher_wildcard_cannot_deny_what_the_closer_one_serves(self) -> None:
        v = DNSSECValidator()
        records = self._zone("MX A RRSIG NSEC")
        _stub_nsec(v, nsecs=records)
        assert v.prove_nodata(self.QNAME, dns.rdatatype.MX, records, _keyring("example.")) is ValidationState.BOGUS

    def test_the_closest_wildcard_still_denies_a_type_it_lacks(self) -> None:
        """Only the closer wildcard's bitmap changes, so that is what decides it."""
        v = DNSSECValidator()
        records = self._zone("A RRSIG NSEC")
        _stub_nsec(v, nsecs=records)
        assert v.prove_nodata(self.QNAME, dns.rdatatype.MX, records, _keyring("example.")) is ValidationState.SECURE

    def test_the_same_rule_governs_the_nxdomain_wildcard_denial(self) -> None:
        v = DNSSECValidator()
        # `*.deep.example.` exists, so nothing under deep.example. is NXDOMAIN.
        records = self._zone("A RRSIG NSEC")
        _stub_nsec(v, nsecs=records)
        assert v.prove_nxdomain(self.QNAME, records, _keyring("example.")) is ValidationState.BOGUS


class TestPositiveWildcardProofMatchesTheLabelsCount:
    """RFC 4035 §5.3.4: the wildcard that signed the data is the one that applies.

    A zone with nested wildcards signs each with a different Labels value.
    Without checking it, the higher wildcard's genuine record and RRSIG can be
    replayed as the answer for a name the lower one really covers, and the
    substituted data comes back authenticated.
    """

    QNAME = dns.name.from_text("a.b.example.")

    @staticmethod
    def _covering():
        # The NSEC owned by *.b.example. covers a.b.example., so the closest
        # encloser is b.example. and the applicable wildcard is *.b.example.
        return rrset("*.b.example.", "NSEC", "example. A RRSIG NSEC")

    def test_the_labels_count_of_the_applicable_wildcard_is_accepted(self) -> None:
        v = DNSSECValidator()
        records = [self._covering()]
        _stub_nsec(v, nsecs=records)
        assert v.prove_wildcard(self.QNAME, 2, records, _keyring("example.")) is ValidationState.SECURE

    def test_a_replayed_higher_wildcard_is_refused(self) -> None:
        """Labels=1 means `*.example.`, which is not the closest encloser here."""
        v = DNSSECValidator()
        records = [self._covering()]
        _stub_nsec(v, nsecs=records)
        assert v.prove_wildcard(self.QNAME, 1, records, _keyring("example.")) is ValidationState.BOGUS

    def test_a_record_that_does_not_cover_the_name_is_skipped(self) -> None:
        v = DNSSECValidator()
        unrelated = rrset("q.other.", "NSEC", "r.other. A RRSIG NSEC")
        records = [unrelated, self._covering()]
        _stub_nsec(v, nsecs=records)
        assert v.prove_wildcard(self.QNAME, 2, records, _keyring("example.")) is ValidationState.SECURE


class TestADSIsNeverDeniedByTheChildItself:
    """RFC 4035 §5.2: the DS lives in the parent, so the child cannot deny it.

    The parent-side exemption that lets a delegation record answer a DS query
    must not also admit the child apex's own record, which carries SOA.
    """

    CHILD = dns.name.from_text("child.example.")

    def test_a_soa_bearing_nsec_cannot_deny_a_ds(self) -> None:
        v = DNSSECValidator()
        apex = rrset("child.example.", "NSEC", "z.child.example. NS SOA RRSIG DNSKEY NSEC")
        _stub_nsec(v, nsecs=[apex])
        assert v.prove_nodata(self.CHILD, dns.rdatatype.DS, [apex], _keyring("child.example.")) is ValidationState.BOGUS

    def test_a_soa_bearing_nsec3_cannot_deny_a_ds(self) -> None:
        v = DNSSECValidator()
        digest = dns.dnssec.nsec3_hash(self.CHILD, "AABBCCDD", 10, 1)
        n3 = _nsec3("child.example.", digest, _successor(digest), "NS SOA RRSIG DNSKEY")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(self.CHILD, dns.rdatatype.DS, [n3], _keyring("child.example.")) is ValidationState.BOGUS

    def test_the_parents_own_record_still_denies_the_ds(self) -> None:
        v = DNSSECValidator()
        parent_side = rrset("child.example.", "NSEC", "z.example. NS RRSIG NSEC")
        _stub_nsec(v, nsecs=[parent_side])
        assert (
            v.prove_nodata(self.CHILD, dns.rdatatype.DS, [parent_side], _keyring("example.")) is ValidationState.SECURE
        )

    def test_the_root_is_exempt_because_it_has_no_parent(self) -> None:
        v = DNSSECValidator()
        apex = rrset(".", "NSEC", "a. NS SOA RRSIG DNSKEY NSEC")
        _stub_nsec(v, nsecs=[apex])
        assert v.prove_nodata(dns.name.root, dns.rdatatype.DS, [apex], {dns.name.root: None}) is ValidationState.SECURE


class TestClosestEncloserMustBeFromTheProperZone:
    """RFC 5155 §8.3: "The DNAME type bit must not be set and the NS type bit
    may only be set if the SOA type bit is set."

    A record failing that came from the parent side of a cut, and describes
    nothing inside the zone below it. Accepting one lets a parent's public,
    correctly signed delegation record stand as the closest encloser for a name
    in the signed child.
    """

    @staticmethod
    def _matching(name: str, types: str):
        digest = dns.dnssec.nsec3_hash(dns.name.from_text(name), "AABBCCDD", 10, 1)
        return _nsec3("example.com.", digest, _successor(digest), types)

    def test_a_delegation_record_is_not_a_closest_encloser(self) -> None:
        v = DNSSECValidator()
        n3 = self._matching("child.example.com.", "NS RRSIG")
        assert v._closest_encloser_nsec3(dns.name.from_text("secret.child.example.com."), [n3], n3[0]) is None

    def test_a_dname_record_is_not_a_closest_encloser(self) -> None:
        v = DNSSECValidator()
        n3 = self._matching("child.example.com.", "DNAME RRSIG")
        assert v._closest_encloser_nsec3(dns.name.from_text("secret.child.example.com."), [n3], n3[0]) is None

    def test_an_apex_carrying_ns_and_soa_is_a_closest_encloser(self) -> None:
        """The child's own apex has both bits, and is the proper zone."""
        v = DNSSECValidator()
        n3 = self._matching("child.example.com.", "NS SOA RRSIG DNSKEY")
        assert v._closest_encloser_nsec3(
            dns.name.from_text("secret.child.example.com."), [n3], n3[0]
        ) == dns.name.from_text("child.example.com.")

    def test_an_ordinary_name_is_a_closest_encloser(self) -> None:
        v = DNSSECValidator()
        n3 = self._matching("child.example.com.", "A RRSIG")
        assert v._closest_encloser_nsec3(
            dns.name.from_text("secret.child.example.com."), [n3], n3[0]
        ) == dns.name.from_text("child.example.com.")


class TestOptOutNXDOMAINIsNotAuthenticated:
    """Opt-out denies signed delegations, not names (RFC 5155 §6).

    A name inside an opt-out range may exist as an unsigned delegation, so the
    name error is returned but not authenticated. In an opt-out TLD that covers
    every unsigned domain, and the records needed are public and correctly
    signed. Google, Cloudflare and Quad9 all clear AD on these answers.
    """

    QNAME = dns.name.from_text("x.example.")

    @staticmethod
    def _proof(opt_out: bool):
        def hashed(name: str) -> str:
            return dns.dnssec.nsec3_hash(dns.name.from_text(name), "AABBCCDD", 10, 1)

        apex, nc, wild = hashed("example."), hashed("x.example."), hashed("*.example.")
        flags = NSEC3_OPT_OUT if opt_out else 0
        # Each record brackets one name, so the three roles cannot overlap.
        return [
            _nsec3("example.", apex, _successor(apex), "NS SOA RRSIG DNSKEY"),
            _nsec3("example.", _predecessor(nc), _successor(nc), "NS", flags=flags),
            _nsec3("example.", _predecessor(wild), _successor(wild), "A RRSIG"),
        ]

    def test_an_opt_out_cover_for_the_next_closer_is_insecure(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._proof(opt_out=True))
        assert v.prove_nxdomain(self.QNAME, [], {}) is ValidationState.INSECURE

    def test_the_same_proof_without_opt_out_is_secure(self) -> None:
        """Only the flag differs, so that is what the verdict turns on."""
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._proof(opt_out=False))
        assert v.prove_nxdomain(self.QNAME, [], {}) is ValidationState.SECURE


class TestNoDelegationProof:
    """Telling "this label is not a cut" apart from "the chain is broken"."""

    def test_nsec_matching_a_name_with_no_ns_or_ds(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("x.example.com.", "NSEC", "y.example.com. TXT RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_delegation(dns.name.from_text("x.example.com."), [], {}) is True

    def test_nsec_matching_a_delegation_proves_nothing(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("x.example.com.", "NSEC", "y.example.com. NS RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_delegation(dns.name.from_text("x.example.com."), [], {}) is False

    def test_nsec_matching_a_signed_delegation_proves_nothing(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("x.example.com.", "NSEC", "y.example.com. DS RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_delegation(dns.name.from_text("x.example.com."), [], {}) is False

    def test_a_covering_nsec_is_an_empty_non_terminal(self) -> None:
        """A name that owns no NSEC owns no records, so it owns no NS."""
        v = DNSSECValidator()
        nsec = rrset("a.example.com.", "NSEC", "z.example.com. A RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_delegation(dns.name.from_text("m.example.com."), [], {}) is True

    def test_nsec3_matching_an_empty_non_terminal(self) -> None:
        v = DNSSECValidator()
        name = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(name, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_delegation(name, [], {}) is True

    def test_nsec3_matching_a_delegation_proves_nothing(self) -> None:
        v = DNSSECValidator()
        name = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(name, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "NS")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_delegation(name, [], {}) is False

    def test_an_nsec_that_neither_matches_nor_covers_proves_nothing(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("a.example.com.", "NSEC", "c.example.com. A RRSIG NSEC")
        _stub_nsec(v, nsecs=[nsec])
        assert v.prove_no_delegation(dns.name.from_text("z.example.com."), [nsec], {}) is False

    def test_an_unrelated_nsec3_proves_nothing(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "0" * 32, "V" * 32, "")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_delegation(dns.name.from_text("x.example.com."), [], {}) is False

    def test_nothing_at_all_proves_nothing(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v)
        assert v.prove_no_delegation(dns.name.from_text("x.example.com."), [], {}) is False

    def test_nsec3_iteration_cap_applies(self) -> None:
        v = DNSSECValidator()
        name = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(name, "AABBCCDD", MAX_NSEC3_ITERATIONS + 1, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "", iterations=MAX_NSEC3_ITERATIONS + 1)
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_delegation(name, [], {}) is False


class TestWildcardNODATA:
    """A name that does not exist, denied a type by the wildcard above it.

    The zone answers NOERROR/NODATA rather than NXDOMAIN because a wildcard
    would have synthesised the name, but holds no record of the queried type.
    Proving that needs the wildcard's own denial, not the queried name's.
    """

    @staticmethod
    def _nsec3_chain(qname: str, wildcard_types: str) -> list:
        apex = dns.name.from_text("example.com.")
        apex_hash = dns.dnssec.nsec3_hash(apex, "AABBCCDD", 10, 1)
        wildcard_hash = dns.dnssec.nsec3_hash(dns.name.from_text("*.example.com."), "AABBCCDD", 10, 1)
        nc_hash = dns.dnssec.nsec3_hash(dns.name.from_text(qname), "AABBCCDD", 10, 1)
        lo, hi = "0" * 32, "V" * 32
        assert lo < nc_hash < hi
        return [
            _nsec3("example.com.", apex_hash, _successor(apex_hash), "A NS SOA RRSIG DNSKEY"),
            _nsec3("example.com.", wildcard_hash, _successor(wildcard_hash), wildcard_types),
            _nsec3("example.com.", lo, hi, "A RRSIG"),
        ]

    def test_nsec3_wildcard_without_the_type_proves_nodata(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._nsec3_chain("x.example.com.", "A AAAA RRSIG"))
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.SECURE

    def test_nsec3_wildcard_holding_the_type_proves_nothing(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._nsec3_chain("x.example.com.", "A TXT RRSIG"))
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.BOGUS

    def test_nsec3_wildcard_with_a_cname_proves_nothing(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=self._nsec3_chain("x.example.com.", "A CNAME RRSIG"))
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.BOGUS

    def test_nsec3_wildcard_needs_the_next_closer_covered(self) -> None:
        """Without a cover for the queried name it may exist and hold the type."""
        v = DNSSECValidator()
        chain = self._nsec3_chain("x.example.com.", "A AAAA RRSIG")
        _stub_nsec(v, nsec3s=chain[:2])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.BOGUS

    def test_an_opt_out_cover_of_the_next_closer_is_not_authenticated(self) -> None:
        """Opt-out leaves the next closer name unproven, so the wildcard may not
        be the closest encloser's. The denial is returned, unauthenticated."""
        v = DNSSECValidator()
        chain = self._nsec3_chain("x.example.com.", "A AAAA RRSIG")
        chain[2] = _nsec3("example.com.", "0" * 32, "V" * 32, "A RRSIG", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=chain)
        assert (
            v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.INSECURE
        )

    def test_nsec_wildcard_without_the_type_proves_nodata(self) -> None:
        v = DNSSECValidator()
        covering = rrset("a.example.com.", "NSEC", "y.example.com. A RRSIG NSEC")
        wildcard = rrset("*.example.com.", "NSEC", "b.example.com. A AAAA RRSIG NSEC")
        _stub_nsec(v, nsecs=[covering, wildcard])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.SECURE

    def test_nsec_wildcard_holding_the_type_proves_nothing(self) -> None:
        v = DNSSECValidator()
        covering = rrset("a.example.com.", "NSEC", "y.example.com. A RRSIG NSEC")
        wildcard = rrset("*.example.com.", "NSEC", "b.example.com. A TXT RRSIG NSEC")
        _stub_nsec(v, nsecs=[covering, wildcard])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.BOGUS

    def test_nsec_wildcard_needs_the_queried_name_covered(self) -> None:
        v = DNSSECValidator()
        wildcard = rrset("*.example.com.", "NSEC", "b.example.com. A AAAA RRSIG NSEC")
        _stub_nsec(v, nsecs=[wildcard])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.TXT, [], {}) is ValidationState.BOGUS


class TestTrimmingGuards:
    """The per-tag caps themselves, exercised at their boundaries."""

    def test_colliding_key_tags_are_capped(self) -> None:
        from recursive_resolver.dnssec import MAX_KEYS_PER_TAG, _trim_keyring

        keys = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for i in range(10):
            keys.add(
                dns.rdata.from_text(
                    dns.rdataclass.IN, dns.rdatatype.DNSKEY, f"257 3 8 AwEAAaz{i}tAm8yTn4Mfeh5eyI96WSVexTBAvk"
                )
            )
        keys.ttl = 300
        assert len(keys) == 10, "distinct payloads so the RRset does not dedupe"
        # Force every key to report the same tag: the KeyTrap shape.
        with patch("dns.dnssec.key_id", return_value=4242):
            trimmed = _trim_keyring({dns.name.from_text("evil.test."): keys})
        assert len(next(iter(trimmed.values()))) == MAX_KEYS_PER_TAG

    def test_colliding_rrsig_tags_are_capped(self) -> None:
        from recursive_resolver.dnssec import MAX_RRSIGS_PER_TAG, _trim_rrsigs

        sigs = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        # Same key tag, distinct signature bytes so the RRset does not dedupe.
        for i in range(6):
            sigs.add(
                dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    f"A 8 2 300 20990101000000 20200101000000 777 evil.test. {'A' * 4}{'BCDE'[i % 4]}{i}==",
                )
            )
        assert len(_trim_rrsigs(sigs)) == MAX_RRSIGS_PER_TAG

    def test_unhashable_name_is_skipped_in_the_no_ds_proof(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "NS")
        _stub_nsec(v, nsec3s=[n3])
        with patch("dns.dnssec.nsec3_hash", side_effect=ValueError("bad salt")):
            assert v.prove_no_ds(dns.name.from_text("child.example.com."), [], {}) is False

    def test_undecodable_next_hash_in_covering(self) -> None:
        """A next-hashed-owner that is not decodable must fail closed."""

        class _BadRdata:
            next = "not-bytes"  # b32encode expects bytes and will raise
            salt = "AABBCCDD"
            iterations = 10
            algorithm = 1
            flags = 0

        class _BadRRset:
            name = dns.name.from_text("AAAA.example.com.")

            def __getitem__(self, index):
                return _BadRdata()

        v = DNSSECValidator()
        assert v._nsec3_covers(dns.name.from_text("x.example.com."), _BadRRset(), _BadRdata()) is False

    def test_nxdomain_where_the_qname_is_its_own_closest_encloser(self) -> None:
        """No next-closer name exists, so no NXDOMAIN proof is possible."""
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "A")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nxdomain(qname, [], {}) is ValidationState.BOGUS


class TestOptOutNodataEdges:
    def test_no_closest_encloser_means_no_opt_out_proof(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "00000000000000000000000000000000", "11111111111111111111111111111111", "A")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    def test_qname_as_its_own_closest_encloser_has_no_next_closer(self) -> None:
        """A matching NSEC3 that does list the type: no NODATA, no opt-out either."""
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "A MX RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is ValidationState.BOGUS

    def test_next_closer_not_covered_by_any_opt_out_record(self) -> None:
        """A closest encloser exists but nothing opts the next-closer name out."""
        v = DNSSECValidator()
        qname = dns.name.from_text("deep.sub.example.com.")
        apex = dns.name.from_text("example.com.")
        apex_hash = dns.dnssec.nsec3_hash(apex, "AABBCCDD", 10, 1)
        # Matches the closest encloser, but its interval is empty and it has no
        # opt-out flag, so the next-closer name is never covered.
        n3 = _nsec3("example.com.", apex_hash, _successor(apex_hash), "A RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is ValidationState.BOGUS


class TestWildcardProofNSEC3:
    """The NSEC3 half of the RFC 4035 §5.3.4 wildcard proof.

    ``.com``, ``.net`` and ``.org`` are NSEC3 zones, so this is the path most
    real wildcard answers take.
    """

    QNAME = dns.name.from_text("anything.example.test.")
    LABELS = 2  # the answer came from *.example.test.

    def test_a_covering_nsec3_proves_the_expansion(self) -> None:
        v = DNSSECValidator()
        covering = _nsec3(
            "example.test.", "00000000000000000000000000000000", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG"
        )
        _stub_nsec(v, nsec3s=[covering])
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is ValidationState.SECURE

    def test_an_opt_out_cover_cannot_authenticate_the_expansion(self) -> None:
        """Opt-out denies signed delegations, not existence (RFC 5155 §6).

        Found in a signed TLD zone whose wildcard answers come with a single
        opt-out NSEC3: four independent public validators all return that data
        with AD unset. Accepting it as SECURE would let a replayed wildcard
        RRset override the real contents of any name inside an opt-out span.
        """
        v = DNSSECValidator()
        covering = _nsec3(
            "example.test.",
            "00000000000000000000000000000000",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "A RRSIG",
            flags=1,
        )
        _stub_nsec(v, nsec3s=[covering])
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is ValidationState.INSECURE

    def test_a_non_opt_out_cover_alongside_an_opt_out_one_still_proves_it(self) -> None:
        v = DNSSECValidator()
        opt_out = _nsec3(
            "example.test.", "00000000000000000000000000000000", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG", flags=1
        )
        solid = _nsec3(
            "example.test.", "00000000000000000000000000000000", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG"
        )
        _stub_nsec(v, nsec3s=[opt_out, solid])
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is ValidationState.SECURE

    def test_an_nsec3_matching_the_next_closer_is_not_covering_it(self) -> None:
        """A record whose owner IS the hash proves the name exists, not that it does not."""
        v = DNSSECValidator()
        digest = dns.dnssec.nsec3_hash(self.QNAME, "AABBCCDD", 10, 1)
        matching = _nsec3("example.test.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG")
        _stub_nsec(v, nsec3s=[matching])
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is ValidationState.BOGUS

    def test_no_denial_records_at_all_proves_nothing(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v)
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is ValidationState.BOGUS

    def test_a_labels_count_leaving_no_next_closer_is_refused(self) -> None:
        """labels >= the owner's label count is not a wildcard expansion at all."""
        v = DNSSECValidator()
        covering = _nsec3(
            "example.test.", "00000000000000000000000000000000", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG"
        )
        _stub_nsec(v, nsec3s=[covering])
        assert v.prove_wildcard(self.QNAME, 3, [], {}) is ValidationState.BOGUS


class TestNSEC3NXDOMAINProof:
    """RFC 5155 §8.4 needs three things, and dropping any one must fail.

    `.com`, `.net` and `.org` are NSEC3 zones, so this is the path most real
    NXDOMAIN proofs take. Only the NSEC variant was covered before.
    """

    ZONE = "example.com."
    QNAME = dns.name.from_text("missing.example.com.")
    SALT, ITER, ALG = "AABBCCDD", 10, 1

    def _hash(self, name: str, iterations: int | None = None) -> str:
        return dns.dnssec.nsec3_hash(
            dns.name.from_text(name), self.SALT, self.ITER if iterations is None else iterations, self.ALG
        )

    def _matching(self, name: str, iterations: int | None = None):
        """An NSEC3 whose owner IS the hash of ``name``: proof it exists."""
        iterations = self.ITER if iterations is None else iterations
        digest = self._hash(name, iterations)
        return _nsec3(self.ZONE, digest, _successor(digest), "NS SOA RRSIG DNSKEY NSEC3PARAM", iterations=iterations)

    def _covering(self, name: str, iterations: int | None = None):
        """An NSEC3 spanning exactly the hash of ``name``: proof it does not exist."""
        iterations = self.ITER if iterations is None else iterations
        digest = self._hash(name, iterations)
        return _nsec3(self.ZONE, _predecessor(digest), _successor(digest), "A RRSIG", iterations=iterations)

    def _complete_proof(self, iterations: int | None = None) -> list:
        return [
            self._matching("example.com.", iterations),
            self._covering("missing.example.com.", iterations),
            self._covering("*.example.com.", iterations),
        ]

    def test_a_complete_proof_is_accepted(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(
            v,
            nsec3s=[
                self._matching("example.com."),  # closest encloser
                self._covering("missing.example.com."),  # next closer absent
                self._covering("*.example.com."),  # no wildcard either
            ],
        )
        assert v.prove_nxdomain(self.QNAME, [], {}) is ValidationState.SECURE

    def test_without_the_next_closer_covered_it_is_refused(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._matching("example.com."), self._covering("*.example.com.")])
        assert v.prove_nxdomain(self.QNAME, [], {}) is ValidationState.BOGUS

    def test_without_the_wildcard_covered_it_is_refused(self) -> None:
        """Otherwise a name a wildcard would have answered is denied as nonexistent."""
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._matching("example.com."), self._covering("missing.example.com.")])
        assert v.prove_nxdomain(self.QNAME, [], {}) is ValidationState.BOGUS

    def test_without_a_closest_encloser_it_is_refused(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._covering("missing.example.com."), self._covering("*.example.com.")])
        assert v.prove_nxdomain(self.QNAME, [], {}) is ValidationState.BOGUS

    def test_an_absurd_iteration_count_is_refused_despite_a_complete_proof(self) -> None:
        """The cap must be what fails this, not a missing part of the proof.

        The hashes are recomputed at each iteration count, so both proofs are
        genuinely complete and only the cap differs between them.
        """

        def attempt(iterations: int) -> ValidationState:
            v = DNSSECValidator()
            _stub_nsec(v, nsec3s=self._complete_proof(iterations))
            return v.prove_nxdomain(self.QNAME, [], {})

        assert attempt(self.ITER) is ValidationState.SECURE
        assert attempt(MAX_NSEC3_ITERATIONS + 1) is ValidationState.BOGUS


class TestNSEC3IterationCapActuallyBites:
    """Each cap must be what rejects the proof, not a coincidentally broken one.

    The earlier cap test asserted only ``not proven`` on input that failed for
    an unrelated reason, so removing the cap left it green. These assert the
    proof succeeds at a sane iteration count and fails at an absurd one, with
    nothing else changed.
    """

    ZONE = "example.com."
    SALT, ALG = "AABBCCDD", 1

    def _digest(self, name: str, iterations: int) -> str:
        return dns.dnssec.nsec3_hash(dns.name.from_text(name), self.SALT, iterations, self.ALG)

    def test_prove_no_ds_cap(self) -> None:
        child = dns.name.from_text("child.example.com.")

        def attempt(iterations: int) -> bool:
            v = DNSSECValidator()
            digest = self._digest("child.example.com.", iterations)
            n3 = _nsec3(self.ZONE, digest, _successor(digest), "NS RRSIG", iterations=iterations)
            _stub_nsec(v, nsec3s=[n3])
            return v.prove_no_ds(child, [], {})

        assert attempt(10) is True
        assert attempt(MAX_NSEC3_ITERATIONS + 1) is False

    def test_prove_nodata_cap(self) -> None:
        qname = dns.name.from_text("nodata.example.com.")

        def attempt(iterations: int) -> ValidationState:
            v = DNSSECValidator()
            digest = self._digest("nodata.example.com.", iterations)
            n3 = _nsec3(self.ZONE, digest, _successor(digest), "A RRSIG", iterations=iterations)
            _stub_nsec(v, nsec3s=[n3])
            return v.prove_nodata(qname, dns.rdatatype.MX, [], {})

        assert attempt(10) is ValidationState.SECURE
        assert attempt(MAX_NSEC3_ITERATIONS + 1) is ValidationState.BOGUS

    def test_prove_wildcard_cap(self) -> None:
        """The wildcard proof hashes too, so it needs the same guard as the others."""
        qname = dns.name.from_text("anything.example.com.")

        def attempt(iterations: int) -> ValidationState:
            v = DNSSECValidator()
            covering = _nsec3(
                self.ZONE,
                "00000000000000000000000000000000",
                "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
                "A RRSIG",
                iterations=iterations,
            )
            _stub_nsec(v, nsec3s=[covering])
            return v.prove_wildcard(qname, 2, [], {})

        assert attempt(10) is ValidationState.SECURE
        assert attempt(MAX_NSEC3_ITERATIONS + 1) is ValidationState.BOGUS


class TestHighNSEC3IterationsDowngradeRatherThanFail:
    """RFC 9276 §3.2 leaves the choice open; the ecosystem picks insecure.

    Unbound, BIND, Knot and PowerDNS all treat an iteration count above their
    cap as a downgrade. Refusing outright makes a validly signed zone with a
    legacy count unresolvable here while everyone else still answers for it.
    The signature is verified first regardless (RFC 5155 §10.3), so the count
    cannot have been tampered with.
    """

    @staticmethod
    def _over_cap():
        return _nsec3("example.com.", "0" * 32, "V" * 32, "NS", iterations=MAX_NSEC3_ITERATIONS + 1)

    def test_the_check_reports_parameters_beyond_the_cap(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._over_cap()])
        assert v.nsec3_beyond_our_limits([], {}) is True

    def test_parameters_within_the_cap_are_fine(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[_nsec3("example.com.", "0" * 32, "V" * 32, "NS", iterations=10)])
        assert v.nsec3_beyond_our_limits([], {}) is False

    def test_no_nsec3_at_all_is_not_beyond_the_cap(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v)
        assert v.nsec3_beyond_our_limits([], {}) is False

    def test_a_delegation_we_cannot_evaluate_is_insecure_not_bogus(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._over_cap()])
        state, ds = v.validate_ds(dns.name.from_text("child.example.com."), [], {})
        assert (state, ds) == (ValidationState.INSECURE, None)

    def test_a_delegation_with_no_proof_at_all_is_still_bogus(self) -> None:
        """The downgrade must not swallow a missing proof."""
        v = DNSSECValidator()
        _stub_nsec(v)
        state, ds = v.validate_ds(dns.name.from_text("child.example.com."), [], {})
        assert (state, ds) == (ValidationState.BOGUS, None)
