"""Unit tests for the DNSSEC validator (no network)."""

from __future__ import annotations

import base64
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
        assert v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.MX, [], {})

    def test_nodata_not_proven_when_the_type_is_present(self) -> None:
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "next.example.com. A MX RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert not v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.MX, [], {})

    def test_nodata_not_proven_when_a_cname_exists(self) -> None:
        """A CNAME at the name means the answer should have been a CNAME."""
        v = DNSSECValidator()
        nsec = rrset("example.com.", "NSEC", "next.example.com. CNAME RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [nsec] if rdtype == dns.rdatatype.NSEC else []
        )
        assert not v.prove_nodata(dns.name.from_text("example.com."), dns.rdatatype.MX, [], {})

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
        assert not v.prove_nxdomain(dns.name.from_text("b.example.com."), [], {})

    def test_nxdomain_proven_with_both_denials(self) -> None:
        v = DNSSECValidator()
        covering = rrset("a.example.com.", "NSEC", "c.example.com. A RRSIG NSEC")
        wildcard = rrset("!.example.com.", "NSEC", "+.example.com. A RRSIG NSEC")
        v._validated_nsec_rrsets = lambda authority, keys, rdtype, budget=None: (  # type: ignore[method-assign]
            [covering, wildcard] if rdtype == dns.rdatatype.NSEC else []
        )
        assert v.prove_nxdomain(dns.name.from_text("b.example.com."), [], {})

    def test_unsigned_authority_proves_nothing(self) -> None:
        v = DNSSECValidator()
        assert not v.prove_nxdomain(dns.name.from_text("b.example.com."), [], {})
        assert not v.prove_nodata(dns.name.from_text("b.example.com."), dns.rdatatype.A, [], {})
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

    def test_signature_validations_are_charged_to_the_budget(self) -> None:
        from recursive_resolver.budget import QueryBudget
        from recursive_resolver.dnssec import MAX_RRSIGS_PER_RRSET

        v = DNSSECValidator()
        data = rrset("evil.test.", "A", "1.2.3.4")
        sigs = dns.rrset.RRset(dns.name.from_text("evil.test."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        for tag in range(50):
            sigs.add(
                dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    f"A 8 2 300 20990101000000 20200101000000 {tag} evil.test. AAAA",
                )
            )
        budget = QueryBudget()
        keys = {dns.name.from_text("evil.test."): self._dnskey_rrset(40)}
        assert v.validate_rrset(data, sigs, keys, budget=budget) is False
        assert 0 < budget.signature_validations <= MAX_RRSIGS_PER_RRSET

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
        """.com uses NSEC3 opt-out; the child's hash is merely covered."""
        v = DNSSECValidator()
        child = dns.name.from_text("child.example.com.")
        digest = dns.dnssec.nsec3_hash(child, "AABBCCDD", 10, 1)
        lo = "0" * 32
        hi = "V" * 32
        assert lo < digest < hi
        n3 = _nsec3("example.com.", lo, hi, "NS", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_no_ds(child, [], {}) is True

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
        assert v.prove_nxdomain(dns.name.from_text("zz.example.com."), [], {}) is False

    def test_nsec3_iteration_cap(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "A", iterations=MAX_NSEC3_ITERATIONS + 1)
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nxdomain(dns.name.from_text("x.example.com."), [], {}) is False

    def test_nsec3_without_a_closest_encloser(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "00000000000000000000000000000000", "11111111111111111111111111111111", "A")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nxdomain(dns.name.from_text("x.example.com."), [], {}) is False

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
        assert v.prove_nxdomain(qname, [], {}) is False

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
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.MX, [], {}) is False

    def test_nsec3_matching_record_without_the_type(self) -> None:
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is True

    def test_nsec3_matching_record_with_the_type_present(self) -> None:
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A MX RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is False

    def test_nsec3_iteration_cap(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "AAAA", "ZZZZ", "A", iterations=MAX_NSEC3_ITERATIONS + 1)
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.MX, [], {}) is False

    def test_nsec3_opt_out_covers_an_unsigned_delegation(self) -> None:
        v = DNSSECValidator()
        qname = dns.name.from_text("deep.sub.example.com.")
        apex = dns.name.from_text("example.com.")
        apex_hash = dns.dnssec.nsec3_hash(apex, "AABBCCDD", 10, 1)
        next_closer = dns.name.from_text("sub.example.com.")
        nc_hash = dns.dnssec.nsec3_hash(next_closer, "AABBCCDD", 10, 1)
        matching = _nsec3("example.com.", apex_hash, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG")
        lo, hi = "0" * 32, "V" * 32
        assert lo < nc_hash < hi
        covering = _nsec3("example.com.", lo, hi, "NS", flags=NSEC3_OPT_OUT)
        _stub_nsec(v, nsec3s=[matching, covering])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is True


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
        assert v.prove_nxdomain(qname, [], {}) is False


class TestOptOutNodataEdges:
    def test_no_closest_encloser_means_no_opt_out_proof(self) -> None:
        v = DNSSECValidator()
        n3 = _nsec3("example.com.", "00000000000000000000000000000000", "11111111111111111111111111111111", "A")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(dns.name.from_text("x.example.com."), dns.rdatatype.MX, [], {}) is False

    def test_qname_as_its_own_closest_encloser_has_no_next_closer(self) -> None:
        """A matching NSEC3 that does list the type: no NODATA, no opt-out either."""
        v = DNSSECValidator()
        qname = dns.name.from_text("x.example.com.")
        digest = dns.dnssec.nsec3_hash(qname, "AABBCCDD", 10, 1)
        n3 = _nsec3("example.com.", digest, _successor(digest), "A MX RRSIG")
        _stub_nsec(v, nsec3s=[n3])
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is False

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
        assert v.prove_nodata(qname, dns.rdatatype.MX, [], {}) is False


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
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is True

    def test_an_nsec3_matching_the_next_closer_is_not_covering_it(self) -> None:
        """A record whose owner IS the hash proves the name exists, not that it does not."""
        v = DNSSECValidator()
        digest = dns.dnssec.nsec3_hash(self.QNAME, "AABBCCDD", 10, 1)
        matching = _nsec3("example.test.", digest, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG")
        _stub_nsec(v, nsec3s=[matching])
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is False

    def test_no_denial_records_at_all_proves_nothing(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v)
        assert v.prove_wildcard(self.QNAME, self.LABELS, [], {}) is False

    def test_a_labels_count_leaving_no_next_closer_is_refused(self) -> None:
        """labels >= the owner's label count is not a wildcard expansion at all."""
        v = DNSSECValidator()
        covering = _nsec3(
            "example.test.", "00000000000000000000000000000000", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "A RRSIG"
        )
        _stub_nsec(v, nsec3s=[covering])
        assert v.prove_wildcard(self.QNAME, 3, [], {}) is False


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
        assert v.prove_nxdomain(self.QNAME, [], {}) is True

    def test_without_the_next_closer_covered_it_is_refused(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._matching("example.com."), self._covering("*.example.com.")])
        assert v.prove_nxdomain(self.QNAME, [], {}) is False

    def test_without_the_wildcard_covered_it_is_refused(self) -> None:
        """Otherwise a name a wildcard would have answered is denied as nonexistent."""
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._matching("example.com."), self._covering("missing.example.com.")])
        assert v.prove_nxdomain(self.QNAME, [], {}) is False

    def test_without_a_closest_encloser_it_is_refused(self) -> None:
        v = DNSSECValidator()
        _stub_nsec(v, nsec3s=[self._covering("missing.example.com."), self._covering("*.example.com.")])
        assert v.prove_nxdomain(self.QNAME, [], {}) is False

    def test_an_absurd_iteration_count_is_refused_despite_a_complete_proof(self) -> None:
        """The cap must be what fails this, not a missing part of the proof.

        The hashes are recomputed at each iteration count, so both proofs are
        genuinely complete and only the cap differs between them.
        """

        def attempt(iterations: int) -> bool:
            v = DNSSECValidator()
            _stub_nsec(v, nsec3s=self._complete_proof(iterations))
            return v.prove_nxdomain(self.QNAME, [], {})

        assert attempt(self.ITER) is True
        assert attempt(MAX_NSEC3_ITERATIONS + 1) is False


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

        def attempt(iterations: int) -> bool:
            v = DNSSECValidator()
            digest = self._digest("nodata.example.com.", iterations)
            n3 = _nsec3(self.ZONE, digest, _successor(digest), "A RRSIG", iterations=iterations)
            _stub_nsec(v, nsec3s=[n3])
            return v.prove_nodata(qname, dns.rdatatype.MX, [], {})

        assert attempt(10) is True
        assert attempt(MAX_NSEC3_ITERATIONS + 1) is False
