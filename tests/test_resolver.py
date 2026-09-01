"""Unit tests for the recursive resolver (mocked DNS, no network)."""

from __future__ import annotations

import time
from unittest.mock import patch

import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from conftest import make_response, referral, root_to_com, sequence

from recursive_resolver import (
    CNAMELoopError,
    InvalidNameError,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    RecursiveResolver,
    ResolutionTimeoutError,
    ServfailError,
    TraceStep,
    UnsupportedRdtypeError,
    ValidationState,
)


def _resolver(**kwargs) -> RecursiveResolver:
    kwargs.setdefault("dnssec", False)
    kwargs.setdefault("cache_enabled", False)
    return RecursiveResolver(**kwargs)


def _chain(final: object) -> list:
    """root -> com -> example.com -> final."""
    return [
        (root_to_com(), "198.41.0.4"),
        (referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"),
        (final, "1.2.3.4"),
    ]


class TestBasicResolution:
    def test_simple_a_resolution(self) -> None:
        resolver = _resolver()
        responses = _chain(make_response(answer=[("example.com.", 300, "A", ["93.184.216.34"])]))
        with patch.object(resolver, "_send_query", side_effect=sequence(responses)):
            assert resolver.resolve("example.com", "A") == ["93.184.216.34"]

    def test_mx_resolution(self) -> None:
        resolver = _resolver()
        responses = _chain(make_response(answer=[("example.com.", 300, "MX", ["10 mail.example.com."])]))
        with patch.object(resolver, "_send_query", side_effect=sequence(responses)):
            assert resolver.resolve("example.com", "MX") == ["10 mail.example.com."]

    def test_nxdomain(self) -> None:
        resolver = _resolver()
        responses = [
            (root_to_com(), "198.41.0.4"),
            (make_response(rcode=dns.rcode.NXDOMAIN, aa=True), "192.5.6.30"),
        ]
        with patch.object(resolver, "_send_query", side_effect=sequence(responses)), pytest.raises(NXDOMAINError):
            resolver.resolve("nonexistent.com", "A")

    def test_nodata(self) -> None:
        resolver = _resolver()
        soa = make_response(
            authority=[("example.com.", 300, "SOA", ["ns1.example.com. a.example.com. 1 3600 900 604800 86400"])],
            aa=True,
        )
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(soa))), pytest.raises(NoAnswerError):
            resolver.resolve("example.com", "AAAA")

    def test_all_servers_timeout(self) -> None:
        resolver = _resolver()
        with patch.object(resolver, "_send_query", return_value=(None, "")), pytest.raises(ResolutionTimeoutError):
            resolver.resolve("example.com", "A")

    def test_max_depth(self) -> None:
        resolver = _resolver(max_depth=3)

        def send(qname, rdtype, nameservers, ctx):
            # Always descend one more label, never answer.
            zone = dns.name.from_text("sub." + str(qname))
            return referral(str(zone), ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(MaxDepthError):
            resolver.resolve("example.com", "A")


class TestCNAME:
    def test_cname_followed_across_zones(self) -> None:
        resolver = _resolver()

        def send(qname, rdtype, nameservers, ctx):
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            if nameservers == ["192.5.6.30"]:
                zone = "example.com." if str(qname).endswith("example.com.") else "other.com."
                return referral(zone, [f"ns1.{zone}"], {f"ns1.{zone}": "1.2.3.4"}), "192.5.6.30"
            if qname == dns.name.from_text("www.example.com."):
                return make_response(answer=[("www.example.com.", 300, "CNAME", ["target.other.com."])]), "1.2.3.4"
            return make_response(answer=[("target.other.com.", 300, "A", ["5.6.7.8"])]), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send):
            answer = resolver.resolve_answer("www.example.com", "A")
        assert answer.records == ["5.6.7.8"]
        assert answer.canonical_name == dns.name.from_text("target.other.com.")

    def test_inline_cname_target_avoids_a_second_walk(self) -> None:
        """A CNAME answered together with its target must not restart from root."""
        resolver = _resolver()
        inline = make_response(
            answer=[
                ("www.example.com.", 300, "CNAME", ["cdn.example.com."]),
                ("cdn.example.com.", 300, "A", ["9.9.9.9"]),
            ]
        )
        responses = [
            (root_to_com(), "198.41.0.4"),
            (referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"),
            (inline, "1.2.3.4"),
        ]
        side_effect = sequence(responses)
        calls = 0

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return side_effect(*args, **kwargs)

        with patch.object(resolver, "_send_query", side_effect=counting):
            answer = resolver.resolve_answer("www.example.com", "A")

        assert answer.records == ["9.9.9.9"]
        assert calls == 3, "should not have re-walked from the root"

    def test_an_inline_cname_target_is_cached_under_its_own_name(self) -> None:
        """The target was answered authoritatively, so it is worth keeping.

        Caching it under the target's name rather than the queried one is what
        lets a later lookup of the target itself hit, and it is the reason the
        second walk can be skipped at all.
        """
        resolver = _resolver(cache_enabled=True)
        inline = make_response(
            answer=[
                ("www.example.com.", 300, "CNAME", ["cdn.example.com."]),
                ("cdn.example.com.", 300, "A", ["9.9.9.9"]),
            ]
        )
        responses = [
            (root_to_com(), "198.41.0.4"),
            (referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"),
            (inline, "1.2.3.4"),
        ]
        with patch.object(resolver, "_send_query", side_effect=sequence(responses)):
            assert resolver.resolve("www.example.com", "A") == ["9.9.9.9"]

        assert resolver.cache is not None
        cached = resolver.cache.get_answer(dns.name.from_text("cdn.example.com."), dns.rdatatype.A)
        assert cached is not None, "the inline target was not cached"
        # No further queries: the target now answers straight from the cache.
        with patch.object(resolver, "_send_query", side_effect=AssertionError("should not query")):
            assert resolver.resolve("cdn.example.com", "A") == ["9.9.9.9"]

    def test_cname_loop_detected(self) -> None:
        resolver = _resolver(max_cname_chain=5)

        def send(qname, rdtype, nameservers, ctx):
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            if nameservers == ["192.5.6.30"]:
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"
            target = "b.example.com." if str(qname).startswith("a.") else "a.example.com."
            return make_response(answer=[(str(qname), 300, "CNAME", [target])]), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(CNAMELoopError):
            resolver.resolve("a.example.com", "A")

    def test_nxdomain_with_cname_follows_the_cname(self) -> None:
        """Some servers return NXDOMAIN plus a CNAME whose target is elsewhere."""
        resolver = _resolver()

        def send(qname, rdtype, nameservers, ctx):
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            if nameservers == ["192.5.6.30"]:
                zone = "example.com." if str(qname).endswith("example.com.") else "other.com."
                return referral(zone, [f"ns1.{zone}"], {f"ns1.{zone}": "1.2.3.4"}), "192.5.6.30"
            if qname == dns.name.from_text("sub.example.com."):
                return (
                    make_response(
                        rcode=dns.rcode.NXDOMAIN,
                        answer=[("sub.example.com.", 300, "CNAME", ["target.other.com."])],
                    ),
                    "1.2.3.4",
                )
            return make_response(answer=[("target.other.com.", 300, "A", ["5.6.7.8"])]), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("sub.example.com", "A") == ["5.6.7.8"]


class TestInputValidation:
    """Bad input must raise a precise error, never a spurious timeout."""

    @pytest.mark.parametrize(
        "name",
        ["a" * 64 + ".com", "foo..com", "", "   "],
    )
    def test_invalid_names_raise_invalid_name_error(self, name: str) -> None:
        resolver = _resolver()
        with pytest.raises(InvalidNameError):
            resolver.resolve(name, "A")

    def test_name_too_long(self) -> None:
        resolver = _resolver()
        with pytest.raises(InvalidNameError):
            resolver.resolve(".".join(["abcdefghij"] * 30), "A")

    @pytest.mark.parametrize(
        "rdtype",
        [
            "BOGUSTYPE",
            "",
            "TXTT",
            # "TYPEnnnnn" parses as a generic type but is range-checked
            # separately, so dnspython raises a bare ValueError here rather
            # than UnknownRdatatype. Nothing from dnspython may escape.
            "TYPE70000",
            "TYPE99999",
        ],
    )
    def test_unknown_rdtype_raises(self, rdtype: str) -> None:
        resolver = _resolver()
        with pytest.raises(UnsupportedRdtypeError):
            resolver.resolve("example.com", rdtype)

    def test_invalid_input_makes_no_queries(self) -> None:
        resolver = _resolver()
        with patch.object(resolver, "_send_query") as send, pytest.raises(InvalidNameError):
            resolver.resolve("foo..com", "A")
        send.assert_not_called()

    def test_idna_2008_is_used(self) -> None:
        """IDNA 2003 maps 'ß' to 'ss', resolving an entirely different domain."""
        resolver = _resolver()
        name = resolver._normalize_qname("straße.de", "A")
        assert str(name) == "xn--strae-oqa.de.", f"got {name} (IDNA 2003 would give strasse.de.)"

    def test_unicode_and_punycode_agree(self) -> None:
        resolver = _resolver()
        assert resolver._normalize_qname("bücher.de", "A") == resolver._normalize_qname("xn--bcher-kva.de", "A")

    def test_ptr_auto_reverse(self) -> None:
        resolver = _resolver()
        assert str(resolver._normalize_qname("8.8.8.8", "PTR")) == "8.8.8.8.in-addr.arpa."

    def test_ptr_ipv6_auto_reverse(self) -> None:
        resolver = _resolver()
        assert str(resolver._normalize_qname("2001:4860:4860::8888", "PTR")).endswith("ip6.arpa.")

    def test_ptr_passthrough_for_arpa_names(self) -> None:
        resolver = _resolver()
        assert str(resolver._normalize_qname("8.8.8.8.in-addr.arpa", "PTR")) == "8.8.8.8.in-addr.arpa."


class TestAnswerAPI:
    """The Answer object, especially the DKIM-critical TXT handling."""

    def test_text_values_concatenates_chunks_without_separator(self) -> None:
        """RFC 6376: multi-chunk TXT strings join with no separator."""
        resolver = _resolver()
        long_key = "v=DKIM1; k=rsa; p=" + "A" * 230
        second = "B" * 100
        response = make_response(answer=[("s._domainkey.example.com.", 300, "TXT", [f'"{long_key}" "{second}"'])])
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(response))):
            answer = resolver.resolve_answer("s._domainkey.example.com", "TXT")

        assert answer.text_values() == [long_key + second]
        # Presentation format keeps the seam, which is exactly the DKIM trap.
        assert '" "' in answer.records[0]

    def test_text_values_rejects_non_character_string_types(self) -> None:
        resolver = _resolver()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(response))):
            answer = resolver.resolve_answer("example.com", "A")
        with pytest.raises(TypeError):
            answer.text_values()

    def test_resolve_rrset_returns_raw_rdata(self) -> None:
        resolver = _resolver()
        response = make_response(answer=[("example.com.", 300, "TXT", ['"chunk-a" "chunk-b"'])])
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(response))):
            rrset = resolver.resolve_rrset("example.com", "TXT")
        assert rrset[0].strings == (b"chunk-a", b"chunk-b")

    def test_answer_reports_dnssec_state(self) -> None:
        resolver = _resolver()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(response))):
            answer = resolver.resolve_answer("example.com", "A")
        assert answer.dnssec is ValidationState.INSECURE
        assert answer.secure is False
        assert answer.ttl == 300


class TestTrace:
    def test_trace_records_every_step(self) -> None:
        resolver = _resolver()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(response))):
            _, trace = resolver.trace_answer("example.com", "A")
        assert [s.response_type for s in trace] == ["referral", "referral", "answer"]
        assert all(isinstance(s, TraceStep) for s in trace)
        assert trace[0].zone == "."

    def test_trace_answer_returns_both(self) -> None:
        """Regression: the trace API used to throw the answer away."""
        resolver = _resolver()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
        with patch.object(resolver, "_send_query", side_effect=sequence(_chain(response))):
            answer, trace = resolver.trace_answer("example.com", "A")
        assert answer is not None
        assert answer.records == ["1.2.3.4"]
        assert len(trace) == 3

    def test_trace_survives_failure(self) -> None:
        resolver = _resolver()
        responses = [
            (root_to_com(), "198.41.0.4"),
            (make_response(rcode=dns.rcode.NXDOMAIN, aa=True), "192.5.6.30"),
        ]
        with patch.object(resolver, "_send_query", side_effect=sequence(responses)):
            answer, trace = resolver.trace_answer("nope.com", "A")
        assert answer is None
        assert trace[-1].response_type == "nxdomain"


class TestGlueless:
    def test_glueless_referral_resolves_ns_hostname(self) -> None:
        resolver = _resolver()

        def send(qname, rdtype, nameservers, ctx):
            if qname == dns.name.from_text("ns1.otherdns.net."):
                return make_response(answer=[("ns1.otherdns.net.", 300, "A", ["9.9.9.9"])]), "1.1.1.1"
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            if nameservers == ["192.5.6.30"]:
                return referral("example.com.", ["ns1.otherdns.net."]), "192.5.6.30"
            return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])]), nameservers[0]

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("example.com", "A") == ["1.2.3.4"]

    def test_all_glueless_ns_failing_raises_servfail(self) -> None:
        resolver = _resolver()

        def send(qname, rdtype, nameservers, ctx):
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            if nameservers == ["192.5.6.30"]:
                return referral("example.com.", ["ns1.broken.net."]), "192.5.6.30"
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ServfailError):
            resolver.resolve("example.com", "A")

    def test_a_budget_that_runs_out_mid_referral_is_a_timeout_not_a_servfail(self) -> None:
        """Same empty result, two causes. Reporting the wrong one hides the reason."""
        resolver = _resolver()

        def send(qname, rdtype, nameservers, ctx):
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            if nameservers == ["192.5.6.30"]:
                # Spend the budget just as the glueless names come up.
                ctx.budget.deadline = time.monotonic() - 1
                return referral("example.com.", ["ns1.broken.net."]), "192.5.6.30"
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolutionTimeoutError):
            resolver.resolve("example.com", "A")


class TestNXDOMAINRetry:
    def test_sibling_nameserver_is_tried_before_accepting_nxdomain(self) -> None:
        resolver = _resolver()
        calls = 0

        def send(qname, rdtype, nameservers, ctx):
            nonlocal calls
            calls += 1
            if calls == 1:
                return (
                    referral("ir.", ["a.nic.ir.", "b.nic.ir."], {"a.nic.ir.": "1.1.1.1", "b.nic.ir.": "2.2.2.2"}),
                    "198.41.0.4",
                )
            if calls == 2:
                return make_response(rcode=dns.rcode.NXDOMAIN, aa=True), "1.1.1.1"
            if calls == 3:
                return referral("example.ir.", ["ns1.example.ir."], {"ns1.example.ir.": "3.3.3.3"}), "2.2.2.2"
            return make_response(answer=[("example.ir.", 300, "A", ["4.4.4.4"])]), "3.3.3.3"

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("example.ir", "A") == ["4.4.4.4"]


class TestDeadline:
    def test_deadline_aborts_slow_resolution(self) -> None:
        import time as _time

        resolver = _resolver(max_resolution_time=0.4, timeout=5.0)

        def slow(qname, rdtype, nameservers, ctx):
            _time.sleep(0.25)
            return root_to_com(), "198.41.0.4"

        with patch.object(resolver, "_send_query", side_effect=slow), pytest.raises(ResolutionTimeoutError):
            resolver.resolve("example.com", "A")

    def test_effective_timeout_is_clamped_to_the_deadline(self) -> None:
        resolver = _resolver(timeout=5.0, max_resolution_time=1.0)
        ctx = resolver._new_context()
        assert 0 < resolver._effective_timeout(ctx) <= 1.01


class TestCacheHitsReportRemainingLifetime:
    """A cache hit must report what is left, not the TTL it arrived with.

    A caller that re-caches on the reported value would otherwise extend the
    lifetime on every hit, and for authenticated data that means outliving the
    signature the TTL was capped to.
    """

    def test_the_reported_ttl_counts_down(self) -> None:
        resolver = _resolver(cache_enabled=True)
        rrset = dns.rrset.from_text("a.test.", 300, "IN", "A", "1.2.3.4")
        assert resolver.cache is not None
        resolver.cache.put_answer("a.test.", "A", rrset, 300)
        first = resolver._check_cache(dns.name.from_text("a.test."), dns.rdatatype.A)
        assert first is not None and first.ttl <= 300
        entry = resolver.cache.get_answer("a.test.", "A")
        assert entry is not None
        # Age the entry by rewriting its expiry, then look again.
        with resolver.cache._lock:
            key = ("A", dns.name.from_text("a.test."), int(dns.rdatatype.A), dns.rdataclass.IN)
            resolver.cache._cache[key].expiry -= 250
        later = resolver._check_cache(dns.name.from_text("a.test."), dns.rdatatype.A)
        assert later is not None
        assert later.ttl < first.ttl, "the reported TTL did not count down"
        assert later.ttl <= 50


class TestDNAME:
    """RFC 6672. Two MUSTs: §3.4 "Recursive caching name servers MUST perform
    CNAME synthesis on behalf of clients", and §8 "A validating resolver MUST
    understand DNAME"."""

    QNAME = "foo.sub.example.com."

    @staticmethod
    def _dname(owner: str = "sub.example.com.", target: str = "target.example.com.", ttl: int = 300):
        return (owner, ttl, "DNAME", [target])

    def _chain_to(self, first, final_name="foo.target.example.com."):
        return [
            (root_to_com(), "198.41.0.4"),
            (referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"),
            (first, "1.2.3.4"),
            (make_response(answer=[(final_name, 300, "A", ["192.0.2.9"])]), "1.2.3.4"),
        ]

    def test_a_dname_alone_is_followed(self) -> None:
        """The server sent no synthesized CNAME, so we make one ourselves."""
        resolver = _resolver()
        responses = self._chain_to(make_response(answer=[self._dname()]))
        with patch.object(resolver, "_send_query", side_effect=sequence(responses)):
            answer = resolver.resolve_answer(self.QNAME, "A")
        assert answer.records == ["192.0.2.9"]
        assert answer.canonical_name == dns.name.from_text("foo.target.example.com.")

    def test_a_dname_with_the_servers_synthesized_cname_is_followed(self) -> None:
        first = make_response(answer=[self._dname(), (self.QNAME, 300, "CNAME", ["foo.target.example.com."])])
        resolver = _resolver()
        with patch.object(resolver, "_send_query", side_effect=sequence(self._chain_to(first))):
            assert resolver.resolve(self.QNAME, "A") == ["192.0.2.9"]

    def test_the_substitution_replaces_only_the_dname_owners_labels(self) -> None:
        resolver = _resolver()
        rrset = dns.rrset.from_text("sub.example.com.", 300, "IN", "DNAME", "target.example.com.")
        assert resolver._dname_target(dns.name.from_text("a.b.sub.example.com."), rrset) == dns.name.from_text(
            "a.b.target.example.com."
        )

    def test_a_dname_does_not_apply_to_its_own_owner(self) -> None:
        """RFC 6672 §2.4: the owner name itself is not rewritten."""
        resolver = _resolver()
        response = make_response(answer=[self._dname()])
        assert (
            resolver._find_dname(response, dns.name.from_text("sub.example.com."), dns.name.from_text("example.com."))
            is None
        )

    def test_an_out_of_bailiwick_dname_is_ignored(self) -> None:
        """A DNAME rewrites a whole subtree; only the zone that holds it may."""
        resolver = _resolver()
        response = make_response(answer=[("sub.elsewhere.test.", 300, "DNAME", ["t.elsewhere.test."])])
        assert (
            resolver._find_dname(
                response, dns.name.from_text("foo.sub.elsewhere.test."), dns.name.from_text("example.com.")
            )
            is None
        )

    def test_the_longest_matching_dname_wins(self) -> None:
        resolver = _resolver()
        response = make_response(
            answer=[self._dname("example.com.", "a.test."), self._dname("sub.example.com.", "b.test.")]
        )
        found = resolver._find_dname(
            response, dns.name.from_text("foo.sub.example.com."), dns.name.from_text("example.com.")
        )
        assert found is not None and found.name == dns.name.from_text("sub.example.com.")

    def test_a_substitution_that_overflows_a_name_is_not_applied(self) -> None:
        """RFC 6672 §3.4.1: an over-long result is a YXDOMAIN, not a redirect."""
        resolver = _resolver()
        long_target = ".".join("x" * 60 for _ in range(4)) + ".test."
        rrset = dns.rrset.from_text("sub.example.com.", 300, "IN", "DNAME", long_target)
        deep = dns.name.from_text(".".join("y" * 60 for _ in range(3)) + ".sub.example.com.")
        assert resolver._dname_target(deep, rrset) is None

    def test_the_synthesized_cname_carries_the_dnames_ttl(self) -> None:
        """RFC 6672 §3.1."""
        resolver = _resolver()
        rrset = dns.rrset.from_text("sub.example.com.", 77, "IN", "DNAME", "target.example.com.")
        synthesized = resolver._synthesize_cname(
            dns.name.from_text(self.QNAME), dns.name.from_text("foo.target.example.com."), rrset
        )
        assert synthesized.ttl == 77
        assert synthesized[0].target == dns.name.from_text("foo.target.example.com.")


class TestANYIsRefused:
    def test_resolve_for_any_raises(self) -> None:
        """Silently answering NODATA also cached a denial for every type."""
        with pytest.raises(UnsupportedRdtypeError, match="ANY cannot be queried"):
            _resolver().resolve("example.com", "ANY")

    def test_nothing_is_cached_by_the_refusal(self) -> None:
        resolver = _resolver(cache_enabled=True)
        with pytest.raises(UnsupportedRdtypeError):
            resolver.resolve("example.com", "ANY")
        assert resolver.cache is not None and len(resolver.cache) == 0


class TestNonDelegatingNSSetIsAnError:
    """An NS set pointing sideways or upwards is a redirection, not a denial."""

    def test_an_upward_ns_set_is_not_nodata(self) -> None:
        resolver = _resolver(require_authoritative=False)
        response = make_response(authority=[("com.", 300, "NS", ["ns1.gtld.test."])], aa=True)
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.A, dns.name.from_text("example.com.")
        )
        assert classification["type"] == "error"

    def test_a_delegation_at_the_qname_is_still_nodata_for_a_ds(self) -> None:
        """The parent handing back the child's NS set with no DS beside it."""
        resolver = _resolver()
        response = make_response(authority=[("example.com.", 300, "NS", ["ns1.example.com."])], aa=True)
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.DS, dns.name.from_text("com.")
        )
        assert classification["type"] == "nodata"


class TestNegativeAnswerSOAMustBelongToTheZone:
    def test_an_soa_from_above_the_zone_does_not_mark_a_negative_answer(self) -> None:
        resolver = _resolver()
        response = make_response(authority=[("com.", 300, "SOA", ["ns.com. a.com. 1 2 3 4 60"])], aa=True)
        assert (
            resolver._marks_negative(
                response.authority[0], dns.name.from_text("example.com."), dns.name.from_text("example.com.")
            )
            is False
        )
        assert (
            resolver._negative_ttl(response, dns.name.from_text("example.com."), dns.name.from_text("example.com."))
            is None
        )

    def test_the_zones_own_soa_does(self) -> None:
        resolver = _resolver()
        response = make_response(
            authority=[("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 2 3 4 60"])], aa=True
        )
        assert (
            resolver._negative_ttl(response, dns.name.from_text("example.com."), dns.name.from_text("example.com."))
            == 60
        )


class TestGlueTTLBoundsTheDelegation:
    """Addresses expire with the glue that carried them, not with the NS set."""

    def test_short_lived_glue_shortens_the_cached_delegation(self) -> None:
        resolver = _resolver(cache_enabled=True)
        response = make_response(
            authority=[("example.com.", 86400, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 60, "A", ["1.2.3.4"])],
            aa=False,
        )
        resolver._cache_delegation(
            dns.name.from_text("example.com."),
            [dns.name.from_text("ns1.example.com.")],
            ["1.2.3.4"],
            response,
            ValidationState.INSECURE,
        )
        assert resolver.cache is not None
        delegation = resolver.cache.get_delegation(dns.name.from_text("example.com."))
        assert delegation is not None
        entry = resolver.cache._cache[("DG", dns.name.from_text("example.com."), 0, 0)]
        import time as _time

        assert entry.expiry - _time.monotonic() <= 61, "the day-long NS TTL outlived the minute-long glue"

    def test_long_lived_glue_leaves_the_ns_ttl_alone(self) -> None:
        resolver = _resolver(cache_enabled=True)
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 86400, "A", ["1.2.3.4"])],
            aa=False,
        )
        resolver._cache_delegation(
            dns.name.from_text("example.com."),
            [dns.name.from_text("ns1.example.com.")],
            ["1.2.3.4"],
            response,
            ValidationState.INSECURE,
        )
        assert resolver.cache is not None
        entry = resolver.cache._cache[("DG", dns.name.from_text("example.com."), 0, 0)]
        import time as _time

        assert 290 < entry.expiry - _time.monotonic() <= 300


class TestGluelessNSUsesBothFamilies:
    def test_aaaa_is_queried_when_ipv6_is_allowed(self) -> None:
        resolver = _resolver(ipv4_only=False)
        ctx = resolver._new_context()
        asked: list[str] = []

        def resolve_iterative(name, rdtype, ctx_, depth, chain):
            asked.append(dns.rdatatype.to_text(rdtype))
            raise NoAnswerError(str(name), dns.rdatatype.to_text(rdtype))

        with patch.object(resolver, "_resolve_iterative", side_effect=resolve_iterative):
            resolver._resolve_ns_names([dns.name.from_text("ns1.example.com.")], ctx, 1, limit=5)
        assert asked == ["A", "AAAA"]

    def test_only_a_is_queried_by_default(self) -> None:
        resolver = _resolver()
        ctx = resolver._new_context()
        asked: list[str] = []

        def resolve_iterative(name, rdtype, ctx_, depth, chain):
            asked.append(dns.rdatatype.to_text(rdtype))
            raise NoAnswerError(str(name), dns.rdatatype.to_text(rdtype))

        with patch.object(resolver, "_resolve_iterative", side_effect=resolve_iterative):
            resolver._resolve_ns_names([dns.name.from_text("ns1.example.com.")], ctx, 1, limit=5)
        assert asked == ["A"]


class TestClassificationEdges:
    """The branches the happy paths never reach."""

    def test_a_dname_whose_substitution_overflows_is_not_a_redirect(self) -> None:
        """Found, but unusable: fall through rather than redirect nowhere."""
        resolver = _resolver()
        long_target = ".".join("x" * 60 for _ in range(4)) + ".test."
        deep = ".".join("y" * 60 for _ in range(3)) + ".sub.example.com."
        response = make_response(
            answer=[("sub.example.com.", 300, "DNAME", [long_target])],
            authority=[("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 2 3 4 60"])],
            aa=True,
        )
        classification = resolver._classify_response(
            response, dns.name.from_text(deep), dns.rdatatype.A, dns.name.from_text("example.com.")
        )
        assert classification["type"] == "nodata"

    def test_an_empty_authoritative_response_is_nodata(self) -> None:
        """No answer, no CNAME, no DNAME, no SOA, no NS set."""
        resolver = _resolver()
        classification = resolver._classify_response(
            make_response(aa=True),
            dns.name.from_text("example.com."),
            dns.rdatatype.A,
            dns.name.from_text("example.com."),
        )
        assert classification["type"] == "nodata"

    def test_an_empty_non_authoritative_response_is_an_error(self) -> None:
        """Nothing in it, and no authority to say so."""
        resolver = _resolver()
        classification = resolver._classify_response(
            make_response(aa=False),
            dns.name.from_text("example.com."),
            dns.rdatatype.A,
            dns.name.from_text("example.com."),
        )
        assert classification["type"] == "error"
        assert "without AA bit" in classification["detail"]

    def test_a_shorter_dname_does_not_displace_a_longer_one(self) -> None:
        resolver = _resolver()
        response = make_response(
            answer=[
                ("sub.example.com.", 300, "DNAME", ["b.test."]),
                ("example.com.", 300, "DNAME", ["a.test."]),
            ]
        )
        found = resolver._find_dname(
            response, dns.name.from_text("foo.sub.example.com."), dns.name.from_text("example.com.")
        )
        assert found is not None and found.name == dns.name.from_text("sub.example.com.")

    def test_a_delegation_with_no_glue_keeps_the_ns_ttl(self) -> None:
        resolver = _resolver(cache_enabled=True)
        response = make_response(authority=[("example.com.", 300, "NS", ["ns1.elsewhere.test."])], aa=False)
        resolver._cache_delegation(
            dns.name.from_text("example.com."),
            [dns.name.from_text("ns1.elsewhere.test.")],
            ["1.2.3.4"],
            response,
            ValidationState.INSECURE,
        )
        assert resolver.cache is not None
        entry = resolver.cache._cache[("DG", dns.name.from_text("example.com."), 0, 0)]
        import time as _time

        assert 290 < entry.expiry - _time.monotonic() <= 300
