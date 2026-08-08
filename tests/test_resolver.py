"""Unit tests for the recursive resolver (mocked DNS, no network)."""

from __future__ import annotations

from unittest.mock import patch

import dns.name
import dns.rcode
import dns.rdatatype
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
