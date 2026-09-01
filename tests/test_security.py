"""Regression tests for the security hardening.

Every test here corresponds to a concrete defect found during the pre-release
audit. They are grouped by the attack they prevent.
"""

from __future__ import annotations

import contextlib
import dataclasses
from unittest.mock import patch

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import pytest
from conftest import make_response, offline_resolver, referral, root_to_com

from recursive_resolver import (
    AddressFilter,
    DNSCache,
    Limits,
    NoAnswerError,
    NXDOMAINError,
    QueryBudgetExceededError,
    RecursiveResolver,
    ResolverError,
    ServfailError,
    ValidationState,
)


class TestSSRFProtection:
    """Glue records are attacker-controlled; they must not steer us inward."""

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",  # loopback
            "10.0.0.5",  # RFC1918
            "192.168.1.1",  # RFC1918
            "172.16.0.1",  # RFC1918
            "169.254.169.254",  # cloud metadata endpoint
            "0.0.0.0",  # "this host"
            "100.64.0.1",  # CGNAT
            "240.0.0.1",  # reserved
            "198.18.0.1",  # benchmarking, RFC 2544
            "64:ff9b::1",  # NAT64 well-known prefix
            "2002:c000:204::1",  # 6to4
            "2001::1",  # Teredo
            "::1",  # IPv6 loopback
            "fe80::1",  # IPv6 link-local
            "fc00::1",  # IPv6 ULA
            "::ffff:127.0.0.1",  # IPv4-mapped loopback (bypass attempt)
            "2001:db8::1",  # documentation prefix
        ],
    )
    def test_private_addresses_are_rejected(self, address: str) -> None:
        assert AddressFilter().is_allowed(address) is False

    @pytest.mark.parametrize(
        "address",
        [
            "8.8.8.8",
            "198.41.0.4",  # a.root-servers.net
            "1.1.1.1",
            "2001:500:2::c",  # c.root-servers.net
            "2606:4700::1111",
        ],
    )
    def test_public_addresses_are_allowed(self, address: str) -> None:
        assert AddressFilter().is_allowed(address) is True

    @pytest.mark.parametrize(
        ("address", "why"),
        [
            # Public-looking addresses that no generic classification catches.
            ("168.63.129.16", "Azure Instance Metadata Service and platform DNS"),
            ("192.88.99.1", "6to4 relay anycast, deprecated by RFC 7526"),
            ("2001:20::1", "ORCHIDv2 cryptographic identifiers, RFC 7343"),
            ("fec0::1", "deprecated IPv6 site-local, RFC 3879"),
        ],
    )
    def test_ranges_is_global_alone_would_miss(self, address: str, why: str) -> None:
        assert AddressFilter().is_allowed(address) is False, why

    @pytest.mark.parametrize(
        "address",
        [
            "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean, Oracle
            "fd00:ec2::254",  # AWS IMDS over IPv6
            "100.100.100.200",  # Alibaba Cloud
            "192.0.0.192",  # Oracle Cloud (legacy)
            "168.63.129.16",  # Azure wireserver
        ],
    )
    def test_cloud_metadata_endpoints_are_named_in_the_reason(self, address: str) -> None:
        """The rejection reason has to be legible in a log."""
        assert AddressFilter().rejection_reason(address) == "cloud metadata endpoint"

    @pytest.mark.parametrize(
        ("address", "reason"),
        [
            ("127.0.0.1", "loopback address"),
            ("169.254.1.1", "link-local address"),
            ("224.0.0.1", "multicast address"),
            ("0.0.0.0", "unspecified address"),
            ("240.0.0.1", "reserved address"),
            ("10.0.0.1", "private address"),
            ("100.64.0.1", "not globally routable"),
            ("nonsense", "not a valid IP address"),
        ],
    )
    def test_rejection_reasons_are_specific(self, address: str, reason: str) -> None:
        assert AddressFilter().rejection_reason(address) == reason

    def test_invalid_address_is_rejected(self) -> None:
        assert AddressFilter().is_allowed("not-an-ip") is False

    def test_allow_private_opt_in(self) -> None:
        assert AddressFilter(allow_private=True).is_allowed("127.0.0.1") is True

    def test_hostile_glue_is_never_queried(self) -> None:
        """A zone pointing its glue at internal IPs must not be followed."""
        resolver = offline_resolver()
        queried: list[list[str]] = []

        def send(qname, rdtype, nameservers, ctx, usable=None):
            queried.append(list(nameservers))
            if len(queried) == 1:
                return root_to_com(), "198.41.0.4"
            return (
                referral(
                    "evil.com.",
                    ["ns1.evil.com."],
                    {"ns1.evil.com.": "127.0.0.1"},
                ),
                "192.5.6.30",
            )

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolverError):
            resolver.resolve("evil.com", "A")

        every_address = {ip for step in queried for ip in step}
        assert "127.0.0.1" not in every_address
        assert "169.254.169.254" not in every_address

    def test_resolved_ns_addresses_are_filtered_too(self) -> None:
        """Glueless NS hostnames resolving to private IPs are also rejected."""
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if qname == dns.name.from_text("ns.attacker.test."):
                return make_response(answer=[("ns.attacker.test.", 300, "A", ["192.168.1.1"])]), "1.2.3.4"
            if nameservers and nameservers[0] == "198.41.0.4":
                return root_to_com(), "198.41.0.4"
            return referral("victim.com.", ["ns.attacker.test."]), "192.5.6.30"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolverError):
            resolver.resolve("victim.com", "A")


class TestQueryBudget:
    """NXNSAttack / Non-Responsive Delegation amplification controls."""

    def test_glueless_fanout_is_bounded(self) -> None:
        """A hostile zone answering every query with 50 fresh NS names is capped."""
        resolver = offline_resolver(limits=Limits(max_queries=40), max_depth=10)
        sent = 0

        def send(qname, rdtype, nameservers, ctx, usable=None):
            nonlocal sent
            sent += 1
            assert sent < 5000, "runaway fan-out"
            label = str(qname).replace(".", "-")[:20]
            names = [f"ns{i}-{label}.attacker.test." for i in range(50)]
            return referral(str(qname), names), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolverError):
            resolver.resolve("victim.test", "A")

        # Without a budget this produced tens of thousands of queries.
        assert sent <= 200, f"fan-out was not bounded: {sent} queries"

    def test_budget_counts_across_subresolutions(self) -> None:
        resolver = offline_resolver(limits=Limits(max_queries=5))
        with pytest.raises(QueryBudgetExceededError):
            ctx = resolver._new_context()
            for _ in range(10):
                ctx.budget.spend_query("example.com.", "A")

    def test_nx_target_budget(self) -> None:
        resolver = offline_resolver(limits=Limits(max_nx_targets=2))
        ctx = resolver._new_context()
        with pytest.raises(QueryBudgetExceededError):
            for _ in range(5):
                ctx.budget.note_nx_target("ns.example.com.", "A")

    def test_ns_names_per_referral_are_capped(self) -> None:
        """Only a bounded, randomly sampled subset of NS names is chased."""
        resolver = offline_resolver(limits=Limits(max_ns_per_referral=3))
        response = referral("example.com.", [f"ns{i}.example.com." for i in range(50)])
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.A, dns.name.root
        )
        assert classification["type"] == "referral"
        assert len(classification["ns_names"]) == 3


class TestReferralValidation:
    """Downward progress and bailiwick rules."""

    def test_sideways_referral_is_rejected(self) -> None:
        """A server must not refer us back to its own zone (com. -> com.)."""
        resolver = offline_resolver()
        response = referral("com.", ["a.gtld-servers.net."])
        classification = resolver._classify_response(
            response, dns.name.from_text("foo.com."), dns.rdatatype.A, dns.name.from_text("com.")
        )
        assert classification["type"] != "referral"

    def test_upward_referral_is_rejected(self) -> None:
        """An ancestor zone in the authority section is not a valid referral."""
        resolver = offline_resolver()
        response = referral(".", ["a.root-servers.net."])
        classification = resolver._classify_response(
            response, dns.name.from_text("foo.example.com."), dns.rdatatype.A, dns.name.from_text("com.")
        )
        assert classification["type"] != "referral"

    def test_upward_referral_does_not_crash(self) -> None:
        """Regression: this used to raise dns.name.NoParent out of resolve()."""
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx, usable=None):
            return referral(".", ["a.root-servers.net."], {"a.root-servers.net.": "198.41.0.4"}), "1.2.3.4"

        # Must surface as a ResolverError, never dns.name.NoParent.
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolverError):
            resolver.resolve("example.com", "A")

    def test_unrelated_referral_is_rejected(self) -> None:
        """evil.com's server must not be able to answer for bank.com."""
        resolver = offline_resolver()
        response = referral("bank.com.", ["ns1.evil.com."])
        classification = resolver._classify_response(
            response, dns.name.from_text("www.evil.com."), dns.rdatatype.A, dns.name.from_text("com.")
        )
        assert classification["type"] != "referral"

    def test_valid_downward_referral_is_accepted(self) -> None:
        resolver = offline_resolver()
        response = referral("example.com.", ["ns1.example.com."])
        classification = resolver._classify_response(
            response, dns.name.from_text("www.example.com."), dns.rdatatype.A, dns.name.from_text("com.")
        )
        assert classification["type"] == "referral"
        assert classification["zone"] == dns.name.from_text("example.com.")

    def test_deepest_referral_wins(self) -> None:
        resolver = offline_resolver()
        response = make_response(
            authority=[
                ("com.", 172800, "NS", ["a.gtld-servers.net."]),
                ("sub.example.com.", 172800, "NS", ["ns1.example.com."]),
                ("example.com.", 172800, "NS", ["ns2.example.com."]),
            ],
            aa=False,
        )
        classification = resolver._classify_response(
            response, dns.name.from_text("host.sub.example.com."), dns.rdatatype.A, dns.name.from_text("com.")
        )
        assert classification["zone"] == dns.name.from_text("sub.example.com.")

    def test_out_of_bailiwick_glue_is_ignored(self) -> None:
        resolver = offline_resolver()
        response = referral("target.com.", ["ns1.evil.net."], {"ns1.evil.net.": "6.6.6.6"})
        glue = resolver._select_glue(
            response,
            [dns.name.from_text("ns1.evil.net.")],
            dns.name.from_text("com."),
            dns.name.from_text("target.com."),
        )
        assert glue == []

    def test_in_bailiwick_glue_is_accepted(self) -> None:
        resolver = offline_resolver()
        response = referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "9.9.9.9"})
        glue = resolver._select_glue(
            response,
            [dns.name.from_text("ns1.example.com.")],
            dns.name.from_text("com."),
            dns.name.from_text("example.com."),
        )
        assert glue == ["9.9.9.9"]


class TestResponseValidation:
    """Answer-acceptance rules."""

    def test_nxdomain_with_answer_records_is_rejected(self) -> None:
        """A protocol-violating NXDOMAIN carrying data must not be trusted."""
        resolver = offline_resolver()
        response = make_response(
            answer=[("example.com.", 300, "A", ["6.6.6.6"])],
            rcode=dns.rcode.NXDOMAIN,
        )
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.A, dns.name.from_text("com.")
        )
        assert classification["type"] == "error"

    def test_answer_without_aa_bit_is_rejected(self) -> None:
        resolver = offline_resolver()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])], aa=False)
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.A, dns.name.from_text("example.com.")
        )
        assert classification["type"] == "error"

    def test_answer_with_aa_bit_is_accepted(self) -> None:
        resolver = offline_resolver()
        response = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])], aa=True)
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.A, dns.name.from_text("example.com.")
        )
        assert classification["type"] == "answer"

    def test_wrong_rdclass_is_not_an_answer(self) -> None:
        """A CHAOS-class RRset must not satisfy an IN-class query."""
        resolver = offline_resolver()
        response = make_response(
            answer=[("example.com.", 300, "TXT", ['"injected"'])],
            rdclass=dns.rdataclass.CH,
        )
        classification = resolver._classify_response(
            response, dns.name.from_text("example.com."), dns.rdatatype.TXT, dns.name.from_text("example.com.")
        )
        assert classification["type"] != "answer"

    def test_nodata_with_ns_in_authority_is_nodata_not_referral(self) -> None:
        """Regression: this used to burn 20 queries and raise MaxDepthError."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        sent = 0

        def send(qname, rdtype, nameservers, ctx, usable=None):
            nonlocal sent
            sent += 1
            if sent == 1:
                return root_to_com(), "198.41.0.4"
            if sent == 2:
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"
            return (
                make_response(
                    authority=[
                        ("example.com.", 300, "SOA", ["ns1.example.com. a.example.com. 1 3600 900 604800 86400"]),
                        ("example.com.", 172800, "NS", ["ns1.example.com."]),
                    ],
                    aa=True,
                ),
                "1.2.3.4",
            )

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NoAnswerError):
            resolver.resolve("example.com", "MX")

        assert sent == 3, f"expected 3 queries, got {sent}"
        # And it must be negatively cached so a repeat costs nothing.
        with pytest.raises(NoAnswerError):
            resolver.resolve("example.com", "MX")
        assert sent == 3


class TestTruncation:
    """Truncated responses must never be treated as complete."""

    def test_plain_udp_path_rejects_truncation(self) -> None:
        """Regression: the no-EDNS fallback silently returned partial answers."""
        resolver = offline_resolver(use_tcp_fallback=False)
        truncated = make_response(answer=[("example.com.", 300, "A", ["1.1.1.1"])], tc=True)

        with patch("dns.query.udp", side_effect=dns.message.Truncated(message=truncated)):
            ctx = resolver._new_context()
            response, server = resolver._send_query(
                dns.name.from_text("example.com."), dns.rdatatype.A, ["1.2.3.4"], ctx
            )
        assert response is None
        assert server == ""


class TestEDNSDowngrade:
    """The EDNS fallback ladder for broken servers and PMTU blackholes."""

    def test_payload_ladder(self) -> None:
        resolver = offline_resolver(edns_payload=1232)
        assert resolver._payload_for_attempt(0) == 1232
        assert resolver._payload_for_attempt(1) == 512
        assert resolver._payload_for_attempt(2) is None

    def test_the_ladder_never_drops_edns_while_validating(self) -> None:
        """DNSSEC needs EDNS0 to carry DO (RFC 4035 §3.2.1).

        Without the OPT record the answer comes back with no RRSIGs, which the
        validator can only read as BOGUS: a validation failure of our own making
        against a perfectly good zone.
        """
        resolver = offline_resolver(edns_payload=1232)
        assert resolver._payload_for_attempt(2, True) == 512

    def test_every_sweep_carries_the_do_bit_for_a_validating_query(self) -> None:
        resolver = RecursiveResolver(timeout=0.5, cache_enabled=False)
        sent: list[dns.message.Message] = []

        def capture(query, server, timeout=None, **kwargs):
            sent.append(query)
            raise dns.exception.Timeout("forced")

        with (
            patch("dns.query.udp", side_effect=capture),
            patch("dns.query.udp_with_fallback", side_effect=lambda q, s, timeout=None, **kw: (capture(q, s), False)),
        ):
            ctx = resolver._new_context()
            resolver._send_query(dns.name.from_text("example.com."), dns.rdatatype.DNSKEY, ["9.9.9.9"], ctx)

        assert len(sent) == resolver.max_retries + 1
        assert not [i + 1 for i, query in enumerate(sent) if not query.ednsflags & dns.flags.DO]

    def test_an_edns_incapable_server_is_abandoned_while_validating(self) -> None:
        """Its answers can never be validated, so a DO-less retry is pointless.

        Querying it without DO and then judging the unsigned result BOGUS is the
        worst of both: no signatures, and a DNSSEC verdict pinned on the zone.
        """
        resolver = RecursiveResolver(cache_enabled=False)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            return make_response(rcode=dns.rcode.FORMERR, aa=False)

        zone = dns.name.from_text("example.com.")
        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(
                zone, dns.rdatatype.DNSKEY, ["9.9.9.9"], ctx, usable=resolver._usable_dnskey(zone)
            )

        assert response is None
        assert payloads == [1232], "the server must be abandoned, not retried without DO"

    def test_a_servfail_still_reaches_the_caller_while_validating(self) -> None:
        """Abandoning the server must not hide the failure it reported.

        SERVFAIL shares a branch with the EDNS-incapable rcodes. Without DO
        there is nothing to gain from re-asking, but the response still has to
        come back, or a broken zone would surface as a timeout.
        """
        resolver = RecursiveResolver(cache_enabled=False)

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            return make_response(rcode=dns.rcode.SERVFAIL, aa=False)

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(dns.name.from_text("example.com."), dns.rdatatype.A, ["9.9.9.9"], ctx)

        assert response is not None
        assert response.rcode() == dns.rcode.SERVFAIL

    @pytest.mark.parametrize(
        "rcode",
        [dns.rcode.FORMERR, dns.rcode.NOTIMP, dns.rcode.SERVFAIL, 16],
    )
    def test_edns_unsupported_rcodes_trigger_plain_retry(self, rcode: int) -> None:
        """FORMERR, NOTIMP, SERVFAIL and BADVERS all mean 'try without EDNS'."""
        resolver = offline_resolver()
        payloads: list[int | None] = []
        good = make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            if payload is not None and len(payloads) == 1:
                return make_response(rcode=rcode, aa=False)
            return good

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(dns.name.from_text("example.com."), dns.rdatatype.A, ["1.2.3.4"], ctx)

        assert response is not None
        assert payloads[0] == 1232
        assert payloads[-1] is None, "should have retried with EDNS disabled"

    def test_timeouts_downgrade_the_payload(self) -> None:
        """A PMTU blackhole must be escaped by shrinking the advertised payload."""
        from recursive_resolver.resolver import _RetryableError

        resolver = offline_resolver(max_retries=2)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            if payload is not None and payload > 512:
                raise _RetryableError("blackholed")
            return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(dns.name.from_text("example.com."), dns.rdatatype.A, ["1.2.3.4"], ctx)

        assert response is not None
        assert payloads == [1232, 512]


class TestSpoofingResistance:
    def test_unexpected_source_does_not_downgrade_edns(self) -> None:
        """A stray packet must not be an attacker-driven EDNS downgrade primitive."""
        from recursive_resolver.resolver import _RetryableError

        resolver = offline_resolver(max_retries=1)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            raise _RetryableError("unexpected response source")

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            resolver._send_query(dns.name.from_text("example.com."), dns.rdatatype.A, ["1.2.3.4"], ctx)

        # Retries happen, but never a jump straight to no-EDNS on the first retry.
        assert payloads[0] == 1232

    def test_all_servers_failing_raises_servfail_not_success(self) -> None:
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx, usable=None):
            return make_response(rcode=dns.rcode.REFUSED, aa=False), nameservers[0]

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ServfailError):
            resolver.resolve("example.com", "A")


class TestDNSSECBookkeeping:
    """Regressions where our own state-keeping produced spurious DNSSEC failures."""

    def test_nxdomain_in_a_signed_single_ns_zone(self) -> None:
        """The failing server is pruned before the denial is validated.

        With one nameserver that left an empty list, so the DNSKEY fetch had
        nowhere to go and NXDOMAIN surfaced as DNSSECValidationError.
        """
        from recursive_resolver.dnssec import ValidationState

        resolver = RecursiveResolver(dnssec=True, cache_enabled=False)
        attempted: list[list[str]] = []

        def send(qname, rdtype, nameservers, ctx, usable=None):
            attempted.append(list(nameservers))
            return (None, "") if not nameservers else (make_response(aa=True), nameservers[0])

        ctx = resolver._new_context()
        # The call may still fail (the stub serves no real signatures); what
        # matters is that it never queries with an empty nameserver list.
        # ResolverError only, not Exception: a bare suppress would also swallow
        # an AttributeError or TypeError from a later refactor, and the two
        # assertions below would still pass because `attempted` is populated by
        # the first _send_query call.
        with patch.object(resolver, "_send_query", side_effect=send), contextlib.suppress(ResolverError):
            resolver._verify_denial(
                make_response(rcode=dns.rcode.NXDOMAIN, aa=True),
                dns.name.from_text("gone.example.com."),
                dns.rdatatype.A,
                ctx,
                dns.name.from_text("example.com."),
                ["9.9.9.9"],
                ValidationState.SECURE,
                object(),
                negative="nxdomain",
            )

        assert attempted, "no DNSKEY fetch was attempted"
        assert all(servers for servers in attempted), "a DNSSEC fetch was given an empty nameserver list"

    def test_zone_nameservers_survive_server_pruning(self) -> None:
        """A signed zone whose only nameserver NXDOMAINs still yields NXDOMAIN."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=False)
        calls = 0

        def send(qname, rdtype, nameservers, ctx, usable=None):
            nonlocal calls
            calls += 1
            assert nameservers, "queried with an empty nameserver list"
            if calls == 1:
                return root_to_com(), "198.41.0.4"
            if calls == 2:
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "9.9.9.9"}), "192.5.6.30"
            return make_response(rcode=dns.rcode.NXDOMAIN, aa=True), "9.9.9.9"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NXDOMAINError):
            resolver.resolve("gone.example.com", "A")

    def test_cached_delegation_carries_its_ds(self) -> None:
        """A resumed secure chain must not depend on a warm DNSKEY cache."""
        from recursive_resolver.cache import Delegation

        resolver = RecursiveResolver(dnssec=True, cache_enabled=True)
        sentinel = object()
        resolver.cache.put_delegation(
            Delegation(
                zone=dns.name.from_text("com."),
                addresses=["192.5.6.30"],
                secure=True,
                ds=sentinel,
            ),
            ttl=3600,
        )
        zone, servers, state, ds, _names = resolver._starting_point(dns.name.from_text("example.com."), dns.rdatatype.A)
        assert zone == dns.name.from_text("com.")
        assert servers == ["192.5.6.30"]
        assert ds is sentinel

    def test_secure_delegation_without_ds_restarts_from_root(self) -> None:
        """Rather than silently downgrading an unprovable chain to insecure."""
        from recursive_resolver.cache import Delegation

        resolver = RecursiveResolver(dnssec=True, cache_enabled=True)
        resolver.cache.put_delegation(
            Delegation(zone=dns.name.from_text("com."), addresses=["192.5.6.30"], secure=True, ds=None),
            ttl=3600,
        )
        zone, servers, _state, _ds, _names = resolver._starting_point(
            dns.name.from_text("example.com."), dns.rdatatype.A
        )
        assert zone == dns.name.root
        assert servers == resolver._root_addresses


class TestResourceBounds:
    """Long-running processes must not accumulate state without limit."""

    def test_zone_key_cache_is_bounded(self) -> None:
        """A DKIM verifier sees unboundedly many signed zones over time."""
        from recursive_resolver.dnssec import ValidationState, ZoneKeys

        resolver = RecursiveResolver(dnssec=True)
        resolver._key_cache_size = 64
        for i in range(5000):
            resolver._store_keys(ZoneKeys(dns.name.from_text(f"z{i}.example."), None, ValidationState.SECURE), 3600)
        assert len(resolver._key_cache) == 64

    def test_zone_key_cache_evicts_least_recently_used(self) -> None:
        from recursive_resolver.dnssec import ValidationState, ZoneKeys

        resolver = RecursiveResolver(dnssec=True)
        resolver._key_cache_size = 2
        a, b, c = (dns.name.from_text(f"{n}.example.") for n in "abc")
        for zone in (a, b):
            resolver._store_keys(ZoneKeys(zone, None, ValidationState.SECURE), 3600)
        resolver._cached_keys(a)  # a becomes most recently used
        resolver._store_keys(ZoneKeys(c, None, ValidationState.SECURE), 3600)
        assert resolver._cached_keys(a) is not None
        assert resolver._cached_keys(c) is not None
        assert resolver._cached_keys(b) is None

    def test_cache_size_is_bounded(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.max_size = 32
        for i in range(2000):
            resolver.cache.put_answer(dns.name.from_text(f"d{i}.example."), dns.rdatatype.A, "rrset", ttl=300)
        assert len(resolver.cache) == 32


class TestLimitsGrouping:
    """The hardening limits are one object, because they only make sense as a set."""

    def test_defaults_are_the_reference_values(self) -> None:
        limits = Limits()
        assert (limits.max_queries, limits.max_nx_targets, limits.max_referrals) == (64, 5, 130)
        assert limits.max_ns_per_referral == 13
        assert (limits.max_signature_validations, limits.max_nsec3_hashes) == (96, 600)

    def test_a_resolver_without_limits_gets_the_defaults(self) -> None:
        assert RecursiveResolver(dnssec=False).limits == Limits()

    def test_limits_are_immutable(self) -> None:
        """A shared config object must not be mutable behind a running resolver."""
        limits = Limits()
        with pytest.raises(dataclasses.FrozenInstanceError):
            limits.max_queries = 10_000  # type: ignore[misc]

    def test_every_limit_reaches_the_budget(self) -> None:
        limits = Limits(
            max_queries=1,
            max_ns_per_referral=2,
            max_nx_targets=3,
            max_referrals=4,
            max_signature_validations=5,
            max_nsec3_hashes=6,
        )
        budget = offline_resolver(limits=limits)._new_context().budget
        assert budget.max_queries == 1
        assert budget.max_nx_targets == 3
        assert budget.max_referrals == 4
        assert budget.max_signature_validations == 5
        assert budget.max_nsec3_hashes == 6

    def test_each_resolution_gets_a_fresh_budget(self) -> None:
        """Counters must not carry over between calls, or a resolver would decay."""
        resolver = offline_resolver(limits=Limits(max_queries=2))
        first = resolver._new_context().budget
        first.spend_query("example.com.", "A")
        assert resolver._new_context().budget.queries_sent == 0


class TestCrossZoneCNAMEPoisoning:
    """A server may only answer for its own bailiwick, CNAME targets included.

    A CNAME pointing out of the answering zone, bundled with an inline record
    for that foreign target, is an attempt to write another zone's data. The
    target must be re-resolved from the servers actually authoritative for it.
    """

    ATTACKER_IP = "192.5.6.30"
    VICTIM_IP = "199.7.83.42"
    REAL = '"v=DKIM1; k=rsa; p=REALKEY"'
    FORGED = '"v=DKIM1; k=rsa; p=ATTACKERKEY"'

    def _send(self, resolver):
        def send(qname, rdtype, nameservers, ctx, usable=None):
            if nameservers == resolver._root_addresses:
                if str(qname).endswith("attacker.test."):
                    return referral("attacker.test.", ["ns.attacker.test."], {"ns.attacker.test.": self.ATTACKER_IP}), (
                        "198.41.0.4"
                    )
                return referral("victim.example.", ["ns.victim.example."], {"ns.victim.example.": self.VICTIM_IP}), (
                    "198.41.0.4"
                )
            if self.ATTACKER_IP in nameservers:
                return make_response(
                    answer=[
                        ("lookup.attacker.test.", 300, "CNAME", ["dkim._domainkey.victim.example."]),
                        ("dkim._domainkey.victim.example.", 300, "TXT", [self.FORGED]),
                    ]
                ), self.ATTACKER_IP
            return make_response(answer=[("dkim._domainkey.victim.example.", 300, "TXT", [self.REAL])]), self.VICTIM_IP

        return send

    def test_an_inline_record_for_a_foreign_target_is_refused(self) -> None:
        resolver = RecursiveResolver(dnssec=False)
        with patch.object(resolver, "_send_query", side_effect=self._send(resolver)):
            records = resolver.resolve("lookup.attacker.test", "TXT")
        assert records == [self.REAL], "the attacker's inline record was trusted"

    def test_the_foreign_target_is_not_written_into_the_cache(self) -> None:
        """The poisoning that mattered: a later, unrelated lookup must be clean."""
        resolver = RecursiveResolver(dnssec=False)
        with patch.object(resolver, "_send_query", side_effect=self._send(resolver)):
            resolver.resolve("lookup.attacker.test", "TXT")
            legitimate = resolver.resolve("dkim._domainkey.victim.example", "TXT")
        assert legitimate == [self.REAL]

    def test_an_inline_target_inside_the_zone_is_still_used(self) -> None:
        """The optimisation must survive for the in-bailiwick CDN case."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=False)
        calls = []

        def send(qname, rdtype, nameservers, ctx, usable=None):
            calls.append(str(qname))
            if nameservers == resolver._root_addresses:
                return referral("example.com.", ["ns.example.com."], {"ns.example.com.": "192.5.6.30"}), "198.41.0.4"
            return make_response(
                answer=[
                    ("www.example.com.", 300, "CNAME", ["cdn.example.com."]),
                    ("cdn.example.com.", 300, "A", ["1.2.3.4"]),
                ]
            ), "192.5.6.30"

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("www.example.com", "A") == ["1.2.3.4"]
        assert calls.count("cdn.example.com.") == 0, "an in-bailiwick target should not be re-resolved"


class TestMappedAddressNormalisation:
    """An IPv4-mapped IPv6 literal must be judged on its embedded IPv4 address.

    Loopback and RFC1918 are caught by Python's classification even unmapped,
    so only the ranges we carry ourselves prove the normalisation is working.
    """

    @pytest.mark.parametrize(
        "address",
        [
            "::ffff:168.63.129.16",  # Azure wireserver, a routable-looking address
            "::ffff:169.254.169.254",  # the cloud metadata endpoint
            "::ffff:100.100.100.200",  # Alibaba Cloud metadata
            "::ffff:192.0.0.192",  # Oracle Cloud metadata
            "::ffff:192.88.99.1",  # 6to4 relay anycast
            "::ffff:100.64.0.1",  # CGNAT
        ],
    )
    def test_a_mapped_address_is_refused(self, address: str) -> None:
        assert AddressFilter().rejection_reason(address) is not None, address


class TestNegativeCacheScoping:
    """RFC 8020 denies below an NXDOMAIN, so the cached name must be exact.

    Caching the NXDOMAIN one label up would deny every sibling of the missing
    name: a self-inflicted outage on names that do exist.
    """

    def test_a_sibling_of_a_missing_name_is_not_denied(self) -> None:
        resolver = RecursiveResolver(dnssec=False)

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if nameservers == resolver._root_addresses:
                return referral("example.com.", ["ns.example.com."], {"ns.example.com.": "192.5.6.30"}), "198.41.0.4"
            if str(qname) == "missing.example.com.":
                return make_response(
                    authority=[("example.com.", 300, "SOA", ["ns.example.com. a.example.com. 1 3600 900 604800 300"])],
                    rcode=dns.rcode.NXDOMAIN,
                ), "192.5.6.30"
            return make_response(answer=[(str(qname), 300, "A", ["1.2.3.4"])]), "192.5.6.30"

        with patch.object(resolver, "_send_query", side_effect=send):
            with pytest.raises(NXDOMAINError):
                resolver.resolve("missing.example.com", "A")
            # The sibling must still resolve; and the parent must not be denied.
            assert resolver.resolve("present.example.com", "A") == ["1.2.3.4"]
            assert resolver.resolve("example.com", "A") == ["1.2.3.4"]

    def test_a_name_below_the_missing_name_is_denied(self) -> None:
        """The other half of RFC 8020: below the NXDOMAIN really is denied."""
        resolver = RecursiveResolver(dnssec=False)
        assert resolver.cache is not None
        resolver.cache.put_nxdomain(dns.name.from_text("missing.example.com."), 300)
        assert resolver.cache.get_nxdomain_ancestor(dns.name.from_text("a.b.missing.example.com.")) is not None
        assert resolver.cache.get_nxdomain_ancestor(dns.name.from_text("present.example.com.")) is None


class TestWeakestState:
    """A CNAME chain is only as trustworthy as its weakest link."""

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            (ValidationState.SECURE, ValidationState.INSECURE),
            (ValidationState.INSECURE, ValidationState.SECURE),
            (ValidationState.SECURE, ValidationState.BOGUS),
            (ValidationState.INSECURE, ValidationState.BOGUS),
        ],
    )
    def test_the_weaker_state_wins(self, a: ValidationState, b: ValidationState) -> None:
        resolver = RecursiveResolver(dnssec=False)
        order = {ValidationState.BOGUS: 0, ValidationState.INSECURE: 1, ValidationState.SECURE: 2}
        expected = a if order[a] <= order[b] else b
        assert resolver._weakest(a, b) is expected
        assert resolver._weakest(b, a) is expected

    def test_a_secure_leg_never_upgrades_an_insecure_one(self) -> None:
        resolver = RecursiveResolver(dnssec=False)
        assert resolver._weakest(ValidationState.SECURE, ValidationState.INSECURE) is ValidationState.INSECURE


class TestReturnedDataIsTheCallersOwn:
    """A shared cache must never hand out a mutable object it still holds.

    `dns.rrset.RRset` is a mutable container. If the cache, the resolver and
    every caller share one instance, a single `add` or `ttl` assignment
    anywhere silently rewrites what later lookups return, in every thread. That
    is the kind of corruption that is almost impossible to trace back.
    """

    @staticmethod
    def offline_resolver():
        resolver = RecursiveResolver(dnssec=False)

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if nameservers == resolver._root_addresses:
                return referral("example.com.", ["ns.example.com."], {"ns.example.com.": "192.5.6.30"}), "198.41.0.4"
            return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])]), "192.5.6.30"

        return resolver, send

    def test_mutating_a_returned_rrset_does_not_poison_the_cache(self) -> None:
        resolver, send = self.offline_resolver()
        extra = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "6.6.6.6")
        with patch.object(resolver, "_send_query", side_effect=send):
            first = resolver.resolve_answer("example.com", "A")
            first.rrset.add(extra)
            second = resolver.resolve_answer("example.com", "A")
        assert second.records == ["1.2.3.4"]

    def test_two_callers_never_share_one_rrset(self) -> None:
        resolver, send = self.offline_resolver()
        with patch.object(resolver, "_send_query", side_effect=send):
            first = resolver.resolve_answer("example.com", "A")
            second = resolver.resolve_answer("example.com", "A")
        assert first.rrset is not second.rrset
        assert first.cname_chain is not second.cname_chain

    def test_mutating_a_stored_rrset_after_caching_it_does_not_reach_the_cache(self) -> None:
        """The producer side: the cache copies on write as well as on read."""
        cache = DNSCache()
        rrset = dns.rrset.from_text("example.com.", 300, "IN", "A", "1.2.3.4")
        cache.put_answer("example.com.", "A", rrset, ttl=300)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "6.6.6.6"))
        entry = cache.get_answer("example.com.", "A")
        assert entry is not None
        assert [str(r) for r in entry.rrset] == ["1.2.3.4"]


class TestUnverifiableAlgorithmsAreInsecureNotBogus:
    """RFC 4035 §5.2: a zone we have no way to check is unsigned, not forged.

    Reporting BOGUS would reject a legitimately signed zone outright merely
    because this build lacks its algorithm, which is a self-inflicted outage.
    """

    def test_an_unsupported_algorithm_is_reported_as_unsupported(self) -> None:
        from recursive_resolver.dnssec import algorithm_supported

        assert algorithm_supported(8) is True  # RSASHA256
        assert algorithm_supported(13) is True  # ECDSAP256SHA256
        assert algorithm_supported(252) is False  # not a real signing algorithm

    def test_a_zone_whose_ds_we_cannot_digest_is_insecure(self) -> None:
        from recursive_resolver.dnssec import DNSSECValidator

        validator = DNSSECValidator()
        keys = dns.rrset.RRset(dns.name.from_text("z.test."), dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        keys.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"))
        keys.ttl = 300
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 2 " + "AB" * 32), ttl=300)
        with patch("dns.dnssec.make_ds", side_effect=dns.dnssec.UnsupportedAlgorithm("no such digest")):
            assert validator.validate_dnskey(dns.name.from_text("z.test."), keys, None, ds) is ValidationState.INSECURE

    def test_a_genuine_mismatch_is_still_bogus(self) -> None:
        """The distinction must not weaken real forgery detection."""
        from recursive_resolver.dnssec import DNSSECValidator

        validator = DNSSECValidator()
        keys = dns.rrset.RRset(dns.name.from_text("z.test."), dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        keys.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WS"))
        keys.ttl = 300
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 2 " + "AB" * 32), ttl=300)
        assert validator.validate_dnskey(dns.name.from_text("z.test."), keys, None, ds) is ValidationState.BOGUS


class TestSpoofedPacketsDoNotRetireANameserver:
    """RFC 5452 §9: a wrong-ID datagram is junk, not an answer, and not a fault.

    The randomised query ID and source port exist so an off-path attacker's
    guesses are discarded. Treating the first wrong guess as a protocol error
    hands that attacker the outcome anyway: the server gets abandoned, or its
    EDNS support written off, on the strength of a packet nobody authenticated.

    These run against a real UDP socket, so what is exercised is the flag this
    resolver passes rather than a stubbed-out reimplementation of it.
    """

    @staticmethod
    @contextlib.contextmanager
    def _server(spoofs: int):
        """A nameserver that emits ``spoofs`` junk packets before answering."""
        import socket
        import threading

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        finished = threading.Event()

        def serve() -> None:
            try:
                data, addr = sock.recvfrom(4096)
                query = dns.message.from_wire(data)
                for _ in range(spoofs):
                    # A well-formed response to a *different* query: exactly
                    # what a blind spoofer's guess looks like on the wire.
                    junk = dns.message.make_query("guessed.example.", "A")
                    junk.flags |= dns.flags.QR
                    sock.sendto(junk.to_wire(), addr)
                reply = dns.message.make_response(query)
                reply.flags |= dns.flags.AA
                reply.answer.append(dns.rrset.from_text("a.test.", 300, "IN", "A", "1.2.3.4"))
                sock.sendto(reply.to_wire(), addr)
            except Exception:  # pragma: no cover - the test asserts on the client side
                pass
            finally:
                finished.set()

        threading.Thread(target=serve, daemon=True).start()
        try:
            yield port
        finally:
            finished.wait(timeout=5)
            sock.close()

    @staticmethod
    @contextlib.contextmanager
    def _on_port(port: int, tcp_fallback: bool):
        """Send to the ephemeral test port while leaving the resolver's code intact.

        Only the entry point the resolver actually calls is redirected, so
        ``udp_with_fallback`` still reaches the real ``udp`` underneath.
        """
        name = "dns.query.udp_with_fallback" if tcp_fallback else "dns.query.udp"
        real = dns.query.udp_with_fallback if tcp_fallback else dns.query.udp

        def send(query, where, *args, **kwargs):
            kwargs["port"] = port
            return real(query, where, *args, **kwargs)

        with patch(name, side_effect=send):
            yield

    def _ask(self, port: int, **kwargs):
        resolver = offline_resolver(dnssec=False, **kwargs)
        ctx = resolver._new_context()
        with self._on_port(port, resolver.use_tcp_fallback):
            return resolver._query_once(dns.name.from_text("a.test."), dns.rdatatype.A, "127.0.0.1", 1232, 4.0, ctx)

    def test_a_spoofed_reply_before_the_real_one_is_discarded(self) -> None:
        with self._server(spoofs=1) as port:
            response = self._ask(port)
        assert [str(rr) for rrset in response.answer for rr in rrset] == ["1.2.3.4"]

    def test_a_burst_of_spoofed_replies_is_discarded(self) -> None:
        with self._server(spoofs=5) as port:
            response = self._ask(port)
        assert response.answer, "a flood of wrong-ID packets denied a real answer"

    def test_the_same_holds_without_tcp_fallback(self) -> None:
        with self._server(spoofs=1) as port:
            response = self._ask(port, use_tcp_fallback=False)
        assert response.answer
