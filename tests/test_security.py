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
from signed_zone import SignedZone, rrset_of

from recursive_resolver import (
    AddressFilter,
    DNSCache,
    DNSSECInsecureError,
    DNSSECValidationError,
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

    def test_a_server_mangling_its_response_is_abandoned_while_validating(self) -> None:
        """The other sign of a server that cannot do EDNS, and the same answer to it."""
        from recursive_resolver.resolver import _MalformedResponseError

        resolver = RecursiveResolver(cache_enabled=False)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            raise _MalformedResponseError("garbage")

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(
                dns.name.from_text("example.com."), dns.rdatatype.DNSKEY, ["9.9.9.9"], ctx
            )

        assert response is None
        assert payloads == [1232]

    def test_a_server_known_not_to_do_edns_is_still_sent_it_while_validating(self) -> None:
        """What was learned below an unsigned cut lasts the whole resolution.

        The same address can serve a signed zone later in it.
        """
        resolver = RecursiveResolver(cache_enabled=False)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            return make_response()

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            ctx.no_edns.add("9.9.9.9")
            resolver._send_query(dns.name.from_text("example.com."), dns.rdatatype.DNSKEY, ["9.9.9.9"], ctx)

        assert payloads == [1232]

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
        """The other half of RFC 8020: below an authenticated NXDOMAIN really is denied."""
        resolver = RecursiveResolver(dnssec=False)
        assert resolver.cache is not None
        resolver.cache.put_nxdomain(dns.name.from_text("missing.example.com."), 300, secure=True)
        assert resolver.cache.get_nxdomain_ancestor(dns.name.from_text("a.b.missing.example.com.")) is not None
        assert resolver.cache.get_nxdomain_ancestor(dns.name.from_text("present.example.com.")) is None

    def test_an_unproven_nxdomain_hides_nothing_below_it(self) -> None:
        """One broken server or spoofed packet must not deny a whole subtree.

        Without a proof, `_domainkey.example.com` answering NXDOMAIN says
        nothing reliable about `sel._domainkey.example.com`, which is queried
        upstream as usual.
        """
        resolver = RecursiveResolver(dnssec=False)
        assert resolver.cache is not None
        resolver.cache.put_nxdomain(dns.name.from_text("_domainkey.example.com."), 300)
        txt = make_response(answer=[("sel._domainkey.example.com.", 300, "TXT", ['"v=DKIM1; p=KEY"'])])
        chain = [
            (root_to_com(), "198.41.0.4"),
            (referral("example.com.", ["ns.example.com."], {"ns.example.com.": "9.9.9.9"}), "192.5.6.30"),
            (txt, "9.9.9.9"),
        ]
        step = {"i": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            i = step["i"]
            step["i"] += 1
            return chain[i] if i < len(chain) else (None, "")

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("sel._domainkey.example.com", "TXT") == ['"v=DKIM1; p=KEY"']


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
        # Digest type 3 (GOST R 34.11-94) is one dnspython cannot compute.
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "12345 8 3 " + "AB" * 32), ttl=300)
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
    def _server(spoofs: int, from_elsewhere: bool = False):
        """A nameserver that emits ``spoofs`` junk packets before answering.

        With ``from_elsewhere``, the junk comes from another socket: an
        exact reply to the query, from an address the query was not sent to.
        """
        import socket
        import threading

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        other.bind(("127.0.0.1", 0))
        finished = threading.Event()

        def serve() -> None:
            try:
                data, addr = sock.recvfrom(4096)
                query = dns.message.from_wire(data)
                for _ in range(spoofs):
                    if from_elsewhere:
                        junk = dns.message.make_response(query)
                        junk.answer.append(dns.rrset.from_text("a.test.", 300, "IN", "A", "6.6.6.6"))
                        other.sendto(junk.to_wire(), addr)
                        continue
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
            other.close()

    @staticmethod
    @contextlib.contextmanager
    def _on_port(port: int):
        """Send to the ephemeral test port while leaving the resolver's code intact."""
        real = dns.query.udp

        def send(query, where, *args, **kwargs):
            kwargs["port"] = port
            return real(query, where, *args, **kwargs)

        with patch("dns.query.udp", side_effect=send):
            yield

    def _ask(self, port: int, **kwargs):
        resolver = offline_resolver(dnssec=False, **kwargs)
        ctx = resolver._new_context()
        with self._on_port(port):
            return resolver._query_once(dns.name.from_text("a.test."), dns.rdatatype.A, "127.0.0.1", 1232, 4.0, ctx)

    def test_a_packet_from_a_third_address_does_not_abort_the_query(self) -> None:
        """No spoofing needed: just send to our ephemeral port from anywhere.

        Such a reply matches the query perfectly except for its source, so it
        must be ignored, and the real answer behind it still used.
        """
        with self._server(spoofs=2, from_elsewhere=True) as port:
            response = self._ask(port)
        assert [str(rr) for rrset in response.answer for rr in rrset] == ["1.2.3.4"]

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


# ── Attacks on a signed zone, with real keys and signatures ─────────────────
#
# Each of these models an attacker who can answer in place of the zone's
# servers (on-path, or a successful spoof) but holds none of its keys. Only
# `_send_query` is replaced; everything the resolver does with the responses,
# including every signature check, is the real code.


def _dnskey_response(zone: SignedZone) -> dns.message.Message:
    response = make_response()
    response.answer += [zone.dnskey_rrset, zone.signed_dnskey()]
    return response


def _signed_referral(child: SignedZone, parent: SignedZone, address: str) -> dns.message.Message:
    zone = str(child.name)
    response = make_response(
        authority=[(zone, 3600, "NS", [f"ns.{zone}"])], additional=[(f"ns.{zone}", 3600, "A", [address])], aa=False
    )
    ds = parent.ds_rrset(child)
    response.authority += [ds, parent.sign(ds)]
    return response


_SOA = "ns.test. admin.test. 1 3600 900 604800 300"


class _World:
    """The root and `test.`, both signed, with `test.` answering through ``handler``.

    ``handler(qname, rdtype)`` returns the response from the `test.` servers,
    or None to fall through to the defaults: each zone's own DNSKEY, and the
    root's signed referral to `test.`.
    """

    def __init__(self, handler, *, extra_zones: tuple[SignedZone, ...] = (), **resolver_kwargs) -> None:
        self.root = SignedZone.create(".")
        self.tld = SignedZone.create("test.")
        self.zones = {z.name: z for z in (self.root, self.tld, *extra_zones)}
        self.handler = handler
        self.queries: list[tuple[str, str]] = []
        resolver_kwargs.setdefault("max_resolution_time", 5)
        self.resolver = RecursiveResolver(trust_anchors=(self.root.anchor_text(),), **resolver_kwargs)

    def send(self, qname, rdtype, nameservers, ctx, usable=None):
        self.queries.append((str(qname), dns.rdatatype.to_text(rdtype)))
        if rdtype == dns.rdatatype.DNSKEY and qname in self.zones:
            response, server = _dnskey_response(self.zones[qname]), nameservers[0]
        elif set(nameservers) & set(self.resolver._root_addresses):
            child = next(z for z in self.zones.values() if z is not self.root and qname.is_subdomain(z.name))
            response, server = _signed_referral(child, self.root, "9.9.9.9"), nameservers[0]
        else:
            response, server = self.handler(qname, rdtype), "9.9.9.9"
            if response is None:
                return None, ""
        if usable is not None and not usable(response):
            return None, ""
        return response, server

    def resolve(self, qname: str, rdtype: str = "A"):
        with patch.object(self.resolver, "_send_query", side_effect=self.send):
            return self.resolver.resolve_answer(qname, rdtype)


class TestAnUnsignedCNAMEBesideASignedDNAME:
    """RFC 6672 §3.4: the resolver synthesises the CNAME a DNAME implies.

    The CNAME a server sends beside a DNAME is unsigned by design, and used to
    be what the target was read from, while the verdict came from the DNAME's
    genuine signature. Anyone able to answer for the zone could point it
    anywhere and have the result come back SECURE.
    """

    def _world(self, *, forged: bool) -> _World:
        dname = rrset_of("sub.test.", "DNAME", "target.test.")
        target = rrset_of("foo.target.test.", "A", "192.0.2.10")

        def handler(qname, rdtype):
            if qname == dns.name.from_text("foo.sub.test."):
                cname_target = "www.evil." if forged else "foo.target.test."
                response = make_response()
                response.answer += [dname, world.tld.sign(dname), rrset_of("foo.sub.test.", "CNAME", cname_target)]
                return response
            if qname == dns.name.from_text("foo.target.test."):
                response = make_response()
                response.answer += [target, world.tld.sign(target)]
                return response
            return None

        world = _World(handler)
        return world

    def test_the_target_comes_from_the_dname_not_the_wire_cname(self) -> None:
        answer = self._world(forged=True).resolve("foo.sub.test.")
        assert answer.canonical_name == dns.name.from_text("foo.target.test.")
        assert answer.records == ["192.0.2.10"]
        assert answer.dnssec is ValidationState.SECURE

    def test_a_consistent_server_cname_changes_nothing(self) -> None:
        answer = self._world(forged=False).resolve("foo.sub.test.")
        assert answer.canonical_name == dns.name.from_text("foo.target.test.")
        assert answer.dnssec is ValidationState.SECURE


class TestReplayedWildcardNSEC:
    """A wildcard's NSEC, renamed, must not deny anything.

    Its signature has a Labels count one short of its owner, so dnspython
    verifies it against the rebuilt `*.<parent>` and it verifies under any
    owner below that parent. Both the record and the signature are public.
    """

    @staticmethod
    def _renamed(zone: SignedZone, nsec_text: str, wildcard: str, owner: str) -> list[dns.rrset.RRset]:
        genuine = rrset_of(wildcard, "NSEC", nsec_text)
        signature = zone.sign(genuine)
        assert signature[0].labels == len(genuine.name.labels) - 2
        nsec = dns.rrset.RRset(dns.name.from_text(owner), dns.rdataclass.IN, dns.rdatatype.NSEC)
        nsec.add(genuine[0])
        nsec.ttl = 300
        sig = dns.rrset.RRset(dns.name.from_text(owner), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        sig.add(signature[0])
        sig.ttl = 300
        return [nsec, sig]

    def test_it_does_not_prove_nodata_for_another_name(self) -> None:
        """`_dmarc.test.` really holds a TXT record; the replay claims it has none."""
        from recursive_resolver.dnssec import DNSSECValidator

        zone = SignedZone.create("test.")
        authority = self._renamed(zone, "_dmarc.test. A RRSIG NSEC", "*.test.", "_dmarc.test.")
        state = DNSSECValidator().prove_nodata(
            dns.name.from_text("_dmarc.test."), dns.rdatatype.TXT, authority, zone.keyring()
        )
        assert state is ValidationState.BOGUS

    def test_it_does_not_prove_nxdomain(self) -> None:
        from recursive_resolver.dnssec import DNSSECValidator

        zone = SignedZone.create("cdn.")
        authority = self._renamed(zone, "cdn. A RRSIG NSEC", "*.cdn.", "!.cdn.")
        state = DNSSECValidator().prove_nxdomain(dns.name.from_text("www.cdn."), authority, zone.keyring())
        assert state is ValidationState.BOGUS

    def test_the_genuine_record_under_its_own_name_still_counts(self) -> None:
        """The wildcard owner's own NSEC is fine: its Labels count is right for `*.test.`."""
        from recursive_resolver.dnssec import DNSSECValidator

        zone = SignedZone.create("test.")
        nsec = rrset_of("*.test.", "NSEC", "_dmarc.test. A RRSIG NSEC")
        state = DNSSECValidator().prove_nodata(
            dns.name.from_text("*.test."), dns.rdatatype.TXT, [nsec, zone.sign(nsec)], zone.keyring()
        )
        assert state is ValidationState.SECURE

    def test_the_resolver_refuses_the_forged_denial_end_to_end(self) -> None:
        def handler(qname, rdtype):
            soa = rrset_of("test.", "SOA", _SOA)
            response = make_response()
            response.authority += [soa, world.tld.sign(soa)]
            response.authority += self._renamed(world.tld, "_dmarc.test. A RRSIG NSEC", "*.test.", "_dmarc.test.")
            return response

        world = _World(handler)
        with pytest.raises(DNSSECValidationError):
            world.resolve("_dmarc.test.", "TXT")
        assert world.resolver.cache.get_nodata("_dmarc.test.", "TXT") is None


class TestAForgedSignerFieldCannotDowngradeASignedZone:
    """The signer field is unverified; the chain of trust must not follow it sideways.

    `test.` is signed and really has an unsigned delegation, `unsigned.test.`,
    whose missing DS it proves with a genuine NSEC. An RRSIG whose signer
    field merely *says* `unsigned.test.` used to send the chain walk there,
    and the genuine proof of that zone's missing DS was then applied to
    whatever name was being judged.
    """

    def _world(self, spoofed: dns.message.Message, final: dns.message.Message | None = None) -> _World:
        victim = SignedZone.create("victim.test.")
        junk = rrset_of("x.test.", "NSEC", "y.test. A")

        def handler(qname, rdtype):
            if rdtype == dns.rdatatype.DS and qname == dns.name.from_text("unsigned.test."):
                soa = rrset_of("test.", "SOA", _SOA)
                nsec = rrset_of("unsigned.test.", "NSEC", "v.test. NS RRSIG NSEC")
                response = make_response()
                response.authority += [soa, world.tld.sign(soa), nsec, world.tld.sign(nsec)]
                return response
            if final is not None and qname == victim.name and rdtype == dns.rdatatype.TXT and world.referred:
                return final
            if spoofed.authority and spoofed.authority[0].rdtype == dns.rdatatype.NS:
                world.referred = True
            return spoofed

        # Any signature at all, as long as its signer field names the unsigned zone.
        impostor = SignedZone(
            name=dns.name.from_text("unsigned.test."),
            private_key=victim.private_key,
            dnskey=victim.dnskey,
            dnskey_rrset=victim.dnskey_rrset,
        )
        spoofed.authority += [junk, impostor.sign(junk)]
        world = _World(handler, extra_zones=(victim,))
        world.tld_zone = world.tld
        world.referred = False
        return world

    def test_a_forged_nxdomain_is_still_bogus(self) -> None:
        nx = make_response(rcode=dns.rcode.NXDOMAIN, authority=[("test.", 300, "SOA", [_SOA])])
        with pytest.raises(DNSSECValidationError):
            self._world(nx).resolve("victim.test.", "TXT")

    def test_a_forged_nodata_at_the_apex_is_still_bogus(self) -> None:
        nd = make_response(authority=[("test.", 300, "SOA", [_SOA])])
        with pytest.raises(DNSSECValidationError):
            self._world(nd).resolve("test.", "CAA")

    def test_a_forged_referral_with_the_ds_stripped_is_still_bogus(self) -> None:
        referral_ = make_response(
            authority=[("victim.test.", 3600, "NS", ["ns.victim.test."])],
            additional=[("ns.victim.test.", 3600, "A", ["6.6.6.6"])],
            aa=False,
        )
        forged = make_response(answer=[("victim.test.", 300, "TXT", ['"v=DKIM1; p=ATTACKERKEY"'])])
        world = self._world(referral_, forged)
        with pytest.raises(DNSSECValidationError):
            world.resolve("victim.test.", "TXT")
        assert world.resolver.cache.get_delegation(dns.name.from_text("victim.test.")) is None


class TestDSWithAnAlgorithmWeCannotCheck:
    """RFC 4035 §5.2: "unverifiable" is read off the signed DS, never off the keys served.

    The DS RRset lists an algorithm 13 key and an algorithm 12 one, which this
    build cannot verify. A forged DNSKEY answer holding only the algorithm 12
    key used to make the zone look unverifiable, so it was treated as
    unsigned.
    """

    def test_dropping_the_supported_key_is_bogus_not_insecure(self) -> None:
        from recursive_resolver.dnssec import DNSSECValidator

        zone = SignedZone.create("z.test.")
        gost = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 12 " + "AAAA" * 16)
        ds = zone.ds_rdataset(zone)
        ds.add(dns.dnssec.make_ds(zone.name, gost, "SHA256"))
        only_gost = dns.rrset.RRset(zone.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        only_gost.add(gost)
        only_gost.ttl = 300
        assert DNSSECValidator().validate_dnskey(zone.name, only_gost, None, ds) is ValidationState.BOGUS
        # The genuine RRset still validates against the same DS set.
        genuine = DNSSECValidator().validate_dnskey(zone.name, zone.dnskey_rrset, zone.signed_dnskey(), ds)
        assert genuine is ValidationState.SECURE

    def test_a_ds_set_naming_only_unsupported_algorithms_is_insecure(self) -> None:
        from recursive_resolver.dnssec import DNSSECValidator

        zone = SignedZone.create("z.test.")
        gost = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 12 " + "AAAA" * 16)
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds.add(dns.dnssec.make_ds(zone.name, gost, "SHA256"), ttl=300)
        assert DNSSECValidator().validate_dnskey(zone.name, zone.dnskey_rrset, None, ds) is ValidationState.INSECURE

    def test_unsupported_ds_records_sent_first_do_not_hide_the_supported_one(self) -> None:
        """Only so many DS are digested, and the order of an RRset is not signed."""
        from recursive_resolver.dnssec import MAX_DS_PER_ZONE, DNSSECValidator

        zone = SignedZone.create("z.test.")
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        for tag in range(MAX_DS_PER_ZONE):
            ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, f"{tag} 12 2 " + "AB" * 32), ttl=300)
        for genuine in zone.ds_rdataset(zone):
            ds.add(genuine, ttl=300)
        state = DNSSECValidator().validate_dnskey(zone.name, zone.dnskey_rrset, zone.signed_dnskey(), ds)
        assert state is ValidationState.SECURE

    def test_a_sha1_ds_is_ignored_beside_a_sha256_one(self) -> None:
        """RFC 4509 §3, so a weak digest cannot stand in for the strong one."""
        from recursive_resolver.dnssec import DNSSECValidator

        zone = SignedZone.create("z.test.")
        other = SignedZone.create("z.test.")
        # dnspython refuses to *create* SHA-1 DS records by default, not to check them.
        sha1 = dns.dnssec.make_ds(zone.name, other.dnskey, "SHA1", policy=dns.dnssec.allow_all_policy)
        ds = zone.ds_rdataset(zone)
        ds.add(sha1)
        state = DNSSECValidator().validate_dnskey(zone.name, other.dnskey_rrset, other.signed_dnskey(), ds)
        assert state is ValidationState.BOGUS
        alone = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        alone.add(sha1, ttl=300)
        state = DNSSECValidator().validate_dnskey(zone.name, other.dnskey_rrset, other.signed_dnskey(), alone)
        assert state is ValidationState.SECURE


class TestKeysDoNotOutliveTheirSignatures:
    """RFC 4035 §5.3.3 applies to DNSKEY and DS as much as to answers.

    Keys used to be cached for their wire TTL, up to a day, with a 60 second
    floor: a rollover or an emergency revocation went unnoticed for that long.
    """

    def test_validated_keys_expire_with_their_signature(self) -> None:
        import time

        world = _World(lambda q, t: None, cache_enabled=True)
        zone = world.tld
        soon = int(time.time()) + 30
        rrsig = zone.sign(zone.dnskey_rrset, expiration=soon)
        response = make_response()
        response.answer += [zone.dnskey_rrset, rrsig]
        ctx = world.resolver._new_context()
        with patch.object(world.resolver, "_send_query", return_value=(response, "9.9.9.9")):
            keys = world.resolver._get_zone_keys(zone.name, world.root.ds_rdataset(zone), ["9.9.9.9"], ctx)
        assert keys.state is ValidationState.SECURE
        assert 0 < keys.expiry - time.monotonic() <= 30

    def test_a_validated_ds_carries_its_signature_cap(self) -> None:
        import time

        from recursive_resolver.dnssec import DNSSECValidator

        parent, child = SignedZone.create("test."), SignedZone.create("z.test.")
        ds = parent.ds_rrset(child)
        authority = [ds, parent.sign(ds, expiration=int(time.time()) + 30)]
        state, rdataset = DNSSECValidator().validate_ds(child.name, authority, parent.keyring())
        assert state is ValidationState.SECURE and rdataset is not None
        assert rdataset.ttl <= 30


class TestLameZonesAreNotAnAmplifier:
    """A zone whose servers all refuse it must cost about one query per server.

    Its in-zone NS names used to be resolved again through the same failing
    servers, recursively, until the budget ran out: 44 to 64 queries at the
    victim's servers per call, reported as a budget attack.
    """

    def test_refusing_in_zone_servers_are_each_asked_once(self) -> None:
        resolver = offline_resolver(dnssec=False)
        servers = {f"ns{i}.example.com.": f"9.9.9.{i}" for i in range(1, 5)}
        sent: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            sent.append(server)
            if server in resolver._root_addresses:
                return root_to_com()
            if server == "192.5.6.30":
                return referral("example.com.", list(servers), servers)
            return make_response(rcode=dns.rcode.REFUSED, aa=False)

        with patch.object(resolver, "_query_once", side_effect=query_once), pytest.raises(ServfailError):
            resolver.resolve("www.example.com", "A")
        assert len([s for s in sent if s.startswith("9.9.9.")]) == 4

    def test_servfail_from_every_server_while_validating_is_one_sweep(self) -> None:
        """Each SERVFAIL was held back while the sweep went on, then only one server dropped: N squared."""
        resolver = RecursiveResolver(cache_enabled=False)
        servers = [f"9.9.9.{i}" for i in range(1, 9)]
        sent: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            sent.append(server)
            return make_response(rcode=dns.rcode.SERVFAIL, aa=False)

        start = (dns.name.from_text("example.com."), list(servers), ValidationState.SECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(ServfailError),
        ):
            resolver.resolve("www.example.com", "A")
        assert len(sent) == len(servers)

    def test_servfail_from_every_server_without_validation_is_linear(self) -> None:
        """Each server is asked with EDNS, then once without: never again on later passes."""
        resolver = offline_resolver(dnssec=False)
        servers = [f"9.9.9.{i}" for i in range(1, 9)]
        sent: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            sent.append(server)
            return make_response(rcode=dns.rcode.SERVFAIL, aa=False)

        start = (dns.name.from_text("example.com."), list(servers), ValidationState.INSECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(ServfailError),
        ):
            resolver.resolve("www.example.com", "A")
        assert len(sent) <= 2 * len(servers)


class TestRedundantQueries:
    def test_an_nxdomain_is_confirmed_by_one_sibling_not_two(self) -> None:
        resolver = offline_resolver(dnssec=False)
        asked: list[list[str]] = []
        nx = make_response(rcode=dns.rcode.NXDOMAIN, authority=[("example.com.", 300, "SOA", [_SOA])])

        def send(qname, rdtype, nameservers, ctx, usable=None):
            asked.append(list(nameservers))
            if set(nameservers) & set(resolver._root_addresses):
                return root_to_com(), nameservers[0]
            if nameservers == ["192.5.6.30"]:
                glue = {f"ns{i}.example.com.": f"9.9.9.{i}" for i in range(1, 5)}
                return referral("example.com.", list(glue), glue), "192.5.6.30"
            return nx, nameservers[0]

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NXDOMAINError):
            resolver.resolve("nope.example.com", "A")
        assert len(asked) == 2 + 2

    def test_cname_chain_lists_each_redirected_name_once(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        records = {
            "a.example.com.": ("CNAME", "b.example.com."),
            "b.example.com.": ("CNAME", "c.example.com."),
            "c.example.com.": ("A", "1.2.3.4"),
        }
        upstream = {"n": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            upstream["n"] += 1
            kind, value = records[str(qname)]
            return make_response(answer=[(str(qname), 300, kind, [value])]), "9.9.9.9"

        start = (dns.name.from_text("example.com."), ["9.9.9.9"], ValidationState.INSECURE, None, [])
        with (
            patch.object(resolver, "_send_query", side_effect=send),
            patch.object(resolver, "_starting_point", return_value=start),
        ):
            cold = resolver.resolve_answer("a.example.com", "A")
            before = upstream["n"]
            warm = resolver.resolve_answer("a.example.com", "A")
        expected = [dns.name.from_text("a.example.com."), dns.name.from_text("b.example.com.")]
        assert cold.cname_chain == expected
        assert warm.cname_chain == expected
        assert warm.canonical_name == dns.name.from_text("c.example.com.")
        # The cached CNAMEs are followed without asking anyone.
        assert upstream["n"] == before

    def test_a_failure_is_remembered_briefly(self) -> None:
        """RFC 9520: retrying callers must not each send the full set of queries again."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        upstream = {"n": 0}

        def send(qname, rdtype, nameservers, ctx, usable=None):
            upstream["n"] += 1
            return make_response(rcode=dns.rcode.REFUSED, aa=False), nameservers[0]

        with patch.object(resolver, "_send_query", side_effect=send):
            for _ in range(3):
                with pytest.raises(ServfailError) as caught:
                    resolver.resolve("broken.example.com", "A")
        first = upstream["n"]
        assert first < 20
        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ServfailError):
            resolver.resolve("broken.example.com", "A")
        assert upstream["n"] == first
        assert caught.value.query_name == "broken.example.com."

    def test_an_unsigned_copy_is_retried_on_one_sibling_only(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)
        sent: list[str] = []
        unsigned = make_response(answer=[("www.example.com.", 300, "A", ["1.2.3.4"])])

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            sent.append(server)
            return unsigned

        servers = [f"9.9.9.{i}" for i in range(1, 7)]
        start = (dns.name.from_text("example.com."), servers, ValidationState.SECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_query_once", side_effect=query_once),
            patch.object(resolver, "_insecurely_delegated", return_value=True),
        ):
            resolver.resolve("www.example.com", "A")
        assert len(sent) == 2


class TestNoDowngradeOfTheEDNSLadderBelowAnUnsignedCut:
    """With validation on, plain DNS used to be off for every zone, signed or not.

    A server that cannot do EDNS was unreachable even for an unsigned zone,
    where nothing is validated and a DO-less answer loses nothing.
    """

    def test_plain_dns_is_tried_where_the_chain_is_insecure(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            if payload is not None:
                return make_response(rcode=dns.rcode.FORMERR, aa=False)
            return make_response(answer=[("www.example.com.", 300, "A", ["1.2.3.4"])])

        start = (dns.name.from_text("example.com."), ["9.9.9.9"], ValidationState.INSECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_query_once", side_effect=query_once),
        ):
            assert resolver.resolve("www.example.com", "A") == ["1.2.3.4"]
        assert payloads[-1] is None

    def test_a_secure_chain_still_never_drops_edns(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            return make_response(rcode=dns.rcode.FORMERR, aa=False)

        start = (dns.name.from_text("example.com."), ["9.9.9.9"], ValidationState.SECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_query_once", side_effect=query_once),
            pytest.raises(ResolverError),
        ):
            resolver.resolve("www.example.com", "A")
        assert None not in payloads


class TestRedirectionsNeedTheAABit:
    """A CNAME or DNAME is an answer, and held to the same rule as one."""

    @pytest.mark.parametrize(
        ("rdtype", "owner", "target"),
        [("CNAME", "www.example.com.", "evil.example.net."), ("DNAME", "example.com.", "example.net.")],
    )
    def test_a_redirection_without_aa_is_an_error(self, rdtype: str, owner: str, target: str) -> None:
        resolver = offline_resolver()
        response = make_response(answer=[(owner, 300, rdtype, [target])], aa=False)
        classification = resolver._classify_response(
            response, dns.name.from_text("www.example.com."), dns.rdatatype.A, dns.name.from_text("example.com.")
        )
        assert classification["type"] == "error"
        assert "AA" in classification["detail"]


class TestDSInReferralForm:
    """A parent may answer a DS query as a referral, with the DS and its RRSIG in AUTHORITY."""

    def test_the_signature_is_looked_for_where_the_ds_is(self) -> None:
        world = _World(lambda q, t: None)
        child = SignedZone.create("z.test.")
        ds = world.tld.ds_rrset(child)
        response = make_response(
            authority=[("z.test.", 3600, "NS", ["ns.z.test."])], additional=[("ns.z.test.", 3600, "A", ["9.9.9.9"])]
        )
        response.authority += [ds, world.tld.sign(ds)]
        world.handler = lambda q, t: response
        answer = world.resolve("z.test.", "DS")
        assert answer.dnssec is ValidationState.SECURE


class TestDNSSECChecksMatchWhatCanBeVerified:
    def test_algorithms_dnspython_refuses_to_validate_are_unsupported(self) -> None:
        """RSAMD5 and DSA zones are unverifiable, so unsigned (RFC 8624), not BOGUS."""
        from recursive_resolver.dnssec import algorithm_supported

        assert algorithm_supported(1) is False
        assert algorithm_supported(3) is False
        assert algorithm_supported(6) is False
        assert algorithm_supported(8) is True

    def test_a_host_that_refuses_sha1_treats_rsasha1_as_unsupported(self) -> None:
        from recursive_resolver import dnssec

        assert dnssec._sha1_signatures_verify() is True, "this host verifies SHA-1"
        assert dnssec.algorithm_supported(5) is True
        with patch.object(dnssec, "_sha1_signatures_verify", return_value=False):
            assert dnssec.algorithm_supported(5) is False
            assert dnssec.algorithm_supported(7) is False
            assert dnssec.algorithm_supported(8) is True

    def test_the_sha1_probe_fails_closed(self) -> None:
        from recursive_resolver import dnssec

        dnssec._sha1_signatures_verify.cache_clear()
        try:
            with patch("dns.dnssec.validate_rrsig", side_effect=dns.dnssec.ValidationFailure("policy")):
                assert dnssec._sha1_signatures_verify() is False
        finally:
            dnssec._sha1_signatures_verify.cache_clear()


class TestNoDSProofFromTheChildApex:
    def test_an_nsec3_bearing_soa_cannot_deny_the_ds(self) -> None:
        """The NSEC branch already refused the child's own apex record; NSEC3 did not."""
        from recursive_resolver.dnssec import DNSSECValidator

        parent = SignedZone.create("test.")
        child = dns.name.from_text("z.test.")
        owner = dns.dnssec.nsec3_hash(child, "", 0, 1)
        nsec3 = rrset_of(f"{owner}.test.", "NSEC3", "1 0 0 - " + "0" * 31 + "G NS SOA RRSIG DNSKEY")
        authority = [nsec3, parent.sign(nsec3)]
        assert DNSSECValidator().prove_no_ds(child, authority, parent.keyring()) is False


class TestAZoneServedByItsGrandparent:
    """The root servers serve `root-servers.net` but not `net`.

    Asked for `net`'s keys, or for the DS of `root-servers.net`, they refer to
    the `net` servers. The chain walk used to ask only the servers it started
    with, so every name in `root-servers.net` came back "material unavailable".
    Here `rs.test.` plays that part.
    """

    TLD_SERVER = "9.9.9.53"

    def _resolver(self, **kwargs) -> tuple[RecursiveResolver, list[tuple[str, str, str]]]:
        root, tld = SignedZone.create("."), SignedZone.create("test.")
        resolver = RecursiveResolver(trust_anchors=(root.anchor_text(),), max_resolution_time=5, **kwargs)
        roots = set(resolver._root_addresses)
        queries: list[tuple[str, str, str]] = []
        rs = dns.name.from_text("rs.test.")
        soa = "ns.rs.test. admin.rs.test. 1 3600 900 604800 300"

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            queries.append((str(qname), dns.rdatatype.to_text(rdtype), server))
            if server == self.TLD_SERVER:
                if rdtype == dns.rdatatype.DNSKEY and qname == tld.name:
                    return _dnskey_response(tld)
                nsec = rrset_of("rs.test.", "NSEC", "z.test. NS RRSIG NSEC")
                tld_soa = rrset_of("test.", "SOA", _SOA)
                response = make_response()
                response.authority += [tld_soa, tld.sign(tld_soa), nsec, tld.sign(nsec)]
                return response
            assert server in roots
            if rdtype == dns.rdatatype.DNSKEY and qname == dns.name.root:
                return _dnskey_response(root)
            if rdtype == dns.rdatatype.DS and qname == tld.name:
                ds = root.ds_rrset(tld)
                response = make_response()
                response.answer += [ds, root.sign(ds)]
                return response
            if qname.is_subdomain(rs) and rdtype != dns.rdatatype.DS:
                return make_response(authority=[("rs.test.", 300, "SOA", [soa])])
            # Like the root: anything about `test.` itself is a referral.
            response = make_response(
                authority=[("test.", 3600, "NS", ["ns.test."])],
                additional=[("ns.test.", 3600, "A", [self.TLD_SERVER])],
                aa=False,
            )
            ds = root.ds_rrset(tld)
            response.authority += [ds, root.sign(ds)]
            return response

        resolver._query_once = query_once
        return resolver, queries

    def test_the_referral_is_followed_for_the_keys(self) -> None:
        resolver, queries = self._resolver()
        with pytest.raises(NoAnswerError):
            resolver.resolve("rs.test.", "A")
        assert ("test.", "DNSKEY", self.TLD_SERVER) in queries
        assert ("rs.test.", "DS", self.TLD_SERVER) in queries

    def test_and_for_the_ds_when_the_keys_are_cached(self) -> None:
        resolver, queries = self._resolver()
        with pytest.raises(NoAnswerError):
            resolver.resolve("rs.test.", "A")
        queries.clear()
        with pytest.raises(NoAnswerError):
            resolver.resolve("rs.test.", "TXT")
        assert not any(rdtype == "DNSKEY" for _name, rdtype, _server in queries)
        assert ("rs.test.", "DS", self.TLD_SERVER) in queries

    def test_the_verdict_is_insecure(self) -> None:
        resolver, _queries = self._resolver(require_dnssec=True)
        with pytest.raises(DNSSECInsecureError):
            resolver.resolve("rs.test.", "A")
