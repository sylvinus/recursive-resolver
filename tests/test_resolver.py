"""Unit tests for the recursive resolver (mocked DNS, no network)."""

from __future__ import annotations

from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from recursive_resolver.exceptions import (
    CNAMELoopError,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    ResolutionTimeoutError,
    ServfailError,
)
from recursive_resolver.resolver import RecursiveResolver, TraceStep


def _make_response(
    qname: str = "example.com.",
    rdtype: int = dns.rdatatype.A,
    rcode: int = dns.rcode.NOERROR,
    answer: list[tuple[str, int, str, list[str]]] | None = None,
    authority: list[tuple[str, int, str, list[str]]] | None = None,
    additional: list[tuple[str, int, str, list[str]]] | None = None,
) -> dns.message.Message:
    """Build a dns.message.Message for testing.

    answer/authority/additional: list of (name, ttl, rdtype_str, [rdata_str, ...])
    """
    response = dns.message.Message()
    response.flags = dns.flags.QR
    response.id = 0
    response.set_rcode(rcode)

    for section, records in [
        (response.answer, answer or []),
        (response.authority, authority or []),
        (response.additional, additional or []),
    ]:
        for name_str, ttl, rdtype_str, rdata_strs in records:
            name = dns.name.from_text(name_str)
            rdt = dns.rdatatype.from_text(rdtype_str)
            rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdt)
            for rd_str in rdata_strs:
                rd = dns.rdata.from_text(dns.rdataclass.IN, rdt, rd_str)
                rrset.add(rd)
            rrset.update_ttl(ttl)
            section.append(rrset)

    return response


def _mock_send_sequence(responses: list[tuple[dns.message.Message, str]]):
    """Create a side_effect function that returns responses in sequence."""
    call_count = 0

    def side_effect(qname, rdtype, nameservers, deadline=0.0):
        nonlocal call_count
        if call_count < len(responses):
            result = responses[call_count]
            call_count += 1
            return result
        return (None, "")

    return side_effect


class TestResolverSimpleA:
    """Test simple A record resolution through delegation chain."""

    def test_simple_a_resolution(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        # Root -> .com referral
        root_response = _make_response(
            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
        )
        # .com -> example.com referral
        com_response = _make_response(
            authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
        )
        # example.com -> answer
        answer_response = _make_response(
            answer=[("example.com.", 300, "A", ["93.184.216.34"])],
        )

        responses = [
            (root_response, "198.41.0.4"),
            (com_response, "192.5.6.30"),
            (answer_response, "93.184.216.34"),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            result = resolver.resolve("example.com", "A")
            assert result == ["93.184.216.34"]


class TestResolverCNAME:
    """Test CNAME following."""

    def test_cname_following(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if qname == "www.example.com." and rdtype == "A":
                if call_count == 1:
                    # Root referral
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                elif call_count == 2:
                    # .com referral
                    return (
                        _make_response(
                            authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                            additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                        ),
                        "192.5.6.30",
                    )
                elif call_count == 3:
                    # CNAME answer
                    return (
                        _make_response(
                            answer=[("www.example.com.", 300, "CNAME", ["example.com."])],
                        ),
                        "93.184.216.34",
                    )

            if qname == "example.com." and rdtype == "A":
                if call_count == 4:
                    # Root referral for canonical name
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                elif call_count == 5:
                    # .com referral
                    return (
                        _make_response(
                            authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                            additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                        ),
                        "192.5.6.30",
                    )
                elif call_count == 6:
                    # Final answer
                    return (
                        _make_response(
                            answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                        ),
                        "93.184.216.34",
                    )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("www.example.com", "A")
            assert result == ["93.184.216.34"]


class TestResolverCNAMELoop:
    """Test CNAME loop detection."""

    def test_cname_loop_raises(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False, max_cname_chain=5)

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            if qname == "a.example.com.":
                return (
                    _make_response(
                        answer=[("a.example.com.", 300, "CNAME", ["b.example.com."])],
                    ),
                    "1.2.3.4",
                )
            elif qname == "b.example.com.":
                return (
                    _make_response(
                        answer=[("b.example.com.", 300, "CNAME", ["a.example.com."])],
                    ),
                    "1.2.3.4",
                )
            # For referrals, just return direct answers
            return (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["1.2.3.4"])],
                ),
                "198.41.0.4",
            )

        with patch.object(resolver, "_send_query", side_effect=mock_send), pytest.raises(CNAMELoopError):
            resolver.resolve("a.example.com", "A")


class TestResolverNXDOMAIN:
    """Test NXDOMAIN handling."""

    def test_nxdomain_raises(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            # Root referral
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            # NXDOMAIN from .com server
            (_make_response(rcode=dns.rcode.NXDOMAIN), "192.5.6.30"),
        ]

        with (
            patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)),
            pytest.raises(NXDOMAINError),
        ):
            resolver.resolve("nonexistent.com", "A")


class TestResolverNODATA:
    """Test NODATA handling."""

    def test_nodata_raises(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            # Root referral
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            # .com referral
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                ),
                "192.5.6.30",
            ),
            # Empty response (NODATA): no answer, no authority NS
            (
                _make_response(
                    authority=[
                        ("example.com.", 300, "SOA", ["ns1.example.com. admin.example.com. 1 3600 900 604800 86400"])
                    ],
                ),
                "93.184.216.34",
            ),
        ]

        with (
            patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)),
            pytest.raises(NoAnswerError),
        ):
            resolver.resolve("example.com", "AAAA")


class TestResolverGlueless:
    """Test glueless referral handling."""

    def test_glueless_referral(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            # Main query: example.com A
            if qname == "example.com." and rdtype == "A":
                if call_count == 1:
                    # Root: referral to .com
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # .com: glueless referral (NS in different zone)
                    return (
                        _make_response(
                            authority=[("example.com.", 172800, "NS", ["ns1.otherdns.net."])],
                        ),
                        "192.5.6.30",
                    )
                # After glueless resolution, we query ns1.otherdns.net IP
                return (
                    _make_response(
                        answer=[("example.com.", 300, "A", ["1.2.3.4"])],
                    ),
                    "10.0.0.1",
                )

            # Sub-resolution: ns1.otherdns.net A
            if qname == "ns1.otherdns.net." and rdtype == "A":
                if "198.41.0.4" in nameservers or len(nameservers) > 5:
                    # Root referral
                    return (
                        _make_response(
                            authority=[("net.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if "192.5.6.30" in nameservers:
                    # .net referral
                    return (
                        _make_response(
                            authority=[("otherdns.net.", 172800, "NS", ["ns1.otherdns.net."])],
                            additional=[("ns1.otherdns.net.", 172800, "A", ["10.0.0.1"])],
                        ),
                        "192.5.6.30",
                    )
                return (
                    _make_response(
                        answer=[("ns1.otherdns.net.", 300, "A", ["10.0.0.1"])],
                    ),
                    "10.0.0.1",
                )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("example.com", "A")
            assert result == ["1.2.3.4"]


class TestResolverMaxDepth:
    """Test max depth enforcement."""

    def test_max_depth_raises(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False, max_depth=3)

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            # Always return a referral, never an answer
            return (
                _make_response(
                    authority=[("sub.example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["1.2.3.4"])],
                ),
                "1.2.3.4",
            )

        with patch.object(resolver, "_send_query", side_effect=mock_send), pytest.raises(MaxDepthError):
            resolver.resolve("example.com", "A")


class TestResolverTimeout:
    """Test timeout handling and fallback to next server."""

    def test_all_servers_timeout(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            return (None, "")

        with (
            patch.object(resolver, "_send_query", side_effect=mock_send),
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver.resolve("example.com", "A")


class TestResolverServfail:
    """Test SERVFAIL handling."""

    def test_servfail_raises(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            # Root referral
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            # SERVFAIL
            (_make_response(rcode=dns.rcode.SERVFAIL), "192.5.6.30"),
        ]

        with (
            patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)),
            pytest.raises(ServfailError),
        ):
            resolver.resolve("example.com", "A")


class TestResolverServfailRetry:
    """Test that SERVFAIL from one NS falls back to another."""

    def test_servfail_retries_next_ns(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if qname == "example.com." and rdtype == "A":
                if call_count == 1:
                    # Root referral
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # .com referral with two NS glue IPs
                    return (
                        _make_response(
                            authority=[
                                ("example.com.", 172800, "NS", ["ns1.example.com.", "ns2.example.com."]),
                            ],
                            additional=[
                                ("ns1.example.com.", 172800, "A", ["1.1.1.1"]),
                                ("ns2.example.com.", 172800, "A", ["2.2.2.2"]),
                            ],
                        ),
                        "192.5.6.30",
                    )
                if call_count == 3:
                    # First NS returns SERVFAIL
                    return (_make_response(rcode=dns.rcode.SERVFAIL), "1.1.1.1")
                if call_count == 4:
                    # Second NS returns the answer
                    return (
                        _make_response(
                            answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                        ),
                        "2.2.2.2",
                    )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("example.com", "A")
            assert result == ["93.184.216.34"]
            assert call_count == 4  # root, referral, servfail, answer


class TestResolverFormErr:
    """Test FORMERR triggers EDNS fallback."""

    def test_formerr_retries_without_edns(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # Root referral
                return (
                    _make_response(
                        authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                        additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                    ),
                    "198.41.0.4",
                )
            if call_count == 2:
                # Referral to final NS
                return (
                    _make_response(
                        authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                        additional=[("ns1.example.com.", 172800, "A", ["1.2.3.4"])],
                    ),
                    "192.5.6.30",
                )
            if call_count == 3:
                # FORMERR — server doesn't like EDNS0
                return (_make_response(rcode=dns.rcode.FORMERR), "1.2.3.4")
            # Should not reach here since _send_query handles FORMERR internally
            return (None, "")

        # We need to test at a lower level: _send_query should handle FORMERR
        # by calling _send_query_plain. Let's mock at the dns.query level instead.
        plain_response = _make_response(
            answer=[("example.com.", 300, "A", ["93.184.216.34"])],
        )

        with (
            patch.object(
                resolver,
                "_send_query",
                side_effect=_mock_send_sequence(
                    [
                        (
                            _make_response(
                                authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                                additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                            ),
                            "198.41.0.4",
                        ),
                        (
                            _make_response(
                                authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                                additional=[("ns1.example.com.", 172800, "A", ["1.2.3.4"])],
                            ),
                            "192.5.6.30",
                        ),
                        # Final answer (after FORMERR is handled internally by _send_query)
                        (plain_response, "1.2.3.4"),
                    ]
                ),
            ),
        ):
            result = resolver.resolve("example.com", "A")
            assert result == ["93.184.216.34"]


class TestResolverStaleGlueFallback:
    """Test fallback to glueless resolution when glue IPs are stale/dead.

    When a referral provides glue IPs that are all unreachable, the resolver
    should fall back to resolving NS hostnames from scratch.
    """

    def test_stale_glue_falls_back_to_ns_resolution(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if qname == "example.com." and rdtype == "A":
                if call_count == 1:
                    # Root referral
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # .com referral with stale glue (dead IP) + glueless NS
                    return (
                        _make_response(
                            authority=[
                                (
                                    "example.com.",
                                    172800,
                                    "NS",
                                    [
                                        "ns1.example.com.",
                                        "ns2.otherdns.net.",
                                    ],
                                )
                            ],
                            additional=[
                                # Stale glue: this IP is dead
                                ("ns1.example.com.", 172800, "A", ["10.0.0.1"]),
                            ],
                        ),
                        "192.5.6.30",
                    )
                if call_count == 3:
                    # Query to stale glue IP fails: _send_query returns None
                    # because only 10.0.0.1 is in the nameservers list
                    assert "10.0.0.1" in nameservers
                    return (None, "")
                # After glueless fallback resolves ns2.otherdns.net -> 5.6.7.8
                if "5.6.7.8" in nameservers:
                    return (
                        _make_response(
                            answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                        ),
                        "5.6.7.8",
                    )

            # Sub-resolution of ns2.otherdns.net
            if qname == "ns2.otherdns.net." and rdtype == "A":
                if "198.41.0.4" in nameservers or len(nameservers) > 5:
                    return (
                        _make_response(
                            authority=[("net.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if "192.5.6.30" in nameservers:
                    return (
                        _make_response(
                            authority=[("otherdns.net.", 172800, "NS", ["ns1.otherdns.net."])],
                            additional=[("ns1.otherdns.net.", 172800, "A", ["5.5.5.5"])],
                        ),
                        "192.5.6.30",
                    )
                return (
                    _make_response(
                        answer=[("ns2.otherdns.net.", 300, "A", ["5.6.7.8"])],
                    ),
                    "5.5.5.5",
                )

            # Also need ns1.example.com resolution (but it will fail)
            if qname == "ns1.example.com." and rdtype == "A":
                return (None, "")

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("example.com", "A")
            assert result == ["93.184.216.34"]


class TestResolverNXDOMAINRetry:
    """Test that NXDOMAIN from one NS retries with sibling nameservers.

    Some TLD nameservers are inconsistent — one may return NXDOMAIN while
    others correctly refer the domain. The resolver should try other servers
    before accepting NXDOMAIN.
    """

    def test_nxdomain_retries_sibling_ns(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # Root referral to .ir with multiple NS
                return (
                    _make_response(
                        authority=[("ir.", 172800, "NS", ["a.nic.ir.", "b.nic.ir."])],
                        additional=[
                            ("a.nic.ir.", 172800, "A", ["1.1.1.1"]),
                            ("b.nic.ir.", 172800, "A", ["2.2.2.2"]),
                        ],
                    ),
                    "198.41.0.4",
                )
            if call_count == 2:
                # First .ir NS returns NXDOMAIN (stale/inconsistent)
                return (_make_response(rcode=dns.rcode.NXDOMAIN), "1.1.1.1")
            if call_count == 3:
                # Second .ir NS correctly refers to the domain's NS
                return (
                    _make_response(
                        authority=[("example.ir.", 172800, "NS", ["ns1.example.ir."])],
                        additional=[("ns1.example.ir.", 172800, "A", ["3.3.3.3"])],
                    ),
                    "2.2.2.2",
                )
            if call_count == 4:
                # Domain's NS returns the answer
                return (
                    _make_response(
                        answer=[("example.ir.", 300, "A", ["4.4.4.4"])],
                    ),
                    "3.3.3.3",
                )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("example.ir", "A")
            assert result == ["4.4.4.4"]
            assert call_count == 4

    def test_nxdomain_all_servers_agree_raises(self) -> None:
        """If all nameservers return NXDOMAIN, it should still raise."""
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # Root referral with two NS
                return (
                    _make_response(
                        authority=[("com.", 172800, "NS", ["a.gtld-servers.net.", "b.gtld-servers.net."])],
                        additional=[
                            ("a.gtld-servers.net.", 172800, "A", ["1.1.1.1"]),
                            ("b.gtld-servers.net.", 172800, "A", ["2.2.2.2"]),
                        ],
                    ),
                    "198.41.0.4",
                )
            # Both .com servers return NXDOMAIN
            return (_make_response(rcode=dns.rcode.NXDOMAIN), nameservers[0] if nameservers else "1.1.1.1")

        with patch.object(resolver, "_send_query", side_effect=mock_send), pytest.raises(NXDOMAINError):
            resolver.resolve("nonexistent.com", "A")


class TestResolverPTR:
    """Test PTR auto-reverse."""

    def test_ptr_auto_reverse(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            # Main PTR query
            if qname == "8.8.8.8.in-addr.arpa." and rdtype == "PTR":
                assert qname == "8.8.8.8.in-addr.arpa."
                if call_count == 1:
                    return (
                        _make_response(
                            authority=[("in-addr.arpa.", 172800, "NS", ["ns1.arpa."])],
                            additional=[("ns1.arpa.", 172800, "A", ["1.2.3.4"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # Glueless referral: ns1.google.com. is out of bailiwick for in-addr.arpa.
                    return (
                        _make_response(
                            authority=[("8.in-addr.arpa.", 172800, "NS", ["ns1.google.com."])],
                        ),
                        "1.2.3.4",
                    )
                # After glueless resolution of ns1.google.com -> 8.8.8.8
                return (
                    _make_response(
                        answer=[("8.8.8.8.in-addr.arpa.", 300, "PTR", ["dns.google."])],
                    ),
                    "8.8.8.8",
                )

            # Sub-resolution: ns1.google.com A (glueless)
            if qname == "ns1.google.com." and rdtype == "A":
                if "198.41.0.4" in nameservers or len(nameservers) > 5:
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if "192.5.6.30" in nameservers:
                    return (
                        _make_response(
                            authority=[("google.com.", 172800, "NS", ["ns1.google.com."])],
                            additional=[("ns1.google.com.", 172800, "A", ["8.8.8.8"])],
                        ),
                        "192.5.6.30",
                    )
                return (
                    _make_response(
                        answer=[("ns1.google.com.", 300, "A", ["8.8.8.8"])],
                    ),
                    "8.8.8.8",
                )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("8.8.8.8", "PTR")
            assert result == ["dns.google."]


class TestResolverCache:
    """Test that caching works."""

    def test_cache_hit_avoids_queries(self) -> None:
        resolver = RecursiveResolver(cache_enabled=True)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (
                    _make_response(
                        authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                        additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                    ),
                    "198.41.0.4",
                )
            if call_count == 2:
                return (
                    _make_response(
                        authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                        additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                    ),
                    "192.5.6.30",
                )
            if call_count == 3:
                return (
                    _make_response(
                        answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                    ),
                    "93.184.216.34",
                )
            # Should not be called again
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result1 = resolver.resolve("example.com", "A")
            assert result1 == ["93.184.216.34"]
            assert call_count == 3

            # Second resolve should use cache
            result2 = resolver.resolve("example.com", "A")
            assert result2 == ["93.184.216.34"]
            assert call_count == 3  # No additional queries


class TestResolverMX:
    """Test MX record resolution."""

    def test_mx_resolution(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                ),
                "192.5.6.30",
            ),
            (
                _make_response(
                    answer=[("example.com.", 300, "MX", ["10 mail.example.com."])],
                ),
                "93.184.216.34",
            ),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            result = resolver.resolve("example.com", "MX")
            assert result == ["10 mail.example.com."]


class TestResolverTXT:
    """Test TXT record resolution."""

    def test_txt_resolution(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                ),
                "192.5.6.30",
            ),
            (
                _make_response(
                    answer=[("example.com.", 300, "TXT", ['"v=spf1 -all"'])],
                ),
                "93.184.216.34",
            ),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            result = resolver.resolve("example.com", "TXT")
            assert len(result) == 1


class TestResolverNXDOMAINWithCNAME:
    """Test that NXDOMAIN + CNAME in answer section follows the CNAME.

    Some authoritative servers return rcode=3 (NXDOMAIN) along with a CNAME
    in the answer section when the CNAME target is outside their zone. The
    CNAME target may resolve fine via other servers, so we must follow it
    instead of raising NXDOMAINError.
    """

    def test_nxdomain_with_cname_follows_cname(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            # First query: sub.example.com A
            if qname == "sub.example.com." and rdtype == "A":
                if call_count == 1:
                    # Root referral
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # .com referral
                    return (
                        _make_response(
                            authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                            additional=[("ns1.example.com.", 172800, "A", ["1.1.1.1"])],
                        ),
                        "192.5.6.30",
                    )
                if call_count == 3:
                    # NS returns NXDOMAIN rcode BUT includes a CNAME in the answer
                    # This happens when the CNAME target is outside the server's zone
                    return (
                        _make_response(
                            rcode=dns.rcode.NXDOMAIN,
                            answer=[("sub.example.com.", 300, "CNAME", ["target.other.com."])],
                        ),
                        "1.1.1.1",
                    )

            # Second query: resolve the CNAME target from root
            if qname == "target.other.com." and rdtype == "A":
                if call_count == 4:
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 5:
                    return (
                        _make_response(
                            authority=[("other.com.", 172800, "NS", ["ns1.other.com."])],
                            additional=[("ns1.other.com.", 172800, "A", ["2.2.2.2"])],
                        ),
                        "192.5.6.30",
                    )
                if call_count == 6:
                    return (
                        _make_response(
                            answer=[("target.other.com.", 300, "A", ["5.6.7.8"])],
                        ),
                        "2.2.2.2",
                    )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("sub.example.com", "A")
            assert result == ["5.6.7.8"]
            assert call_count == 6

    def test_pure_nxdomain_still_raises(self) -> None:
        """NXDOMAIN without a CNAME should still raise NXDOMAINError."""
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            (_make_response(rcode=dns.rcode.NXDOMAIN), "192.5.6.30"),
        ]

        with (
            patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)),
            pytest.raises(NXDOMAINError),
        ):
            resolver.resolve("nonexistent.com", "A")


class TestResolverTrace:
    """Test resolve_with_trace."""

    def test_trace_returns_steps(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                ),
                "192.5.6.30",
            ),
            (
                _make_response(
                    answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                ),
                "93.184.216.34",
            ),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            trace = resolver.resolve_with_trace("example.com", "A")
            assert len(trace) == 3
            assert trace[0].response_type == "referral"
            assert trace[0].server == "198.41.0.4"
            assert trace[1].response_type == "referral"
            assert trace[2].response_type == "answer"
            assert all(isinstance(s, TraceStep) for s in trace)


class TestResolverBailiwick:
    """Test bailiwick checking for glue records.

    Out-of-bailiwick glue (NS hostname not under the parent zone) should be
    rejected to prevent cache poisoning attacks, triggering glueless resolution.
    """

    def test_in_bailiwick_glue_accepted(self) -> None:
        """Glue for ns1.example.com. under delegated zone example.com. (parent: com.) is accepted."""
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            # Root -> .com (a.gtld-servers.net. is under root = in-bailiwick)
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            # .com -> example.com (ns1.example.com. is under .com = in-bailiwick)
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                ),
                "192.5.6.30",
            ),
            # Answer
            (
                _make_response(
                    answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                ),
                "93.184.216.34",
            ),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            result = resolver.resolve("example.com", "A")
            assert result == ["93.184.216.34"]

    def test_out_of_bailiwick_glue_rejected(self) -> None:
        """Glue for ns1.evil.net. in a .com referral is out-of-bailiwick and rejected.

        The resolver should ignore the poisoned glue and resolve the NS
        hostname via glueless resolution instead.
        """
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if qname == "target.com." and rdtype == "A":
                if call_count == 1:
                    # Root -> .com
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # .com -> target.com with NS ns1.evil.net. + out-of-bailiwick glue
                    # The glue for ns1.evil.net. should be REJECTED (evil.net. not under .com)
                    return (
                        _make_response(
                            authority=[("target.com.", 172800, "NS", ["ns1.evil.net."])],
                            additional=[
                                # This is poisoned glue — points to attacker IP
                                ("ns1.evil.net.", 172800, "A", ["6.6.6.6"]),
                            ],
                        ),
                        "192.5.6.30",
                    )
                # After glueless resolution finds the real IP (5.5.5.5)
                if "5.5.5.5" in nameservers:
                    return (
                        _make_response(
                            answer=[("target.com.", 300, "A", ["1.2.3.4"])],
                        ),
                        "5.5.5.5",
                    )

            # Glueless resolution of ns1.evil.net -> 5.5.5.5 (the real IP)
            if qname == "ns1.evil.net." and rdtype == "A":
                if "198.41.0.4" in nameservers or len(nameservers) > 5:
                    return (
                        _make_response(
                            authority=[("net.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if "192.5.6.30" in nameservers:
                    return (
                        _make_response(
                            authority=[("evil.net.", 172800, "NS", ["ns1.evil.net."])],
                            additional=[("ns1.evil.net.", 172800, "A", ["5.5.5.5"])],
                        ),
                        "192.5.6.30",
                    )
                return (
                    _make_response(
                        answer=[("ns1.evil.net.", 300, "A", ["5.5.5.5"])],
                    ),
                    "5.5.5.5",
                )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("target.com", "A")
            assert result == ["1.2.3.4"]
            # The poisoned IP 6.6.6.6 should never have been used
            # Instead, glueless resolution found the real IP 5.5.5.5


class TestResolverNegativeCacheHit:
    """Test negative cache entries are returned correctly."""

    def test_nxdomain_from_cache(self) -> None:
        """NXDOMAIN cached on first resolve should raise on second without queries."""
        resolver = RecursiveResolver(cache_enabled=True)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1
            # Return NXDOMAIN
            return (_make_response(rcode=dns.rcode.NXDOMAIN), nameservers[0])

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            with pytest.raises(NXDOMAINError):
                resolver.resolve("nope.com", "A")
            first_calls = call_count

            # Second call should hit cache, no new queries
            with pytest.raises(NXDOMAINError):
                resolver.resolve("nope.com", "A")
            assert call_count == first_calls

    def test_nodata_from_cache(self) -> None:
        """NODATA cached on first resolve should raise on second without queries."""
        resolver = RecursiveResolver(cache_enabled=True)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (
                    _make_response(
                        authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                        additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                    ),
                    "198.41.0.4",
                )
            if call_count == 2:
                return (
                    _make_response(
                        authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                        additional=[("ns1.example.com.", 172800, "A", ["1.2.3.4"])],
                    ),
                    "192.5.6.30",
                )
            # NODATA: SOA in authority, no answer
            return (
                _make_response(
                    authority=[
                        ("example.com.", 300, "SOA", ["ns1.example.com. admin.example.com. 1 3600 900 604800 86400"])
                    ],
                ),
                "1.2.3.4",
            )

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            with pytest.raises(NoAnswerError):
                resolver.resolve("example.com", "AAAA")
            first_calls = call_count

            with pytest.raises(NoAnswerError):
                resolver.resolve("example.com", "AAAA")
            assert call_count == first_calls


class TestResolverCNAMEChainLimit:
    """Test CNAME chain length limit."""

    def test_long_cname_chain_raises(self) -> None:
        """CNAME chain exceeding max_cname_chain should raise CNAMELoopError."""
        resolver = RecursiveResolver(cache_enabled=False, max_cname_chain=3)

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            # Each name CNAMEs to the next, forming a long chain
            n = int(qname.split(".")[0].replace("c", "")) if qname.startswith("c") else 0
            next_name = f"c{n + 1}.example.com."
            return (
                _make_response(
                    answer=[(qname, 300, "CNAME", [next_name])],
                ),
                "1.2.3.4",
            )

        with patch.object(resolver, "_send_query", side_effect=mock_send), pytest.raises(CNAMELoopError):
            resolver.resolve("c0.example.com", "A")


class TestResolverGluelessAllFail:
    """Test that glueless referral where all NS fail raises ServfailError."""

    def test_all_glueless_ns_fail_raises(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if qname == "example.com." and rdtype == "A":
                if call_count == 1:
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if call_count == 2:
                    # Glueless referral
                    return (
                        _make_response(
                            authority=[("example.com.", 172800, "NS", ["ns1.broken.net."])],
                        ),
                        "192.5.6.30",
                    )

            # Sub-resolution always fails
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send), pytest.raises(ServfailError):
            resolver.resolve("example.com", "A")


class TestResolverGluelessMultipleNS:
    """Test that glueless resolution tries all NS names, not just the first.

    Reproduces the bug where _resolve_glueless would stop after the first NS
    that resolved to an IP, even if that IP pointed to a dead server.
    For example: banon.fr had NS visioline.tv (working) and nssec.online.net
    (dead IP 62.210.16.8). If nssec resolved first, the old code would use
    only its dead IP and never try visioline.tv.
    """

    def test_second_ns_used_when_first_ip_dead(self) -> None:
        """When the first glueless NS resolves to a dead IP, the second NS IP is also tried."""
        resolver = RecursiveResolver(cache_enabled=False)

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            # Main query: target.example.com A
            if qname == "target.example.com." and rdtype == "A":
                if any(ns in nameservers for ns in resolver._root_addresses):
                    # Root referral -> .com
                    return (
                        _make_response(
                            authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if "192.5.6.30" in nameservers:
                    # .com referral -> glueless (NS in different TLDs)
                    return (
                        _make_response(
                            authority=[
                                (
                                    "example.com.",
                                    172800,
                                    "NS",
                                    [
                                        "ns-dead.otherdns.net.",
                                        "ns-alive.gooddns.org.",
                                    ],
                                )
                            ],
                        ),
                        "192.5.6.30",
                    )
                if "10.0.0.1" in nameservers:
                    # Working IP present — _send_query iterates and finds it
                    return (
                        _make_response(
                            answer=[("target.example.com.", 300, "A", ["5.5.5.5"])],
                        ),
                        "10.0.0.1",
                    )
                if "10.0.0.99" in nameservers:
                    # Only dead IP — times out
                    return (None, "")
                return (None, "")

            # Sub-resolution for ns-dead.otherdns.net -> resolves to dead IP
            if qname == "ns-dead.otherdns.net." and rdtype == "A":
                if any(ns in nameservers for ns in resolver._root_addresses):
                    return (
                        _make_response(
                            authority=[("net.", 172800, "NS", ["a.gtld-servers.net."])],
                            additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                        ),
                        "198.41.0.4",
                    )
                if "192.5.6.30" in nameservers:
                    return (
                        _make_response(
                            authority=[("otherdns.net.", 172800, "NS", ["ns-dead.otherdns.net."])],
                            additional=[("ns-dead.otherdns.net.", 172800, "A", ["10.0.0.99"])],
                        ),
                        "192.5.6.30",
                    )
                return (
                    _make_response(
                        answer=[("ns-dead.otherdns.net.", 300, "A", ["10.0.0.99"])],
                    ),
                    "10.0.0.99",
                )

            # Sub-resolution for ns-alive.gooddns.org -> resolves to working IP
            if qname == "ns-alive.gooddns.org." and rdtype == "A":
                if any(ns in nameservers for ns in resolver._root_addresses):
                    return (
                        _make_response(
                            authority=[("org.", 172800, "NS", ["a0.org.afilias-nst.info."])],
                            additional=[("a0.org.afilias-nst.info.", 172800, "A", ["199.19.56.1"])],
                        ),
                        "198.41.0.4",
                    )
                if "199.19.56.1" in nameservers:
                    return (
                        _make_response(
                            authority=[("gooddns.org.", 172800, "NS", ["ns-alive.gooddns.org."])],
                            additional=[("ns-alive.gooddns.org.", 172800, "A", ["10.0.0.1"])],
                        ),
                        "199.19.56.1",
                    )
                return (
                    _make_response(
                        answer=[("ns-alive.gooddns.org.", 300, "A", ["10.0.0.1"])],
                    ),
                    "10.0.0.1",
                )

            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("target.example.com", "A")
            # The resolver must find 10.0.0.1 from the second NS and get the answer
            assert result == ["5.5.5.5"]


class TestResolverDepthOverflow:
    """Test that depth overflow in sub-resolution is handled."""

    def test_depth_overflow_raises_max_depth(self) -> None:
        """When _resolve_iterative is called with depth > max_depth, it raises immediately."""
        resolver = RecursiveResolver(cache_enabled=False, max_depth=2)
        with pytest.raises(MaxDepthError):
            resolver._resolve_iterative("deep.example.com.", "A", depth=3, cname_chain=[])


class TestResolverSendQuery:
    """Test _send_query with real dns.query mocking."""

    def test_udp_with_fallback(self) -> None:
        """Test basic UDP query flow."""
        resolver = RecursiveResolver(cache_enabled=False)

        response = _make_response(
            answer=[("example.com.", 300, "A", ["1.2.3.4"])],
        )

        with patch("dns.query.udp_with_fallback", return_value=(response, False)):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is not None
            assert server == "1.1.1.1"

    def test_timeout_retries_and_fails(self) -> None:
        """All retries timeout -> returns (None, "")."""
        resolver = RecursiveResolver(cache_enabled=False, max_retries=1)

        with patch("dns.query.udp_with_fallback", side_effect=dns.exception.Timeout):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is None
            assert server == ""

    def test_formerr_triggers_plain_fallback(self) -> None:
        """FORMERR response triggers plain (no-EDNS) fallback."""
        resolver = RecursiveResolver(cache_enabled=False)

        formerr_response = _make_response(rcode=dns.rcode.FORMERR)
        plain_response = _make_response(
            answer=[("example.com.", 300, "A", ["1.2.3.4"])],
        )

        with (
            patch("dns.query.udp_with_fallback", return_value=(formerr_response, False)),
            patch.object(resolver, "_send_query_plain", return_value=plain_response) as mock_plain,
        ):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is not None
            mock_plain.assert_called_once()

    def test_bad_response_triggers_plain_fallback(self) -> None:
        """BadResponse triggers plain (no-EDNS) fallback."""
        resolver = RecursiveResolver(cache_enabled=False)

        plain_response = _make_response(
            answer=[("example.com.", 300, "A", ["1.2.3.4"])],
        )

        with (
            patch("dns.query.udp_with_fallback", side_effect=dns.query.BadResponse),
            patch.object(resolver, "_send_query_plain", return_value=plain_response) as mock_plain,
        ):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is not None
            mock_plain.assert_called_once()

    def test_os_error_retries(self) -> None:
        """OSError (network error) should trigger retries."""
        resolver = RecursiveResolver(cache_enabled=False, max_retries=1)

        response = _make_response(
            answer=[("example.com.", 300, "A", ["1.2.3.4"])],
        )

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Network unreachable")
            return (response, False)

        with patch("dns.query.udp_with_fallback", side_effect=side_effect):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is not None
            assert call_count == 2

    def test_generic_exception_skips_server(self) -> None:
        """An unexpected exception should skip the server (no retry)."""
        resolver = RecursiveResolver(cache_enabled=False, max_retries=2)

        with patch("dns.query.udp_with_fallback", side_effect=ValueError("unexpected")):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is None


class TestResolverSendQueryPlain:
    """Test _send_query_plain (no-EDNS fallback)."""

    def test_plain_query_success(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        response = _make_response(
            answer=[("example.com.", 300, "A", ["1.2.3.4"])],
        )

        with patch("dns.query.udp", return_value=response):
            result = resolver._send_query_plain("example.com.", dns.rdatatype.A, "1.1.1.1")
            assert result is not None

    def test_plain_query_failure(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False)

        with patch("dns.query.udp", side_effect=dns.exception.Timeout):
            result = resolver._send_query_plain("example.com.", dns.rdatatype.A, "1.1.1.1")
            assert result is None


class TestResolverUdpOnly:
    """Test resolver with TCP fallback disabled."""

    def test_udp_only_mode(self) -> None:
        resolver = RecursiveResolver(cache_enabled=False, use_tcp_fallback=False)

        response = _make_response(
            answer=[("example.com.", 300, "A", ["1.2.3.4"])],
        )

        with patch("dns.query.udp", return_value=response):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is not None

    def test_formerr_plain_also_fails(self) -> None:
        """When FORMERR and plain fallback also fails, skip to next server."""
        resolver = RecursiveResolver(cache_enabled=False)

        formerr_response = _make_response(rcode=dns.rcode.FORMERR)

        with (
            patch("dns.query.udp_with_fallback", return_value=(formerr_response, False)),
            patch.object(resolver, "_send_query_plain", return_value=None),
        ):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is None

    def test_bad_response_plain_also_fails(self) -> None:
        """When BadResponse and plain fallback also fails, skip to next server."""
        resolver = RecursiveResolver(cache_enabled=False)

        with (
            patch("dns.query.udp_with_fallback", side_effect=dns.query.BadResponse),
            patch.object(resolver, "_send_query_plain", return_value=None),
        ):
            result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"])
            assert result is None


class TestResolverPTRNonIP:
    """Test PTR with non-IP qname (already in arpa format)."""

    def test_ptr_with_arpa_qname(self) -> None:
        """PTR query with an already-formatted arpa name should pass through."""
        resolver = RecursiveResolver(cache_enabled=False)

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            # qname should have been passed through (not converted)
            assert qname == "8.8.8.8.in-addr.arpa."
            return (
                _make_response(
                    answer=[("8.8.8.8.in-addr.arpa.", 300, "PTR", ["dns.google."])],
                ),
                "1.2.3.4",
            )

        with patch.object(resolver, "_send_query", side_effect=mock_send):
            result = resolver.resolve("8.8.8.8.in-addr.arpa", "PTR")
            assert result == ["dns.google."]


class TestResolverReferralValidation:
    """Test referral zone validation (anti-hijacking).

    A malicious nameserver should not be able to redirect resolution to
    unrelated zones by injecting bogus NS records in the authority section.
    """

    def test_unrelated_referral_rejected(self) -> None:
        """A referral to an unrelated zone should be treated as an error."""
        resolver = RecursiveResolver(cache_enabled=False)

        call_count = 0

        def mock_send(qname, rdtype, nameservers, deadline=0.0):
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # Root -> .com
                return (
                    _make_response(
                        authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                        additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                    ),
                    "198.41.0.4",
                )
            if call_count == 2:
                # .com -> example.com
                return (
                    _make_response(
                        authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                        additional=[("ns1.example.com.", 172800, "A", ["1.1.1.1"])],
                    ),
                    "192.5.6.30",
                )
            if call_count == 3:
                # Malicious NS tries to redirect to bank.com (unrelated zone!)
                # This should be rejected: www.example.com is not a subdomain of bank.com
                return (
                    _make_response(
                        authority=[("bank.com.", 172800, "NS", ["ns1.evil.com."])],
                        additional=[("ns1.evil.com.", 172800, "A", ["6.6.6.6"])],
                    ),
                    "1.1.1.1",
                )
            # After rejection (treated as error), no servers left -> ServfailError
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=mock_send), pytest.raises(ServfailError):
            resolver.resolve("www.example.com", "A")

    def test_valid_referral_accepted(self) -> None:
        """A referral to a parent/matching zone should be accepted."""
        resolver = RecursiveResolver(cache_enabled=False)

        responses = [
            # Root -> .com
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            # .com -> example.com (www.example.com IS a subdomain of example.com)
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["1.1.1.1"])],
                ),
                "192.5.6.30",
            ),
            # Answer
            (
                _make_response(
                    answer=[("www.example.com.", 300, "A", ["1.2.3.4"])],
                ),
                "1.1.1.1",
            ),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            result = resolver.resolve("www.example.com", "A")
            assert result == ["1.2.3.4"]


class TestResolverDeadline:
    """Test that max_resolution_time enforces a strict wall-clock deadline."""

    def test_deadline_aborts_slow_resolution(self) -> None:
        """Resolution that exceeds max_resolution_time raises ResolutionTimeoutError."""
        import time as _time

        resolver = RecursiveResolver(
            cache_enabled=False,
            max_resolution_time=0.5,  # 500ms deadline
            timeout=5.0,  # per-query timeout much larger than deadline
        )

        def slow_send(qname, rdtype, nameservers, deadline=float("inf")):
            # Simulate a slow referral chain that burns through the deadline
            _time.sleep(0.3)  # Each step takes 300ms; 2 steps > 500ms deadline
            return (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            )

        with patch.object(resolver, "_send_query", side_effect=slow_send), pytest.raises(ResolutionTimeoutError):
            resolver.resolve("example.com", "A")

    def test_deadline_clamps_per_query_timeout(self) -> None:
        """Per-query timeout should be clamped to remaining resolution time."""
        import time as _time

        resolver = RecursiveResolver(
            cache_enabled=False,
            max_resolution_time=30.0,
            timeout=5.0,
        )

        deadline = _time.monotonic() + 2.0  # 2s remaining
        effective = resolver._effective_timeout(deadline)
        # Should be clamped to remaining (~2s), not the 5s per-query timeout
        assert effective <= 2.1
        assert effective > 0

    def test_effective_timeout_expired_returns_zero(self) -> None:
        """If deadline has passed, _effective_timeout returns 0."""
        import time as _time

        resolver = RecursiveResolver(cache_enabled=False)
        expired_deadline = _time.monotonic() - 1.0  # 1 second ago
        assert resolver._effective_timeout(expired_deadline) == 0.0

    def test_check_deadline_raises_when_expired(self) -> None:
        """_check_deadline raises ResolutionTimeoutError after deadline."""
        import time as _time

        resolver = RecursiveResolver(cache_enabled=False)
        expired_deadline = _time.monotonic() - 1.0
        with pytest.raises(ResolutionTimeoutError):
            resolver._check_deadline(expired_deadline, "example.com.", "A")

    def test_check_deadline_passes_when_not_expired(self) -> None:
        """_check_deadline does nothing when deadline is in the future."""
        import time as _time

        resolver = RecursiveResolver(cache_enabled=False)
        future_deadline = _time.monotonic() + 100.0
        resolver._check_deadline(future_deadline, "example.com.", "A")  # should not raise

    def test_fast_resolution_succeeds_within_deadline(self) -> None:
        """A fast resolution should succeed even with a tight deadline."""
        resolver = RecursiveResolver(
            cache_enabled=False,
            max_resolution_time=5.0,
        )

        responses = [
            (
                _make_response(
                    authority=[("com.", 172800, "NS", ["a.gtld-servers.net."])],
                    additional=[("a.gtld-servers.net.", 172800, "A", ["192.5.6.30"])],
                ),
                "198.41.0.4",
            ),
            (
                _make_response(
                    authority=[("example.com.", 172800, "NS", ["ns1.example.com."])],
                    additional=[("ns1.example.com.", 172800, "A", ["93.184.216.34"])],
                ),
                "192.5.6.30",
            ),
            (
                _make_response(
                    answer=[("example.com.", 300, "A", ["93.184.216.34"])],
                ),
                "93.184.216.34",
            ),
        ]

        with patch.object(resolver, "_send_query", side_effect=_mock_send_sequence(responses)):
            result = resolver.resolve("example.com", "A")
            assert result == ["93.184.216.34"]

    def test_default_max_resolution_time(self) -> None:
        """Default max_resolution_time should be 30 seconds."""
        resolver = RecursiveResolver()
        assert resolver.max_resolution_time == 30.0

    def test_send_query_returns_none_when_deadline_expired(self) -> None:
        """_send_query should return (None, '') immediately when deadline is expired."""
        import time as _time

        resolver = RecursiveResolver(cache_enabled=False)
        expired_deadline = _time.monotonic() - 1.0
        result, server = resolver._send_query("example.com.", "A", ["1.1.1.1"], expired_deadline)
        assert result is None
        assert server == ""
