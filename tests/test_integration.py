"""Integration tests that perform real DNS queries over the network.

Run with: pytest -m integration
"""

from __future__ import annotations

import pytest

from recursive_resolver import NXDOMAINError, RecursiveResolver, TraceStep

pytestmark = pytest.mark.integration


@pytest.fixture
def resolver() -> RecursiveResolver:
    return RecursiveResolver(timeout=5.0, ipv4_only=True)


class TestRealResolution:
    def test_a_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("sylvainzimmer.com", "A")
        assert len(result) > 0
        # Should be valid IPv4 addresses
        for ip in result:
            parts = ip.split(".")
            assert len(parts) == 4

    def test_aaaa_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("google.com", "AAAA")
        assert len(result) > 0
        # IPv6 addresses contain colons
        for ip in result:
            assert ":" in ip

    def test_mx_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("google.com", "MX")
        assert len(result) > 0
        # MX records have priority + hostname
        for mx in result:
            parts = mx.split()
            assert len(parts) == 2
            assert parts[0].isdigit()

    def test_txt_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("google.com", "TXT")
        assert len(result) > 0

    def test_ns_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("google.com", "NS")
        assert len(result) > 0

    def test_cname_chain(self, resolver: RecursiveResolver) -> None:
        # www.github.com is a well-known CNAME
        result = resolver.resolve("www.github.com", "A")
        assert len(result) > 0

    def test_nxdomain(self, resolver: RecursiveResolver) -> None:
        with pytest.raises(NXDOMAINError):
            resolver.resolve("this-domain-definitely-does-not-exist-xyz123.com", "A")

    def test_ptr_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("8.8.8.8", "PTR")
        assert len(result) > 0
        # Should resolve to dns.google or similar
        assert any("google" in r.lower() or "dns" in r.lower() for r in result)

    def test_soa_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("google.com", "SOA")
        assert len(result) > 0

    def test_trace(self, resolver: RecursiveResolver) -> None:
        trace = resolver.resolve_with_trace("example.com", "A")
        assert len(trace) >= 2  # At least root referral + answer
        assert all(isinstance(step, TraceStep) for step in trace)
        # First step should be from a root server
        assert trace[0].response_type == "referral"
        # Last step should be an answer
        assert trace[-1].response_type == "answer"

    def test_cache_speedup(self, resolver: RecursiveResolver) -> None:
        # First query populates cache
        result1 = resolver.resolve("example.com", "A")
        # Second query should hit cache
        result2 = resolver.resolve("example.com", "A")
        assert result1 == result2
        assert resolver.cache is not None
        assert resolver.cache.stats.hits > 0
