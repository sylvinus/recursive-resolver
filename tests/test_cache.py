"""Tests for the DNS cache: answers, negative entries and delegations."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import dns.name
import dns.rdatatype
import pytest
from conftest import make_response, referral, root_to_com

from recursive_resolver import NoAnswerError, NXDOMAINError, RecursiveResolver
from recursive_resolver.cache import Delegation, DNSCache

EXAMPLE = dns.name.from_text("example.com.")
A = dns.rdatatype.A


class TestAnswerCache:
    def test_put_and_get(self) -> None:
        cache = DNSCache()
        cache.put_answer(EXAMPLE, A, "rrset", ttl=300)
        entry = cache.get_answer(EXAMPLE, A)
        assert entry is not None
        assert entry.rrset == "rrset"

    def test_miss(self) -> None:
        assert DNSCache().get_answer("nothing.example.", A) is None

    def test_case_insensitive_and_idn_safe(self) -> None:
        """Name-keyed entries are immune to str.lower()/IDNA mismatches."""
        cache = DNSCache()
        cache.put_answer(dns.name.from_text("Bücher.de."), A, "rrset", ttl=300)
        assert cache.get_answer(dns.name.from_text("bücher.de."), A) is not None
        assert cache.get_answer(dns.name.from_text("xn--bcher-kva.de."), A) is not None

    def test_expiry(self) -> None:
        cache = DNSCache()
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put_answer(EXAMPLE, A, "rrset", ttl=10)
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 5):
            assert cache.get_answer(EXAMPLE, A) is not None
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 11):
            assert cache.get_answer(EXAMPLE, A) is None

    def test_ttl_zero_is_honoured_by_default(self) -> None:
        """min_ttl defaults to 0 so TTL-0 records are genuinely not cached."""
        cache = DNSCache()
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put_answer(EXAMPLE, A, "rrset", ttl=0)
            assert cache.get_answer(EXAMPLE, A) is None

    def test_ttl_ceiling(self) -> None:
        cache = DNSCache(max_ttl=600)
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put_answer(EXAMPLE, A, "rrset", ttl=99999)
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 601):
            assert cache.get_answer(EXAMPLE, A) is None

    def test_lru_eviction(self) -> None:
        cache = DNSCache(max_size=2)
        a, b, c = (dns.name.from_text(f"{x}.com.") for x in "abc")
        cache.put_answer(a, A, "a", ttl=300)
        cache.put_answer(b, A, "b", ttl=300)
        cache.get_answer(a, A)  # a becomes most-recently-used
        cache.put_answer(c, A, "c", ttl=300)
        assert cache.get_answer(a, A) is not None
        assert cache.get_answer(c, A) is not None
        assert cache.stats.evictions == 1

    def test_stats(self) -> None:
        cache = DNSCache()
        cache.put_answer(EXAMPLE, A, "rrset", ttl=300)
        cache.get_answer(EXAMPLE, A)
        cache.get_answer(dns.name.from_text("other.com."), A)
        assert (cache.stats.hits, cache.stats.misses) == (1, 1)
        assert cache.stats.hit_rate == 0.5

    def test_thread_safety(self) -> None:
        cache = DNSCache(max_size=100)
        errors: list[Exception] = []

        def worker(start: int) -> None:
            try:
                for i in range(200):
                    name = dns.name.from_text(f"d{(start + i) % 150}.com.")
                    cache.put_answer(name, A, f"v{i}", ttl=300)
                    cache.get_answer(name, A)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n * 50,)) for n in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


class TestNegativeCache:
    def test_nxdomain_is_keyed_by_name_not_type(self) -> None:
        """RFC 2308 §5: NXDOMAIN applies to the name, whatever the type."""
        cache = DNSCache()
        cache.put_nxdomain(EXAMPLE, ttl=300)
        assert cache.get_nxdomain(EXAMPLE) is not None
        assert cache.get_nxdomain_ancestor(EXAMPLE) == EXAMPLE

    def test_harden_below_nxdomain(self) -> None:
        """RFC 8020: nothing can exist below a non-existent name."""
        cache = DNSCache()
        cache.put_nxdomain(dns.name.from_text("gone.example.com."), ttl=300)
        found = cache.get_nxdomain_ancestor(dns.name.from_text("deep.under.gone.example.com."))
        assert found == dns.name.from_text("gone.example.com.")

    def test_unrelated_names_are_not_covered(self) -> None:
        cache = DNSCache()
        cache.put_nxdomain(dns.name.from_text("gone.example.com."), ttl=300)
        assert cache.get_nxdomain_ancestor(dns.name.from_text("live.example.com.")) is None

    def test_nodata_is_keyed_by_name_and_type(self) -> None:
        cache = DNSCache()
        cache.put_nodata(EXAMPLE, dns.rdatatype.MX, ttl=300)
        assert cache.get_nodata(EXAMPLE, dns.rdatatype.MX) is not None
        assert cache.get_nodata(EXAMPLE, A) is None

    def test_negative_ttl_ceiling(self) -> None:
        cache = DNSCache(max_negative_ttl=60)
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put_nxdomain(EXAMPLE, ttl=99999)
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 61):
            assert cache.get_nxdomain(EXAMPLE) is None


class TestDelegationCache:
    def test_put_and_closest(self) -> None:
        cache = DNSCache()
        cache.put_delegation(Delegation(zone=dns.name.from_text("com."), addresses=["1.2.3.4"]), ttl=3600)
        found = cache.closest_delegation(dns.name.from_text("deep.sub.example.com."))
        assert found is not None
        assert found.zone == dns.name.from_text("com.")

    def test_deepest_delegation_wins(self) -> None:
        cache = DNSCache()
        cache.put_delegation(Delegation(zone=dns.name.from_text("com."), addresses=["1.2.3.4"]), ttl=3600)
        cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.6.7.8"]), ttl=3600)
        found = cache.closest_delegation(dns.name.from_text("www.example.com."))
        assert found is not None and found.zone == EXAMPLE

    def test_depth_limit_keeps_only_tlds(self) -> None:
        """max_delegation_depth=1 caches root->TLD cuts and nothing deeper."""
        cache = DNSCache(max_delegation_depth=1)
        cache.put_delegation(Delegation(zone=dns.name.from_text("com."), addresses=["1.2.3.4"]), ttl=3600)
        cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.6.7.8"]), ttl=3600)
        assert cache.get_delegation(dns.name.from_text("com.")) is not None
        assert cache.get_delegation(EXAMPLE) is None

    def test_a_cached_delegation_is_isolated_from_its_producer_and_its_readers(self) -> None:
        """Delegation holds mutable lists; sharing them across threads is the hazard.

        Answers already go through _isolate. Without the same treatment here, a
        caller appending to `delegation.addresses` would silently rewrite the
        cached zone cut for every other thread.
        """
        cache = DNSCache()
        original = Delegation(zone=EXAMPLE, addresses=["1.2.3.4"], ns_names=["ns1.example.com."])
        cache.put_delegation(original, ttl=3600)

        # The producer must not be able to reach back into the stored entry.
        original.addresses.append("6.6.6.6")
        original.ns_names.append("evil.example.com.")

        first = cache.get_delegation(EXAMPLE)
        assert first is not None
        assert first.addresses == ["1.2.3.4"]
        assert first.ns_names == ["ns1.example.com."]

        # Nor may one reader's mutation be visible to the next.
        first.addresses.append("7.7.7.7")
        second = cache.closest_delegation(dns.name.from_text("www.example.com."))
        assert second is not None
        assert second.addresses == ["1.2.3.4"]

    def test_empty_delegation_is_not_returned(self) -> None:
        cache = DNSCache()
        cache.put_delegation(Delegation(zone=dns.name.from_text("com."), addresses=[]), ttl=3600)
        assert cache.closest_delegation(dns.name.from_text("x.com.")) is None

    def test_clear(self) -> None:
        cache = DNSCache()
        cache.put_answer(EXAMPLE, A, "rrset", ttl=300)
        assert len(cache) == 1
        cache.clear()
        assert len(cache) == 0


class TestResolverCacheIntegration:
    def test_delegation_cache_avoids_the_root_on_the_second_lookup(self) -> None:
        """The whole point: a warm cache must not re-query a root server."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True, cache_answers=False)
        servers_asked: list[str] = []

        def send(qname, rdtype, nameservers, ctx):
            servers_asked.append(nameservers[0])
            if nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers[0] == "192.5.6.30":
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"
            return make_response(answer=[(str(qname), 300, "A", ["9.9.9.9"])]), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send):
            resolver.resolve("a.example.com", "A")
            first = len(servers_asked)
            resolver.resolve("b.example.com", "A")

        second_round = servers_asked[first:]
        assert not any(s in resolver._root_addresses for s in second_round), "second lookup still hit a root server"

    def test_answer_cache_hit_avoids_all_queries(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        calls = 0

        def send(qname, rdtype, nameservers, ctx):
            nonlocal calls
            calls += 1
            if calls == 1:
                return root_to_com(), "198.41.0.4"
            if calls == 2:
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"
            return make_response(answer=[("example.com.", 300, "A", ["9.9.9.9"])]), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("example.com", "A") == ["9.9.9.9"]
            assert calls == 3
            assert resolver.resolve("example.com", "A") == ["9.9.9.9"]
            assert calls == 3

    def test_cache_answers_false_still_refetches(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True, cache_answers=False)
        calls = 0

        def send(qname, rdtype, nameservers, ctx):
            nonlocal calls
            calls += 1
            if nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers[0] == "192.5.6.30":
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"
            return make_response(answer=[("example.com.", 300, "A", ["9.9.9.9"])]), "1.2.3.4"

        with patch.object(resolver, "_send_query", side_effect=send):
            resolver.resolve("example.com", "A")
            before = calls
            resolver.resolve("example.com", "A")
        assert calls > before, "answers must not be cached when cache_answers=False"

    def test_nxdomain_below_cached_nxdomain_costs_nothing(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_nxdomain(dns.name.from_text("gone.example.com."), ttl=300)
        with patch.object(resolver, "_send_query") as send, pytest.raises(NXDOMAINError):
            resolver.resolve("host.gone.example.com", "A")
        send.assert_not_called()

    def test_negative_ttl_comes_from_the_soa(self) -> None:
        """RFC 2308 §5: use min(SOA TTL, SOA MINIMUM), not a fixed constant."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        response = make_response(
            authority=[("example.com.", 900, "SOA", ["ns1.example.com. a.example.com. 1 3600 900 604800 120"])],
            aa=True,
        )
        assert resolver._negative_ttl(response, EXAMPLE) == 120

    def test_nodata_is_cached(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_nodata(EXAMPLE, dns.rdatatype.MX, ttl=300)
        with patch.object(resolver, "_send_query") as send, pytest.raises(NoAnswerError):
            resolver.resolve("example.com", "MX")
        send.assert_not_called()


class TestNamedCacheDepths:
    """Zone-cut caching depth can be named instead of given as a number."""

    def test_names_map_to_label_depths(self) -> None:
        from recursive_resolver.cache import resolve_cache_depth

        assert resolve_cache_depth("tld") == 1
        assert resolve_cache_depth("all") is None
        assert resolve_cache_depth("none") == -1

    def test_integers_and_none_pass_through(self) -> None:
        from recursive_resolver.cache import resolve_cache_depth

        assert resolve_cache_depth(3) == 3
        assert resolve_cache_depth(None) is None

    def test_names_are_case_and_space_insensitive(self) -> None:
        from recursive_resolver.cache import resolve_cache_depth

        assert resolve_cache_depth("  TLD ") == 1

    def test_an_unknown_name_is_rejected(self) -> None:
        from recursive_resolver.cache import resolve_cache_depth

        with pytest.raises(ValueError, match="unknown cache depth"):
            resolve_cache_depth("sometimes")

    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            ("none", []),
            ("tld", ["com."]),
            ("all", ["com.", "co.uk.", "example.com.", "mail.example.com."]),
        ],
    )
    def test_each_level_keeps_the_right_cuts(self, level: str, expected: list[str]) -> None:
        cache = DNSCache(max_delegation_depth=level)
        kept = []
        for zone in ("com.", "co.uk.", "example.com.", "mail.example.com."):
            name = dns.name.from_text(zone)
            cache.put_delegation(Delegation(zone=name, addresses=["9.9.9.9"]), ttl=3600)
            if cache.get_delegation(name) is not None:
                kept.append(zone)
        assert kept == expected

    def test_tld_level_still_skips_the_root_on_a_second_lookup(self) -> None:
        """The point of the setting: never query a root server, re-resolve the rest."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True, max_delegation_cache_depth="tld")
        servers: list[str] = []

        def send(qname, rdtype, nameservers, ctx):
            servers.append(nameservers[0])
            if nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers[0] == "192.5.6.30":
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "9.9.9.9"}), "192.5.6.30"
            return make_response(answer=[(str(qname), 300, "A", ["1.2.3.4"])]), "9.9.9.9"

        with patch.object(resolver, "_send_query", side_effect=send):
            resolver.resolve("a.example.com", "A")
            first = len(servers)
            resolver.resolve("b.example.com", "A")

        second = servers[first:]
        assert not any(s in resolver._root_addresses for s in second), "should not re-query a root server"
        # The cut below the TLD was not kept, so it is walked again.
        assert "192.5.6.30" in second

    def test_the_resolver_accepts_a_level_name(self) -> None:
        resolver = RecursiveResolver(dnssec=False, max_delegation_cache_depth="tld")
        assert resolver.cache is not None
        assert resolver.cache.max_delegation_depth == 1
