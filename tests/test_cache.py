"""Tests for the DNS cache module."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from recursive_resolver.cache import DNSCache


class TestDNSCache:
    def test_put_and_get(self) -> None:
        cache = DNSCache()
        cache.put("example.com", "A", rrset="fake-rrset", ttl=300)
        entry = cache.get("example.com", "A")
        assert entry is not None
        assert entry.rrset == "fake-rrset"
        assert entry.is_negative is False

    def test_get_missing_key(self) -> None:
        cache = DNSCache()
        entry = cache.get("nonexistent.com", "A")
        assert entry is None

    def test_case_insensitive(self) -> None:
        cache = DNSCache()
        cache.put("Example.COM", "a", rrset="rrset", ttl=300)
        entry = cache.get("example.com", "A")
        assert entry is not None
        assert entry.rrset == "rrset"

    def test_expiry(self) -> None:
        cache = DNSCache(min_ttl=1)
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put("example.com", "A", rrset="rrset", ttl=1)

        # Before expiry
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 0.5):
            entry = cache.get("example.com", "A")
            assert entry is not None

        # After expiry
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 2.0):
            entry = cache.get("example.com", "A")
            assert entry is None

    def test_negative_caching(self) -> None:
        cache = DNSCache(negative_ttl=60)
        cache.put("nxdomain.example.com", "A", rrset=None, is_negative=True)
        entry = cache.get("nxdomain.example.com", "A")
        assert entry is not None
        assert entry.is_negative is True
        assert entry.rrset is None

    def test_stats_tracking(self) -> None:
        cache = DNSCache()
        assert cache.stats.hits == 0
        assert cache.stats.misses == 0
        assert cache.stats.hit_rate == 0.0

        cache.put("example.com", "A", rrset="rrset", ttl=300)

        # Hit
        cache.get("example.com", "A")
        assert cache.stats.hits == 1
        assert cache.stats.misses == 0
        assert cache.stats.hit_rate == 1.0

        # Miss
        cache.get("other.com", "A")
        assert cache.stats.hits == 1
        assert cache.stats.misses == 1
        assert cache.stats.hit_rate == 0.5

    def test_lru_eviction(self) -> None:
        cache = DNSCache(max_size=2)
        cache.put("a.com", "A", rrset="a", ttl=300)
        cache.put("b.com", "A", rrset="b", ttl=300)
        # Access a.com so b.com is LRU
        cache.get("a.com", "A")
        # Adding c.com should evict b.com (least recently used)
        cache.put("c.com", "A", rrset="c", ttl=300)

        assert cache.get("a.com", "A") is not None
        assert cache.get("c.com", "A") is not None
        # b.com was evicted (LRU when a.com was accessed making b.com least recent)
        # Actually: after put a, put b, get a: order is [b, a]. Evict b.
        assert cache.stats.evictions == 1

    def test_ttl_clamping_min(self) -> None:
        cache = DNSCache(min_ttl=60)
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put("example.com", "A", rrset="rrset", ttl=5)  # below min

        # Should still be alive at 30s (because min_ttl=60 was applied)
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 30):
            entry = cache.get("example.com", "A")
            assert entry is not None

    def test_ttl_clamping_max(self) -> None:
        cache = DNSCache(max_ttl=600)
        now = time.monotonic()
        with patch("recursive_resolver.cache.time.monotonic", return_value=now):
            cache.put("example.com", "A", rrset="rrset", ttl=99999)

        # Should be expired after max_ttl
        with patch("recursive_resolver.cache.time.monotonic", return_value=now + 601):
            entry = cache.get("example.com", "A")
            assert entry is None

    def test_clear(self) -> None:
        cache = DNSCache()
        cache.put("example.com", "A", rrset="rrset", ttl=300)
        assert len(cache) == 1
        cache.clear()
        assert len(cache) == 0

    def test_thread_safety(self) -> None:
        cache = DNSCache(max_size=100)
        errors: list[Exception] = []

        def writer(start: int) -> None:
            try:
                for i in range(50):
                    cache.put(f"domain-{start + i}.com", "A", rrset=f"rrset-{start + i}", ttl=300)
            except Exception as e:
                errors.append(e)

        def reader() -> None:
            try:
                for i in range(100):
                    cache.get(f"domain-{i}.com", "A")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer, args=(0,)),
            threading.Thread(target=writer, args=(50,)),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_different_rdtypes_separate_entries(self) -> None:
        cache = DNSCache()
        cache.put("example.com", "A", rrset="a-rrset", ttl=300)
        cache.put("example.com", "AAAA", rrset="aaaa-rrset", ttl=300)

        a_entry = cache.get("example.com", "A")
        aaaa_entry = cache.get("example.com", "AAAA")
        assert a_entry is not None
        assert aaaa_entry is not None
        assert a_entry.rrset == "a-rrset"
        assert aaaa_entry.rrset == "aaaa-rrset"
