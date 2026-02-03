"""Thread-safe DNS cache with TTL expiry and negative caching."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class CacheEntry:
    """A single cached DNS response."""

    rrset: Any  # dns.rrset.RRset or None for negative entries
    expiry: float  # time.monotonic() value when this entry expires
    is_negative: bool = False


@dataclass
class CacheStats:
    """Cache hit/miss statistics."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0

    @property
    def hit_rate(self) -> float:
        """Return the cache hit rate as a float between 0.0 and 1.0."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total


class DNSCache:
    """Thread-safe DNS cache with TTL-based expiry and negative caching.

    Uses time.monotonic() for TTL tracking (immune to system clock adjustments).

    Args:
        max_size: Maximum number of entries. 0 means unlimited.
        min_ttl: Minimum TTL in seconds (clamps short TTLs).
        max_ttl: Maximum TTL in seconds (clamps long TTLs).
        negative_ttl: TTL for negative cache entries (NXDOMAIN/NODATA) in seconds.
    """

    def __init__(
        self,
        max_size: int = 10000,
        min_ttl: int = 10,
        max_ttl: int = 86400,
        negative_ttl: int = 300,
    ) -> None:
        self.max_size = max_size
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self._cache: dict[tuple[str, str, str], CacheEntry] = {}
        self._access_order: list[tuple[str, str, str]] = []
        self._lock = threading.Lock()
        self.stats = CacheStats()

    def get(self, qname: str, rdtype: str, rdclass: str = "IN") -> CacheEntry | None:
        """Look up an entry in the cache.

        Returns the CacheEntry if found and not expired, otherwise None.
        Expired entries are removed on access.
        """
        key = (qname.lower(), rdtype.upper(), rdclass.upper())
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            if time.monotonic() >= entry.expiry:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                self.stats.misses += 1
                return None
            # Move to end of access order (most recently used)
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            self.stats.hits += 1
            return entry

    def put(
        self,
        qname: str,
        rdtype: str,
        rrset: Any,
        ttl: int | None = None,
        rdclass: str = "IN",
        is_negative: bool = False,
    ) -> None:
        """Store an entry in the cache.

        Args:
            qname: The query name.
            rdtype: The record type (e.g. "A", "AAAA").
            rrset: The dns.rrset.RRset to cache (or None for negative entries).
            ttl: TTL in seconds. If None, uses negative_ttl for negative entries or min_ttl.
            rdclass: The record class (default "IN").
            is_negative: Whether this is a negative cache entry (NXDOMAIN/NODATA).
        """
        key = (qname.lower(), rdtype.upper(), rdclass.upper())

        if ttl is None:
            ttl = self.negative_ttl if is_negative else self.min_ttl
        ttl = max(self.min_ttl, min(ttl, self.max_ttl))

        expiry = time.monotonic() + ttl
        entry = CacheEntry(rrset=rrset, expiry=expiry, is_negative=is_negative)

        with self._lock:
            # Evict if at capacity
            if self.max_size > 0 and len(self._cache) >= self.max_size and key not in self._cache:
                self._evict_one()

            self._cache[key] = entry
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)

    def _evict_one(self) -> None:
        """Evict the least recently used entry. Must be called under lock."""
        if self._access_order:
            oldest_key = self._access_order.pop(0)
            self._cache.pop(oldest_key, None)
            self.stats.evictions += 1

    def clear(self) -> None:
        """Remove all entries from the cache."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()

    def __len__(self) -> int:
        """Return the number of entries in the cache (including potentially expired ones)."""
        with self._lock:
            return len(self._cache)
