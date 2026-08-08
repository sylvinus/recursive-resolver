"""Thread-safe DNS cache with TTL expiry, negative caching and delegation caching.

Three kinds of entry share one LRU:

``answer``
    A final RRset for a (name, type, class) tuple.
``negative``
    An NXDOMAIN (keyed by *name* only, per RFC 2308 §5) or a NODATA (keyed by
    name and type).
``delegation``
    The nameservers for a zone cut. Caching these is what stops every single
    resolution from starting with a query to a root server.

Keys are :class:`dns.name.Name` objects rather than strings, so lookups are
correctly case-insensitive and immune to the ``str.lower()`` / IDNA mismatches
that plague string keys.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from typing import Any

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

# Named delegation-cache levels. Only the levels with a reason to exist are
# named; any label depth still works as an integer if you have an unusual need.
# The number is a label depth: the root is 0, ``com.`` is 1, ``example.com.``
# is 2.
CACHE_DEPTHS: dict[str, int | None] = {
    # Cache nothing. Every lookup walks from a root server.
    "none": -1,
    # Cache only the delegations the root hands out, so lookups start at the
    # TLD servers and never touch a root server, while everything below the TLD
    # is re-resolved every time. TLD delegations change very rarely, which makes
    # this a good production setting when answer freshness matters.
    "tld": 1,
    # Cache every zone cut.
    "all": None,
}


def resolve_cache_depth(value: int | str | None) -> int | None:
    """Turn a level name or an integer into a label depth.

    Accepts any key of :data:`CACHE_DEPTHS`, an integer depth, or None for
    unlimited.
    """
    if value is None or isinstance(value, int):
        return value
    text = value.strip().lower()
    if text in CACHE_DEPTHS:
        return CACHE_DEPTHS[text]
    try:
        return int(text)
    except ValueError:
        raise ValueError(
            f"unknown cache depth {value!r}; use an integer or one of: {', '.join(CACHE_DEPTHS)}"
        ) from None


# Entry-kind tags used to namespace the shared LRU.
_ANSWER = "A"
_NODATA = "ND"
_NXDOMAIN = "NX"
_DELEGATION = "DG"

CacheKey = tuple[str, dns.name.Name, int, int]


@dataclass
class CacheEntry:
    """A single cached DNS response."""

    rrset: Any  # dns.rrset.RRset, Delegation, or None for NXDOMAIN
    expiry: float  # time.monotonic() value when this entry expires
    is_negative: bool = False
    secure: bool = False  # DNSSEC-authenticated


@dataclass
class Delegation:
    """A cached zone cut: the nameservers authoritative for ``zone``.

    ``ds`` carries the validated DS rdataset for the zone so a resumed
    resolution can rebuild the chain of trust without depending on a separate
    DNSKEY cache still being warm.
    """

    zone: dns.name.Name
    addresses: list[str] = field(default_factory=list)
    ns_names: list[str] = field(default_factory=list)
    secure: bool = False
    ds: Any = None


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

    Uses ``time.monotonic()`` for TTL tracking (immune to system clock changes)
    and an :class:`~collections.OrderedDict` for O(1) LRU maintenance.

    Args:
        max_size: Maximum number of entries. 0 means unlimited.
        min_ttl: Floor applied to record TTLs, in seconds. 0 honours the wire
            TTL exactly, which is what you want when freshness matters:
            key rotation, GSLB failover.
        max_ttl: Ceiling applied to record TTLs, in seconds.
        negative_ttl: Fallback TTL for negative entries when the authority
            section carries no usable SOA.
        max_negative_ttl: Ceiling applied to SOA-derived negative TTLs.
        max_delegation_depth: How deep to cache zone cuts. Either a label depth
            (root = 0, ``com.`` = 1, ``example.com.`` = 2) or one of the names
            in :data:`CACHE_DEPTHS`: ``"tld"``, ``"all"``, ``"none"``.
            ``None`` caches every level.
    """

    def __init__(
        self,
        max_size: int = 10000,
        min_ttl: int = 0,
        max_ttl: int = 86400,
        negative_ttl: int = 300,
        max_negative_ttl: int = 3600,
        max_delegation_depth: int | str | None = None,
    ) -> None:
        self.max_size = max_size
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self.max_negative_ttl = max_negative_ttl
        self.max_delegation_depth = resolve_cache_depth(max_delegation_depth)
        self._cache: OrderedDict[CacheKey, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self.stats = CacheStats()

    # ── internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _name(name: dns.name.Name | str) -> dns.name.Name:
        if isinstance(name, dns.name.Name):
            return name
        return dns.name.from_text(name)

    @staticmethod
    def _rdtype(rdtype: int | str) -> int:
        if isinstance(rdtype, int):
            return rdtype
        return int(dns.rdatatype.from_text(rdtype))

    def _clamp(self, ttl: int, negative: bool = False) -> int:
        ceiling = self.max_negative_ttl if negative else self.max_ttl
        return max(self.min_ttl, min(int(ttl), ceiling))

    def _get(self, key: CacheKey) -> CacheEntry | None:
        """Fetch and LRU-touch a key. Must be called under the lock."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.monotonic() >= entry.expiry:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return entry

    def _put(self, key: CacheKey, entry: CacheEntry) -> None:
        """Insert a key. Must be called under the lock."""
        if self.max_size > 0 and key not in self._cache and len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
            self.stats.evictions += 1
        self._cache[key] = entry
        self._cache.move_to_end(key)

    # ── answers ─────────────────────────────────────────────────────────

    @staticmethod
    def _isolate(rrset: Any) -> Any:
        """Return a copy of an RRset, so cache and caller never share one.

        A :class:`dns.rrset.RRset` is a mutable container. Handing the same
        object to the cache and to a caller means an ``add`` or a ``ttl``
        assignment anywhere silently rewrites what every later lookup returns,
        across every thread. Copying is cheap because the rdata objects inside
        are immutable and stay shared; only the container is duplicated.
        """
        if isinstance(rrset, dns.rrset.RRset):
            return rrset.copy()
        return rrset

    def get_answer(
        self, qname: dns.name.Name | str, rdtype: int | str, rdclass: int = dns.rdataclass.IN
    ) -> CacheEntry | None:
        """Look up a positive answer. Returns None on miss or expiry.

        The returned entry carries a private copy of the RRset; mutating it
        cannot affect the cache or any other caller.
        """
        key: CacheKey = (_ANSWER, self._name(qname), self._rdtype(rdtype), rdclass)
        with self._lock:
            entry = self._get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            self.stats.hits += 1
            return replace(entry, rrset=self._isolate(entry.rrset))

    def put_answer(
        self,
        qname: dns.name.Name | str,
        rdtype: int | str,
        rrset: Any,
        ttl: int,
        rdclass: int = dns.rdataclass.IN,
        secure: bool = False,
    ) -> None:
        """Store a positive answer, taking a private copy of the RRset."""
        key: CacheKey = (_ANSWER, self._name(qname), self._rdtype(rdtype), rdclass)
        entry = CacheEntry(rrset=self._isolate(rrset), expiry=time.monotonic() + self._clamp(ttl), secure=secure)
        with self._lock:
            self._put(key, entry)

    # ── negative answers ────────────────────────────────────────────────

    def get_nxdomain(self, qname: dns.name.Name | str) -> CacheEntry | None:
        """Look up a cached NXDOMAIN for this exact name."""
        key: CacheKey = (_NXDOMAIN, self._name(qname), 0, 0)
        with self._lock:
            return self._get(key)

    def get_nxdomain_ancestor(self, qname: dns.name.Name | str) -> dns.name.Name | None:
        """Return a cached NXDOMAIN ancestor of ``qname``, if any.

        Implements RFC 8020 / ``harden-below-nxdomain``: if ``foo.example.com``
        does not exist, nothing below it can exist either. This is the primary
        defence against random-subdomain (water torture) floods.
        """
        name = self._name(qname)
        with self._lock:
            current = name
            while True:
                if self._get((_NXDOMAIN, current, 0, 0)) is not None:
                    return current
                if current == dns.name.root:
                    return None
                try:
                    current = current.parent()
                except dns.name.NoParent:  # pragma: no cover - guarded by the root check
                    return None

    def put_nxdomain(self, qname: dns.name.Name | str, ttl: int | None = None) -> None:
        """Store an NXDOMAIN, keyed by name only (RFC 2308 §5)."""
        key: CacheKey = (_NXDOMAIN, self._name(qname), 0, 0)
        effective = self.negative_ttl if ttl is None else ttl
        expiry = time.monotonic() + self._clamp(effective, negative=True)
        entry = CacheEntry(rrset=None, expiry=expiry, is_negative=True)
        with self._lock:
            self._put(key, entry)

    def get_nodata(
        self, qname: dns.name.Name | str, rdtype: int | str, rdclass: int = dns.rdataclass.IN
    ) -> CacheEntry | None:
        """Look up a cached NODATA for this name and type."""
        key: CacheKey = (_NODATA, self._name(qname), self._rdtype(rdtype), rdclass)
        with self._lock:
            return self._get(key)

    def put_nodata(
        self,
        qname: dns.name.Name | str,
        rdtype: int | str,
        ttl: int | None = None,
        rdclass: int = dns.rdataclass.IN,
    ) -> None:
        """Store a NODATA for this name and type."""
        key: CacheKey = (_NODATA, self._name(qname), self._rdtype(rdtype), rdclass)
        effective = self.negative_ttl if ttl is None else ttl
        expiry = time.monotonic() + self._clamp(effective, negative=True)
        entry = CacheEntry(rrset=None, expiry=expiry, is_negative=True)
        with self._lock:
            self._put(key, entry)

    # ── delegations ─────────────────────────────────────────────────────

    def put_delegation(self, delegation: Delegation, ttl: int) -> None:
        """Cache the nameservers for a zone cut, subject to the depth limit."""
        depth = len(delegation.zone) - 1  # dns.name length includes the root label
        if self.max_delegation_depth is not None and depth > self.max_delegation_depth:
            return
        key: CacheKey = (_DELEGATION, delegation.zone, 0, 0)
        entry = CacheEntry(rrset=delegation, expiry=time.monotonic() + self._clamp(ttl))
        with self._lock:
            self._put(key, entry)

    def get_delegation(self, zone: dns.name.Name) -> Delegation | None:
        """Look up the cached delegation for exactly this zone."""
        with self._lock:
            entry = self._get((_DELEGATION, zone, 0, 0))
            if entry is None:
                return None
            delegation: Delegation = entry.rrset
            return delegation

    def closest_delegation(self, qname: dns.name.Name) -> Delegation | None:
        """Return the deepest cached delegation that is an ancestor of ``qname``.

        This is what lets a resolution start partway down the tree instead of
        at a root server on every single call.
        """
        with self._lock:
            current = qname
            while True:
                entry = self._get((_DELEGATION, current, 0, 0))
                if entry is not None:
                    delegation: Delegation = entry.rrset
                    if delegation.addresses:
                        return delegation
                if current == dns.name.root:
                    return None
                try:
                    current = current.parent()
                except dns.name.NoParent:  # pragma: no cover - guarded by the root check
                    return None

    # ── maintenance ─────────────────────────────────────────────────────

    def clear(self) -> None:
        """Remove all entries from the cache."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Return the number of entries in the cache (including expired ones)."""
        with self._lock:
            return len(self._cache)
