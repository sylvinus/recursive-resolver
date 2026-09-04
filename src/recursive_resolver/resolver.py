"""Core iterative DNS resolution engine.

Implements true recursive (iterative) resolution starting from root servers,
with DNSSEC validation, a shared per-resolution work budget, strict
downward-progress and bailiwick rules, and address filtering on nameserver IPs.

dnspython is used for wire-format parsing, UDP/TCP transport and DNSSEC
primitives; the iteration algorithm itself is implemented here.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.reversename
import dns.rrset

from .addresses import AddressFilter
from .budget import Limits, QueryBudget
from .cache import Delegation, DNSCache
from .dnssec import (
    CLOCK_SKEW,
    DNSSECValidator,
    ValidationState,
    ZoneKeys,
    cryptography_available,
    find_rrsig,
)
from .exceptions import (
    CNAMELoopError,
    DNSSECInsecureError,
    DNSSECMaterialUnavailableError,
    DNSSECUnavailableError,
    DNSSECValidationError,
    InvalidNameError,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    QueryBudgetExceededError,
    ResolutionTimeoutError,
    ResolverError,
    ServfailError,
    UnsupportedRdtypeError,
)
from .roots import get_root_addresses
from .singleflight import SingleFlight

logger = logging.getLogger(__name__)

# Server ordering and referral sampling are anti-attacker controls: their whole
# purpose is to deny a hostile zone any say in which server we talk to. The
# Mersenne Twister behind `random` is seeded predictably and its state is
# recoverable from enough observed output, so a CSPRNG is used instead. At this
# call rate the cost is not measurable.
_RANDOM = secrets.SystemRandom()

# Errnos meaning "this address family or host is simply not reachable from
# here": retrying is pointless, so the server is abandoned immediately.
_FATAL_ERRNOS = frozenset({errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL})

# Post-DNS-Flag-Day-2020 consensus UDP payload size. Unbound, PowerDNS and
# Knot all default to 1232; 4096 invites IP fragmentation, which is both a
# cache-poisoning vector and a common cause of silent blackholing.
DEFAULT_EDNS_PAYLOAD = 1232

# Ceiling on validated zone keys held across resolutions. A backstop against a
# resolver being walked through millions of signed zones, not a tuning knob:
# an entry is a few hundred bytes, and 2048 zones is far past any real working
# set.
MAX_KEY_CACHE_SIZE = 2048


@dataclass
class TraceStep:
    """A single step in the resolution trace."""

    server: str
    qname: str
    rdtype: str
    response_type: str  # "answer", "referral", "cname", "nxdomain", "nodata", "error"
    detail: str = ""
    rcode: int = 0
    zone: str = ""
    dnssec: str = ""


@dataclass
class Answer:
    """A resolved DNS answer, with the raw records preserved.

    ``records`` gives presentation-format strings for convenience, but anything
    that must round-trip exactly should use :attr:`rrset` or
    :meth:`text_values`.
    """

    qname: dns.name.Name
    canonical_name: dns.name.Name
    rdtype: dns.rdatatype.RdataType
    rrset: dns.rrset.RRset
    ttl: int
    dnssec: ValidationState = ValidationState.INSECURE
    cname_chain: list[dns.name.Name] = field(default_factory=list)

    @property
    def records(self) -> list[str]:
        """Presentation-format strings, one per record."""
        return [str(rr) for rr in self.rrset]

    @property
    def secure(self) -> bool:
        """True if the answer was DNSSEC-validated."""
        return self.dnssec is ValidationState.SECURE

    def text_values(self) -> list[str]:
        """Character-string values, one per record, correctly concatenated.

        A TXT record may be split into several ``<character-string>`` chunks of
        at most 255 octets. RFC 6376 §3.6.2.2 (DKIM) and RFC 7208 §3.3 (SPF)
        require them to be joined with *no* separator. Presentation format
        instead renders them as ``"chunk1" "chunk2"``, so any consumer that
        strips quotes naively corrupts the value: for an RSA-2048 DKIM key,
        always split in two, that means a key that never verifies. This method
        does the right thing.

        Raises:
            TypeError: if the record type has no character-string content.
        """
        values: list[str] = []
        for rr in self.rrset:
            strings = getattr(rr, "strings", None)
            if strings is None:
                raise TypeError(f"{dns.rdatatype.to_text(self.rrset.rdtype)} records have no character-string content")
            values.append(b"".join(strings).decode("utf-8", "surrogateescape"))
        return values


@dataclass
class _Context:
    """State shared across one resolve() call and all its sub-resolutions."""

    budget: QueryBudget
    trace: list[TraceStep] | None = None
    dnssec: bool = True


class RecursiveResolver:
    """Iterative DNS resolver that resolves queries starting from root servers.

    Args:
        timeout: Per-query UDP/TCP timeout in seconds.
        max_depth: Maximum delegation depth before raising MaxDepthError.
        max_cname_chain: Maximum CNAME follows before raising CNAMELoopError.
        cache_enabled: Master switch for all caching.
        cache_answers: Cache final answer RRsets. Set False when freshness
            matters (key rotation, GSLB failover) while still caching
            delegations.
        max_delegation_cache_depth: How deep to cache zone cuts. Either a label
            depth (root=0, ``com.``=1, ``example.com.``=2) or a name:
            ``"tld"`` caches only the root's delegations, so lookups start at
            the TLD servers and never touch a root server while everything
            below is re-resolved; ``"all"`` (the default) keeps every cut;
            ``"none"`` disables delegation caching. Any other label depth can be
            given as an integer.
        min_ttl: Floor applied to cached record TTLs. 0 honours the wire TTL
            exactly. Never applied to negative entries or to authenticated
            data, whose TTL is already capped by its signature.
        use_tcp_fallback: Fall back to TCP when a response is truncated.
        max_retries: Retries per nameserver. Each retry also downgrades EDNS.
        ipv4_only: Only use IPv4 addresses for queries.
        max_resolution_time: Hard cap on total wall-clock time per resolve().
            The default covers a cold walk from the root that has to resolve
            glueless NS hostnames and survive a dead nameserver; with a warm
            delegation cache an ordinary lookup finishes in a fraction of it.
        limits: Hardening limits against hostile zones (query fan-out,
            NXNSAttack, KeyTrap). See :class:`~recursive_resolver.Limits`; the
            defaults are the values production resolvers ship.
        edns_payload: Advertised EDNS0 UDP payload size.
        dnssec: Validate DNSSEC. Bogus data raises DNSSECValidationError;
            legitimately unsigned zones resolve normally.
        require_dnssec: Additionally reject unsigned (insecure) answers.
        require_authoritative: Only accept answers and negative responses that
            have the AA bit set.
        allow_private_addresses: Permit private/loopback nameserver addresses.
            Leave False unless you run split-horizon DNS you fully trust.
        extra_blocked_networks: Further CIDRs to refuse, added to the built-in
            rules rather than replacing them.
        idna_codec: IDNA codec for unicode names. Defaults to IDNA 2008
            (practical), matching browsers and mail systems.
        trust_anchors: DS records for the root, in presentation format.
            ``None`` uses the IANA anchors. Override only to validate against a
            private root, or in tests. An empty tuple is rejected rather than
            treated as ``None``.

    Most arguments are readable as an attribute of the same name. The cache and
    address settings are not: they are applied to :attr:`cache` and
    :attr:`address_filter`, which are live objects you are meant to interact
    with. Assigning to any of these after construction is unsupported: it
    cannot affect a call already in flight, and nothing revalidates it. Build a
    new resolver instead.

    Instances are thread-safe. Share one across a thread pool to get the shared
    cache and the deduplication of concurrent identical queries.
    """

    def __init__(
        self,
        timeout: float = 2.0,
        max_depth: int = 20,
        max_cname_chain: int = 10,
        cache_enabled: bool = True,
        cache_answers: bool = True,
        max_delegation_cache_depth: int | str | None = None,
        min_ttl: int = 0,
        use_tcp_fallback: bool = True,
        max_retries: int = 2,
        ipv4_only: bool = True,
        max_resolution_time: float = 15.0,
        limits: Limits | None = None,
        edns_payload: int = DEFAULT_EDNS_PAYLOAD,
        dnssec: bool = True,
        require_dnssec: bool = False,
        require_authoritative: bool = True,
        allow_private_addresses: bool = False,
        extra_blocked_networks: list[str] | None = None,
        idna_codec: Any = None,
        trust_anchors: tuple[str, ...] | None = None,
        clock_skew: int = CLOCK_SKEW,
    ) -> None:
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_cname_chain = max_cname_chain
        self.use_tcp_fallback = use_tcp_fallback
        self.max_retries = max_retries
        self.ipv4_only = ipv4_only
        self.max_resolution_time = max_resolution_time
        self.limits = limits if limits is not None else Limits()
        # An OPT record carries the payload size in the class field, so a value
        # outside 16 bits reaches dnspython as a bad rdclass and comes back as a
        # bare ValueError from inside the query path. Everything leaving this
        # package is a ResolverError, so it is caught where it is configured.
        if not 0 <= edns_payload <= 65535:
            raise ValueError(f"edns_payload must be between 0 and 65535, got {edns_payload}")
        self.edns_payload = edns_payload
        self.require_dnssec = require_dnssec
        self.require_authoritative = require_authoritative
        self.cache_answers = cache_answers
        self._key_cache_size = MAX_KEY_CACHE_SIZE

        if dnssec and not cryptography_available():
            raise DNSSECUnavailableError()
        self.dnssec = dnssec
        self._validator: DNSSECValidator | None = None
        if dnssec:
            # `is not None`, not truthiness: an explicit empty tuple is a
            # caller error, and DNSSECValidator rejects it. Falling back to the
            # IANA anchors there would be the opposite of what was asked for.
            self._validator = (
                DNSSECValidator(trust_anchors=trust_anchors, clock_skew=clock_skew)
                if trust_anchors is not None
                else DNSSECValidator(clock_skew=clock_skew)
            )

        self.address_filter = AddressFilter(extra_blocked_networks, allow_private=allow_private_addresses)
        self.cache = (
            DNSCache(min_ttl=min_ttl, max_delegation_depth=max_delegation_cache_depth) if cache_enabled else None
        )
        self.idna_codec = idna_codec if idna_codec is not None else self._default_idna_codec()

        self._root_addresses = self.address_filter.filter(get_root_addresses(ipv4_only=ipv4_only))
        self._key_cache: OrderedDict[dns.name.Name, ZoneKeys] = OrderedDict()
        self._key_lock = threading.Lock()
        self._singleflight: SingleFlight[Answer] = SingleFlight()

    @staticmethod
    def _default_idna_codec() -> Any:
        """IDNA 2008 if available, else IDNA 2003 with a warning.

        IDNA 2003 maps German ``ß`` to ``ss``, so ``straße.de`` would be
        resolved as the entirely different domain ``strasse.de``. Browsers and
        mail systems use IDNA 2008/UTS-46, so we must too.
        """
        codec = getattr(dns.name, "IDNA_2008_Practical", None)
        if codec is not None and getattr(dns.name, "have_idna_2008", False):
            return codec
        logger.warning(
            "IDNA 2008 unavailable (install the 'idna' package); falling back to IDNA 2003, "
            "which resolves some internationalised names to different domains."
        )
        return dns.name.IDNA_2003

    # ── public API ──────────────────────────────────────────────────────

    def resolve(self, qname: str, rdtype: str = "A") -> list[str]:
        """Resolve a DNS query iteratively from root servers.

        Args:
            qname: The domain name to query (or an IP address for PTR lookups).
            rdtype: The record type (e.g. "A", "AAAA", "MX", "TXT").

        Returns:
            Presentation-format strings for the answer records. For TXT-like
            records that must round-trip exactly, prefer
            :meth:`resolve_answer` and ``Answer.text_values()``.

        Raises:
            ResolverError: any resolution failure; see the exceptions module.
        """
        return self.resolve_answer(qname, rdtype).records

    def resolve_rrset(self, qname: str, rdtype: str = "A") -> dns.rrset.RRset:
        """Resolve and return the raw dnspython RRset, preserving rdata structure."""
        return self.resolve_answer(qname, rdtype).rrset

    def resolve_answer(self, qname: str, rdtype: str = "A") -> Answer:
        """Resolve and return the full :class:`Answer`, including DNSSEC status.

        The :class:`Answer` is the caller's own: concurrent callers collapsed
        into one upstream resolution each get a separate copy, so nothing they
        do to it can be seen by another thread or by the cache.
        """
        name = self._normalize_qname(qname, rdtype)
        rdtype_int = self._parse_rdtype(rdtype)
        key = (name, rdtype_int)

        def work() -> Answer:
            ctx = self._new_context()
            return self._resolve_entry(name, rdtype_int, ctx)

        answer = self._singleflight.do(key, work, wait_timeout=self.max_resolution_time)
        return replace(answer, rrset=answer.rrset.copy(), cname_chain=list(answer.cname_chain))

    def trace_answer(self, qname: str, rdtype: str = "A") -> tuple[Answer | None, list[TraceStep]]:
        """Resolve, returning both the answer and the trace.

        The answer is ``None`` if resolution failed; the trace is still
        returned so the failure can be diagnosed.
        """
        name = self._normalize_qname(qname, rdtype)
        rdtype_int = self._parse_rdtype(rdtype)
        trace: list[TraceStep] = []
        ctx = self._new_context(trace=trace)
        try:
            answer = self._resolve_entry(name, rdtype_int, ctx)
        except ResolverError:
            return None, trace
        return answer, trace

    # ── input handling ──────────────────────────────────────────────────

    def _new_context(self, trace: list[TraceStep] | None = None) -> _Context:
        budget = self.limits.budget(deadline=time.monotonic() + self.max_resolution_time)
        return _Context(budget=budget, trace=trace, dnssec=self.dnssec)

    def _parse_rdtype(self, rdtype: str) -> dns.rdatatype.RdataType:
        """Validate and convert a record type, raising UnsupportedRdtypeError."""
        text = rdtype.strip().upper()
        if not text:
            raise UnsupportedRdtypeError(rdtype, "empty record type")
        try:
            value = dns.rdatatype.from_text(text)
        except dns.rdatatype.UnknownRdatatype as exc:
            raise UnsupportedRdtypeError(rdtype, "unknown record type") from exc
        except ValueError as exc:
            # "TYPEnnnnn" parses as a generic type but is range-checked
            # separately, so a number above 65535 raises a plain ValueError
            # rather than UnknownRdatatype. Nothing from dnspython may escape.
            raise UnsupportedRdtypeError(rdtype, "record type out of range") from exc
        if value == dns.rdatatype.ANY:
            # An ANY response carries several RRsets at once, and an `Answer`
            # holds exactly one, so there is nothing this API could return.
            # Silently letting it through was worse than refusing: no RRset
            # ever matched the query type, so a fully populated answer was
            # read as NODATA and cached as one, which then denied the name for
            # every later query of any type. RFC 8482 has servers answering
            # ANY minimally in any case; ask for the types you want.
            raise UnsupportedRdtypeError(rdtype, "ANY cannot be queried; ask for specific types")
        if dns.rdatatype.is_metatype(value):
            raise UnsupportedRdtypeError(rdtype, "meta record types cannot be queried")
        return value

    def _normalize_qname(self, qname: str, rdtype: str) -> dns.name.Name:
        """Validate the query name, IDNA-encoding it and handling PTR reversal."""
        if not isinstance(qname, str) or not qname.strip():
            raise InvalidNameError(str(qname), "empty name")

        if rdtype.strip().upper() == "PTR":
            try:
                addr = ipaddress.ip_address(qname.strip())
            except ValueError:
                pass
            else:
                return dns.reversename.from_address(str(addr))

        try:
            name = dns.name.from_text(qname, idna_codec=self.idna_codec)
        except dns.name.LabelTooLong as exc:
            raise InvalidNameError(qname, "a label exceeds 63 octets") from exc
        except dns.name.NameTooLong as exc:
            raise InvalidNameError(qname, "name exceeds 255 octets") from exc
        except dns.name.EmptyLabel as exc:
            raise InvalidNameError(qname, "empty label") from exc
        except dns.exception.DNSException as exc:
            raise InvalidNameError(qname, str(exc) or type(exc).__name__) from exc
        except UnicodeError as exc:
            raise InvalidNameError(qname, f"IDNA encoding failed: {exc}") from exc

        if not name.is_absolute():
            name = name.concatenate(dns.name.root)
        return name

    # ── resolution ──────────────────────────────────────────────────────

    def _resolve_entry(self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType, ctx: _Context) -> Answer:
        answer = self._resolve_iterative(qname, rdtype, ctx, depth=0, cname_chain=[])
        if self.require_dnssec and answer.dnssec is not ValidationState.SECURE:
            raise DNSSECInsecureError(str(qname), dns.rdatatype.to_text(rdtype))
        return answer

    def _require_proven_denial(self, state: ValidationState, qname: dns.name.Name, rdtype_text: str) -> None:
        """Hold a denial to the same standard as an answer under ``require_dnssec``.

        A negative answer leaves through an exception rather than an ``Answer``,
        so the check in :meth:`_resolve_entry` never sees it. Without this, the
        strict mode refuses an unsigned *answer* while accepting an unsigned
        "no such name" for the same zone.
        """
        if self.require_dnssec and state is not ValidationState.SECURE:
            raise DNSSECInsecureError(str(qname), rdtype_text)

    def _check_cache(self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType) -> Answer | None:
        """Consult the cache for a positive or negative entry."""
        if self.cache is None:
            return None

        # A cached denial has to clear the same bar as a fresh one. It is
        # stored before the strict-mode check runs, so without re-checking here
        # the first query fails closed and every one after it is served the
        # denial straight from cache.
        nx = self.cache.get_nxdomain_ancestor(qname)
        if nx is not None:
            # RFC 8020: nothing exists below a non-existent name.
            self._require_proven_denial(
                ValidationState.SECURE if nx.secure else ValidationState.INSECURE,
                qname,
                dns.rdatatype.to_text(rdtype),
            )
            raise NXDOMAINError(str(qname), dns.rdatatype.to_text(rdtype))

        nodata = self.cache.get_nodata(qname, rdtype)
        if nodata is not None:
            self._require_proven_denial(
                ValidationState.SECURE if nodata.secure else ValidationState.INSECURE,
                qname,
                dns.rdatatype.to_text(rdtype),
            )
            raise NoAnswerError(str(qname), dns.rdatatype.to_text(rdtype))

        if not self.cache_answers:
            return None
        entry = self.cache.get_answer(qname, rdtype)
        if entry is None or entry.rrset is None:
            return None
        return Answer(
            qname=qname,
            canonical_name=qname,
            rdtype=rdtype,
            rrset=entry.rrset,
            # What is left of the entry, not the TTL it arrived with. A caller
            # re-caching on this value would otherwise extend the lifetime on
            # every hit, and for authenticated data that means outliving the
            # signature the TTL was capped to (RFC 4035 §5.3.3).
            ttl=max(0, int(entry.expiry - time.monotonic())),
            dnssec=ValidationState.SECURE if entry.secure else ValidationState.INSECURE,
        )

    def _starting_point(
        self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType
    ) -> tuple[dns.name.Name, list[str], ValidationState, Any, list[dns.name.Name]]:
        """Pick where to begin: a cached delegation if we have one, else the root.

        A DS record is published by the *parent* zone, so a cached delegation
        for the qname itself would send the query to the child, which does not
        hold its own DS and correctly answers NODATA. Start one label up.

        The delegation's NS *names* come back too, not just its addresses. If
        every cached address has gone dead the walk has nothing else to try,
        and a zone whose glue has changed under a long delegation TTL would
        stay dark for as long as that TTL - even though re-resolving the
        hostnames would find it immediately.
        """
        lookup = qname
        if rdtype == dns.rdatatype.DS and qname != dns.name.root:
            lookup = qname.parent()
        if self.cache is not None:
            delegation = self.cache.closest_delegation(lookup)
            if delegation is not None:
                addresses = self.address_filter.filter(delegation.addresses)
                if addresses:
                    state = ValidationState.SECURE if delegation.secure else ValidationState.INSECURE
                    # Resuming a secure chain needs either the zone's DS or
                    # cached keys; without one of them we cannot prove the link
                    # back to the root, so restart from the root rather than
                    # silently downgrade to insecure.
                    unprovable = delegation.ds is None and self._cached_keys(delegation.zone) is None
                    if self.dnssec and state is ValidationState.SECURE and unprovable:
                        return dns.name.root, list(self._root_addresses), ValidationState.SECURE, None, []
                    names = [dns.name.from_text(n) for n in delegation.ns_names]
                    return delegation.zone, addresses, state, delegation.ds, names
        return dns.name.root, list(self._root_addresses), ValidationState.SECURE, None, []

    def _resolve_iterative(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
    ) -> Answer:
        """Core iterative resolution loop."""
        rdtype_text = dns.rdatatype.to_text(rdtype)
        if depth > self.max_depth:
            raise MaxDepthError(str(qname), rdtype_text, self.max_depth)
        if ctx.budget.expired():
            raise ResolutionTimeoutError(str(qname), rdtype_text)

        cached = self._check_cache(qname, rdtype)
        if cached is not None:
            return cached

        current_zone, current_nameservers, chain_state, current_ds, cached_ns_names = self._starting_point(
            qname, rdtype
        )
        # `current_nameservers` is pruned as servers fail, but DNSSEC key
        # fetches must keep talking to the zone's full server set: otherwise a
        # single-nameserver signed zone returning NXDOMAIN leaves us with an
        # empty list and we report a DNSSEC failure of our own making.
        zone_nameservers = list(current_nameservers)
        # Seeded from the cached delegation so a dead address set still has its
        # hostnames to fall back on.
        pending_ns_names: list[dns.name.Name] = cached_ns_names
        tried_addresses: set[str] = set()
        nxdomain_retries_left = 2

        for _ in range(self.max_depth):
            if ctx.budget.expired():
                raise ResolutionTimeoutError(str(qname), rdtype_text)

            tried_addresses.update(current_nameservers)
            response, server = self._send_query(qname, rdtype, current_nameservers, ctx)
            if response is None:
                fallback = self._fallback_nameservers(pending_ns_names, tried_addresses, ctx, depth)
                if fallback:
                    current_nameservers = fallback
                    continue
                raise ResolutionTimeoutError(str(qname), rdtype_text)

            classification = self._classify_response(response, qname, rdtype, current_zone)
            kind = classification["type"]
            self._record_trace(ctx, server, qname, rdtype_text, classification, response, current_zone, chain_state)

            if self._serves_an_unsigned_copy(response, kind, chain_state, ctx):
                siblings = [ns for ns in current_nameservers if ns != server]
                if siblings:
                    logger.debug(
                        "Unsigned %s for %s/%s from %s in signed zone %s, trying siblings",
                        kind,
                        qname,
                        rdtype_text,
                        server,
                        current_zone,
                    )
                    current_nameservers = siblings
                    continue
                # Every server answers unsigned, so this is the zone and not
                # one stale copy of it. Fall through and judge what we have.

            if kind == "answer":
                return self._handle_answer(
                    response,
                    classification,
                    qname,
                    rdtype,
                    ctx,
                    current_zone,
                    zone_nameservers,
                    chain_state,
                    current_ds,
                    cname_chain,
                )

            if kind == "cname":
                return self._handle_cname(
                    response,
                    classification,
                    qname,
                    rdtype,
                    ctx,
                    depth,
                    cname_chain,
                    current_zone,
                    zone_nameservers,
                    chain_state,
                    current_ds,
                )

            if kind == "referral":
                ctx.budget.note_referral(str(qname), rdtype_text)
                child_zone: dns.name.Name = classification["zone"]
                chain_state, current_ds = self._advance_dnssec(
                    response,
                    child_zone,
                    current_zone,
                    zone_nameservers,
                    chain_state,
                    current_ds,
                    ctx,
                )
                ns_names: list[dns.name.Name] = classification["ns_names"]
                # An NS name inside the zone it serves can only be reached via
                # glue: resolving it independently needs the very servers we are
                # trying to find. Prefer the out-of-zone names for both the
                # glueless path and any later fallback.
                resolvable = [n for n in ns_names if not n.is_subdomain(child_zone)] or ns_names
                pending_ns_names = resolvable
                glue = self._select_glue(response, ns_names, current_zone, child_zone)
                if not glue:
                    glue = self._resolve_ns_names(resolvable, ctx, depth + 1, limit=self.limits.max_ns_per_referral)
                if not glue:
                    # Resolving the NS names returns nothing both when they do
                    # not resolve and when the budget ran out underneath. Only
                    # the first is a server failure.
                    if ctx.budget.expired():
                        raise ResolutionTimeoutError(str(qname), rdtype_text)
                    raise ServfailError(str(qname), rdtype_text)
                self._cache_delegation(child_zone, ns_names, glue, response, chain_state, current_ds)
                current_zone = child_zone
                current_nameservers = glue
                zone_nameservers = list(glue)
                nxdomain_retries_left = 2
                continue

            if kind == "nxdomain":
                current_nameservers = [ns for ns in current_nameservers if ns != server]
                if current_nameservers and nxdomain_retries_left > 0:
                    nxdomain_retries_left -= 1
                    logger.debug("NXDOMAIN from %s for %s/%s, trying siblings", server, qname, rdtype_text)
                    continue
                denial, proof_ttl = self._verify_denial(
                    response,
                    qname,
                    rdtype,
                    ctx,
                    current_zone,
                    zone_nameservers,
                    chain_state,
                    current_ds,
                    negative="nxdomain",
                )
                if self.cache is not None:
                    self.cache.put_nxdomain(
                        qname,
                        self._cacheable_negative_ttl(response, qname, current_zone, denial, proof_ttl),
                        secure=denial is ValidationState.SECURE,
                    )
                self._require_proven_denial(denial, qname, rdtype_text)
                raise NXDOMAINError(str(qname), rdtype_text)

            if kind == "nodata":
                denial, proof_ttl = self._verify_denial(
                    response,
                    qname,
                    rdtype,
                    ctx,
                    current_zone,
                    zone_nameservers,
                    chain_state,
                    current_ds,
                    negative="nodata",
                )
                if self.cache is not None:
                    self.cache.put_nodata(
                        qname,
                        rdtype,
                        self._cacheable_negative_ttl(response, qname, current_zone, denial, proof_ttl),
                        secure=denial is ValidationState.SECURE,
                    )
                self._require_proven_denial(denial, qname, rdtype_text)
                raise NoAnswerError(str(qname), rdtype_text)

            # "error" / "lame": drop this server and try another.
            current_nameservers = [ns for ns in current_nameservers if ns != server]
            if not current_nameservers:
                # Every address we have refuses or errors. A stale delegation
                # naming a provider that no longer serves the zone looks exactly
                # like this, so resolve the referral's other NS names before
                # giving up: one of them is usually the live one.
                fallback = self._fallback_nameservers(pending_ns_names, tried_addresses, ctx, depth)
                if fallback:
                    current_nameservers = fallback
                    continue
                raise ServfailError(str(qname), rdtype_text, rcode=response.rcode())

        raise MaxDepthError(str(qname), rdtype_text, self.max_depth)

    def _record_trace(
        self,
        ctx: _Context,
        server: str,
        qname: dns.name.Name,
        rdtype_text: str,
        classification: dict[str, Any],
        response: dns.message.Message,
        zone: dns.name.Name,
        state: ValidationState,
    ) -> None:
        if ctx.trace is None:
            return
        ctx.trace.append(
            TraceStep(
                server=server,
                qname=str(qname),
                rdtype=rdtype_text,
                response_type=classification["type"],
                detail=classification.get("detail", ""),
                rcode=response.rcode(),
                zone=str(zone),
                dnssec=state.value,
            )
        )

    def _handle_answer(
        self,
        response: dns.message.Message,
        classification: dict[str, Any],
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: Any,
        cname_chain: list[dns.name.Name],
    ) -> Answer:
        rrset: dns.rrset.RRset = classification["rrset"]
        validated, ttl = self._validate_answer(response, rrset, qname, rdtype, ctx, zone, nameservers, state, ds)
        if self.cache is not None and self.cache_answers:
            self.cache.put_answer(qname, rdtype, rrset, ttl, secure=validated is ValidationState.SECURE)
        return Answer(
            qname=qname,
            canonical_name=qname,
            rdtype=rdtype,
            rrset=rrset,
            ttl=ttl,
            dnssec=validated,
            cname_chain=list(cname_chain),
        )

    def _handle_cname(
        self,
        response: dns.message.Message,
        classification: dict[str, Any],
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: Any,
    ) -> Answer:
        rdtype_text = dns.rdatatype.to_text(rdtype)
        target: dns.name.Name = classification["target"]
        cname_rrset: dns.rrset.RRset = classification["cname_rrset"]

        if target in cname_chain or target == qname:
            raise CNAMELoopError(str(qname), [str(n) for n in cname_chain + [target]])
        if len(cname_chain) >= self.max_cname_chain:
            raise CNAMELoopError(str(qname), [str(n) for n in cname_chain + [target]])

        dname_rrset: dns.rrset.RRset | None = classification.get("dname_rrset")
        cname_state, cname_ttl = self._validate_answer(
            response, cname_rrset, qname, dns.rdatatype.CNAME, ctx, zone, nameservers, state, ds, dname_rrset
        )
        if self.cache is not None and self.cache_answers:
            self.cache.put_answer(
                qname,
                dns.rdatatype.CNAME,
                cname_rrset,
                cname_ttl,
                secure=cname_state is ValidationState.SECURE,
            )

        # The target's records may already be present in this very response
        # (the normal case for CDN and ESP zones). Using them avoids a second
        # full walk from the root.
        #
        # Only when the target is inside the answering server's zone. A server
        # is authoritative for its own bailiwick and nothing else, so a CNAME
        # pointing out of the zone plus an inline record for that foreign
        # target is an attempt to write another zone's data: the classic
        # cross-zone cache-poisoning trick. Answers for a foreign target must
        # be fetched from the servers that are actually authoritative for it,
        # which the fall-through below does.
        inline = self._find_answer_rrset(response, target, rdtype) if target.is_subdomain(zone) else None
        if inline is not None:
            inline_state, inline_ttl = self._validate_answer(
                response, inline, target, rdtype, ctx, zone, nameservers, state, ds
            )
            if self.cache is not None and self.cache_answers:
                self.cache.put_answer(target, rdtype, inline, inline_ttl, secure=inline_state is ValidationState.SECURE)
            return Answer(
                qname=qname,
                canonical_name=target,
                rdtype=rdtype,
                rrset=inline,
                ttl=min(cname_ttl, inline_ttl),
                dnssec=self._weakest(cname_state, inline_state),
                cname_chain=[*cname_chain, qname],
            )

        logger.debug("Following CNAME %s -> %s for %s", qname, target, rdtype_text)
        answer = self._resolve_iterative(target, rdtype, ctx, depth + 1, [*cname_chain, qname])
        return Answer(
            qname=qname,
            canonical_name=answer.canonical_name,
            rdtype=rdtype,
            rrset=answer.rrset,
            # The chain is only good for as long as its shortest-lived link,
            # exactly as its DNSSEC state is that of its weakest one.
            ttl=min(cname_ttl, answer.ttl),
            dnssec=self._weakest(cname_state, answer.dnssec),
            cname_chain=[*cname_chain, qname, *answer.cname_chain],
        )

    @staticmethod
    def _weakest(a: ValidationState, b: ValidationState) -> ValidationState:
        """The weaker of two validation states (BOGUS < INSECURE < SECURE)."""
        order = {ValidationState.BOGUS: 0, ValidationState.INSECURE: 1, ValidationState.SECURE: 2}
        return a if order[a] <= order[b] else b

    # ── response classification ─────────────────────────────────────────

    @staticmethod
    def _find_answer_rrset(response: dns.message.Message, name: dns.name.Name, rdtype: int) -> dns.rrset.RRset | None:
        for rrset in response.answer:
            if rrset.name == name and rrset.rdtype == rdtype and rrset.rdclass == dns.rdataclass.IN:
                return rrset
        return None

    def _classify_response(
        self,
        response: dns.message.Message,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        current_zone: dns.name.Name,
    ) -> dict[str, Any]:
        """Classify a response into answer, cname, referral, nxdomain, nodata or error."""
        rcode = response.rcode()
        authoritative = bool(response.flags & dns.flags.AA)

        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return {"type": "error", "rcode": rcode, "detail": dns.rcode.to_text(rcode)}

        # A direct answer of the requested type, in the IN class.
        answer_rrset = self._find_answer_rrset(response, qname, rdtype)
        if answer_rrset is not None:
            if rcode == dns.rcode.NXDOMAIN:
                # NXDOMAIN with data in the answer section is a protocol
                # violation; do not treat the data as authoritative.
                return {"type": "error", "rcode": rcode, "detail": "NXDOMAIN with answer records"}
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "answer without AA bit"}
            return {"type": "answer", "rrset": answer_rrset, "ttl": answer_rrset.ttl}

        # A DS is published by the parent, so a parent that responds with a
        # referral may carry the DS in the authority section. Take it from
        # there: following the referral would land on the child, which does not
        # hold its own DS.
        if rdtype == dns.rdatatype.DS and rcode == dns.rcode.NOERROR:
            for rrset in response.authority:
                if rrset.name == qname and rrset.rdtype == dns.rdatatype.DS and rrset.rdclass == dns.rdataclass.IN:
                    return {"type": "answer", "rrset": rrset, "ttl": rrset.ttl}

        # A CNAME must be considered before NXDOMAIN: some servers return
        # NXDOMAIN alongside a CNAME whose target lives outside their zone.
        if rdtype != dns.rdatatype.CNAME:
            cname_rrset = self._find_answer_rrset(response, qname, dns.rdatatype.CNAME)
            if cname_rrset is not None:
                return {
                    "type": "cname",
                    "target": cname_rrset[0].target,
                    "cname_rrset": cname_rrset,
                    "dname_rrset": self._find_dname(response, qname, current_zone),
                    "ttl": cname_rrset.ttl,
                    "detail": f"-> {cname_rrset[0].target}",
                }

        # A DNAME rewrites everything below its owner. The server should have
        # sent a synthesized CNAME with it, and the branch above would have
        # taken that; when it did not, RFC 6672 §3.4 makes the synthesis our
        # job: "Recursive caching name servers MUST perform CNAME synthesis on
        # behalf of clients."
        dname_rrset = self._find_dname(response, qname, current_zone)
        if dname_rrset is not None:
            target = self._dname_target(qname, dname_rrset)
            if target is not None:
                return {
                    "type": "cname",
                    "target": target,
                    "cname_rrset": self._synthesize_cname(qname, target, dname_rrset),
                    "dname_rrset": dname_rrset,
                    "ttl": dname_rrset.ttl,
                    "detail": f"DNAME {dname_rrset.name} -> {target}",
                }

        if rcode == dns.rcode.NXDOMAIN:
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "NXDOMAIN without AA bit"}
            return {"type": "nxdomain"}

        # An SOA owning the qname or an ancestor marks a negative answer
        # (RFC 2308), which takes precedence over any NS records also present.
        for rrset in response.authority:
            if not self._marks_negative(rrset, qname, current_zone):
                continue
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "NODATA without AA bit"}
            return {"type": "nodata"}

        referral = self._find_referral(response, qname, current_zone, rdtype)
        if referral is not None:
            return referral

        # An NS set that points sideways, upwards, or at a zone the qname does
        # not live under is a server sending us somewhere else, not one telling
        # us the name has no records. Reading it as NODATA caches a denial on a
        # lame server's say-so and stops the sweep before its siblings are
        # asked, so it is an error whatever the AA bit says.
        #
        # A delegation *at* the qname is the exception, and only for a DS: the
        # parent handing back the child's NS set with no DS beside it is what
        # an unsigned delegation looks like, and that really is a NODATA.
        ns_sets = [
            rrset
            for rrset in response.authority
            if rrset.rdtype == dns.rdatatype.NS and rrset.rdclass == dns.rdataclass.IN
        ]
        if ns_sets and not any(self._delegates_towards(rrset.name, qname, current_zone) for rrset in ns_sets):
            return {"type": "error", "rcode": rcode, "detail": "NS set that does not delegate below this zone"}

        if self.require_authoritative and not authoritative:
            return {"type": "error", "rcode": rcode, "detail": "empty response without AA bit"}
        return {"type": "nodata"}

    def _find_dname(
        self, response: dns.message.Message, qname: dns.name.Name, zone: dns.name.Name
    ) -> dns.rrset.RRset | None:
        """The DNAME in this answer that rewrites ``qname``, if any.

        It must own a *proper* ancestor of the queried name - a DNAME never
        applies to its own owner (RFC 6672 §2.4) - and it must be in the zone
        we asked, for the same reason inline CNAME targets are: a DNAME is a
        licence to rewrite a whole subtree, and one for a subtree the answering
        server does not hold is an attempt to rewrite somebody else's.
        """
        best: dns.rrset.RRset | None = None
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.DNAME or rrset.rdclass != dns.rdataclass.IN:
                continue
            if rrset.name == qname or not qname.is_subdomain(rrset.name):
                continue
            if not rrset.name.is_subdomain(zone):
                logger.debug("Ignoring out-of-bailiwick DNAME at %s (zone %s)", rrset.name, zone)
                continue
            # The longest match wins, as for any other name-based lookup.
            if best is None or len(rrset.name) > len(best.name):
                best = rrset
        return best

    @staticmethod
    def _dname_target(qname: dns.name.Name, dname_rrset: dns.rrset.RRset) -> dns.name.Name | None:
        """Apply the DNAME substitution to ``qname`` (RFC 6672 §3.4.1).

        The owner's labels are stripped from the queried name and the DNAME's
        target put in their place. A result longer than a legal name is a
        YXDOMAIN condition, and the redirection simply does not apply.
        """
        try:
            return qname.relativize(dname_rrset.name).concatenate(dname_rrset[0].target)
        except dns.exception.DNSException as exc:
            logger.debug("DNAME substitution for %s is not a usable name: %s", qname, exc)
            return None

    @staticmethod
    def _synthesize_cname(qname: dns.name.Name, target: dns.name.Name, dname_rrset: dns.rrset.RRset) -> dns.rrset.RRset:
        """The CNAME the DNAME implies, with the DNAME's TTL (RFC 6672 §3.1)."""
        rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.CNAME)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CNAME, target.to_text()))
        rrset.ttl = dname_rrset.ttl
        return rrset

    @staticmethod
    def _delegates_towards(owner: dns.name.Name, qname: dns.name.Name, current_zone: dns.name.Name) -> bool:
        """Does an NS set at ``owner`` hand us onward toward ``qname``?

        The same progress rule :meth:`_find_referral` enforces, without its
        DS-specific exception, so a caller can tell "a delegation we chose not
        to follow" from "a server pointing somewhere it has no business
        pointing".
        """
        return owner != current_zone and owner.is_subdomain(current_zone) and qname.is_subdomain(owner)

    @staticmethod
    def _marks_negative(rrset: dns.rrset.RRset, qname: dns.name.Name, current_zone: dns.name.Name) -> bool:
        """Is this the SOA that makes the response a negative answer (RFC 2308)?

        It has to be in class IN, to own the queried name or an ancestor of it,
        and to belong to the zone we are actually talking to. A server offering
        an SOA for some zone above the one it was asked about is not answering
        the question, and taking it would let it deny a name it holds nothing
        about - and set the negative TTL while it was at it.
        """
        return (
            rrset.rdtype == dns.rdatatype.SOA
            and rrset.rdclass == dns.rdataclass.IN
            and qname.is_subdomain(rrset.name)
            and rrset.name.is_subdomain(current_zone)
        )

    def _find_referral(
        self,
        response: dns.message.Message,
        qname: dns.name.Name,
        current_zone: dns.name.Name,
        rdtype: dns.rdatatype.RdataType = dns.rdatatype.A,
    ) -> dict[str, Any] | None:
        """Locate a valid downward referral, enforcing strict progress.

        The delegated zone must be a *proper* subdomain of the zone we asked
        (``dns.name.is_subdomain`` includes equality, so a naive check lets a
        server refer us back to its own zone forever) and the qname must lie
        at or below it. Anything else is a lame or hostile response.
        """
        best: dns.rrset.RRset | None = None
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.NS or rrset.rdclass != dns.rdataclass.IN:
                continue
            owner = rrset.name
            if owner == current_zone or not owner.is_subdomain(current_zone):
                logger.debug("Ignoring non-descending referral to %s from zone %s", owner, current_zone)
                continue
            if not qname.is_subdomain(owner):
                logger.debug("Ignoring referral to %s (qname %s is not below it)", owner, qname)
                continue
            if rdtype == dns.rdatatype.DS and owner == qname:
                # The parent delegates this name but did not hand us the DS;
                # descending would ask the child for a record it never holds.
                logger.debug("Not following the %s delegation for a DS query", owner)
                continue
            if best is None or len(owner) > len(best.name):
                best = rrset

        if best is None:
            return None

        ns_names = [rr.target for rr in best]
        if len(ns_names) > self.limits.max_ns_per_referral:
            # Random sample rather than a prefix: a deterministic slice is
            # attacker-orderable (PowerDNS uses the same approach).
            ns_names = _RANDOM.sample(ns_names, self.limits.max_ns_per_referral)
        detail = f"NS: {', '.join(str(n) for n in ns_names[:3])}"
        return {
            "type": "referral",
            "zone": best.name,
            "ns_names": ns_names,
            "ttl": best.ttl,
            "detail": detail,
        }

    def _select_glue(
        self,
        response: dns.message.Message,
        ns_names: list[dns.name.Name],
        current_zone: dns.name.Name,
        child_zone: dns.name.Name,
    ) -> list[str]:
        """Extract usable glue addresses from the additional section.

        Bailiwick is judged against the zone we *asked*: never against a zone
        name taken from the response, which the attacker controls. Glue for a
        name outside the responding server's bailiwick is discarded; the
        hostname is resolved independently instead.

        All addresses are then passed through the nameserver address filter,
        which is what stops a hostile zone from pointing us at 127.0.0.1 or
        the cloud metadata endpoint.
        """
        wanted = set(ns_names)
        addresses: list[str] = []
        for rrset in response.additional:
            if rrset.name not in wanted or rrset.rdclass != dns.rdataclass.IN:
                continue
            if rrset.rdtype != dns.rdatatype.A and not (rrset.rdtype == dns.rdatatype.AAAA and not self.ipv4_only):
                continue
            if not rrset.name.is_subdomain(current_zone) and not rrset.name.is_subdomain(child_zone):
                logger.debug("Rejecting out-of-bailiwick glue for %s (zone %s)", rrset.name, current_zone)
                continue
            addresses.extend(str(rr.address) for rr in rrset)

        allowed = self.address_filter.filter(addresses)
        if len(allowed) != len(addresses):
            rejected = set(addresses) - set(allowed)
            logger.warning("Rejected non-public glue addresses for zone %s: %s", child_zone, sorted(rejected))
        return allowed

    def _cache_delegation(
        self,
        zone: dns.name.Name,
        ns_names: list[dns.name.Name],
        addresses: list[str],
        response: dns.message.Message,
        state: ValidationState,
        ds: Any = None,
    ) -> None:
        if self.cache is None or not addresses:
            return
        ttl = 0
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS and rrset.name == zone:
                ttl = rrset.ttl
                break
        if ttl <= 0:
            return
        # The addresses expire with the glue that carried them, not with the NS
        # set. A delegation whose NS records live for a day but whose glue
        # lives for a minute is how an operator moves a nameserver, and holding
        # the old address for the day would follow them nowhere.
        wanted = set(ns_names)
        glue_ttls = [
            rrset.ttl
            for rrset in response.additional
            if rrset.name in wanted and rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) and rrset.ttl > 0
        ]
        if glue_ttls:
            ttl = min(ttl, *glue_ttls)
        self.cache.put_delegation(
            Delegation(
                zone=zone,
                addresses=list(addresses),
                ns_names=[str(n) for n in ns_names],
                secure=state is ValidationState.SECURE,
                ds=ds,
            ),
            ttl=ttl,
        )

    # ── glueless NS resolution ──────────────────────────────────────────

    def _fallback_nameservers(
        self,
        ns_names: list[dns.name.Name],
        tried: set[str],
        ctx: _Context,
        depth: int,
    ) -> list[str]:
        """Resolve a referral's NS names, returning only addresses not yet tried.

        Used when the addresses we already hold are dead or refuse: stale glue,
        or a parent delegation still naming a provider that has dropped the
        zone. Bounded by the same per-referral cap as the ordinary glueless
        path, and by the shared budget.
        """
        if not ns_names:
            return []
        resolved = self._resolve_ns_names(ns_names, ctx, depth + 1, limit=self.limits.max_ns_per_referral)
        fresh = [address for address in resolved if address not in tried]
        if fresh:
            logger.debug("Falling back to %d freshly resolved nameserver address(es)", len(fresh))
        return fresh

    def _resolve_ns_names(self, ns_names: list[dns.name.Name], ctx: _Context, depth: int, limit: int) -> list[str]:
        """Resolve NS hostnames that had no usable glue.

        Bounded by ``limit`` names and by the shared NX-target budget: an
        attacker's NS names deliberately fail to resolve, and absorbing an
        unbounded number of those failures is the NXNSAttack amplification
        primitive.
        """
        # Both families, unless the caller asked for v4 only. A nameserver set
        # reachable only over IPv6 is otherwise unreachable however the
        # resolver is configured, because the hostname would only ever be
        # looked up for an A record.
        wanted = [dns.rdatatype.A] if self.ipv4_only else [dns.rdatatype.A, dns.rdatatype.AAAA]
        resolved: list[str] = []
        for ns_name in ns_names[:limit]:
            if ctx.budget.expired() or ctx.budget.remaining_queries() <= 0:
                break
            for rdtype in wanted:
                if ctx.budget.expired() or ctx.budget.remaining_queries() <= 0:
                    break
                try:
                    answer = self._resolve_iterative(ns_name, rdtype, ctx, depth, [])
                except QueryBudgetExceededError:
                    raise
                except ResolverError as exc:
                    logger.debug("Failed to resolve glueless NS %s/%s: %s", ns_name, dns.rdatatype.to_text(rdtype), exc)
                    ctx.budget.note_nx_target(str(ns_name), dns.rdatatype.to_text(rdtype))
                    continue
                resolved.extend(str(rr.address) for rr in answer.rrset)
        return self.address_filter.filter(resolved)

    # ── DNSSEC ──────────────────────────────────────────────────────────

    def _cached_keys(self, zone: dns.name.Name) -> ZoneKeys | None:
        with self._key_lock:
            keys = self._key_cache.get(zone)
            if keys is None:
                return None
            if keys.expiry and time.monotonic() >= keys.expiry:
                del self._key_cache[zone]
                return None
            self._key_cache.move_to_end(zone)
            return keys

    def _store_keys(self, keys: ZoneKeys, ttl: int) -> None:
        keys.expiry = time.monotonic() + max(60, min(ttl, 86400))
        with self._key_lock:
            # Bounded LRU: a long-running verifier sees a effectively unlimited
            # number of signed zones, and a DNSKEY RRset is not small.
            if keys.zone not in self._key_cache and len(self._key_cache) >= self._key_cache_size:
                self._key_cache.popitem(last=False)
            self._key_cache[keys.zone] = keys
            self._key_cache.move_to_end(keys.zone)

    def _usable_dnskey(self, zone: dns.name.Name) -> Callable[[dns.message.Message], bool]:
        """Did this server actually serve the zone's signed DNSKEY RRset?

        A lame server, or one authoritative only for the parent, answers
        ``NOERROR`` with an empty answer section and the delegation in
        AUTHORITY. That says nothing about the zone, so the sweep must go on to
        the siblings rather than treat it as the zone's final word.
        """

        def check(response: dns.message.Message) -> bool:
            if response.rcode() != dns.rcode.NOERROR:
                return False
            if self.require_authoritative and not response.flags & dns.flags.AA:
                return False
            if self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY) is None:
                return False
            # No RRSIG means no verdict is possible either: a middlebox that
            # strips the DO bit produces exactly this, and judging it BOGUS
            # would condemn the zone for someone else's fault.
            return find_rrsig(list(response.answer), zone, dns.rdatatype.DNSKEY) is not None

        return check

    def _usable_ds(self, zone: dns.name.Name) -> Callable[[dns.message.Message], bool]:
        """Did this server say anything about whether ``zone`` is delegated?

        What is rejected here is the response that says nothing: an error
        rcode, or an empty non-authoritative one, which is a server unable to
        answer the question rather than a statement about the delegation.

        Only two answers settle it: the DS itself, or a denial of it. Both are
        signed and re-checked by the validator, so neither needs the AA bit -
        a parent may legitimately answer a DS query with a referral, carrying
        the DS or the NSEC3 in AUTHORITY with AA clear, and several ccTLDs do.

        Anything else is rejected, and the SOA-only response is the one that
        matters. This is only ever asked of a parent whose own keys have
        already validated, and a signed zone denying a DS sends NSEC or NSEC3
        alongside the SOA; a server sending the SOA by itself cannot sign its
        denials, which is not the same as the zone saying the child is
        unsigned. Accepting it hands the validator half a proof and the whole
        delegation is called forged on the strength of one misconfigured
        server. Registries running a mixed NS set have both kinds in the same
        zone, so the verdict turned on which one the shuffle picked. Sweeping
        past them reaches a server that does answer, and if none does, "could
        not retrieve" is the honest verdict.
        """

        def check(response: dns.message.Message) -> bool:
            if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return False
            records = list(response.answer) + list(response.authority)
            if any(rrset.rdtype == dns.rdatatype.DS and rrset.name == zone for rrset in records):
                return True
            # A referral to a cut *above* the queried name says "ask further
            # down", and the denial it carries belongs to that higher cut, not
            # to this delegation. Taking it as an answer is how a server
            # authoritative only for the TLD gets to condemn a zone two labels
            # below it: the NSEC is genuine and signed, and proves nothing
            # about the name that was asked for.
            if any(
                rrset.rdtype == dns.rdatatype.NS and rrset.name != zone and zone.is_subdomain(rrset.name)
                for rrset in records
            ):
                return False
            return any(rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3) for rrset in records)

        return check

    def _get_zone_keys(self, zone: dns.name.Name, ds: Any, nameservers: list[str], ctx: _Context) -> ZoneKeys:
        """Fetch and validate a zone's DNSKEY RRset.

        Raises:
            DNSSECMaterialUnavailableError: if no nameserver supplied the
                DNSKEY. Being unable to *retrieve* validation material is a
                resolution failure, not evidence of tampering: reporting it as
                BOGUS would turn every lame or slow nameserver into an
                apparent attack.
        """
        assert self._validator is not None
        cached = self._cached_keys(zone)
        if cached is not None:
            return cached

        response, _server = self._send_query(
            zone, dns.rdatatype.DNSKEY, nameservers, ctx, usable=self._usable_dnskey(zone)
        )
        if response is None:
            raise DNSSECMaterialUnavailableError(str(zone), "DNSKEY")

        dnskey_rrset = self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY)
        if dnskey_rrset is None:  # pragma: no cover - the predicate rules this out
            raise DNSSECMaterialUnavailableError(str(zone), "DNSKEY")
        rrsig = find_rrsig(list(response.answer), zone, dns.rdatatype.DNSKEY)

        if zone == dns.name.root:
            root_ok = self._validator.validate_root_dnskey(dnskey_rrset, rrsig, budget=ctx.budget)
            state = ValidationState.SECURE if root_ok else ValidationState.BOGUS
        elif ds is None:
            state = ValidationState.BOGUS
        else:
            # May be INSECURE: a zone signed only with algorithms this build
            # cannot verify is unverifiable rather than forged.
            state = self._validator.validate_dnskey(zone, dnskey_rrset, rrsig, ds, budget=ctx.budget)

        secure = state is ValidationState.SECURE
        keys = ZoneKeys(zone, dnskey_rrset if secure else None, state)
        if secure:
            self._store_keys(keys, dnskey_rrset.ttl)
        return keys

    def _descend_chain(
        self,
        target: dns.name.Name,
        zone: dns.name.Name,
        ds: Any,
        nameservers: list[str],
        ctx: _Context,
    ) -> tuple[dns.name.Name, Any, ValidationState]:
        """Extend the chain of trust from ``zone`` down to ``target``.

        A nameserver that is authoritative for both a parent and a child zone
        answers straight from the child, so we never see the intermediate
        referral and our idea of the current zone lags behind the zone that
        actually signed the data. ``.cz`` serving ``nic.cz`` and Nominet
        serving both ``uk`` and ``co.uk`` are the common real-world cases.

        Here we walk the missing labels one at a time, asking the servers we
        are already talking to for each intermediate DS.

        Most of those labels are not delegation points. ``_dmarc.example.com``
        and ``3.200.in-addr.arpa`` hold no records of their own; they exist
        only because something below them does. A parent asked for their DS
        answers with a denial that matches no delegation, and reading that as
        a broken chain condemns every name underneath. Such a label is skipped
        instead: the zone in force does not change at a name that is not a cut.
        """
        assert self._validator is not None
        if target == zone or not target.is_subdomain(zone):
            return zone, ds, ValidationState.SECURE

        remaining = [
            dns.name.Name(target.labels[index:]) for index in range(len(target.labels) - len(zone.labels) - 1, -1, -1)
        ]
        for next_zone in remaining:
            keys = self._get_zone_keys(zone, ds, nameservers, ctx)
            if keys.state is ValidationState.INSECURE:
                return zone, None, ValidationState.INSECURE
            if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
                return zone, None, ValidationState.BOGUS

            response, _server = self._send_query(
                next_zone, dns.rdatatype.DS, nameservers, ctx, usable=self._usable_ds(next_zone)
            )
            if response is None:
                # Could not retrieve the DS: indeterminate, not tampered with.
                raise DNSSECMaterialUnavailableError(str(next_zone), "DS")

            records = list(response.answer) + list(response.authority)
            keyring = keys.as_keyring()
            state, next_ds = self._validator.validate_ds(next_zone, records, keyring, budget=ctx.budget)
            if state is ValidationState.BOGUS and self._validator.prove_no_delegation(
                next_zone, records, keyring, budget=ctx.budget
            ):
                # Not a cut: an empty non-terminal, or a name with records but
                # no NS. The zone in force is unchanged, so carry on down.
                continue
            if state is not ValidationState.SECURE:
                return next_zone, None, state
            zone, ds = next_zone, next_ds

        return zone, ds, ValidationState.SECURE

    def _align_zone(
        self,
        signer: dns.name.Name | None,
        zone: dns.name.Name,
        ds: Any,
        nameservers: list[str],
        ctx: _Context,
    ) -> tuple[dns.name.Name, Any, ValidationState]:
        """Move the chain forward to whichever zone actually signed the data."""
        if signer is None or signer == zone or not signer.is_subdomain(zone):
            return zone, ds, ValidationState.SECURE
        return self._descend_chain(signer, zone, ds, nameservers, ctx)

    def _insecurely_delegated(
        self,
        name: dns.name.Name,
        zone: dns.name.Name,
        ds: Any,
        nameservers: list[str],
        ctx: _Context,
    ) -> bool:
        """True if ``name`` lives under a delegation ``zone`` proves is unsigned.

        Unsigned data is not automatically bogus: a server authoritative for
        both a parent and a child answers straight from the child, and if that
        child has no DS the answer is insecure, not forged. Signed ccTLD
        subzones serving unsigned children this way are common, and every
        validating resolver we cross-checked calls the result insecure.

        Without an RRSIG there is no signer to align on, so the delegations
        between the zone we believe we are in and the name we got data for have
        to be walked explicitly. A stripped signature inside the zone itself
        still ends up bogus: proving no DS requires an NSEC bitmap with NS in
        it, which a non-delegation name does not have.
        """
        if name == zone or not name.is_subdomain(zone):
            return False
        _zone, _ds, state = self._descend_chain(name, zone, ds, nameservers, ctx)
        return state is ValidationState.INSECURE

    @staticmethod
    def _authority_signer(response: dns.message.Message) -> dns.name.Name | None:
        """The signer of the DS/NSEC/NSEC3 records in the authority section."""
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rr in rrset:
                if rr.type_covered in (dns.rdatatype.DS, dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                    signer: dns.name.Name = rr.signer
                    return signer
        return None

    def _advance_dnssec(
        self,
        response: dns.message.Message,
        child_zone: dns.name.Name,
        parent_zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        parent_ds: Any,
        ctx: _Context,
    ) -> tuple[ValidationState, Any]:
        """Establish the DNSSEC state of a child zone from its parent's referral."""
        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return ValidationState.INSECURE, None

        if not self._usable_ds(child_zone)(response):
            # A referral from a signed parent normally carries the DS, or the
            # NSEC/NSEC3 denying it, alongside the NS set. This one carries
            # neither, so the server has said nothing about whether the child
            # is signed. Reading that silence as forgery is how a single
            # server that omits the proof condemns a whole delegation, and
            # registries run mixed NS sets where only some of them do it.
            #
            # There is also nothing here to align on: no signature, so no
            # signer, so no way to tell that the answer came from a zone below
            # the one we thought we were querying - which is exactly what a
            # registry serving `com.<cc>` off its own TLD servers does. So walk
            # the delegations from the parent down to the child instead of
            # asking for one DS: that sweeps each NS set for each cut in turn,
            # and finds the intermediate zone a flat DS query cannot see.
            reached, chain_ds, chain_state = self._descend_chain(child_zone, parent_zone, parent_ds, nameservers, ctx)
            if chain_state is ValidationState.BOGUS:
                raise DNSSECValidationError(
                    str(child_zone), "DS", f"delegation from {reached} is neither signed nor provably unsigned"
                )
            if chain_state is ValidationState.INSECURE:
                return ValidationState.INSECURE, None
            return ValidationState.SECURE, chain_ds

        # The referral may have been answered from a zone below the one we
        # believe we are querying; catch up before validating the DS.
        signer = self._authority_signer(response)
        parent_zone, parent_ds, aligned = self._align_zone(signer, parent_zone, parent_ds, nameservers, ctx)
        if aligned is ValidationState.INSECURE:
            return ValidationState.INSECURE, None
        if aligned is ValidationState.BOGUS:
            raise DNSSECValidationError(str(child_zone), "DS", f"broken chain of trust at {parent_zone}")

        if child_zone == parent_zone:
            return ValidationState.SECURE, parent_ds

        parent_keys = self._get_zone_keys(parent_zone, parent_ds, nameservers, ctx)
        if parent_keys.state is ValidationState.INSECURE:
            return ValidationState.INSECURE, None
        if parent_keys.state is not ValidationState.SECURE or parent_keys.dnskey_rrset is None:
            raise DNSSECValidationError(str(child_zone), "DS", f"cannot establish DNSKEY for parent zone {parent_zone}")

        child_state, ds = self._validator.validate_ds(
            child_zone, list(response.authority), parent_keys.as_keyring(), budget=ctx.budget
        )
        if child_state is ValidationState.BOGUS:
            raise DNSSECValidationError(
                str(child_zone), "DS", f"delegation from {parent_zone} is neither signed nor provably unsigned"
            )
        return child_state, ds

    def _validate_answer(
        self,
        response: dns.message.Message,
        rrset: dns.rrset.RRset,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: Any,
        dname_rrset: dns.rrset.RRset | None = None,
    ) -> tuple[ValidationState, int]:
        """Validate an answer RRset, returning its DNSSEC state and cache TTL.

        The TTL comes back with the state because RFC 4035 §5.3.3 caps how long
        authenticated data may be held: no longer than the RRset's own TTL, the
        RRSIG's TTL, the RRSIG's Original TTL, or the time left before the
        signature expires. Without the last of those, a record signed with a
        short-lived RRSIG and a long TTL is served as authenticated long after
        the signature it rests on has expired.
        """
        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return ValidationState.INSECURE, rrset.ttl

        rrsig = find_rrsig(list(response.answer), rrset.name, rdtype)
        if rrsig is None:
            # A CNAME synthesized from a DNAME carries no signature of its own,
            # and must not (RFC 6672 §3.3): the DNAME's signature is what
            # authenticates the redirection, and the CNAME follows from it by
            # construction. So validate the DNAME and inherit its verdict.
            if rdtype == dns.rdatatype.CNAME and dname_rrset is not None:
                return self._validate_answer(
                    response, dname_rrset, qname, dns.rdatatype.DNAME, ctx, zone, nameservers, state, ds
                )
            if self._insecurely_delegated(rrset.name, zone, ds, nameservers, ctx):
                return ValidationState.INSECURE, rrset.ttl
            raise DNSSECValidationError(
                str(qname), dns.rdatatype.to_text(rdtype), "zone is signed but the answer carries no RRSIG"
            )

        # The signer tells us which zone really produced this data; a server
        # authoritative for both a parent and a child answers from the child
        # without ever emitting the intermediate referral.
        #
        # Only a zone that contains the owner name can have signed it (RFC 4035
        # §5.3.1). The signer here comes off the wire, so without that check an
        # attacker names a zone of their own and we walk the chain of trust
        # down to it and fetch its keys - work they can provoke with a single
        # spoofed packet, for a signature that cannot verify anyway.
        #
        # This is only a hint about which zone to go and fetch keys for. It is
        # never a security decision: whatever zone it picks, `validated_rrsig`
        # still requires a signature naming that zone as its signer and that
        # zone to contain the owner name, so a wrong hint costs a wasted fetch
        # and a BOGUS verdict, never a false SECURE.
        signer: dns.name.Name = rrsig[0].signer
        if rrset.name.is_subdomain(signer):
            zone, ds, aligned = self._align_zone(signer, zone, ds, nameservers, ctx)
        else:
            aligned = ValidationState.SECURE
        if aligned is ValidationState.INSECURE:
            return ValidationState.INSECURE, rrset.ttl
        if aligned is ValidationState.BOGUS:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"broken chain of trust at {zone}")

        keys = self._get_zone_keys(zone, ds, nameservers, ctx)
        if keys.state is ValidationState.INSECURE:
            # The zone is signed with algorithms we cannot verify, so we have
            # no more assurance about this answer than for an unsigned zone.
            return ValidationState.INSECURE, rrset.ttl
        if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"no valid DNSKEY for zone {zone}")

        keyring = keys.as_keyring()
        signature = self._validator.validated_rrsig(rrset, rrsig, keyring, budget=ctx.budget)
        if signature is None:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), "RRSIG did not verify")
        ttl = min(
            rrset.ttl,
            rrsig.ttl,
            int(signature.original_ttl),
            max(0, int(signature.expiration) - int(time.time())),
        )

        # A signature covering fewer labels than the owner name has means the
        # answer was synthesised from a wildcard. That signature verifies for
        # every name the wildcard could cover, so on its own it lets a replayed
        # wildcard record stand in for a name that has different real data.
        # RFC 4035 §5.3.4 requires a proof that no closer match exists.
        #
        # The Labels count is read from the signature that actually verified,
        # never from the first rdata in the RRSIG RRset. An RRSIG RRset can
        # carry several rdata in an order the attacker chooses, only one of
        # which verified; a decoy naming a larger Labels count would otherwise
        # make a wildcard expansion look like an ordinary answer and skip the
        # proof entirely.
        # A query for the wildcard name itself is answered by an exact match, not
        # by expansion (RFC 4592 §2.2.1), and comes with no denial records. Its
        # RRSIG always covers one label fewer than the owner has, so the test
        # below would read every such answer as an expansion and demand a proof
        # that cannot exist.
        if not rrset.name.is_wild() and signature.labels < len(rrset.name.labels) - 1:
            proven = self._validator.prove_wildcard(
                rrset.name, signature.labels, list(response.authority), keyring, budget=ctx.budget
            )
            if proven is ValidationState.INSECURE:
                # Only an opt-out NSEC3 denies the queried name, and opt-out
                # denies nothing about names that are not signed delegations.
                # The data is returned, unauthenticated, as every public
                # validating resolver returns it.
                return ValidationState.INSECURE, ttl
            if proven is not ValidationState.SECURE:
                if self._validator.nsec3_beyond_our_limits(list(response.authority), keyring, ctx.budget):
                    return ValidationState.INSECURE, ttl
                raise DNSSECValidationError(
                    str(qname),
                    dns.rdatatype.to_text(rdtype),
                    "wildcard-expanded answer without a proof that no closer match exists",
                )
        return ValidationState.SECURE, ttl

    def _verify_denial(
        self,
        response: dns.message.Message,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: Any,
        negative: str,
    ) -> tuple[ValidationState, int | None]:
        """Validate the denial-of-existence proof for a negative answer.

        Returns the state the *denial* was established in, so a caller running
        with ``require_dnssec`` can hold a "this does not exist" to the same
        standard as an answer. Being told a name has no CAA record, or no MX,
        on unauthenticated evidence is exactly the thing that mode exists to
        refuse.

        The second element caps how long the denial may be cached, or None when
        nothing constrains it. See :meth:`_denial_ttl_cap`.
        """
        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return ValidationState.INSECURE, None

        signer = self._authority_signer(response)
        zone, ds, aligned = self._align_zone(signer, zone, ds, nameservers, ctx)
        if aligned is ValidationState.INSECURE:
            return ValidationState.INSECURE, None
        if aligned is ValidationState.BOGUS:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"broken chain of trust at {zone}")

        # Nothing in the authority section is signed. As for a positive answer,
        # that is what an insecurely delegated child served by its own parent
        # looks like, so check the delegation before demanding a proof.
        if signer is None and self._insecurely_delegated(qname, zone, ds, nameservers, ctx):
            return ValidationState.INSECURE, None

        keys = self._get_zone_keys(zone, ds, nameservers, ctx)
        if keys.state is ValidationState.INSECURE:
            return ValidationState.INSECURE, None
        if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"no valid DNSKEY for zone {zone}")
        keyring = keys.as_keyring()
        authority = list(response.authority)
        if self._validator.nsec3_beyond_our_limits(authority, keyring, ctx.budget):
            return ValidationState.INSECURE, None
        proven = self._proven_denial(qname, rdtype, authority, keyring, ctx, negative)
        if proven is not ValidationState.BOGUS:
            return proven, self._denial_ttl_cap(authority)

        # This server's proof does not hold up. RFC 4035 §5.5: "If the
        # resolver has other servers to try, it SHOULD try one of them before
        # concluding the answer is Bogus." One server out of sync with the
        # rest of its NS set - serving an NSEC3 chain from before the last
        # re-signing, say - would otherwise make the zone intermittently
        # unresolvable, on the say-so of the one machine that is wrong.
        #
        # The sweep is expressed as a usability predicate, so `_send_query`
        # moves on until a server produces a denial that actually proves
        # something, and stops when the NS set or the budget runs out. Nothing
        # is relaxed: whatever comes back is validated the same way.
        fresh, _server = self._send_query(
            qname, rdtype, nameservers, ctx, usable=self._usable_denial(qname, rdtype, keyring, ctx, negative)
        )
        if fresh is not None:
            authority = list(fresh.authority)
            proven = self._proven_denial(qname, rdtype, authority, keyring, ctx, negative)
            if proven is not ValidationState.BOGUS:
                return proven, self._denial_ttl_cap(authority)
        raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"unproven {negative} in a signed zone")

    @staticmethod
    def _denial_ttl_cap(authority: list[dns.rrset.RRset]) -> int | None:
        """How long the records proving a denial stay authenticated, in seconds.

        RFC 4035 §5.3.3 caps authenticated data at its signature's original TTL
        and at the time left before that signature expires. A denial is
        authenticated data too: without this, a proof that expires in a minute
        is served as proven for as long as ``max_negative_ttl`` allows.

        The minimum is taken over every RRSIG in the authority section rather
        than the one that verified, which the prover does not report back. That
        can only shorten the lifetime, never extend it.
        """
        now = int(time.time())
        caps = [
            min(int(rrset.ttl), int(sig.original_ttl), max(0, int(sig.expiration) - now))
            for rrset in authority
            if rrset.rdtype == dns.rdatatype.RRSIG
            for sig in rrset
            if sig.type_covered in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3, dns.rdatatype.SOA)
        ]
        return min(caps) if caps else None

    def _proven_denial(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        authority: list[dns.rrset.RRset],
        keyring: dict[dns.name.Name, Any],
        ctx: _Context,
        negative: str,
    ) -> ValidationState:
        """How well this authority section proves the denial.

        BOGUS means nothing here proves it. INSECURE means the proof rests on
        an opt-out NSEC3, which says a range holds no signed delegations rather
        than no names: something inside it may exist, so the answer is returned
        without being authenticated.
        """
        assert self._validator is not None
        if negative == "nxdomain":
            return self._validator.prove_nxdomain(qname, authority, keyring, budget=ctx.budget)
        return self._validator.prove_nodata(qname, rdtype, authority, keyring, budget=ctx.budget)

    def _usable_denial(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        keyring: dict[dns.name.Name, Any],
        ctx: _Context,
        negative: str,
    ) -> Callable[[dns.message.Message], bool]:
        """Did this server send a denial that proves anything?

        Used to sweep past a server whose proof does not validate. The check is
        the real one, run against each candidate in turn, so a server only
        satisfies it by actually answering the question.
        """

        def check(response: dns.message.Message) -> bool:
            if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return False
            # The same bar `_classify_response` sets for a negative answer, so
            # the sweep cannot accept from a sibling what the ordinary path
            # would have refused.
            if self.require_authoritative and not response.flags & dns.flags.AA:
                return False
            state = self._proven_denial(qname, rdtype, list(response.authority), keyring, ctx, negative)
            return state is not ValidationState.BOGUS

        return check

    def _serves_an_unsigned_copy(
        self,
        response: dns.message.Message,
        kind: str,
        state: ValidationState,
        ctx: _Context,
    ) -> bool:
        """Did this server answer for a signed zone without a single signature?

        Same rule as :meth:`_usable_denial`, one level up. RFC 4035 §5.5: "If
        the resolver has other servers to try, it SHOULD try one of them before
        concluding the answer is Bogus." A server holding a stale *unsigned*
        copy of a zone its siblings serve signed answers authoritatively with
        no RRSIG anywhere, so every type it is asked for reads as forged and
        its NODATA proves nothing. Found in the wild on a signed ccTLD
        registry whose four nameservers included one such copy: landing on it
        made the whole zone intermittently bogus, on the say-so of the one
        machine that was wrong.

        The test is syntactic and costs no crypto: under a chain of trust that
        says the zone is signed, every positive answer and every denial carries
        a signature, so a response with none at all is evidence about the
        server rather than about the data. Nothing is relaxed - the sibling's
        answer is validated exactly as this one would have been, and a zone
        whose every server answers unsigned still ends BOGUS, because the
        caller runs out of servers and judges the last response it holds.

        Referrals are excluded: the delegation NS RRset is unsigned by design
        (RFC 4035 §2.2), and :meth:`_advance_dnssec` fetches the DS from the
        parent's own NS set rather than trusting what the referral carried.
        """
        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return False
        if kind not in ("answer", "cname", "nodata", "nxdomain"):
            return False
        return not any(
            rrset.rdtype == dns.rdatatype.RRSIG
            for section in (response.answer, response.authority)
            for rrset in section
        )

    def _negative_ttl(
        self, response: dns.message.Message, qname: dns.name.Name, current_zone: dns.name.Name
    ) -> int | None:
        """Derive the negative-caching TTL from the authority SOA (RFC 2308 §5)."""
        for rrset in response.authority:
            if self._marks_negative(rrset, qname, current_zone):
                soa = rrset[0]
                return int(min(rrset.ttl, soa.minimum))
        return None

    def _cacheable_negative_ttl(
        self,
        response: dns.message.Message,
        qname: dns.name.Name,
        current_zone: dns.name.Name,
        denial: ValidationState,
        proof_ttl: int | None,
    ) -> int | None:
        """The SOA-derived negative TTL, held to the proof's own lifetime.

        A proven denial must not outlive the signatures that proved it, or it
        goes on being served as authenticated after nothing vouches for it
        (RFC 4035 §5.3.3).
        """
        ttl = self._negative_ttl(response, qname, current_zone)
        if denial is not ValidationState.SECURE or proof_ttl is None:
            return ttl
        return proof_ttl if ttl is None else min(ttl, proof_ttl)

    # ── transport ───────────────────────────────────────────────────────

    def _order_servers(self, nameservers: list[str]) -> list[str]:
        servers = self.address_filter.filter(nameservers)
        _RANDOM.shuffle(servers)
        return servers

    def _effective_timeout(self, ctx: _Context) -> float:
        return min(self.timeout, ctx.budget.time_remaining())

    def _send_query(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        nameservers: list[str],
        ctx: _Context,
        usable: Callable[[dns.message.Message], bool] | None = None,
    ) -> tuple[dns.message.Message | None, str]:
        """Send a query to a set of nameservers, sweeping breadth-first.

        Every server is tried once before any is retried. Retrying one server
        three times before touching the next means a single dead nameserver
        costs ``max_retries + 1`` full timeouts while a healthy sibling sits
        unused: enough, at the default budget, to fail a resolution that would
        otherwise have succeeded immediately.

        Each successive sweep also degrades EDNS: full payload, then 512 bytes,
        then no EDNS at all - except while validating, where the last rung stays
        at 512 with DO set, because an answer with no OPT has no DO and is worth
        nothing to us. Without the payload step a path with a broken PMTU
        blackholes every large response identically and no amount of retrying
        recovers: the classic silent failure for large TXT answers. TCP
        fallback does not help there, because nothing arrives to carry the TC
        bit.

        Args:
            usable: Optional predicate deciding whether a response actually
                answers what was asked. A server that answers ``NOERROR`` with
                an empty answer section - a lame delegation, or a parent-side
                server returning a referral - is not evidence about the data,
                only about that server, so the sweep continues to its siblings
                and ``(None, "")`` is returned only once every server has been
                given a chance. Callers that validate use this so a single lame
                server cannot masquerade as missing DNSSEC material.
        """
        rdtype_text = dns.rdatatype.to_text(rdtype)
        servers = self._order_servers(nameservers)
        abandoned: set[str] = set()
        # Servers that answered in a way meaning "I do not speak EDNS".
        no_edns: set[str] = set()
        # Servers that answered, but not with what was asked for.
        unusable: set[str] = set()
        # An error response held back in case nothing better turns up.
        last_resort: tuple[dns.message.Message, str] | None = None

        for attempt in range(self.max_retries + 1):
            for server in servers:
                if server in abandoned or server in unusable:
                    continue

                timeout = self._effective_timeout(ctx)
                if timeout <= 0:
                    return None, ""
                payload = None if server in no_edns else self._payload_for_attempt(attempt, ctx.dnssec)

                ctx.budget.spend_query(str(qname), rdtype_text)
                try:
                    response = self._query_once(qname, rdtype, server, payload, timeout, ctx)
                except _RetryableError as exc:
                    logger.debug(
                        "No answer from %s for %s/%s (sweep %d): %s", server, qname, rdtype_text, attempt + 1, exc
                    )
                    continue
                except _FatalServerError as exc:
                    logger.debug("Abandoning %s for %s/%s: %s", server, qname, rdtype_text, exc)
                    abandoned.add(server)
                    continue
                except _MalformedResponseError as exc:
                    # A mangled response often means the server dislikes EDNS.
                    logger.debug("Malformed response from %s for %s/%s: %s", server, qname, rdtype_text, exc)
                    if payload is not None and not ctx.dnssec:
                        no_edns.add(server)
                    else:
                        # While validating there is no point retrying without
                        # EDNS: no OPT means no DO, so the answer comes back
                        # unsigned and unusable. See _payload_for_attempt.
                        abandoned.add(server)
                    continue

                rcode = response.rcode()
                if payload is not None and rcode in _EDNS_UNSUPPORTED_RCODES:
                    # FORMERR / NOTIMP / SERVFAIL / BADVERS are all emitted by
                    # servers and middleboxes that cannot cope with an OPT
                    # record. Retry this one without EDNS on the next sweep,
                    # unless we are validating, where a DO-less answer is worth
                    # nothing to us: keep the response instead, so a genuine
                    # SERVFAIL still reaches the caller as one.
                    logger.debug("rcode %s from %s, dropping EDNS for it", dns.rcode.to_text(rcode), server)
                    if ctx.dnssec:
                        abandoned.add(server)
                        if last_resort is None:
                            last_resort = (response, server)
                    else:
                        no_edns.add(server)
                    continue
                if usable is not None and not usable(response):
                    logger.debug("Unusable %s/%s response from %s, sweeping on", qname, rdtype_text, server)
                    unusable.add(server)
                    continue
                return response, server

            if len(abandoned) + len(unusable) == len(servers):
                break

        # Only for callers with no predicate: one that asked for specific
        # validation material wants "could not retrieve", not an error response.
        if usable is None and last_resort is not None:
            return last_resort
        return None, ""

    def _payload_for_attempt(self, attempt: int, dnssec: bool = False) -> int | None:
        """EDNS payload for a retry attempt; ``None`` means no EDNS at all."""
        if attempt <= 0:
            return self.edns_payload
        if attempt == 1:
            return min(512, self.edns_payload)
        # DNSSEC needs EDNS0 to carry the DO bit (RFC 4035 3.2.1). Dropping the
        # OPT record on the last sweep means the answer comes back with no
        # RRSIGs at all, which the validator can only read as BOGUS: a
        # self-inflicted validation failure against a perfectly good zone.
        return min(512, self.edns_payload) if dnssec else None

    def _query_once(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        server: str,
        payload: int | None,
        timeout: float,
        ctx: _Context,
    ) -> dns.message.Message:
        """Send one query, translating dnspython failures into internal signals."""
        try:
            if payload is None:
                query = dns.message.make_query(qname, rdtype, use_edns=False)
            else:
                want_dnssec = ctx.dnssec
                query = dns.message.make_query(qname, rdtype, use_edns=0, payload=payload, want_dnssec=want_dnssec)
            # RD=0: we iterate ourselves rather than asking the server to.
            query.flags &= ~dns.flags.RD
        except dns.exception.DNSException as exc:  # pragma: no cover - name is pre-validated
            raise _FatalServerError(f"cannot build query: {exc}") from exc

        # ignore_errors keeps listening when a datagram arrives that is not an
        # answer to this query, instead of giving up on the first one. The
        # acceptance test is unchanged - dnspython still requires the reply to
        # match the query - so nothing forged is let through; what changes is
        # that an off-path spoofer cannot retire a healthy nameserver by
        # racing in a single wrong-ID packet, which is the whole point of the
        # randomised ID and source port (RFC 5452 §9).
        try:
            if self.use_tcp_fallback:
                response, _used_tcp = dns.query.udp_with_fallback(query, server, timeout=timeout, ignore_errors=True)
            else:
                # raise_on_truncation is essential: without it a truncated
                # response is silently returned with a partial answer section.
                response = dns.query.udp(query, server, timeout=timeout, raise_on_truncation=True, ignore_errors=True)
        except dns.message.Truncated as exc:
            raise _RetryableError("truncated response and TCP fallback is disabled") from exc
        except dns.exception.Timeout as exc:
            raise _RetryableError(str(exc)) from exc
        except EOFError as exc:
            # dnspython raises this when a TCP peer closes mid-response.
            raise _RetryableError(f"connection closed: {exc}") from exc
        except OSError as exc:
            if exc.errno in _FATAL_ERRNOS:
                raise _FatalServerError(str(exc)) from exc
            raise _RetryableError(str(exc)) from exc
        except dns.query.UnexpectedSource as exc:
            # A stray or spoofed packet. Do not let it downgrade our EDNS or
            # permanently retire an otherwise healthy nameserver.
            raise _RetryableError(f"unexpected response source: {exc}") from exc
        except dns.exception.FormError as exc:
            raise _MalformedResponseError(str(exc)) from exc
        except dns.exception.DNSException as exc:
            raise _MalformedResponseError(str(exc)) from exc

        return response


class _RetryableError(Exception):
    """Internal: the query should be retried against the same server."""


class _FatalServerError(Exception):
    """Internal: this server is unusable; move on immediately."""


class _MalformedResponseError(Exception):
    """Internal: the response could not be parsed or did not match the query."""


_EDNS_UNSUPPORTED_RCODES = frozenset(
    {
        int(dns.rcode.FORMERR),
        int(dns.rcode.NOTIMP),
        int(dns.rcode.SERVFAIL),
        16,  # BADVERS / BADSIG: the EDNS extended rcode for "bad OPT version"
    }
)
