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
import random
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.reversename
import dns.rrset

from .addresses import AddressFilter
from .budget import Limits, QueryBudget
from .cache import Delegation, DNSCache
from .dnssec import DNSSECValidator, ValidationState, ZoneKeys, cryptography_available, find_rrsig
from .exceptions import (
    CNAMELoopError,
    DNSSECInsecureError,
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
        min_ttl: Floor applied to cached TTLs. 0 honours the wire TTL exactly.
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
            Defaults to the IANA anchors. Override only to validate against a
            private root, or in tests.

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
    ) -> None:
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_cname_chain = max_cname_chain
        self.use_tcp_fallback = use_tcp_fallback
        self.max_retries = max_retries
        self.ipv4_only = ipv4_only
        self.max_resolution_time = max_resolution_time
        self.limits = limits if limits is not None else Limits()
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
            self._validator = DNSSECValidator(trust_anchors=trust_anchors) if trust_anchors else DNSSECValidator()

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
        if dns.rdatatype.is_metatype(value) and value != dns.rdatatype.ANY:
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

    def _check_cache(self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType) -> Answer | None:
        """Consult the cache for a positive or negative entry."""
        if self.cache is None:
            return None

        nx = self.cache.get_nxdomain_ancestor(qname)
        if nx is not None:
            # RFC 8020: nothing exists below a non-existent name.
            raise NXDOMAINError(str(qname), dns.rdatatype.to_text(rdtype))

        if self.cache.get_nodata(qname, rdtype) is not None:
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
            ttl=entry.rrset.ttl,
            dnssec=ValidationState.SECURE if entry.secure else ValidationState.INSECURE,
        )

    def _starting_point(
        self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType
    ) -> tuple[dns.name.Name, list[str], ValidationState, Any]:
        """Pick where to begin: a cached delegation if we have one, else the root.

        A DS record is published by the *parent* zone, so a cached delegation
        for the qname itself would send the query to the child, which does not
        hold its own DS and correctly answers NODATA. Start one label up.
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
                        return dns.name.root, list(self._root_addresses), ValidationState.SECURE, None
                    return delegation.zone, addresses, state, delegation.ds
        return dns.name.root, list(self._root_addresses), ValidationState.SECURE, None

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

        current_zone, current_nameservers, chain_state, current_ds = self._starting_point(qname, rdtype)
        # `current_nameservers` is pruned as servers fail, but DNSSEC key
        # fetches must keep talking to the zone's full server set: otherwise a
        # single-nameserver signed zone returning NXDOMAIN leaves us with an
        # empty list and we report a DNSSEC failure of our own making.
        zone_nameservers = list(current_nameservers)
        pending_ns_names: list[dns.name.Name] = []
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
                self._verify_denial(
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
                    self.cache.put_nxdomain(qname, self._negative_ttl(response, qname))
                raise NXDOMAINError(str(qname), rdtype_text)

            if kind == "nodata":
                self._verify_denial(
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
                    self.cache.put_nodata(qname, rdtype, self._negative_ttl(response, qname))
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
        validated = self._validate_answer(response, rrset, qname, rdtype, ctx, zone, nameservers, state, ds)
        if self.cache is not None and self.cache_answers:
            self.cache.put_answer(qname, rdtype, rrset, rrset.ttl, secure=validated is ValidationState.SECURE)
        return Answer(
            qname=qname,
            canonical_name=qname,
            rdtype=rdtype,
            rrset=rrset,
            ttl=rrset.ttl,
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

        cname_state = self._validate_answer(
            response, cname_rrset, qname, dns.rdatatype.CNAME, ctx, zone, nameservers, state, ds
        )
        if self.cache is not None and self.cache_answers:
            self.cache.put_answer(
                qname,
                dns.rdatatype.CNAME,
                cname_rrset,
                cname_rrset.ttl,
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
            inline_state = self._validate_answer(response, inline, target, rdtype, ctx, zone, nameservers, state, ds)
            if self.cache is not None and self.cache_answers:
                self.cache.put_answer(target, rdtype, inline, inline.ttl, secure=inline_state is ValidationState.SECURE)
            return Answer(
                qname=qname,
                canonical_name=target,
                rdtype=rdtype,
                rrset=inline,
                ttl=inline.ttl,
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
            ttl=answer.ttl,
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
                    "ttl": cname_rrset.ttl,
                    "detail": f"-> {cname_rrset[0].target}",
                }

        if rcode == dns.rcode.NXDOMAIN:
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "NXDOMAIN without AA bit"}
            return {"type": "nxdomain"}

        # An SOA owning the qname or an ancestor marks a negative answer
        # (RFC 2308), which takes precedence over any NS records also present.
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.SOA and qname.is_subdomain(rrset.name):
                if self.require_authoritative and not authoritative:
                    return {"type": "error", "rcode": rcode, "detail": "NODATA without AA bit"}
                return {"type": "nodata"}

        referral = self._find_referral(response, qname, current_zone, rdtype)
        if referral is not None:
            return referral

        if self.require_authoritative and not authoritative:
            return {"type": "error", "rcode": rcode, "detail": "empty response without AA bit"}
        return {"type": "nodata"}

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
            ns_names = random.sample(ns_names, self.limits.max_ns_per_referral)
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
            if rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.AAAA and not self.ipv4_only:
                pass
            else:
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
        resolved: list[str] = []
        for ns_name in ns_names[:limit]:
            if ctx.budget.expired() or ctx.budget.remaining_queries() <= 0:
                break
            try:
                answer = self._resolve_iterative(ns_name, dns.rdatatype.A, ctx, depth, [])
            except QueryBudgetExceededError:
                raise
            except ResolverError as exc:
                logger.debug("Failed to resolve glueless NS %s: %s", ns_name, exc)
                ctx.budget.note_nx_target(str(ns_name), "A")
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

    def _get_zone_keys(self, zone: dns.name.Name, ds: Any, nameservers: list[str], ctx: _Context) -> ZoneKeys:
        """Fetch and validate a zone's DNSKEY RRset.

        Raises:
            ResolutionTimeoutError: if the DNSKEY could not be fetched at all.
                Being unable to *retrieve* validation material is a resolution
                failure, not evidence of tampering: reporting it as BOGUS
                would turn every slow nameserver into an apparent attack.
        """
        assert self._validator is not None
        cached = self._cached_keys(zone)
        if cached is not None:
            return cached

        response, _server = self._send_query(zone, dns.rdatatype.DNSKEY, nameservers, ctx)
        if response is None:
            raise ResolutionTimeoutError(str(zone), "DNSKEY")

        dnskey_rrset = self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY)
        if dnskey_rrset is None:
            return ZoneKeys(zone, None, ValidationState.BOGUS)
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
        """
        assert self._validator is not None
        if target == zone or not target.is_subdomain(zone):
            return zone, ds, ValidationState.SECURE

        while zone != target:
            index = len(target.labels) - len(zone.labels) - 1
            next_zone = dns.name.Name(target.labels[index:])

            keys = self._get_zone_keys(zone, ds, nameservers, ctx)
            if keys.state is ValidationState.INSECURE:
                return zone, None, ValidationState.INSECURE
            if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
                return zone, None, ValidationState.BOGUS

            response, _server = self._send_query(next_zone, dns.rdatatype.DS, nameservers, ctx)
            if response is None:
                # Could not retrieve the DS: indeterminate, not tampered with.
                raise ResolutionTimeoutError(str(next_zone), "DS")

            records = list(response.answer) + list(response.authority)
            state, next_ds = self._validator.validate_ds(next_zone, records, keys.as_keyring(), budget=ctx.budget)
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
    ) -> ValidationState:
        """Validate an answer RRset, returning its DNSSEC state."""
        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return ValidationState.INSECURE

        rrsig = find_rrsig(list(response.answer), rrset.name, rdtype)
        if rrsig is None:
            raise DNSSECValidationError(
                str(qname), dns.rdatatype.to_text(rdtype), "zone is signed but the answer carries no RRSIG"
            )

        # The signer tells us which zone really produced this data; a server
        # authoritative for both a parent and a child answers from the child
        # without ever emitting the intermediate referral.
        zone, ds, aligned = self._align_zone(rrsig[0].signer, zone, ds, nameservers, ctx)
        if aligned is ValidationState.INSECURE:
            return ValidationState.INSECURE
        if aligned is ValidationState.BOGUS:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"broken chain of trust at {zone}")

        keys = self._get_zone_keys(zone, ds, nameservers, ctx)
        if keys.state is ValidationState.INSECURE:
            # The zone is signed with algorithms we cannot verify, so we have
            # no more assurance about this answer than for an unsigned zone.
            return ValidationState.INSECURE
        if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"no valid DNSKEY for zone {zone}")

        keyring = keys.as_keyring()
        if not self._validator.validate_rrset(rrset, rrsig, keyring, budget=ctx.budget):
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), "RRSIG did not verify")

        # A signature covering fewer labels than the owner name has means the
        # answer was synthesised from a wildcard. That signature verifies for
        # every name the wildcard could cover, so on its own it lets a replayed
        # wildcard record stand in for a name that has different real data.
        # RFC 4035 §5.3.4 requires a proof that no closer match exists.
        if rrsig[0].labels < len(rrset.name.labels) - 1:
            proven = self._validator.prove_wildcard(
                rrset.name, rrsig[0].labels, list(response.authority), keyring, budget=ctx.budget
            )
            if not proven:
                raise DNSSECValidationError(
                    str(qname),
                    dns.rdatatype.to_text(rdtype),
                    "wildcard-expanded answer without a proof that no closer match exists",
                )
        return ValidationState.SECURE

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
    ) -> None:
        """Validate the denial-of-existence proof for a negative answer."""
        if not ctx.dnssec or self._validator is None or state is not ValidationState.SECURE:
            return

        signer = self._authority_signer(response)
        zone, ds, aligned = self._align_zone(signer, zone, ds, nameservers, ctx)
        if aligned is ValidationState.INSECURE:
            return
        if aligned is ValidationState.BOGUS:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"broken chain of trust at {zone}")

        keys = self._get_zone_keys(zone, ds, nameservers, ctx)
        if keys.state is ValidationState.INSECURE:
            return
        if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
            raise DNSSECValidationError(str(qname), dns.rdatatype.to_text(rdtype), f"no valid DNSKEY for zone {zone}")
        keyring = keys.as_keyring()
        authority = list(response.authority)
        if negative == "nxdomain":
            proven = self._validator.prove_nxdomain(qname, authority, keyring, budget=ctx.budget)
        else:
            proven = self._validator.prove_nodata(qname, rdtype, authority, keyring, budget=ctx.budget)
        if not proven:
            raise DNSSECValidationError(
                str(qname), dns.rdatatype.to_text(rdtype), f"unproven {negative} in a signed zone"
            )

    @staticmethod
    def _negative_ttl(response: dns.message.Message, qname: dns.name.Name) -> int | None:
        """Derive the negative-caching TTL from the authority SOA (RFC 2308 §5)."""
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.SOA and qname.is_subdomain(rrset.name):
                soa = rrset[0]
                return int(min(rrset.ttl, soa.minimum))
        return None

    # ── transport ───────────────────────────────────────────────────────

    def _order_servers(self, nameservers: list[str]) -> list[str]:
        servers = self.address_filter.filter(nameservers)
        random.shuffle(servers)
        return servers

    def _effective_timeout(self, ctx: _Context) -> float:
        return min(self.timeout, ctx.budget.time_remaining())

    def _send_query(
        self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType, nameservers: list[str], ctx: _Context
    ) -> tuple[dns.message.Message | None, str]:
        """Send a query to a set of nameservers, sweeping breadth-first.

        Every server is tried once before any is retried. Retrying one server
        three times before touching the next means a single dead nameserver
        costs ``max_retries + 1`` full timeouts while a healthy sibling sits
        unused: enough, at the default budget, to fail a resolution that would
        otherwise have succeeded immediately.

        Each successive sweep also degrades EDNS: full payload, then 512 bytes,
        then no EDNS at all. Without the payload step a path with a broken PMTU
        blackholes every large response identically and no amount of retrying
        recovers: the classic silent failure for large TXT answers. TCP
        fallback does not help there, because nothing arrives to carry the TC
        bit.
        """
        rdtype_text = dns.rdatatype.to_text(rdtype)
        servers = self._order_servers(nameservers)
        abandoned: set[str] = set()
        # Servers that answered in a way meaning "I do not speak EDNS".
        no_edns: set[str] = set()

        for attempt in range(self.max_retries + 1):
            for server in servers:
                if server in abandoned:
                    continue

                timeout = self._effective_timeout(ctx)
                if timeout <= 0:
                    return None, ""
                payload = None if server in no_edns else self._payload_for_attempt(attempt)

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
                    if payload is not None:
                        no_edns.add(server)
                    else:
                        abandoned.add(server)
                    continue

                rcode = response.rcode()
                if payload is not None and rcode in _EDNS_UNSUPPORTED_RCODES:
                    # FORMERR / NOTIMP / SERVFAIL / BADVERS are all emitted by
                    # servers and middleboxes that cannot cope with an OPT
                    # record. Retry this one without EDNS on the next sweep.
                    logger.debug("rcode %s from %s, dropping EDNS for it", dns.rcode.to_text(rcode), server)
                    no_edns.add(server)
                    continue
                return response, server

            if len(abandoned) == len(servers):
                break

        return None, ""

    def _payload_for_attempt(self, attempt: int) -> int | None:
        """EDNS payload for a retry attempt; ``None`` means no EDNS at all."""
        if attempt <= 0:
            return self.edns_payload
        if attempt == 1:
            return min(512, self.edns_payload)
        return None

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

        try:
            if self.use_tcp_fallback:
                response, _used_tcp = dns.query.udp_with_fallback(query, server, timeout=timeout)
            else:
                # raise_on_truncation is essential: without it a truncated
                # response is silently returned with a partial answer section.
                response = dns.query.udp(query, server, timeout=timeout, raise_on_truncation=True)
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
