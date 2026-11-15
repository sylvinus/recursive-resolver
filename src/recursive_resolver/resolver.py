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
from typing import Any, Literal, TypedDict

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.reversename
import dns.rrset

from .addresses import AddressFilter
from .budget import Limits, QueryBudget
from .cache import Delegation, DNSCache
from .dnssec import (
    CLOCK_SKEW,
    DNSSECValidator,
    Keyring,
    ValidationState,
    ZoneKeys,
    _trim_keyring,
    authenticated_ttl,
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
from .singleflight import SingleFlight, clone_error

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

# The subset raised by the local stack before anything is sent, and which hold
# for every address of the family: no route at all, no IPv6 configured. One is
# enough to stop trying that family for the rest of the resolution.
_FAMILY_ERRNOS = frozenset({errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL})

# How many NS hostnames of a glueless delegation are resolved before the zone
# is queried. Resolving every one up front, in both address families, spent
# most of the query budget before the question was even asked; two keeps a
# spare server for the DNSSEC key fetches, and the rest are resolved only if
# those fail.
_NS_NAMES_AHEAD = 2

# Retries of a sibling after an NXDOMAIN, and after an answer with no
# signature at all in a signed zone, before the response is believed.
_NXDOMAIN_RETRIES = 1
_UNSIGNED_COPY_RETRIES = 1

# The address family each address record type belongs to.
_FAMILY_OF = {dns.rdatatype.A: 4, dns.rdatatype.AAAA: 6}


def _family(address: str) -> int:
    return 6 if ":" in address else 4


# Post-DNS-Flag-Day-2020 consensus UDP payload size. Unbound, PowerDNS and
# Knot all default to 1232; 4096 invites IP fragmentation, which is both a
# cache-poisoning vector and a common cause of silent blackholing.
DEFAULT_EDNS_PAYLOAD = 1232

# Ceiling on validated zone keys held across resolutions. A backstop against a
# resolver being walked through millions of signed zones, not a tuning knob:
# an entry is a few hundred bytes, and 2048 zones is far past any real working
# set.
MAX_KEY_CACHE_SIZE = 2048


ResponseKind = Literal["answer", "cname", "referral", "nxdomain", "nodata", "error"]


@dataclass
class TraceStep:
    """A single step in the resolution trace.

    ``dnssec`` is the state of the chain of trust when the query was sent, then
    replaced by the verdict on the response once one is reached: a response
    that fails validation shows ``bogus`` here.
    """

    server: str
    qname: str
    rdtype: str
    response_type: str  # one of ResponseKind
    detail: str = ""
    rcode: int = 0
    zone: str = ""
    dnssec: str = ""


class Trace(list[TraceStep]):
    """The steps of a traced resolution, and the error it ended with, if any."""

    error: ResolverError | None = None


class _Classification(TypedDict, total=False):
    """What a response is, as decided by `_classify_response`."""

    type: ResponseKind
    detail: str
    rcode: int
    ttl: int
    rrset: dns.rrset.RRset
    target: dns.name.Name
    cname_rrset: dns.rrset.RRset
    dname_rrset: dns.rrset.RRset | None
    zone: dns.name.Name
    ns_names: list[dns.name.Name]


@dataclass
class Answer:
    """A resolved DNS answer, with the raw records preserved.

    ``records`` gives presentation-format strings for convenience, but anything
    that must round-trip exactly should use :attr:`rrset` or
    :meth:`text_values`.

    ``cname_chain`` lists the names that were redirected, in order: for
    ``a -> b -> c`` it is ``[a, b]`` and ``canonical_name`` is ``c``.
    """

    qname: dns.name.Name
    canonical_name: dns.name.Name
    rdtype: dns.rdatatype.RdataType
    rrset: dns.rrset.RRset
    ttl: int
    dnssec: ValidationState
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
    # Addresses found for each (NS hostname, address type), or None when the
    # lookup failed, so neither is paid for twice.
    ns_addresses: dict[tuple[dns.name.Name, int], list[str] | None] = field(default_factory=dict)
    # Address families the local stack cannot send to at all.
    unreachable_families: set[int] = field(default_factory=set)
    # (zone, server) pairs that answered that zone with an error rcode.
    failed_servers: set[tuple[dns.name.Name, str]] = field(default_factory=set)
    # DS lookups made while walking a chain of trust, by (zone, child).
    chain_steps: dict[tuple[dns.name.Name, dns.name.Name], tuple[ValidationState, Any, bool]] = field(
        default_factory=dict
    )
    # Set by `_send_query` when it gave up without a single server being
    # reachable, as opposed to servers that did not answer in time.
    unreachable: bool = False
    # Set by `_send_query`: the servers that answered its last query with an
    # error rcode it held back rather than returned.
    answered_with_error: set[str] = field(default_factory=set)
    # Servers that showed they cannot do EDNS; see `_send_query`.
    no_edns: set[str] = field(default_factory=set)
    # True while the walk queries a zone whose chain of trust is not secure,
    # where nothing will be validated and plain DNS is an acceptable fallback.
    chain_insecure: bool = False


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
            legitimately unsigned zones resolve normally. With validation off,
            answers report :attr:`ValidationState.DISABLED`.
        require_dnssec: Additionally reject unsigned (insecure) answers.
        require_authoritative: Only accept answers, CNAME and DNAME
            redirections, and negative responses that have the AA bit set.
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

    Every argument is keyword-only. Out-of-range values raise ``ValueError``.

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
        *,
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
        if not timeout > 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        if not max_resolution_time > 0:
            raise ValueError(f"max_resolution_time must be positive, got {max_resolution_time}")
        if max_depth < 1:
            raise ValueError(f"max_depth must be at least 1, got {max_depth}")
        if max_cname_chain < 0 or max_retries < 0 or clock_skew < 0:
            raise ValueError("max_cname_chain, max_retries and clock_skew must not be negative")
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
    def _default_idna_codec() -> dns.name.IDNACodec:
        """IDNA 2008 if available, else IDNA 2003 with a warning.

        IDNA 2003 maps German ``ß`` to ``ss``, so ``straße.de`` would be
        resolved as the entirely different domain ``strasse.de``. Browsers and
        mail systems use IDNA 2008/UTS-46, so we must too. It needs the `idna`
        package, which the `idna` extra of dnspython pulls in.
        """
        if dns.name.have_idna_2008:
            return dns.name.IDNA_2008_Practical
        logger.warning(
            "IDNA 2008 unavailable (install the 'idna' package); falling back to IDNA 2003, "
            "which resolves some internationalised names to different domains."
        )
        return dns.name.IDNA_2003

    # ── public API ──────────────────────────────────────────────────────

    def resolve(self, qname: str | dns.name.Name, rdtype: str | int = "A") -> list[str]:
        """Resolve a DNS query iteratively from root servers.

        Args:
            qname: The domain name to query (or an IP address for PTR lookups),
                as text or as a :class:`dns.name.Name`.
            rdtype: The record type, as text ("A", "MX", "TXT") or as a
                :class:`dns.rdatatype.RdataType`.

        Returns:
            Presentation-format strings for the answer records. For TXT-like
            records that must round-trip exactly, prefer
            :meth:`resolve_answer` and ``Answer.text_values()``.

        Raises:
            ResolverError: any resolution failure; see the exceptions module.
        """
        return self.resolve_answer(qname, rdtype).records

    def resolve_rrset(self, qname: str | dns.name.Name, rdtype: str | int = "A") -> dns.rrset.RRset:
        """Resolve and return the raw dnspython RRset, preserving rdata structure."""
        return self.resolve_answer(qname, rdtype).rrset

    def resolve_answer(self, qname: str | dns.name.Name, rdtype: str | int = "A") -> Answer:
        """Resolve and return the full :class:`Answer`, including DNSSEC status.

        The :class:`Answer` is the caller's own: concurrent callers collapsed
        into one upstream resolution each get a separate copy, so nothing they
        do to it can be seen by another thread or by the cache.
        """
        rdtype_int = self._parse_rdtype(rdtype)
        name = self._normalize_qname(qname, rdtype_int)
        key = (name, rdtype_int)
        # The deadline starts now, not when the work starts: a caller left
        # waiting on a slow identical call and then running its own would
        # otherwise get two full allowances.
        deadline = time.monotonic() + self.max_resolution_time

        def work() -> Answer:
            return self._resolve_entry(name, rdtype_int, self._new_context(deadline=deadline))

        answer = self._singleflight.do(key, work, wait_timeout=self.max_resolution_time)
        return replace(answer, rrset=answer.rrset.copy(), cname_chain=list(answer.cname_chain))

    def trace_answer(self, qname: str | dns.name.Name, rdtype: str | int = "A") -> tuple[Answer | None, Trace]:
        """Resolve, returning both the answer and the trace.

        The answer is ``None`` if resolution failed; the trace is still
        returned so the failure can be diagnosed, and its ``error`` attribute
        holds the exception.
        """
        rdtype_int = self._parse_rdtype(rdtype)
        name = self._normalize_qname(qname, rdtype_int)
        trace = Trace()
        ctx = self._new_context(trace=trace)
        try:
            answer = self._resolve_entry(name, rdtype_int, ctx)
        except ResolverError as exc:
            trace.error = exc
            return None, trace
        return answer, trace

    # ── input handling ──────────────────────────────────────────────────

    def _new_context(self, trace: list[TraceStep] | None = None, deadline: float | None = None) -> _Context:
        if deadline is None:
            deadline = time.monotonic() + self.max_resolution_time
        return _Context(budget=self.limits.budget(deadline=deadline), trace=trace, dnssec=self.dnssec)

    def _parse_rdtype(self, rdtype: str | int) -> dns.rdatatype.RdataType:
        """Validate and convert a record type, raising UnsupportedRdtypeError."""
        if isinstance(rdtype, int) and not isinstance(rdtype, bool):
            try:
                value = dns.rdatatype.RdataType.make(rdtype)
            except ValueError as exc:
                raise UnsupportedRdtypeError(str(rdtype), "record type out of range") from exc
            return self._check_queryable(value, str(rdtype))
        if not isinstance(rdtype, str):
            raise UnsupportedRdtypeError(repr(rdtype), "record type must be a string or an RdataType")
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
        return self._check_queryable(value, rdtype)

    def _check_queryable(self, value: dns.rdatatype.RdataType, rdtype: str) -> dns.rdatatype.RdataType:
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
        if value == dns.rdatatype.RRSIG and self.dnssec:
            # An RRSIG RRset has no RRSIG of its own to validate it with, so in
            # a signed zone every answer would come back BOGUS.
            raise UnsupportedRdtypeError(rdtype, "RRSIG cannot be validated; query the covered type instead")
        return value

    def _normalize_qname(self, qname: str | dns.name.Name, rdtype: int) -> dns.name.Name:
        """Validate the query name, IDNA-encoding it and handling PTR reversal."""
        if isinstance(qname, dns.name.Name):
            return qname if qname.is_absolute() else qname.concatenate(dns.name.root)
        if not isinstance(qname, str) or not qname.strip():
            raise InvalidNameError(str(qname), "empty name")
        qname = qname.strip()
        if qname == "@":
            # Zone-file shorthand for the origin, which dnspython reads as the
            # root. Nobody passing it means the root.
            raise InvalidNameError(qname, "'@' is zone-file shorthand, not a domain name")

        if rdtype == dns.rdatatype.PTR:
            try:
                addr = ipaddress.ip_address(qname)
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
        try:
            answer = self._resolve_iterative(qname, rdtype, ctx, depth=0, cname_chain=[])
            if self.require_dnssec and answer.dnssec is not ValidationState.SECURE:
                raise DNSSECInsecureError(str(qname), dns.rdatatype.to_text(rdtype))
        except ResolverError as exc:
            exc.query_name = str(qname)
            exc.query_type = dns.rdatatype.to_text(rdtype)
            raise
        if not ctx.dnssec:
            return replace(answer, dnssec=ValidationState.DISABLED)
        return answer

    # Failures worth remembering for a few seconds (RFC 9520): the servers did
    # answer, or provably could not, and asking again at once would get the
    # same. Running out of time or budget says nothing about the name.
    _CACHEABLE_FAILURES = (ServfailError, DNSSECValidationError, DNSSECMaterialUnavailableError)

    def _cached_failure(self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType) -> None:
        if self.cache is None:
            return
        error = self.cache.get_failure(qname, rdtype)
        if error is not None:
            logger.debug("Recent failure for %s/%s is cached: %s", qname, dns.rdatatype.to_text(rdtype), error)
            raise clone_error(error)

    def _remember_failure(self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType, error: ResolverError) -> None:
        if self.cache is not None and isinstance(error, self._CACHEABLE_FAILURES):
            # A copy: the original carries on up the stack and is annotated
            # on the way.
            self.cache.put_failure(qname, rdtype, clone_error(error))

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

    def _cached_cname(
        self, qname: dns.name.Name, rdtype: dns.rdatatype.RdataType
    ) -> tuple[dns.name.Name, int, ValidationState] | None:
        """A cached CNAME at ``qname``, as (target, remaining TTL, state)."""
        if self.cache is None or not self.cache_answers or rdtype == dns.rdatatype.CNAME:
            return None
        entry = self.cache.get_answer(qname, dns.rdatatype.CNAME, record_stats=False)
        if entry is None or entry.rrset is None:
            return None
        state = ValidationState.SECURE if entry.secure else ValidationState.INSECURE
        return entry.rrset[0].target, max(0, int(entry.expiry - time.monotonic())), state

    def _resolve_iterative(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
    ) -> Answer:
        """Resolve one name: from the cache if possible, else by walking down to it."""
        rdtype_text = dns.rdatatype.to_text(rdtype)
        if depth > self.max_depth:
            raise MaxDepthError(str(qname), rdtype_text, self.max_depth)
        if ctx.budget.expired():
            raise ResolutionTimeoutError(str(qname), rdtype_text)

        cached = self._check_cache(qname, rdtype)
        if cached is not None:
            return cached
        self._cached_failure(qname, rdtype)
        cname = self._cached_cname(qname, rdtype)
        if cname is not None:
            target, ttl, state = cname
            logger.debug("Following cached CNAME %s -> %s for %s", qname, target, rdtype_text)
            return self._follow_cname(qname, target, rdtype, ctx, depth, cname_chain, state, ttl)

        try:
            return self._walk(qname, rdtype, ctx, depth, cname_chain)
        except ResolverError as exc:
            self._remember_failure(qname, rdtype, exc)
            raise

    def _walk(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
    ) -> Answer:
        """Core iterative resolution loop."""
        rdtype_text = dns.rdatatype.to_text(rdtype)
        current_zone, current_nameservers, chain_state, current_ds, cached_ns_names = self._starting_point(
            qname, rdtype
        )
        # `current_nameservers` is pruned as servers fail, but DNSSEC key
        # fetches must keep talking to the zone's full server set: otherwise a
        # single-nameserver signed zone returning NXDOMAIN leaves us with an
        # empty list and we report a DNSSEC failure of our own making.
        zone_nameservers = list(current_nameservers)
        # Seeded from the cached delegation so a dead address set still has its
        # hostnames to fall back on. Names inside the zone they serve are left
        # out here and below: they can only be reached through glue, and
        # resolving one sends the walk back through the very delegation that
        # is failing, again and again until the budget runs out.
        pending_ns_names = [n for n in cached_ns_names if not n.is_subdomain(current_zone)]
        tried_addresses: set[str] = set()
        nxdomain_retries_left = _NXDOMAIN_RETRIES
        unsigned_retries_left = _UNSIGNED_COPY_RETRIES
        referrals = 0

        # Every pass sends at least one query or ends the walk, so the query
        # budget bounds this loop; this bound is only a backstop.
        for _ in range(self.max_depth + self.limits.max_queries):
            if ctx.budget.expired():
                raise ResolutionTimeoutError(str(qname), rdtype_text)

            # A server that already refused this zone will refuse it again.
            live = [ns for ns in current_nameservers if (current_zone, ns) not in ctx.failed_servers]
            if current_nameservers and not live:
                fallback = self._fallback_nameservers(pending_ns_names, tried_addresses, ctx, depth)
                if fallback:
                    current_nameservers = fallback
                    zone_nameservers.extend(a for a in fallback if a not in zone_nameservers)
                    continue
                raise ServfailError(
                    str(qname), rdtype_text, reason=f"every nameserver for {current_zone} refused the query"
                )
            current_nameservers = live

            tried_addresses.update(current_nameservers)
            # Plain DNS is a usable last rung only where nothing is validated.
            ctx.chain_insecure = chain_state is not ValidationState.SECURE
            try:
                response, server = self._send_query(qname, rdtype, current_nameservers, ctx)
            finally:
                ctx.chain_insecure = False
            if response is None:
                fallback = self._fallback_nameservers(pending_ns_names, tried_addresses, ctx, depth)
                if fallback:
                    current_nameservers = fallback
                    zone_nameservers.extend(a for a in fallback if a not in zone_nameservers)
                    continue
                if ctx.unreachable and not ctx.budget.expired():
                    raise ServfailError(
                        str(qname), rdtype_text, reason=f"no nameserver for {current_zone} is reachable from here"
                    )
                raise ResolutionTimeoutError(str(qname), rdtype_text)

            classification = self._classify_response(response, qname, rdtype, current_zone)
            kind = classification["type"]
            step = self._record_trace(
                ctx, server, qname, rdtype_text, classification, response, current_zone, chain_state
            )

            if unsigned_retries_left > 0 and self._serves_an_unsigned_copy(response, kind, chain_state, ctx):
                siblings = [ns for ns in current_nameservers if ns != server]
                if siblings:
                    # One sibling is asked, not all of them: if it answers
                    # unsigned too, this is the zone and not one stale copy of
                    # it, and the response is judged on what it holds.
                    unsigned_retries_left -= 1
                    logger.debug(
                        "Unsigned %s for %s/%s from %s in signed zone %s, trying a sibling",
                        kind,
                        qname,
                        rdtype_text,
                        server,
                        current_zone,
                    )
                    current_nameservers = siblings
                    continue

            if kind == "referral":
                referrals += 1
                if referrals > self.max_depth:
                    raise MaxDepthError(str(qname), rdtype_text, self.max_depth)
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
                pending_ns_names = [n for n in ns_names if not n.is_subdomain(child_zone)]
                glue = self._select_glue(response, ns_names, current_zone, child_zone)
                if not glue:
                    glue = self._resolve_ns_names(pending_ns_names, ctx, depth + 1)
                if not glue:
                    # Resolving the NS names returns nothing both when they do
                    # not resolve and when the budget ran out underneath. Only
                    # the first is a server failure.
                    if ctx.budget.expired():
                        raise ResolutionTimeoutError(str(qname), rdtype_text)
                    raise ServfailError(
                        str(qname), rdtype_text, reason=f"no usable address for any nameserver of {child_zone}"
                    )
                self._cache_delegation(child_zone, ns_names, glue, response, chain_state, current_ds)
                current_zone = child_zone
                current_nameservers = glue
                zone_nameservers = list(glue)
                nxdomain_retries_left = _NXDOMAIN_RETRIES
                unsigned_retries_left = _UNSIGNED_COPY_RETRIES
                continue

            if kind == "nxdomain":
                siblings = [ns for ns in current_nameservers if ns != server]
                if siblings and nxdomain_retries_left > 0:
                    nxdomain_retries_left -= 1
                    logger.debug("NXDOMAIN from %s for %s/%s, asking a sibling", server, qname, rdtype_text)
                    current_nameservers = siblings
                    continue

            if kind == "error":
                # Drop this server, and any other that answered this query with
                # an error on the way: the sweep has already asked them.
                failed = {server, *ctx.answered_with_error}
                if response.rcode() in (dns.rcode.REFUSED, dns.rcode.NOTAUTH):
                    ctx.failed_servers.update((current_zone, ns) for ns in failed)
                current_nameservers = [ns for ns in current_nameservers if ns not in failed]
                if current_nameservers:
                    continue
                # Every address we have refuses or errors. A stale delegation
                # naming a provider that no longer serves the zone looks exactly
                # like this, so resolve the referral's other NS names before
                # giving up: one of them is usually the live one.
                fallback = self._fallback_nameservers(pending_ns_names, tried_addresses, ctx, depth)
                if fallback:
                    current_nameservers = fallback
                    zone_nameservers.extend(a for a in fallback if a not in zone_nameservers)
                    continue
                raise ServfailError(
                    str(qname),
                    rdtype_text,
                    rcode=response.rcode(),
                    reason=f"every nameserver for {current_zone} failed ({classification.get('detail', 'error')})",
                )

            try:
                return self._conclude(
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
                    step,
                )
            except DNSSECValidationError:
                self._mark_step(step, ValidationState.BOGUS)
                raise

        raise ServfailError(str(qname), rdtype_text, reason="resolution made no progress")  # pragma: no cover

    def _conclude(
        self,
        response: dns.message.Message,
        classification: _Classification,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: dns.rdataset.Rdataset | None,
        step: TraceStep | None,
    ) -> Answer:
        """Turn a final response into an answer, or into the denial it is."""
        rdtype_text = dns.rdatatype.to_text(rdtype)
        kind = classification["type"]
        if kind == "answer":
            answer = self._handle_answer(response, classification, qname, rdtype, ctx, zone, nameservers, state, ds)
            self._mark_step(step, answer.dnssec)
            return answer
        if kind == "cname":
            return self._handle_cname(
                response, classification, qname, rdtype, ctx, depth, cname_chain, zone, nameservers, state, ds
            )

        negative: Literal["nxdomain", "nodata"] = "nxdomain" if kind == "nxdomain" else "nodata"
        denial, proof_ttl = self._verify_denial(
            response, qname, rdtype, ctx, zone, nameservers, state, ds, negative=negative
        )
        self._mark_step(step, denial)
        ttl = self._cacheable_negative_ttl(response, qname, zone, denial, proof_ttl)
        # RFC 2308 §5: a negative answer with no SOA carries no TTL to cache it
        # for, and SHOULD NOT be cached.
        if self.cache is not None and ttl is not None:
            if negative == "nxdomain":
                self.cache.put_nxdomain(qname, ttl, secure=denial is ValidationState.SECURE)
            else:
                self.cache.put_nodata(qname, rdtype, ttl, secure=denial is ValidationState.SECURE)
        self._require_proven_denial(denial, qname, rdtype_text)
        if negative == "nxdomain":
            raise NXDOMAINError(str(qname), rdtype_text)
        raise NoAnswerError(str(qname), rdtype_text)

    def _record_trace(
        self,
        ctx: _Context,
        server: str,
        qname: dns.name.Name,
        rdtype_text: str,
        classification: _Classification,
        response: dns.message.Message,
        zone: dns.name.Name,
        state: ValidationState,
    ) -> TraceStep | None:
        if ctx.trace is None:
            return None
        step = TraceStep(
            server=server,
            qname=str(qname),
            rdtype=rdtype_text,
            response_type=classification["type"],
            detail=classification.get("detail", ""),
            rcode=response.rcode(),
            zone=str(zone),
            dnssec=state.value if ctx.dnssec else ValidationState.DISABLED.value,
        )
        ctx.trace.append(step)
        return step

    @staticmethod
    def _mark_step(step: TraceStep | None, state: ValidationState) -> None:
        """Record on a trace step the verdict its response ended up with."""
        if step is not None and step.dnssec != ValidationState.DISABLED.value:
            step.dnssec = state.value

    def _handle_answer(
        self,
        response: dns.message.Message,
        classification: _Classification,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: dns.rdataset.Rdataset | None,
    ) -> Answer:
        rrset: dns.rrset.RRset = classification["rrset"]
        validated, ttl = self._validate_answer(
            response, rrset, qname, rdtype, ctx, zone, nameservers, state, ds, classification.get("dname_rrset")
        )
        if self.cache is not None and self.cache_answers:
            self.cache.put_answer(qname, rdtype, rrset, ttl, secure=validated is ValidationState.SECURE)
        return Answer(
            qname=qname,
            canonical_name=qname,
            rdtype=rdtype,
            rrset=rrset,
            ttl=ttl,
            dnssec=validated,
        )

    def _check_cname_chain(self, qname: dns.name.Name, target: dns.name.Name, cname_chain: list[dns.name.Name]) -> None:
        if target in cname_chain or target == qname or len(cname_chain) >= self.max_cname_chain:
            raise CNAMELoopError(str(qname), [str(n) for n in cname_chain + [target]])

    def _follow_cname(
        self,
        qname: dns.name.Name,
        target: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
        cname_state: ValidationState,
        cname_ttl: int,
    ) -> Answer:
        """Resolve a CNAME's target and present the result as the answer for ``qname``."""
        self._check_cname_chain(qname, target, cname_chain)
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
            cname_chain=[qname, *answer.cname_chain],
        )

    def _handle_cname(
        self,
        response: dns.message.Message,
        classification: _Classification,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        ctx: _Context,
        depth: int,
        cname_chain: list[dns.name.Name],
        zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        ds: dns.rdataset.Rdataset | None,
    ) -> Answer:
        rdtype_text = dns.rdatatype.to_text(rdtype)
        target: dns.name.Name = classification["target"]
        cname_rrset: dns.rrset.RRset = classification["cname_rrset"]
        self._check_cname_chain(qname, target, cname_chain)

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
                cname_chain=[qname],
            )

        logger.debug("Following CNAME %s -> %s for %s", qname, target, rdtype_text)
        return self._follow_cname(qname, target, rdtype, ctx, depth, cname_chain, cname_state, cname_ttl)

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
    ) -> _Classification:
        """Classify a response into answer, cname, referral, nxdomain, nodata or error."""
        rcode = response.rcode()
        authoritative = bool(response.flags & dns.flags.AA)

        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return {"type": "error", "rcode": rcode, "detail": dns.rcode.to_text(rcode)}

        # A DNAME rewrites everything below its owner, and nothing can exist
        # below it (RFC 6672 §2.3), so it decides the response before anything
        # else does. The CNAME it implies is synthesised here from the DNAME
        # itself (§3.4: "Recursive caching name servers MUST perform CNAME
        # synthesis on behalf of clients"), and whatever CNAME the server sent
        # alongside is ignored. It is unsigned by design, so taking its target
        # instead would let anyone add an unsigned CNAME pointing anywhere next
        # to a genuine signed DNAME and have the redirection validate.
        dname_rrset = self._find_dname(response, qname, current_zone)
        if dname_rrset is not None:
            if self.require_authoritative and not authoritative:
                return {"type": "error", "rcode": rcode, "detail": "DNAME without AA bit"}
            target = self._dname_target(qname, dname_rrset)
            if target is None:
                return {"type": "error", "rcode": rcode, "detail": "DNAME substitution is longer than a name can be"}
            synthesized = self._synthesize_cname(qname, target, dname_rrset)
            if rdtype == dns.rdatatype.CNAME:
                return {"type": "answer", "rrset": synthesized, "ttl": synthesized.ttl, "dname_rrset": dname_rrset}
            return {
                "type": "cname",
                "target": target,
                "cname_rrset": synthesized,
                "dname_rrset": dname_rrset,
                "ttl": dname_rrset.ttl,
                "detail": f"DNAME {dname_rrset.name} -> {target}",
            }

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
                if self.require_authoritative and not authoritative:
                    return {"type": "error", "rcode": rcode, "detail": "CNAME without AA bit"}
                return {
                    "type": "cname",
                    "target": cname_rrset[0].target,
                    "cname_rrset": cname_rrset,
                    "dname_rrset": None,
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
        rrset.add(dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, target))
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
    ) -> _Classification | None:
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
            # DEBUG, not WARNING: the zone chooses its glue, so a hostile one
            # could otherwise write a log line per referral.
            rejected = set(addresses) - set(allowed)
            logger.debug("Rejected non-public glue addresses for zone %s: %s", child_zone, sorted(rejected))
        return allowed

    def _cache_delegation(
        self,
        zone: dns.name.Name,
        ns_names: list[dns.name.Name],
        addresses: list[str],
        response: dns.message.Message,
        state: ValidationState,
        ds: dns.rdataset.Rdataset | None = None,
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
        # The DNSSEC verdict cached with the cut must not outlive what proved
        # it: the DS's signature for a signed child, the denial's for an
        # unsigned one (RFC 4035 §5.3.3).
        if ds is not None:
            ttl = min(ttl, int(ds.ttl))
        elif state is ValidationState.INSECURE:
            proof_ttl = self._denial_ttl_cap(list(response.authority))
            if proof_ttl is not None:
                ttl = min(ttl, proof_ttl)
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
        fresh = self._resolve_ns_names(ns_names, ctx, depth + 1, tried=tried)
        if fresh:
            logger.debug("Falling back to %d freshly resolved nameserver address(es)", len(fresh))
        return fresh

    def _resolve_ns_names(
        self, ns_names: list[dns.name.Name], ctx: _Context, depth: int, tried: set[str] | None = None
    ) -> list[str]:
        """Resolve NS hostnames that had no usable glue, a few at a time.

        Names are taken in random order until `_NS_NAMES_AHEAD` of them have
        produced addresses not in ``tried``. The others are left for
        `_fallback_nameservers`, should those fail, and every lookup is
        remembered for the rest of the resolution, so a name is never paid for
        twice. AAAA is asked for only when IPv6 is enabled and the name had no
        usable A record.

        Bounded by ``max_ns_per_referral`` names and by the shared NX-target
        budget: an attacker's NS names deliberately fail to resolve, and
        absorbing an unbounded number of those failures is the NXNSAttack
        amplification primitive.
        """
        seen = set(tried or ())
        wanted = [dns.rdatatype.A] if self.ipv4_only else [dns.rdatatype.A, dns.rdatatype.AAAA]
        candidates = list(ns_names[: self.limits.max_ns_per_referral])
        _RANDOM.shuffle(candidates)
        fresh: list[str] = []
        productive = 0
        for ns_name in candidates:
            found = False
            for rdtype in wanted:
                if _FAMILY_OF[rdtype] in ctx.unreachable_families:
                    continue
                if ctx.budget.expired() or ctx.budget.remaining_queries() <= 0:
                    return fresh
                new = [a for a in self._ns_addresses(ns_name, rdtype, ctx, depth) if a not in seen]
                if new:
                    seen.update(new)
                    fresh.extend(new)
                    found = True
                    break
            if found:
                productive += 1
                if productive >= _NS_NAMES_AHEAD:
                    break
        return fresh

    def _ns_addresses(
        self, ns_name: dns.name.Name, rdtype: dns.rdatatype.RdataType, ctx: _Context, depth: int
    ) -> list[str]:
        """The usable addresses of one NS hostname, looked up at most once per resolution."""
        key = (ns_name, int(rdtype))
        if key in ctx.ns_addresses:
            return ctx.ns_addresses[key] or []
        rdtype_text = dns.rdatatype.to_text(rdtype)
        try:
            answer = self._resolve_iterative(ns_name, rdtype, ctx, depth, [])
        except QueryBudgetExceededError:
            raise
        except ResolverError as exc:
            logger.debug("Failed to resolve glueless NS %s/%s: %s", ns_name, rdtype_text, exc)
            ctx.ns_addresses[key] = None
            # A name with no AAAA is not a failed target: most nameservers
            # have none, and counting them would end the resolution after five.
            if not (rdtype == dns.rdatatype.AAAA and isinstance(exc, NoAnswerError)):
                ctx.budget.note_nx_target(str(ns_name), rdtype_text)
            return []
        addresses = self.address_filter.filter([str(rr.address) for rr in answer.rrset])
        ctx.ns_addresses[key] = addresses
        return addresses

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
        """Cache validated keys for ``ttl`` seconds, which must already be capped by their signature."""
        if ttl <= 0:
            return
        keys.expiry = time.monotonic() + min(ttl, 86400)
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

    @staticmethod
    def _noting_rejects(
        usable: Callable[[dns.message.Message], bool], rejected: list[dns.message.Message] | None
    ) -> Callable[[dns.message.Message], bool]:
        """``usable``, also collecting the responses it turns down into ``rejected``."""
        if rejected is None:
            return usable

        def check(response: dns.message.Message) -> bool:
            if usable(response):
                return True
            rejected.append(response)
            return False

        return check

    def _get_zone_keys(
        self,
        zone: dns.name.Name,
        ds: dns.rdataset.Rdataset | None,
        nameservers: list[str],
        ctx: _Context,
        rejected: list[dns.message.Message] | None = None,
    ) -> ZoneKeys:
        """Fetch and validate a zone's DNSKEY RRset.

        Responses that do not carry it are appended to ``rejected``, if given.

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
            zone,
            dns.rdatatype.DNSKEY,
            nameservers,
            ctx,
            usable=self._noting_rejects(self._usable_dnskey(zone), rejected),
        )
        if response is None:
            raise DNSSECMaterialUnavailableError(str(zone), "DNSKEY")

        dnskey_rrset = self._find_answer_rrset(response, zone, dns.rdatatype.DNSKEY)
        if dnskey_rrset is None:  # pragma: no cover - the predicate rules this out
            raise DNSSECMaterialUnavailableError(str(zone), "DNSKEY")
        rrsig = find_rrsig(list(response.answer), zone, dns.rdatatype.DNSKEY)

        signature = None
        if zone == dns.name.root:
            state, signature = self._validator.check_root_dnskey(dnskey_rrset, rrsig, budget=ctx.budget)
        elif ds is None:
            state = ValidationState.BOGUS
        else:
            # May be INSECURE: a zone signed only with algorithms this build
            # cannot verify is unverifiable rather than forged.
            state, signature = self._validator.check_dnskey(zone, dnskey_rrset, rrsig, ds, budget=ctx.budget)

        if state is not ValidationState.SECURE:
            return ZoneKeys(zone, None, state)
        # Kept trimmed (revoked keys out, colliding tags capped), which is what
        # every validation against them would compute anyway.
        keys = ZoneKeys(zone, _trim_keyring({zone: dnskey_rrset})[zone], state)
        # Like any authenticated data, the keys are good for no longer than
        # the signature over them (RFC 4035 §5.3.3). Holding them for the wire
        # TTL instead would ignore a rollover or an emergency revocation for
        # up to a day.
        if rrsig is not None and signature is not None:
            self._store_keys(keys, authenticated_ttl(dnskey_rrset, rrsig, signature))
        return keys

    def _descend_chain(
        self,
        target: dns.name.Name,
        zone: dns.name.Name,
        ds: dns.rdataset.Rdataset | None,
        nameservers: list[str],
        ctx: _Context,
    ) -> tuple[dns.name.Name, dns.rdataset.Rdataset | None, ValidationState]:
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

        The servers may also serve the target and not the zones in between: the
        root servers serve ``root-servers.net`` but not ``net``. Asked about
        ``net`` they refer us to its servers, and that referral is followed:
        from then on the walk asks them.

        Each DS lookup is remembered for the rest of the resolution, so a walk
        that several answers need is paid for once.
        """
        assert self._validator is not None
        if target == zone or not target.is_subdomain(zone):
            return zone, ds, ValidationState.SECURE

        remaining = [
            dns.name.Name(target.labels[index:]) for index in range(len(target.labels) - len(zone.labels) - 1, -1, -1)
        ]
        servers = nameservers
        # The zone `servers` are known to serve, which their glue is judged by.
        bailiwick = zone
        for next_zone in remaining:
            rejected: list[dns.message.Message] = []
            try:
                keys = self._get_zone_keys(zone, ds, servers, ctx, rejected)
            except DNSSECMaterialUnavailableError:
                servers = self._referred_servers(rejected, zone, bailiwick)
                if not servers:
                    raise
                bailiwick = zone
                keys = self._get_zone_keys(zone, ds, servers, ctx)
            if keys.state is ValidationState.INSECURE:
                return zone, None, ValidationState.INSECURE
            if keys.state is not ValidationState.SECURE or keys.dnskey_rrset is None:
                return zone, None, ValidationState.BOGUS

            step = ctx.chain_steps.get((zone, next_zone))
            if step is None:
                rejected = []
                try:
                    step = self._chain_step(next_zone, keys, servers, ctx, rejected)
                except DNSSECMaterialUnavailableError:
                    # The keys came from the cache, so the servers were never
                    # asked about `zone` itself until now.
                    servers = self._referred_servers(rejected, zone, bailiwick)
                    if not servers:
                        raise
                    bailiwick = zone
                    step = self._chain_step(next_zone, keys, servers, ctx)
                ctx.chain_steps[(zone, next_zone)] = step
            state, next_ds, is_cut = step
            if not is_cut:
                # Not a cut: an empty non-terminal, or a name with records but
                # no NS. The zone in force is unchanged, so carry on down.
                continue
            if state is not ValidationState.SECURE:
                return next_zone, None, state
            zone, ds = next_zone, next_ds

        return zone, ds, ValidationState.SECURE

    def _chain_step(
        self,
        next_zone: dns.name.Name,
        keys: ZoneKeys,
        nameservers: list[str],
        ctx: _Context,
        rejected: list[dns.message.Message] | None = None,
    ) -> tuple[ValidationState, dns.rdataset.Rdataset | None, bool]:
        """Ask for the DS of ``next_zone``: (state, DS, whether it is a zone cut at all).

        Responses that do not settle it are appended to ``rejected``, if given.
        """
        assert self._validator is not None
        response, _server = self._send_query(
            next_zone,
            dns.rdatatype.DS,
            nameservers,
            ctx,
            usable=self._noting_rejects(self._usable_ds(next_zone), rejected),
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
            return state, None, False
        return state, next_ds, True

    def _referred_servers(
        self, rejected: list[dns.message.Message], zone: dns.name.Name, bailiwick: dns.name.Name
    ) -> list[str]:
        """The glue of the first referral to ``zone`` among ``rejected``, from servers for ``bailiwick``.

        Glue only, so a validation never sets off a lookup of NS names. What
        those servers send is still checked against the keys above them.
        """
        for response in rejected:
            if response.rcode() != dns.rcode.NOERROR:
                continue
            referral = self._find_referral(response, zone, bailiwick, dns.rdatatype.DNSKEY)
            if referral is None or referral["zone"] != zone:
                continue
            glue = self._select_glue(response, referral["ns_names"], bailiwick, zone)
            if glue:
                logger.debug("Following the referral to %s for its DNSSEC material", zone)
                return glue
        return []

    def _align_zone(
        self,
        signer: dns.name.Name | None,
        zone: dns.name.Name,
        ds: dns.rdataset.Rdataset | None,
        nameservers: list[str],
        ctx: _Context,
    ) -> tuple[dns.name.Name, dns.rdataset.Rdataset | None, ValidationState]:
        """Move the chain forward to whichever zone actually signed the data.

        ``signer`` must contain the name being judged; `_authority_signer`
        only returns one that does.
        """
        if signer is None or signer == zone or not signer.is_subdomain(zone):
            return zone, ds, ValidationState.SECURE
        return self._descend_chain(signer, zone, ds, nameservers, ctx)

    def _insecurely_delegated(
        self,
        name: dns.name.Name,
        zone: dns.name.Name,
        ds: dns.rdataset.Rdataset | None,
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
    def _authority_signer(response: dns.message.Message, name: dns.name.Name) -> dns.name.Name | None:
        """The signer of the DS/NSEC/NSEC3 records in the authority section.

        Only a signer containing ``name``, the name the records are judged
        for, counts. The field comes off the wire unverified and the chain of
        trust is walked down to it, so a signer outside ``name`` would let an
        attacker point the walk at any unsigned delegation in the zone and
        have the proof of *that* zone's missing DS applied to ``name``: a
        signed zone downgraded to insecure with one spoofed packet.
        """
        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rr in rrset:
                if rr.type_covered not in (dns.rdatatype.DS, dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                    continue
                signer: dns.name.Name = rr.signer
                if name.is_subdomain(signer):
                    return signer
        return None

    def _advance_dnssec(
        self,
        response: dns.message.Message,
        child_zone: dns.name.Name,
        parent_zone: dns.name.Name,
        nameservers: list[str],
        state: ValidationState,
        parent_ds: dns.rdataset.Rdataset | None,
        ctx: _Context,
    ) -> tuple[ValidationState, dns.rdataset.Rdataset | None]:
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
        signer = self._authority_signer(response, child_zone)
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
        ds: dns.rdataset.Rdataset | None,
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

        if rdtype == dns.rdatatype.CNAME and dname_rrset is not None:
            # A CNAME synthesized from a DNAME carries no signature of its own,
            # and must not (RFC 6672 §3.3): the DNAME's signature is what
            # authenticates the redirection, and the CNAME was built from it
            # by `_classify_response`. So validate the DNAME and inherit its
            # verdict.
            return self._validate_answer(
                response, dname_rrset, qname, dns.rdatatype.DNAME, ctx, zone, nameservers, state, ds
            )

        rrsig = find_rrsig(list(response.answer), rrset.name, rdtype)
        if rrsig is None and rdtype == dns.rdatatype.DS:
            # A parent answering in referral form carries the DS, and the
            # RRSIG over it, in AUTHORITY.
            rrsig = find_rrsig(list(response.authority), rrset.name, rdtype)
        if rrsig is None:
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
        # This is only a hint about which zone to go and fetch keys for. A
        # wrong one cannot produce a false SECURE: `validated_rrsig` still
        # requires a signature naming that zone as its signer and that zone to
        # contain the owner name. Nor a false INSECURE: the walk only ever
        # covers delegations between the zone in force and the owner name, so
        # an unsigned cut it finds really is above the data.
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
        ttl = authenticated_ttl(rrset, rrsig, signature)

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
        ds: dns.rdataset.Rdataset | None,
        negative: Literal["nxdomain", "nodata"],
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

        signer = self._authority_signer(response, qname)
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
        keyring: Keyring,
        ctx: _Context,
        negative: Literal["nxdomain", "nodata"],
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
        keyring: Keyring,
        ctx: _Context,
        negative: Literal["nxdomain", "nodata"],
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
        whose servers answer unsigned still ends BOGUS: the caller asks one
        sibling, then judges the response it holds.

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
        (RFC 4035 §5.3.3). None when the response has no SOA, and so nothing
        to cache it for.
        """
        ttl = self._negative_ttl(response, qname, current_zone)
        if ttl is None or denial is not ValidationState.SECURE or proof_ttl is None:
            return ttl
        return min(ttl, proof_ttl)

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
        nothing to us. "Validating" means a zone whose chain of trust is
        secure: below an unsigned delegation nothing is checked, and a server
        that cannot do EDNS is still worth asking in plain DNS.

        Without the payload step a path with a broken PMTU
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
        validating = ctx.dnssec and not ctx.chain_insecure
        servers = self._order_servers(nameservers)
        abandoned: set[str] = set()
        # Servers that could not be reached at all, as opposed to ones that
        # answered badly or not in time.
        unreachable: set[str] = set()
        # Servers that answered in a way meaning "I do not speak EDNS". Kept for
        # the whole resolution: rediscovering it on every query cost each such
        # server two queries per pass, quadratic over a zone whose servers all
        # fail. Never used while validating, where plain DNS is no answer.
        no_edns = ctx.no_edns
        # Servers that answered, but not with what was asked for.
        unusable: set[str] = set()
        # An error response held back in case nothing better turns up.
        last_resort: tuple[dns.message.Message, str] | None = None
        ctx.answered_with_error = set()
        ctx.unreachable = False

        for attempt in range(self.max_retries + 1):
            for server in servers:
                if server in abandoned or server in unusable:
                    continue
                if _family(server) in ctx.unreachable_families:
                    abandoned.add(server)
                    unreachable.add(server)
                    continue

                timeout = self._effective_timeout(ctx)
                if timeout <= 0:
                    return None, ""
                if server in no_edns and not validating:
                    payload = None
                else:
                    payload = self._payload_for_attempt(attempt, validating)

                logger.debug("Querying %s for %s/%s (EDNS payload %s)", server, qname, rdtype_text, payload)
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
                    if exc.errno in _FATAL_ERRNOS:
                        unreachable.add(server)
                    if exc.errno in _FAMILY_ERRNOS:
                        # Nothing was sent, so nothing is charged, and no other
                        # address of this family is tried for the rest of the
                        # resolution: on a host without IPv6 every AAAA-derived
                        # server would otherwise cost a query each.
                        ctx.budget.refund_query()
                        ctx.unreachable_families.add(_family(server))
                    continue
                except _MalformedResponseError as exc:
                    # A mangled response often means the server dislikes EDNS.
                    logger.debug("Malformed response from %s for %s/%s: %s", server, qname, rdtype_text, exc)
                    if payload is not None and not validating:
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
                    if validating:
                        abandoned.add(server)
                        ctx.answered_with_error.add(server)
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

        ctx.unreachable = len(unreachable) == len(servers)
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

        # ignore_errors and ignore_unexpected keep listening when a datagram
        # arrives that is not an answer to this query - a wrong ID, a mangled
        # packet, or one from an address we did not send to - instead of
        # giving up on the first one. The acceptance test is unchanged:
        # dnspython still requires the reply to come from the server and match
        # the query, so nothing forged is let through. What changes is that
        # nobody can retire a healthy nameserver by racing in a single junk
        # packet, which takes no spoofing at all when it comes from a third
        # address and needs only our ephemeral port. Randomised IDs and ports
        # exist to make that race unwinnable (RFC 5452 §9).
        try:
            try:
                # raise_on_truncation is essential: without it a truncated
                # response is silently returned with a partial answer section.
                response = dns.query.udp(
                    query,
                    server,
                    timeout=timeout,
                    raise_on_truncation=True,
                    ignore_errors=True,
                    ignore_unexpected=True,
                )
            except dns.message.Truncated as exc:
                if not self.use_tcp_fallback:
                    raise _RetryableError("truncated response and TCP fallback is disabled") from exc
                # What is left of the whole call's deadline, not a fresh
                # allowance as udp_with_fallback would give.
                remaining = self._effective_timeout(ctx)
                if remaining <= 0:
                    raise _RetryableError("no time left to retry over TCP") from exc
                response = dns.query.tcp(query, server, timeout=remaining)
                if response.flags & dns.flags.TC:
                    # TCP has no size limit to truncate at, so this is a broken
                    # server, and the partial answer must not be used.
                    raise _FatalServerError("truncated response over TCP") from exc
        except dns.exception.Timeout as exc:
            raise _RetryableError(str(exc)) from exc
        except EOFError as exc:
            # dnspython raises this when a TCP peer closes mid-response.
            raise _RetryableError(f"connection closed: {exc}") from exc
        except OSError as exc:
            if exc.errno in _FATAL_ERRNOS:
                raise _FatalServerError(str(exc), errno=exc.errno) from exc
            raise _RetryableError(str(exc)) from exc
        except dns.exception.FormError as exc:
            raise _MalformedResponseError(str(exc)) from exc
        except dns.exception.DNSException as exc:
            raise _MalformedResponseError(str(exc)) from exc

        return response


class _RetryableError(Exception):
    """Internal: the query should be retried against the same server."""


class _FatalServerError(Exception):
    """Internal: this server is unusable; move on immediately."""

    def __init__(self, message: str, errno: int | None = None) -> None:
        super().__init__(message)
        self.errno = errno


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
