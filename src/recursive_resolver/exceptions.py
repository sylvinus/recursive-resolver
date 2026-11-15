"""Exception hierarchy for the recursive DNS resolver.

Every error raised out of :meth:`RecursiveResolver.resolve` is a
:class:`ResolverError`.  Nothing from dnspython is allowed to escape: input
validation errors, malformed-response errors and DNSSEC failures are all
translated into the classes below. Invalid constructor arguments are the one
exception: they raise :class:`ValueError`, before any resolution starts.
"""

from __future__ import annotations

from typing import Any

import dns.rcode


def _restore(cls: type[ResolverError], args: tuple[Any, ...], state: dict[str, Any]) -> ResolverError:
    """Rebuild a pickled :class:`ResolverError` without re-running ``__init__``."""
    error = cls.__new__(cls)
    error.args = args
    error.__dict__.update(state)
    return error


class ResolverError(Exception):
    """Base exception for all resolver errors.

    Attributes:
        qname: The name being resolved when the error occurred. This can be a
            CNAME target or a nameserver hostname rather than the name the
            caller asked for; that one is in ``query_name``.
        rdtype: The record type being resolved, likewise.
        query_name: The name passed to ``resolve()``, once the error has left it.
        query_type: The record type passed to ``resolve()``, likewise.
    """

    def __init__(self, message: str, qname: str | None = None, rdtype: str | None = None) -> None:
        self.qname = qname
        self.rdtype = rdtype
        self.query_name: str | None = None
        self.query_type: str | None = None
        super().__init__(message)

    def __reduce__(self) -> tuple[Any, ...]:
        # The subclasses build their message from several arguments while
        # `args` holds only the finished string, so the default reduction
        # calls `__init__` with the wrong arity. That breaks pickling, and
        # with it process pools and task queues.
        return (_restore, (type(self), self.args, self.__dict__))


class NXDOMAINError(ResolverError):
    """The queried domain name does not exist (NXDOMAIN rcode)."""

    def __init__(self, qname: str, rdtype: str | None = None) -> None:
        super().__init__(f"NXDOMAIN: {qname}", qname=qname, rdtype=rdtype)


class NoAnswerError(ResolverError):
    """The domain exists but has no records of the requested type (NODATA)."""

    def __init__(self, qname: str, rdtype: str) -> None:
        super().__init__(f"No {rdtype} records for {qname}", qname=qname, rdtype=rdtype)


class MaxDepthError(ResolverError):
    """Resolution exceeded the maximum delegation depth."""

    def __init__(self, qname: str, rdtype: str, max_depth: int) -> None:
        self.max_depth = max_depth
        super().__init__(
            f"Max depth {max_depth} exceeded resolving {qname}/{rdtype}",
            qname=qname,
            rdtype=rdtype,
        )


class ResolutionTimeoutError(ResolverError):
    """All nameservers timed out, or the overall deadline elapsed."""

    def __init__(self, qname: str, rdtype: str) -> None:
        super().__init__(f"All nameservers timed out for {qname}/{rdtype}", qname=qname, rdtype=rdtype)


class CNAMELoopError(ResolverError):
    """A loop was detected while following CNAME records."""

    def __init__(self, qname: str, chain: list[str]) -> None:
        self.chain = chain
        super().__init__(
            f"CNAME loop detected for {qname}: {' -> '.join(chain)}",
            qname=qname,
        )


class ServfailError(ResolverError):
    """No nameserver could answer: error responses, lame servers, or none reachable.

    The name follows the SERVFAIL a stub resolver would be handed. ``rcode`` is
    the last error rcode received, if any, and ``reason`` says what went wrong.
    """

    def __init__(self, qname: str, rdtype: str, rcode: int | None = None, reason: str | None = None) -> None:
        self.rcode = rcode
        if reason is None:
            reason = "error response from every nameserver"
        self.reason = reason
        msg = f"Server failure resolving {qname}/{rdtype}: {reason}"
        if rcode is not None:
            msg += f" (last rcode {dns.rcode.to_text(dns.rcode.Rcode.make(rcode))})"
        super().__init__(msg, qname=qname, rdtype=rdtype)


class InvalidNameError(ResolverError):
    """The query name is not a valid DNS name.

    Raised for oversized labels, oversized names, empty interior labels and
    names that cannot be IDNA-encoded. Previously these surfaced as spurious
    timeouts because they were raised while building the query.
    """

    def __init__(self, qname: str, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Invalid domain name {qname!r}: {reason}", qname=qname)


class UnsupportedRdtypeError(ResolverError):
    """The requested record type is unknown or not supported."""

    def __init__(self, rdtype: str, reason: str = "unknown record type") -> None:
        super().__init__(f"Unsupported record type {rdtype!r}: {reason}", rdtype=rdtype)


class QueryBudgetExceededError(ResolverError):
    """The resolution exceeded its work budget.

    Guards against amplification attacks (NXNSAttack / Non-Responsive
    Delegation) where a hostile zone provokes unbounded query fan-out.
    """

    def __init__(self, qname: str | None, rdtype: str | None, resource: str, limit: int) -> None:
        self.resource = resource
        self.limit = limit
        where = f" resolving {qname}/{rdtype}" if qname is not None else ""
        super().__init__(
            f"Query budget exceeded{where}: {resource} limit of {limit} reached",
            qname=qname,
            rdtype=rdtype,
        )


class DNSSECMaterialUnavailableError(ResolverError):
    """A DNSKEY or DS could not be retrieved, so no verdict can be reached.

    Deliberately **not** a :class:`DNSSECError`: nothing was validated and
    nothing failed to validate. One lame nameserver in a zone's NS set, or a
    SERVFAIL from every one of them, means the validation material never
    arrived; reporting that as bogus turns a transient server fault into an
    apparent attack. Consumers that treat :class:`DNSSECError` as "refuse to
    use this data" should let this one fall through to ordinary retry handling.
    """

    def __init__(self, qname: str, rdtype: str, reason: str = "no usable response from any nameserver") -> None:
        self.reason = reason
        super().__init__(
            f"Could not retrieve DNSSEC material {qname}/{rdtype}: {reason}",
            qname=qname,
            rdtype=rdtype,
        )


class DNSSECError(ResolverError):
    """Base class for DNSSEC validation problems."""


class DNSSECValidationError(DNSSECError):
    """DNSSEC validation failed: the data is bogus.

    The zone is signed but the signatures, the delegation chain or the
    denial-of-existence proof did not validate. Treat this as a possible
    attack: the data must not be used.
    """

    def __init__(self, qname: str, rdtype: str, reason: str) -> None:
        self.reason = reason
        super().__init__(f"DNSSEC validation failed for {qname}/{rdtype}: {reason}", qname=qname, rdtype=rdtype)


class DNSSECInsecureError(DNSSECError):
    """The answer is unsigned and ``require_dnssec=True`` was requested."""

    def __init__(self, qname: str, rdtype: str, reason: str = "zone is not signed") -> None:
        self.reason = reason
        super().__init__(
            f"DNSSEC-authenticated data required for {qname}/{rdtype} but {reason}",
            qname=qname,
            rdtype=rdtype,
        )


class DNSSECUnavailableError(ResolverError):
    """DNSSEC validation was requested but dnspython's DNSSEC support is off.

    dnspython enables it only with `cryptography` installed and recent enough.
    """

    def __init__(self) -> None:
        super().__init__(
            "DNSSEC validation requires the 'cryptography' package, version 50 or later. "
            "Install it with: pip install 'recursive-resolver[dnssec]' "
            "(or construct the resolver with dnssec=False)."
        )
