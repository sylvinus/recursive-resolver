"""Exception hierarchy for the recursive DNS resolver.

Every error raised out of :meth:`RecursiveResolver.resolve` is a
:class:`ResolverError`.  Nothing from dnspython is allowed to escape: input
validation errors, malformed-response errors and DNSSEC failures are all
translated into the classes below.
"""

from __future__ import annotations


class ResolverError(Exception):
    """Base exception for all resolver errors."""

    def __init__(self, message: str, qname: str | None = None, rdtype: str | None = None) -> None:
        self.qname = qname
        self.rdtype = rdtype
        super().__init__(message)


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
    """All nameservers returned SERVFAIL or other error responses."""

    def __init__(self, qname: str, rdtype: str, rcode: int | None = None) -> None:
        self.rcode = rcode
        msg = f"SERVFAIL resolving {qname}/{rdtype}"
        if rcode is not None:
            msg += f" (rcode={rcode})"
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

    def __init__(self, qname: str, rdtype: str, resource: str, limit: int) -> None:
        self.resource = resource
        self.limit = limit
        super().__init__(
            f"Query budget exceeded resolving {qname}/{rdtype}: {resource} limit of {limit} reached",
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
    """DNSSEC validation was requested but the `cryptography` package is missing."""

    def __init__(self) -> None:
        super().__init__(
            "DNSSEC validation requires the 'cryptography' package. "
            "Install it with: pip install 'recursive-resolver[dnssec]' "
            "(or construct the resolver with dnssec=False)."
        )
