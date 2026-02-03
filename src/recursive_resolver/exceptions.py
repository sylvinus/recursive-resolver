"""Exception hierarchy for the recursive DNS resolver."""

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
    """All nameservers timed out during resolution."""

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
