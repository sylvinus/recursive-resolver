"""Core iterative DNS resolution engine.

Implements true recursive (iterative) resolution starting from root servers.
Uses dnspython only for wire-format parsing and UDP/TCP transport.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import time
from dataclasses import dataclass
from typing import Any

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.reversename

from .cache import DNSCache
from .exceptions import (
    CNAMELoopError,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    ResolutionTimeoutError,
    ServfailError,
)
from .roots import get_root_addresses

logger = logging.getLogger(__name__)


@dataclass
class TraceStep:
    """A single step in the resolution trace."""

    server: str
    qname: str
    rdtype: str
    response_type: str  # "answer", "referral", "cname", "nxdomain", "nodata", "error"
    detail: str = ""
    rcode: int = 0


class RecursiveResolver:
    """Iterative DNS resolver that resolves queries starting from root servers.

    Args:
        timeout: Per-query UDP/TCP timeout in seconds.
        max_depth: Maximum delegation depth before raising MaxDepthError.
        max_cname_chain: Maximum CNAME follows before raising CNAMELoopError.
        cache_enabled: Whether to enable response caching.
        use_tcp_fallback: Whether to fall back to TCP when response is truncated.
        max_retries: Number of retries per nameserver on timeout.
        ipv4_only: Only use IPv4 addresses for queries.
        max_resolution_time: Hard cap on the total wall-clock time for a single
            resolve() call, in seconds.  Covers all sub-queries, retries,
            glueless sub-resolutions, and CNAME chasing.  Default: 30s.
    """

    SUPPORTED_TYPES = frozenset(
        {"A", "AAAA", "CNAME", "MX", "TXT", "SOA", "PTR", "NS", "SRV", "CAA", "DNSKEY", "DS", "NAPTR"}
    )

    def __init__(
        self,
        timeout: float = 5.0,
        max_depth: int = 20,
        max_cname_chain: int = 10,
        cache_enabled: bool = True,
        use_tcp_fallback: bool = True,
        max_retries: int = 2,
        ipv4_only: bool = True,
        max_resolution_time: float = 30.0,
    ) -> None:
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_cname_chain = max_cname_chain
        self.use_tcp_fallback = use_tcp_fallback
        self.max_retries = max_retries
        self.ipv4_only = ipv4_only
        self.max_resolution_time = max_resolution_time
        self.cache = DNSCache() if cache_enabled else None
        self._root_addresses = get_root_addresses(ipv4_only=ipv4_only)

    def resolve(self, qname: str, rdtype: str = "A") -> list[str]:
        """Resolve a DNS query iteratively from root servers.

        Args:
            qname: The domain name to query (or IP address for PTR lookups).
            rdtype: The record type (e.g. "A", "AAAA", "MX", "TXT").

        Returns:
            A list of string representations of the answer records.

        Raises:
            NXDOMAINError: The domain does not exist.
            NoAnswerError: The domain exists but has no records of the requested type.
            MaxDepthError: Resolution exceeded maximum delegation depth.
            ResolutionTimeoutError: All nameservers timed out.
            CNAMELoopError: A CNAME loop was detected.
            ServfailError: All nameservers returned errors.
        """
        qname = self._normalize_qname(qname, rdtype)
        rdtype = rdtype.upper()
        deadline = time.monotonic() + self.max_resolution_time

        result = self._resolve_iterative(qname, rdtype, depth=0, cname_chain=[], deadline=deadline)
        return result

    def resolve_with_trace(self, qname: str, rdtype: str = "A") -> list[TraceStep]:
        """Resolve a DNS query and return a trace of all resolution steps.

        Args:
            qname: The domain name to query.
            rdtype: The record type.

        Returns:
            A list of TraceStep objects showing each step of the resolution.
        """
        qname = self._normalize_qname(qname, rdtype)
        rdtype = rdtype.upper()
        deadline = time.monotonic() + self.max_resolution_time
        trace: list[TraceStep] = []
        self._resolve_iterative(qname, rdtype, depth=0, cname_chain=[], trace=trace, deadline=deadline)
        return trace

    def _normalize_qname(self, qname: str, rdtype: str) -> str:
        """Normalize the query name. Auto-converts IP addresses for PTR lookups."""
        if rdtype.upper() == "PTR":
            try:
                addr = ipaddress.ip_address(qname)
                return str(dns.reversename.from_address(str(addr)))
            except ValueError:
                pass
        # Ensure FQDN
        if not qname.endswith("."):
            qname = qname + "."
        return qname

    def _check_deadline(self, deadline: float, qname: str, rdtype: str) -> None:
        """Raise ResolutionTimeoutError if the overall resolution deadline has passed."""
        if time.monotonic() >= deadline:
            raise ResolutionTimeoutError(qname, rdtype)

    def _effective_timeout(self, deadline: float) -> float:
        """Return per-query timeout clamped to the remaining resolution time."""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return 0.0
        return min(self.timeout, remaining)

    def _resolve_iterative(
        self,
        qname: str,
        rdtype: str,
        depth: int,
        cname_chain: list[str],
        trace: list[TraceStep] | None = None,
        deadline: float = float("inf"),
    ) -> list[str]:
        """Core iterative resolution loop.

        Starts from root servers and follows delegations until an answer is found.
        """
        if depth > self.max_depth:
            raise MaxDepthError(qname, rdtype, self.max_depth)
        self._check_deadline(deadline, qname, rdtype)

        # Check cache
        if self.cache is not None:
            cached = self.cache.get(qname, rdtype)
            if cached is not None:
                if cached.is_negative:
                    if cached.rrset is None:
                        raise NXDOMAINError(qname)
                    raise NoAnswerError(qname, rdtype)
                if cached.rrset is not None:
                    return [str(rr) for rr in cached.rrset]

        current_nameservers = list(self._root_addresses)
        # Track NS names from the most recent referral for stale-glue fallback
        pending_ns_names: list[str] = []
        # Limit NXDOMAIN retries to avoid O(n) queries on large NS sets
        nxdomain_retries_left = 2

        for _ in range(self.max_depth):
            self._check_deadline(deadline, qname, rdtype)
            response, server = self._send_query(qname, rdtype, current_nameservers, deadline)
            if response is None:
                # All nameservers timed out — try resolving NS names as fallback
                # (handles stale/dead glue IPs from referrals)
                if pending_ns_names:
                    resolved_ips = self._resolve_glueless(pending_ns_names, depth + 1, max_ns=2, deadline=deadline)
                    if resolved_ips:
                        current_nameservers = resolved_ips
                        pending_ns_names = []
                        continue
                raise ResolutionTimeoutError(qname, rdtype)

            classification = self._classify_response(response, qname, rdtype)

            if trace is not None:
                trace.append(
                    TraceStep(
                        server=server,
                        qname=qname,
                        rdtype=rdtype,
                        response_type=classification["type"],
                        detail=classification.get("detail", ""),
                        rcode=response.rcode(),
                    )
                )

            if classification["type"] == "answer":
                answers = [str(rr) for rr in classification["rrset"]]
                if self.cache is not None:
                    self.cache.put(qname, rdtype, classification["rrset"], ttl=classification["ttl"])
                return answers

            elif classification["type"] == "cname":
                cname_target = classification["target"]
                if cname_target in cname_chain:
                    raise CNAMELoopError(qname, cname_chain + [cname_target])
                if len(cname_chain) >= self.max_cname_chain:
                    raise CNAMELoopError(qname, cname_chain + [cname_target])
                # Cache the CNAME record itself
                if self.cache is not None and "cname_rrset" in classification:
                    self.cache.put(qname, "CNAME", classification["cname_rrset"], ttl=classification.get("ttl", 300))
                # Restart resolution from root for the CNAME target
                return self._resolve_iterative(
                    cname_target, rdtype, depth + 1, cname_chain + [qname], trace=trace, deadline=deadline
                )

            elif classification["type"] == "referral":
                ns_names = classification["ns_names"]
                glue_ips = classification["glue_ips"]
                # Always remember NS names for stale-glue fallback
                pending_ns_names = ns_names
                # Reset NXDOMAIN retry counter for each new delegation level
                nxdomain_retries_left = 2

                if glue_ips:
                    current_nameservers = glue_ips
                else:
                    # Glueless referral — resolve NS hostnames
                    resolved_ips = self._resolve_glueless(ns_names, depth + 1, deadline=deadline)
                    if resolved_ips:
                        current_nameservers = resolved_ips
                    else:
                        raise ServfailError(qname, rdtype)

            elif classification["type"] == "nxdomain":
                # Try a few other nameservers before accepting NXDOMAIN
                # (handles inconsistent TLD nameservers, e.g. one of several
                # .ir servers returning NXDOMAIN while others have the zone)
                current_nameservers = [ns for ns in current_nameservers if ns != server]
                if current_nameservers and nxdomain_retries_left > 0:
                    nxdomain_retries_left -= 1
                    logger.debug(
                        "NXDOMAIN from %s for %s/%s, trying %d remaining servers (%d retries left)",
                        server,
                        qname,
                        rdtype,
                        len(current_nameservers),
                        nxdomain_retries_left,
                    )
                    continue
                if self.cache is not None:
                    self.cache.put(qname, rdtype, None, is_negative=True)
                raise NXDOMAINError(qname, rdtype)

            elif classification["type"] == "nodata":
                if self.cache is not None:
                    self.cache.put(qname, rdtype, "NODATA", is_negative=True)
                raise NoAnswerError(qname, rdtype)

            elif classification["type"] == "error":
                # Remove the failing server and try others
                current_nameservers = [ns for ns in current_nameservers if ns != server]
                if not current_nameservers:
                    raise ServfailError(qname, rdtype, rcode=response.rcode())
                continue

        raise MaxDepthError(qname, rdtype, self.max_depth)

    def _send_query(
        self, qname: str, rdtype: str, nameservers: list[str], deadline: float = float("inf")
    ) -> tuple[dns.message.Message | None, str]:
        """Send a DNS query to a list of nameservers.

        Shuffles the nameserver list and tries each with retries.
        Returns (response, server_ip) or (None, "") if all fail.
        """
        servers = list(nameservers)
        random.shuffle(servers)

        rdtype_int = dns.rdatatype.from_text(rdtype)

        for server in servers:
            for attempt in range(self.max_retries + 1):
                qry_timeout = self._effective_timeout(deadline)
                if qry_timeout <= 0:
                    return None, ""

                try:
                    query = dns.message.make_query(qname, rdtype_int, use_edns=0, payload=4096)
                    # RD=0: we iterate ourselves
                    query.flags &= ~dns.flags.RD

                    if self.use_tcp_fallback:
                        response, used_tcp = dns.query.udp_with_fallback(query, server, timeout=qry_timeout)
                    else:
                        response = dns.query.udp(query, server, timeout=qry_timeout)

                    # FORMERR often means the server doesn't like EDNS0 — retry without it
                    if response.rcode() == dns.rcode.FORMERR:
                        plain_response = self._send_query_plain(qname, rdtype_int, server, deadline)
                        if plain_response is not None:
                            return plain_response, server
                        break

                    return response, server

                except dns.query.BadResponse:
                    # Try without EDNS (some servers don't support it)
                    plain_response = self._send_query_plain(qname, rdtype_int, server, deadline)
                    if plain_response is not None:
                        return plain_response, server
                    break

                except (dns.exception.Timeout, OSError):
                    logger.debug("Timeout querying %s for %s/%s (attempt %d)", server, qname, rdtype, attempt + 1)
                    continue

                except Exception as e:
                    logger.debug("Error querying %s for %s/%s: %s", server, qname, rdtype, e)
                    break

        return None, ""

    def _send_query_plain(
        self, qname: str, rdtype_int: dns.rdatatype.RdataType, server: str, deadline: float = float("inf")
    ) -> dns.message.Message | None:
        """Send a query without EDNS0 (fallback for servers that reject EDNS)."""
        qry_timeout = self._effective_timeout(deadline)
        if qry_timeout <= 0:
            return None
        try:
            query = dns.message.make_query(qname, rdtype_int)
            query.flags &= ~dns.flags.RD
            return dns.query.udp(query, server, timeout=qry_timeout)
        except Exception:
            return None

    def _classify_response(self, response: dns.message.Message, qname: str, rdtype: str) -> dict[str, Any]:
        """Classify a DNS response into answer, cname, referral, nxdomain, nodata, or error."""
        rcode = response.rcode()
        rdtype_int = dns.rdatatype.from_text(rdtype)
        qname_obj = dns.name.from_text(qname)

        # Server error (but not NXDOMAIN — handled below after checking for CNAME)
        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return {"type": "error", "rcode": rcode}

        # Check for answer in answer section
        for rrset in response.answer:
            if rrset.name == qname_obj and rrset.rdtype == rdtype_int:
                return {
                    "type": "answer",
                    "rrset": rrset,
                    "ttl": rrset.ttl,
                }

        # Check for CNAME in answer section — must come before NXDOMAIN check
        # because a server may return NXDOMAIN + CNAME when the CNAME target
        # is outside its zone (the target may resolve fine via other servers)
        for rrset in response.answer:
            if rrset.name == qname_obj and rrset.rdtype == dns.rdatatype.CNAME:
                target = str(rrset[0].target)
                return {
                    "type": "cname",
                    "target": target,
                    "cname_rrset": rrset,
                    "ttl": rrset.ttl,
                }

        # NXDOMAIN (only if no CNAME was found above)
        if rcode == dns.rcode.NXDOMAIN:
            return {"type": "nxdomain"}

        # Check for referral (NS in authority, no answer)
        ns_names: list[str] = []
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_names.append(str(rr.target))

        if ns_names:
            # The zone being delegated is the owner of the NS rrset
            delegated_zone: dns.name.Name | None = None
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    delegated_zone = rrset.name
                    break

            # Referral validation: the qname must be at or below the delegated zone.
            # This prevents a malicious server from redirecting us to unrelated zones
            # (e.g., evil.com's NS returning a referral for bank.com).
            if delegated_zone is not None and not qname_obj.is_subdomain(delegated_zone):
                logger.debug(
                    "Ignoring referral to %s (qname %s is not a subdomain)",
                    delegated_zone,
                    qname,
                )
                return {"type": "error", "rcode": rcode}

            glue_ips = self._extract_glue(response, ns_names, delegated_zone)
            detail = f"NS: {', '.join(ns_names[:3])}"
            if glue_ips:
                detail += f" (glue: {', '.join(glue_ips[:3])})"
            return {
                "type": "referral",
                "ns_names": ns_names,
                "glue_ips": glue_ips,
                "detail": detail,
            }

        # NODATA: NOERROR but no answer and no referral
        return {"type": "nodata"}

    def _extract_glue(
        self,
        response: dns.message.Message,
        ns_names: list[str],
        delegated_zone: dns.name.Name | None = None,
    ) -> list[str]:
        """Extract glue A/AAAA records from the additional section for the given NS names.

        Applies bailiwick checking: only accepts glue records for NS hostnames
        that are at or below the parent zone (the zone of the responding server).
        This prevents cache poisoning from out-of-bailiwick glue injected by
        a malicious authority server, while still accepting legitimate sibling
        glue (e.g. a.gtld-servers.net. as glue for .com from root servers).
        """
        glue_ips: list[str] = []
        ns_name_objs = {dns.name.from_text(ns) for ns in ns_names}

        # The parent zone is what the responding server is authoritative for.
        # Glue is in-bailiwick if the NS hostname is under this parent zone.
        parent_zone = delegated_zone.parent() if delegated_zone is not None else None

        for rrset in response.additional:
            if rrset.name not in ns_name_objs:
                continue
            if rrset.rdtype != dns.rdatatype.A and (rrset.rdtype != dns.rdatatype.AAAA or self.ipv4_only):
                continue
            # Bailiwick check: only accept glue if the NS hostname
            # is within the parent zone (in-bailiwick)
            if parent_zone is not None and not rrset.name.is_subdomain(parent_zone):
                logger.debug(
                    "Rejected out-of-bailiwick glue for %s (parent zone: %s)",
                    rrset.name,
                    parent_zone,
                )
                continue
            for rr in rrset:
                glue_ips.append(str(rr.address))

        return glue_ips

    def _resolve_glueless(
        self, ns_names: list[str], depth: int, max_ns: int = 0, deadline: float = float("inf")
    ) -> list[str]:
        """Resolve NS hostnames that had no glue records in the referral.

        Resolves up to max_ns NS names (all if 0) and collects all their IPs.
        Does NOT stop at the first success — the resolved IP may point to a
        dead server, so we need alternatives for _send_query to try.

        Args:
            ns_names: List of NS hostnames to resolve.
            depth: Current recursion depth.
            max_ns: Maximum number of NS names to try (0 = all).
            deadline: Absolute monotonic deadline for the overall resolution.
        """
        resolved_ips: list[str] = []
        names_to_try = ns_names[:max_ns] if max_ns > 0 else ns_names
        for ns_name in names_to_try:
            if time.monotonic() >= deadline:
                break
            if not ns_name.endswith("."):
                ns_name = ns_name + "."
            try:
                ips = self._resolve_iterative(ns_name, "A", depth=depth, cname_chain=[], deadline=deadline)
                resolved_ips.extend(ips)
            except Exception:
                logger.debug("Failed to resolve glueless NS %s", ns_name)
                continue
        return resolved_ips
