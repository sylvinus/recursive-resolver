"""Address sanity checks for nameserver IPs.

A referral's glue records are attacker-controlled data, and so are the A/AAAA
records returned when resolving a glueless NS hostname. Without filtering, any
domain owner can point their zone's nameservers at ``127.0.0.1``, RFC1918
space, or a cloud metadata endpoint and turn a resolver into an unauthenticated
internal-network prober (a DNS-driven SSRF).

Classification comes from Python's :mod:`ipaddress`, which tracks the IANA
special-purpose address registries: an address is refused unless it is globally
routable and none of loopback, link-local, multicast, reserved or private. That
is deliberately not a hand-maintained CIDR list: it stays correct as IANA
allocates, and it covers CGNAT, the documentation prefixes, ``0.0.0.0/8``,
``240.0.0.0/4`` and benchmarking space.

A short built-in list then adds the ranges classification does not refuse, or
did not always refuse. Two kinds: addresses that look public but serve instance
metadata (Azure's ``168.63.129.16``), and the IPv6 transition prefixes that
carry an IPv4 address inside them. CVE-2024-4032 corrected
``is_private``/``is_global`` for several of those prefixes, so an interpreter
older than 3.10.14 does not agree with a current one about, say,
``2002:a9fe:a9fe::1`` - link-local metadata wrapped in 6to4. The rest of the
family a current stdlib does refuse; they are listed anyway, as policy, because
none of them is a nameserver location and the control should not read
differently on different supported versions.

The order of the checks below (specific categories before ``is_private``, since
loopback and link-local are subsets of it in Python's model), the ``is_global``
catch-all for shared address space, and the idea of naming the cloud-metadata
endpoints explicitly are adapted from ``core/services/ssrf.py`` in
https://github.com/suitenumerique/messages: Copyright (c) 2025 Direction
Interministérielle du Numérique, Gouvernement Français, MIT Licensed.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Ranges Python's ipaddress module still reports as globally routable, but which
# no public nameserver legitimately occupies. Each is cited so the list can be
# audited rather than trusted.
_BUILTIN_BLOCKED_NETWORKS: tuple[str, ...] = (
    # Azure Instance Metadata Service and platform DNS. A genuinely public
    # address, so no generic classification catches it.
    "168.63.129.16/32",
    # 6to4 relay anycast, deprecated by RFC 7526 but still routed in places.
    "192.88.99.0/24",
    # ORCHIDv2 (RFC 7343): cryptographic identifiers, never a real host.
    "2001:20::/28",
    # Deprecated IPv6 site-local (RFC 3879); some networks still route it.
    "fec0::/10",
    # IPv6 transition prefixes: each embeds an IPv4 address, so reaching one
    # reaches whatever that address is. Not a nameserver location either way.
    # Classification refuses these on a current stdlib; some of them only since
    # CVE-2024-4032, so they are stated here rather than assumed.
    "2002::/16",  # 6to4 (RFC 3056)
    "2001::/32",  # Teredo (RFC 4380)
    "64:ff9b::/96",  # NAT64 well-known prefix (RFC 6052)
    "64:ff9b:1::/48",  # NAT64 local-use prefix (RFC 8215)
    "::/96",  # deprecated IPv4-compatible IPv6 (RFC 4291 §2.5.5.1)
)

# Named purely so a rejection can say *why*. Every one of these is already
# caught by the classification above; listing them makes the logs legible.
CLOUD_METADATA_ADDRESSES: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean, Oracle
        "fd00:ec2::254",  # AWS IMDS over IPv6
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud (legacy)
        "168.63.129.16",  # Azure wireserver
    }
)


def _parse_networks(networks: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(n) for n in networks)


_BUILTIN_PARSED = _parse_networks(_BUILTIN_BLOCKED_NETWORKS)


class AddressFilter:
    """Decides whether an IP address may be used as a nameserver.

    Args:
        extra_blocked_networks: Further CIDRs to refuse, such as your own
            internal ranges. These are added to the built-in rules, never
            substituted for them: a blocklist that quietly shrinks when you
            extend it is a bad way to build a security control.
        allow_private: If True, accept any syntactically valid address. Only set
            this for split-horizon or lab setups where you fully trust every
            zone you will ever resolve: it disables the SSRF control entirely.
    """

    def __init__(
        self,
        extra_blocked_networks: Iterable[str] | None = None,
        allow_private: bool = False,
    ) -> None:
        self.allow_private = allow_private
        self._networks: tuple[IPNetwork, ...] = _BUILTIN_PARSED + _parse_networks(extra_blocked_networks or ())

    def rejection_reason(self, address: str) -> str | None:
        """Return why ``address`` is unusable as a nameserver, or None if it is fine."""
        try:
            addr: IPAddress = ipaddress.ip_address(address)
        except ValueError:
            return "not a valid IP address"

        if self.allow_private:
            return None

        # An IPv4-mapped IPv6 address (::ffff:a.b.c.d) must be judged on its
        # embedded IPv4 address, or it is a trivial bypass of every v4 rule.
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped

        if str(addr) in CLOUD_METADATA_ADDRESSES:
            return "cloud metadata endpoint"
        if addr.is_loopback:
            return "loopback address"
        if addr.is_link_local:
            return "link-local address"
        if addr.is_multicast:
            return "multicast address"
        if addr.is_unspecified:
            return "unspecified address"
        if addr.is_reserved:
            return "reserved address"
        if addr.is_private:
            return "private address"
        # Catches what the specific tests above miss, notably CGNAT
        # (100.64.0.0/10), which is neither private nor reserved here.
        if not addr.is_global:
            return "not globally routable"
        for network in self._networks:
            if addr.version == network.version and addr in network:
                return f"blocked range {network}"
        return None

    def is_allowed(self, address: str) -> bool:
        """Return True if ``address`` is a routable public IP we may query."""
        return self.rejection_reason(address) is None

    def filter(self, addresses: Iterable[str]) -> list[str]:
        """Return only the addresses that are allowed, preserving order."""
        return [a for a in addresses if self.is_allowed(a)]
