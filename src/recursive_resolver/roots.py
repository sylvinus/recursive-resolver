"""Hardcoded root server hints (13 servers, IPv4 + IPv6).

Source: https://www.internic.net/domain/named.root
"""

from __future__ import annotations

# Root server name -> (IPv4, IPv6)
ROOT_SERVERS: dict[str, tuple[str, str]] = {
    "a.root-servers.net": ("198.41.0.4", "2001:503:ba3e::2:30"),
    "b.root-servers.net": ("170.247.170.2", "2801:1b8:10::b"),
    "c.root-servers.net": ("192.33.4.12", "2001:500:2::c"),
    "d.root-servers.net": ("199.7.91.13", "2001:500:2d::d"),
    "e.root-servers.net": ("192.203.230.10", "2001:500:a8::e"),
    "f.root-servers.net": ("192.5.5.241", "2001:500:2f::f"),
    "g.root-servers.net": ("192.112.36.4", "2001:500:12::d0d"),
    "h.root-servers.net": ("198.97.190.53", "2001:500:1::53"),
    "i.root-servers.net": ("192.36.148.17", "2001:7fe::53"),
    "j.root-servers.net": ("192.58.128.30", "2001:503:c27::2:30"),
    "k.root-servers.net": ("193.0.14.129", "2001:7fd::1"),
    "l.root-servers.net": ("199.7.83.42", "2001:500:9f::42"),
    "m.root-servers.net": ("202.12.27.33", "2001:dc3::35"),
}


def get_root_addresses(ipv4_only: bool = True) -> list[str]:
    """Return a list of root server IP addresses.

    Args:
        ipv4_only: If True, return only IPv4 addresses. If False, return both IPv4 and IPv6.

    Returns:
        List of IP address strings.
    """
    addresses: list[str] = []
    for ipv4, ipv6 in ROOT_SERVERS.values():
        addresses.append(ipv4)
        if not ipv4_only:
            addresses.append(ipv6)
    return addresses
