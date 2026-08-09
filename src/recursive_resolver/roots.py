"""Root server hints and the DNSSEC root trust anchors.

Root hints source: https://www.internic.net/domain/named.root
Trust anchor source: https://data.iana.org/root-anchors/root-anchors.xml
"""

from __future__ import annotations

# Root server name -> (IPv4, IPv6). Verified against named.root.
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

# DS records for the root zone, in presentation format.
#
# Only currently-valid anchors are listed: KSK-2017 (tag 20326, valid from
# 2017-02-02) and KSK-2024 (tag 38696, valid from 2024-07-18).
#
# Format: keytag algorithm digest_type digest
ROOT_TRUST_ANCHORS: tuple[str, ...] = (
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)


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
