"""An in-memory signed zone, so DNSSEC success paths are testable offline.

Validation logic that is only ever exercised against live DNS is logic that
cannot be tested deterministically, cannot be tested in CI without a network,
and cannot be tested at all for the cases the internet does not happen to
provide. This builds a real signed zone entirely in process, with real keys, real
signatures and real DS digests.

ECDSA P-256 (algorithm 13) is used because key generation and signing are fast
enough to run inside a unit test.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

ALGORITHM = dns.dnssec.Algorithm.ECDSAP256SHA256
DIGEST = dns.dnssec.DSDigest.SHA256

# A wide signature validity window keeps the fixture stable over time.
INCEPTION = 1_600_000_000
EXPIRATION = 4_000_000_000


def rrset_of(name: str, rdtype: str, *rdatas: str, ttl: int = 300) -> dns.rrset.RRset:
    """Build an IN-class RRset from presentation-format rdata."""
    rdt = dns.rdatatype.from_text(rdtype)
    out = dns.rrset.RRset(dns.name.from_text(name), dns.rdataclass.IN, rdt)
    for rdata in rdatas:
        out.add(dns.rdata.from_text(dns.rdataclass.IN, rdt, rdata))
    out.ttl = ttl
    return out


@dataclass
class SignedZone:
    """A zone with a working key, able to sign RRsets and yield its own DS."""

    name: dns.name.Name
    private_key: ec.EllipticCurvePrivateKey
    dnskey: dns.rdata.Rdata
    dnskey_rrset: dns.rrset.RRset

    @classmethod
    def create(cls, zone: str) -> SignedZone:
        name = dns.name.from_text(zone)
        private_key = ec.generate_private_key(ec.SECP256R1())
        # flags=257: zone key with the Secure Entry Point bit set.
        dnskey = dns.dnssec.make_dnskey(private_key.public_key(), ALGORITHM, flags=257)
        dnskey_rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        dnskey_rrset.add(dnskey)
        dnskey_rrset.ttl = 3600
        return cls(name=name, private_key=private_key, dnskey=dnskey, dnskey_rrset=dnskey_rrset)

    def sign(self, rrset: dns.rrset.RRset) -> dns.rrset.RRset:
        """Return the RRSIG RRset covering ``rrset``, signed by this zone."""
        rrsig = dns.dnssec.sign(
            rrset,
            self.private_key,
            self.name,
            self.dnskey,
            inception=INCEPTION,
            expiration=EXPIRATION,
        )
        out = dns.rrset.RRset(rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        out.add(rrsig)
        out.ttl = rrset.ttl
        return out

    def signed_dnskey(self) -> dns.rrset.RRset:
        """The RRSIG over this zone's own DNSKEY RRset (the self-signature)."""
        return self.sign(self.dnskey_rrset)

    def ds_rdataset(self, child: SignedZone) -> dns.rdataset.Rdataset:
        """The DS rdataset this zone would publish for ``child``."""
        rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        rdataset.add(dns.dnssec.make_ds(child.name, child.dnskey, DIGEST), ttl=3600)
        return rdataset

    def ds_rrset(self, child: SignedZone) -> dns.rrset.RRset:
        """The DS RRset for ``child``, as it appears in this zone."""
        out = dns.rrset.RRset(child.name, dns.rdataclass.IN, dns.rdatatype.DS)
        out.add(dns.dnssec.make_ds(child.name, child.dnskey, DIGEST))
        out.ttl = 3600
        return out

    def keyring(self) -> dict[dns.name.Name, dns.rrset.RRset]:
        return {self.name: self.dnskey_rrset}

    def anchor_text(self) -> str:
        """This zone's DS in presentation format, for use as a trust anchor."""
        ds = dns.dnssec.make_ds(self.name, self.dnskey, DIGEST)
        return ds.to_text()
