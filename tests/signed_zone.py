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

import time
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
REVOKE = 0x0080  # RFC 5011 §7
DIGEST = dns.dnssec.DSDigest.SHA256

# A realistic signature validity window, computed at import so the fixture
# stays valid as time passes. It must be realistic rather than merely wide:
# RFC 4034 §3.1.5 compares inception and expiration as serial numbers per RFC
# 1982, so a window spanning more than 2^31 seconds - about 68 years - reads as
# wrapped and is refused, here and by Unbound alike. Real zones sign for days.
_NOW = int(time.time())
INCEPTION = _NOW - 3600
EXPIRATION = _NOW + 30 * 86400


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

    def sign(self, rrset: dns.rrset.RRset, expiration: int = EXPIRATION) -> dns.rrset.RRset:
        """Return the RRSIG RRset covering ``rrset``, signed by this zone."""
        rrsig = dns.dnssec.sign(
            rrset,
            self.private_key,
            self.name,
            self.dnskey,
            inception=INCEPTION,
            expiration=expiration,
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

    def revoked(self) -> SignedZone:
        """The same zone after revoking its key (RFC 5011 §2.1).

        Revocation is the REVOKE bit set on the *same* key material, so the
        holder of the private key can still produce signatures that verify
        against it. That is the point: a validator that ignores the bit keeps
        trusting a key its owner has publicly withdrawn.
        """
        revoked_key = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            f"{self.dnskey.flags | REVOKE} {self.dnskey.protocol} {self.dnskey.algorithm} "
            f"{dns.rdata._base64ify(self.dnskey.key, chunksize=0)}",
        )
        rrset = dns.rrset.RRset(self.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        rrset.add(revoked_key)
        rrset.ttl = self.dnskey_rrset.ttl
        return SignedZone(name=self.name, private_key=self.private_key, dnskey=revoked_key, dnskey_rrset=rrset)

    def anchor_text(self) -> str:
        """This zone's DS in presentation format, for use as a trust anchor."""
        ds = dns.dnssec.make_ds(self.name, self.dnskey, DIGEST)
        return ds.to_text()
