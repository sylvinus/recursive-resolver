"""Shared fixtures, CLI options and DNS message builders for the test suite."""

from __future__ import annotations

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from recursive_resolver import RecursiveResolver

# Every supported type that a plain list of apex domains can exercise. PTR
# needs an IP, and SRV/NAPTR need _service._proto labels, so they are covered by
# the unit and integration suites instead.
DEFAULT_CSV_TYPES = "A,AAAA,MX,TXT,NS,SOA,CAA,CNAME,DS,DNSKEY"

ROOT_REFERRAL_NS = "a.gtld-servers.net."
ROOT_REFERRAL_IP = "192.5.6.30"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--csv", action="store", default=None, help="Path to a CSV file with domains for bulk testing")
    parser.addoption(
        "--types",
        action="store",
        default=DEFAULT_CSV_TYPES,
        help=f"Comma-separated record types for the bulk harness (default: {DEFAULT_CSV_TYPES})",
    )
    parser.addoption("--sample", action="store", type=int, default=0, help="Randomly sample N domains (0 = all)")


@pytest.fixture
def csv_path(request: pytest.FixtureRequest) -> str | None:
    return request.config.getoption("--csv")  # type: ignore[return-value]


def make_response(
    answer=None,
    authority=None,
    additional=None,
    rcode=dns.rcode.NOERROR,
    aa: bool = True,
    tc: bool = False,
    rdclass: int = dns.rdataclass.IN,
) -> dns.message.Message:
    """Build a dns.message.Message for testing.

    Each section is a list of ``(name, ttl, rdtype, [rdata, ...])`` tuples.
    ``aa`` defaults to True because the resolver now requires the AA bit on
    answers and negative responses; referrals should pass ``aa=False``.
    """
    response = dns.message.Message()
    response.flags = dns.flags.QR
    if aa:
        response.flags |= dns.flags.AA
    if tc:
        response.flags |= dns.flags.TC
    response.id = 0
    response.set_rcode(rcode)

    for section, records in [
        (response.answer, answer or []),
        (response.authority, authority or []),
        (response.additional, additional or []),
    ]:
        for name_str, ttl, rdtype_str, rdata_strs in records:
            name = dns.name.from_text(name_str)
            rdt = dns.rdatatype.from_text(rdtype_str)
            rrset = dns.rrset.RRset(name, rdclass, rdt)
            for rd_str in rdata_strs:
                rrset.add(dns.rdata.from_text(rdclass, rdt, rd_str))
            rrset.ttl = ttl
            section.append(rrset)

    return response


def referral(zone: str, ns_names: list[str], glue: dict[str, str] | None = None) -> dns.message.Message:
    """Build a referral response (AA clear, NS in authority, glue in additional)."""
    additional = [(name, 172800, "A", [ip]) for name, ip in (glue or {}).items()]
    return make_response(
        authority=[(zone, 172800, "NS", ns_names)],
        additional=additional,
        aa=False,
    )


def root_to_com() -> dns.message.Message:
    """The standard root -> .com referral used by most tests."""
    return referral("com.", [ROOT_REFERRAL_NS], {ROOT_REFERRAL_NS: ROOT_REFERRAL_IP})


def nodata(zone: str) -> dns.message.Message:
    """A NODATA response: authoritative, SOA in authority, no answer."""
    return make_response(
        authority=[(zone, 300, "SOA", [f"ns1.{zone} admin.{zone} 1 3600 900 604800 86400"])],
        aa=True,
    )


def sequence(responses: list[tuple[dns.message.Message, str]]):
    """Return a _send_query side effect that replays responses in order."""
    state = {"i": 0}

    def side_effect(qname, rdtype, nameservers, ctx, usable=None):
        i = state["i"]
        if i < len(responses):
            state["i"] += 1
            return responses[i]
        return (None, "")

    return side_effect


def offline_resolver(**kwargs: object) -> RecursiveResolver:
    """A resolver wired for unit tests: no DNSSEC, no cache, unless overridden.

    Shared rather than redefined per module so the defaults for offline unit
    tests are set in one place.
    """
    kwargs.setdefault("dnssec", False)
    kwargs.setdefault("cache_enabled", False)
    return RecursiveResolver(**kwargs)  # type: ignore[arg-type]
