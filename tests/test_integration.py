"""Integration tests that perform real DNS queries over the network.

Run with: pytest -m integration
"""

from __future__ import annotations

import pytest

from recursive_resolver import (
    DNSSECInsecureError,
    DNSSECValidationError,
    NXDOMAINError,
    RecursiveResolver,
    TraceStep,
    ValidationState,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def resolver() -> RecursiveResolver:
    return RecursiveResolver(timeout=3.0, ipv4_only=True, max_resolution_time=20.0)


class TestRealResolution:
    def test_a_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("example.com", "A")
        assert result and all(len(ip.split(".")) == 4 for ip in result)

    def test_aaaa_record(self, resolver: RecursiveResolver) -> None:
        assert all(":" in ip for ip in resolver.resolve("google.com", "AAAA"))

    def test_mx_record(self, resolver: RecursiveResolver) -> None:
        for mx in resolver.resolve("google.com", "MX"):
            priority, host = mx.split()
            assert priority.isdigit() and host.endswith(".")

    def test_txt_record(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("google.com", "TXT")

    def test_ns_record(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("google.com", "NS")

    def test_soa_record(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("google.com", "SOA")

    def test_caa_record(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("cloudflare.com", "CAA")

    def test_cname_chain(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("www.github.com", "A")

    def test_ptr_record(self, resolver: RecursiveResolver) -> None:
        result = resolver.resolve("8.8.8.8", "PTR")
        assert any("google" in r.lower() or "dns" in r.lower() for r in result)

    def test_nxdomain(self, resolver: RecursiveResolver) -> None:
        with pytest.raises(NXDOMAINError):
            resolver.resolve("this-domain-definitely-does-not-exist-xyz123.com", "A")

    def test_tld_apex(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("com", "NS")

    def test_root_apex(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve(".", "NS")

    def test_idn_unicode_and_punycode_agree(self, resolver: RecursiveResolver) -> None:
        assert resolver.resolve("bücher.de", "A") == resolver.resolve("xn--bcher-kva.de", "A")


class TestRealDNSSEC:
    """DNSSEC must accept valid zones, reject bogus ones and allow unsigned ones."""

    @pytest.mark.parametrize("domain", ["cloudflare.com", "ietf.org", "nlnetlabs.nl", "internetsociety.org"])
    def test_signed_zones_validate(self, resolver: RecursiveResolver, domain: str) -> None:
        assert resolver.resolve_answer(domain, "A").dnssec is ValidationState.SECURE

    @pytest.mark.parametrize("domain", ["google.com", "github.com", "amazon.com"])
    def test_unsigned_zones_resolve_as_insecure(self, resolver: RecursiveResolver, domain: str) -> None:
        assert resolver.resolve_answer(domain, "A").dnssec is ValidationState.INSECURE

    @pytest.mark.parametrize("domain", ["dnssec-failed.org", "rhybar.cz", "bogus.nlnetlabs.nl"])
    def test_bogus_zones_are_rejected(self, resolver: RecursiveResolver, domain: str) -> None:
        with pytest.raises(DNSSECValidationError):
            resolver.resolve(domain, "A")

    def test_zone_cut_shared_with_parent(self, resolver: RecursiveResolver) -> None:
        """.cz serves nic.cz from the same servers, hiding the intermediate cut."""
        assert resolver.resolve_answer("nic.cz", "A").dnssec is ValidationState.SECURE

    def test_multi_label_zone_cut(self, resolver: RecursiveResolver) -> None:
        """uk. and co.uk. are served by the same nameservers."""
        assert resolver.resolve("bbc.co.uk", "A")

    def test_require_dnssec_rejects_unsigned(self) -> None:
        strict = RecursiveResolver(require_dnssec=True, max_resolution_time=20.0)
        with pytest.raises(DNSSECInsecureError):
            strict.resolve("google.com", "A")

    def test_require_dnssec_accepts_signed(self) -> None:
        strict = RecursiveResolver(require_dnssec=True, max_resolution_time=20.0)
        assert strict.resolve("cloudflare.com", "A")

    def test_dnssec_can_be_disabled(self) -> None:
        plain = RecursiveResolver(dnssec=False, max_resolution_time=20.0)
        assert plain.resolve_answer("dnssec-failed.org", "A").dnssec is ValidationState.INSECURE


class TestRealDKIM:
    """The headline use case: fetching DKIM keys correctly."""

    @pytest.mark.parametrize(
        "selector",
        ["s1._domainkey.stripe.com", "k1._domainkey.mailchimp.com", "zendesk1._domainkey.zendesk.com"],
    )
    def test_dkim_key_is_retrievable(self, resolver: RecursiveResolver, selector: str) -> None:
        answer = resolver.resolve_answer(selector, "TXT")
        values = answer.text_values()
        assert values and any("k=rsa" in v or "v=DKIM1" in v for v in values)

    def test_multi_chunk_key_has_no_separator(self, resolver: RecursiveResolver) -> None:
        """An RSA-2048 key is split across chunks; joining must add nothing."""
        answer = resolver.resolve_answer("zendesk1._domainkey.zendesk.com", "TXT")
        value = answer.text_values()[0]
        assert '" "' not in value
        assert " " not in value.split("p=")[1], "base64 key must not contain a chunk seam"

    def test_dmarc_record(self, resolver: RecursiveResolver) -> None:
        assert any("DMARC1" in v for v in resolver.resolve_answer("_dmarc.google.com", "TXT").text_values())


class TestRealTraceAndCache:
    def test_trace(self, resolver: RecursiveResolver) -> None:
        answer, trace = resolver.trace_answer("example.com", "A")
        assert answer is not None
        assert len(trace) >= 2
        assert all(isinstance(step, TraceStep) for step in trace)
        assert trace[0].response_type == "referral"
        assert trace[-1].response_type == "answer"

    def test_cache_speedup(self, resolver: RecursiveResolver) -> None:
        first = resolver.resolve("example.com", "A")
        assert resolver.resolve("example.com", "A") == first
        assert resolver.cache is not None
        assert resolver.cache.stats.hits > 0

    def test_delegation_cache_skips_the_root(self, resolver: RecursiveResolver) -> None:
        """A second lookup under the same TLD must not re-query a root server."""
        resolver.resolve("example.com", "A")
        _answer, trace = resolver.trace_answer("iana.org", "A")
        resolver.resolve("wikipedia.org", "A")
        _answer2, trace2 = resolver.trace_answer("en.wikipedia.org", "A")
        assert trace2, "expected a trace"
        assert trace2[0].server not in resolver._root_addresses


class TestRealDowngradeResistance:
    """An INSECURE verdict must be earned by a validated proof, never assumed.

    If a missing DS were enough on its own, an attacker who can strip records
    could downgrade any signed zone to unsigned and then serve forged data.
    """

    def test_insecure_requires_a_validated_no_ds_proof(self, resolver: RecursiveResolver) -> None:
        import dns.flags
        import dns.message
        import dns.name
        import dns.query
        import dns.rdatatype

        from recursive_resolver.dnssec import ValidationState

        # google.com is genuinely unsigned: .com carries no DS for it, only an
        # NSEC3 opt-out proof that none exists.
        assert resolver.resolve_answer("google.com", "A").dnssec is ValidationState.INSECURE

        plain = RecursiveResolver(dnssec=False, max_resolution_time=20.0)
        com_ns = plain.resolve("a.gtld-servers.net", "A")[0]
        query = dns.message.make_query("google.com", dns.rdatatype.A, use_edns=0, payload=1232, want_dnssec=True)
        query.flags &= ~dns.flags.RD
        referral = dns.query.udp_with_fallback(query, com_ns, timeout=5)[0]

        com = dns.name.from_text("com.")
        google = dns.name.from_text("google.com.")
        keys = resolver._cached_keys(com)
        assert keys is not None and keys.state is ValidationState.SECURE, "com. keys should be validated by now"
        keyring = keys.as_keyring()

        # With the real proof: insecure.
        state, _ds = resolver._validator.validate_ds(google, list(referral.authority), keyring)
        assert state is ValidationState.INSECURE

        # Proof stripped entirely: bogus, not a silent downgrade.
        stripped = [s for s in referral.authority if s.rdtype not in (dns.rdatatype.NSEC3, dns.rdatatype.RRSIG)]
        state, _ds = resolver._validator.validate_ds(google, stripped, keyring)
        assert state is ValidationState.BOGUS

        # Proof present but unsigned (forged): bogus.
        unsigned = [s for s in referral.authority if s.rdtype != dns.rdatatype.RRSIG]
        state, _ds = resolver._validator.validate_ds(google, unsigned, keyring)
        assert state is ValidationState.BOGUS
