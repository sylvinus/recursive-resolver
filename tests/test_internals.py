"""Coverage of construction, configuration and the less-travelled error paths.

Error paths in a resolver are exactly the paths a hostile zone drives, so they
are exercised explicitly rather than left to chance.
"""

from __future__ import annotations

import ipaddress
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import dns.exception
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import pytest
from conftest import make_response, offline_resolver, referral, root_to_com

from recursive_resolver import (
    AddressFilter,
    CNAMELoopError,
    DNSSECInsecureError,
    DNSSECMaterialUnavailableError,
    DNSSECUnavailableError,
    DNSSECValidationError,
    InvalidNameError,
    Limits,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    QueryBudgetExceededError,
    RecursiveResolver,
    ResolutionTimeoutError,
    ResolverError,
    ServfailError,
    UnsupportedRdtypeError,
    ValidationState,
)
from recursive_resolver.budget import QueryBudget
from recursive_resolver.cache import CacheStats, Delegation, DNSCache
from recursive_resolver.dnssec import ZoneKeys
from recursive_resolver.roots import ROOT_SERVERS, get_root_addresses
from recursive_resolver.singleflight import SingleFlight

EXAMPLE = dns.name.from_text("example.com.")


class TestEntryPoints:
    def test_module_execution(self) -> None:
        """`python -m recursive_resolver` must work as an entry point."""
        result = subprocess.run(
            [sys.executable, "-m", "recursive_resolver", "--version"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "recursive-resolver" in result.stdout

    def test_importing_main_does_not_run_the_cli(self) -> None:
        """Importing the module must not exit the interpreter."""
        result = subprocess.run(
            [sys.executable, "-c", "import recursive_resolver.__main__; print('imported')"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "imported" in result.stdout


class TestRoots:
    def test_ipv4_only(self) -> None:
        addresses = get_root_addresses(ipv4_only=True)
        assert len(addresses) == 13
        assert all(":" not in a for a in addresses)

    def test_dual_stack(self) -> None:
        addresses = get_root_addresses(ipv4_only=False)
        assert len(addresses) == 26
        assert sum(":" in a for a in addresses) == 13

    def test_every_root_letter_is_present(self) -> None:
        assert sorted(name[0] for name in ROOT_SERVERS) == list("abcdefghijklm")


class TestAddressFilterEdges:
    def test_allow_private_still_rejects_garbage(self) -> None:
        assert AddressFilter(allow_private=True).is_allowed("not-an-ip") is False

    def test_allow_private_accepts_loopback(self) -> None:
        assert AddressFilter(allow_private=True).is_allowed("127.0.0.1") is True

    def test_extra_networks_are_additive(self) -> None:
        f = AddressFilter(extra_blocked_networks=["8.8.8.0/24"])
        assert f.is_allowed("8.8.8.8") is False
        assert f.is_allowed("192.88.99.1") is False
        assert f.is_allowed("1.1.1.1") is True

    def test_multicast_and_unspecified_are_rejected(self) -> None:
        f = AddressFilter()
        assert f.is_allowed("224.0.0.1") is False
        assert f.is_allowed("::") is False

    def test_ipv6_transition_prefixes_are_rejected_by_our_own_list(self) -> None:
        """Each wraps an IPv4 address, here 169.254.169.254 or 127.0.0.1.

        Stdlib classification catches these on a current interpreter, but did
        not before CVE-2024-4032, so the built-in list must catch them on its
        own. Checked with classification switched off.
        """
        f = AddressFilter()
        f._networks = tuple(n for n in f._networks if n.version == 6)
        for address in (
            "2002:a9fe:a9fe::1",  # 6to4
            "2001:0:53aa:64c:0:5faa:a9fe:a9fe",  # Teredo
            "64:ff9b::a9fe:a9fe",  # NAT64 well-known
            "64:ff9b:1::a9fe:a9fe",  # NAT64 local-use
            "::0.0.0.1",  # IPv4-compatible
        ):
            assert any(ipaddress.ip_address(address) in network for network in f._networks), (
                f"{address} is not in any built-in blocked network"
            )

    def test_real_public_ipv6_nameservers_are_still_allowed(self) -> None:
        f = AddressFilter()
        assert f.is_allowed("2001:4860:4860::8888") is True
        assert f.is_allowed("2620:fe::fe") is True


class TestBudgetEdges:
    def test_referral_budget(self) -> None:
        budget = QueryBudget(max_referrals=2)
        budget.note_referral("a.", "A")
        budget.note_referral("a.", "A")
        with pytest.raises(QueryBudgetExceededError) as exc:
            budget.note_referral("a.", "A")
        assert "referrals" in str(exc.value)

    def test_remaining_and_time(self) -> None:
        budget = QueryBudget(max_queries=3, deadline=time.monotonic() + 60)
        assert budget.remaining_queries() == 3
        budget.spend_query("a.", "A")
        assert budget.remaining_queries() == 2
        assert budget.expired() is False
        assert budget.time_remaining() > 0

    def test_expired_budget(self) -> None:
        budget = QueryBudget(deadline=time.monotonic() - 1)
        assert budget.expired() is True
        assert budget.time_remaining() == 0.0


class TestCacheEdges:
    def test_hit_rate_of_an_untouched_cache(self) -> None:
        assert CacheStats().hit_rate == 0.0

    def test_rdtype_accepts_text(self) -> None:
        cache = DNSCache()
        cache.put_answer(EXAMPLE, "MX", "rrset", ttl=300)
        assert cache.get_answer(EXAMPLE, "MX") is not None

    def test_qname_accepts_text(self) -> None:
        cache = DNSCache()
        cache.put_answer("example.com.", dns.rdatatype.A, "rrset", ttl=300)
        assert cache.get_answer(EXAMPLE, dns.rdatatype.A) is not None

    def test_delegation_lookup_for_an_unknown_zone(self) -> None:
        assert DNSCache().get_delegation(EXAMPLE) is None

    def test_delegation_depth_none_caches_every_level(self) -> None:
        cache = DNSCache(max_delegation_depth=None)
        deep = dns.name.from_text("a.b.c.example.com.")
        cache.put_delegation(Delegation(zone=deep, addresses=["9.9.9.9"]), ttl=300)
        assert cache.get_delegation(deep) is not None


class TestSingleFlightEdges:
    def test_slow_leader_does_not_block_a_waiter_forever(self) -> None:
        sf: SingleFlight[str] = SingleFlight()
        release = threading.Event()
        started = threading.Event()

        def slow() -> str:
            started.set()
            release.wait(timeout=5)
            return "leader"

        leader = threading.Thread(target=lambda: sf.do("k", slow))
        leader.start()
        started.wait(timeout=2)
        # The waiter gives up on the leader and does the work itself.
        assert sf.do("k", lambda: "self-served", wait_timeout=0.05) == "self-served"
        release.set()
        leader.join()


class TestConstruction:
    def test_dnssec_without_cryptography_is_refused_clearly(self) -> None:
        with (
            patch("recursive_resolver.resolver.cryptography_available", return_value=False),
            pytest.raises(DNSSECUnavailableError) as exc,
        ):
            RecursiveResolver(dnssec=True)
        assert "cryptography" in str(exc.value)

    def test_dnssec_off_works_without_cryptography(self) -> None:
        with patch("recursive_resolver.resolver.cryptography_available", return_value=False):
            assert RecursiveResolver(dnssec=False) is not None

    def test_an_empty_trust_anchor_tuple_is_not_a_silent_fallback(self) -> None:
        """() must not quietly mean "use the IANA anchors", which is its opposite."""
        with pytest.raises(ValueError, match="must not be empty"):
            RecursiveResolver(dnssec=True, trust_anchors=())

    def test_trust_anchors_none_uses_the_iana_defaults(self) -> None:
        assert len(RecursiveResolver(dnssec=True, trust_anchors=None)._validator._root_ds) == 2

    def test_idna_2008_is_preferred(self) -> None:
        assert RecursiveResolver._default_idna_codec() is dns.name.IDNA_2008_Practical

    def test_idna_2003_fallback_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """Without the idna package we must say so: the results differ."""
        with patch.object(dns.name, "have_idna_2008", False), caplog.at_level("WARNING"):
            codec = RecursiveResolver._default_idna_codec()
        assert codec is dns.name.IDNA_2003
        assert "IDNA 2008 unavailable" in caplog.text

    def test_ipv6_mode_includes_v6_roots(self) -> None:
        resolver = offline_resolver(ipv4_only=False)
        assert any(":" in a for a in resolver._root_addresses)


class TestInputValidationEdges:
    def test_meta_rdtypes_are_refused(self) -> None:
        with pytest.raises(UnsupportedRdtypeError) as exc:
            offline_resolver().resolve("example.com", "AXFR")
        assert "meta" in str(exc.value)

    def test_any_is_refused(self) -> None:
        """An `Answer` holds one RRset, so there is nothing ANY could return.

        Letting it through was worse than refusing: no RRset ever matched the
        query type, so a fully populated answer read as NODATA and was cached
        as one, denying the name for every later query of any type.
        """
        with pytest.raises(UnsupportedRdtypeError, match="ANY cannot be queried"):
            offline_resolver()._parse_rdtype("ANY")

    def test_a_resolve_call_for_any_is_refused_too(self) -> None:
        with pytest.raises(UnsupportedRdtypeError):
            offline_resolver().resolve("example.com", "ANY")

    def test_relative_names_are_made_absolute(self) -> None:
        assert offline_resolver()._normalize_qname("example.com", "A").is_absolute()

    def test_a_relative_name_with_no_room_for_the_root_label_is_refused(self) -> None:
        from recursive_resolver import InvalidNameError

        relative = dns.name.Name([b"a" * 63, b"a" * 63, b"a" * 63, b"a" * 62])
        with pytest.raises(InvalidNameError, match="255 octets"):
            offline_resolver().resolve(relative, "A")

    def test_non_string_input(self) -> None:
        from recursive_resolver import InvalidNameError

        with pytest.raises(InvalidNameError):
            offline_resolver().resolve(None, "A")  # type: ignore[arg-type]

    def test_idna_failure_is_reported_as_an_invalid_name(self) -> None:
        from recursive_resolver import InvalidNameError

        resolver = offline_resolver()
        with (
            patch("dns.name.from_text", side_effect=UnicodeError("bad idna")),
            pytest.raises(InvalidNameError) as exc,
        ):
            resolver.resolve("bad­.example", "A")
        assert "IDNA" in str(exc.value)

    def test_other_dns_errors_are_reported_as_invalid_names(self) -> None:
        from recursive_resolver import InvalidNameError

        resolver = offline_resolver()
        with (
            patch("dns.name.from_text", side_effect=dns.exception.SyntaxError("nope")),
            pytest.raises(InvalidNameError),
        ):
            resolver.resolve("weird.example", "A")


class TestLoopErrorPaths:
    def test_deadline_inside_the_delegation_loop(self) -> None:
        resolver = offline_resolver(max_resolution_time=0.05)
        calls = 0

        def send(qname, rdtype, nameservers, ctx):
            nonlocal calls
            calls += 1
            time.sleep(0.06)
            return root_to_com(), "198.41.0.4"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolutionTimeoutError):
            resolver.resolve("example.com", "A")

    def test_stale_glue_falls_back_to_resolving_ns_names(self) -> None:
        """Dead glue must not end the resolution while a live NS name exists."""
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx):
            if qname == dns.name.from_text("ns2.otherdns.net."):
                return make_response(answer=[("ns2.otherdns.net.", 300, "A", ["9.9.9.9"])]), "1.1.1.1"
            if nameservers and nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers == ["192.5.6.30"]:
                return (
                    referral(
                        "example.com.",
                        ["ns1.example.com.", "ns2.otherdns.net."],
                        {"ns1.example.com.": "203.0.113.9"},  # filtered: TEST-NET-3
                    ),
                    "192.5.6.30",
                )
            if nameservers == ["9.9.9.9"]:
                return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])]), "9.9.9.9"
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("example.com", "A") == ["1.2.3.4"]

    def test_dead_glue_with_no_alternative_fails_boundedly(self) -> None:
        """Dead glue plus an unresolvable NS name must fail without spinning."""
        from recursive_resolver import ResolverError

        resolver = offline_resolver()
        calls = 0

        def send(qname, rdtype, nameservers, ctx):
            nonlocal calls
            calls += 1
            if nameservers and nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers == ["192.5.6.30"]:
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "9.9.9.9"}), "192.5.6.30"
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ResolverError):
            resolver.resolve("example.com", "A")
        assert calls < 200, f"stale-glue fallback was not bounded: {calls} queries"

    def test_cname_chain_limit(self) -> None:
        resolver = offline_resolver(max_cname_chain=2)

        def send(qname, rdtype, nameservers, ctx):
            if nameservers and nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers == ["192.5.6.30"]:
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "9.9.9.9"}), "192.5.6.30"
            n = int(str(qname).split(".")[0][1:])
            return make_response(answer=[(str(qname), 300, "CNAME", [f"c{n + 1}.example.com."])]), "9.9.9.9"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(CNAMELoopError):
            resolver.resolve("c0.example.com", "A")

    def test_nxdomain_without_aa_is_not_trusted(self) -> None:
        resolver = offline_resolver()
        classification = resolver._classify_response(
            make_response(rcode=dns.rcode.NXDOMAIN, aa=False), EXAMPLE, dns.rdatatype.A, EXAMPLE
        )
        assert classification["type"] == "error"
        assert "AA" in classification["detail"]

    def test_nodata_without_aa_is_not_trusted(self) -> None:
        resolver = offline_resolver()
        response = make_response(
            authority=[("example.com.", 300, "SOA", ["ns1.example.com. a.example.com. 1 3600 900 604800 86400"])],
            aa=False,
        )
        classification = resolver._classify_response(response, EXAMPLE, dns.rdatatype.A, EXAMPLE)
        assert classification["type"] == "error"

    def test_require_authoritative_can_be_relaxed(self) -> None:
        resolver = offline_resolver(require_authoritative=False)
        classification = resolver._classify_response(
            make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])], aa=False),
            EXAMPLE,
            dns.rdatatype.A,
            EXAMPLE,
        )
        assert classification["type"] == "answer"

    def test_negative_ttl_without_an_soa(self) -> None:
        assert offline_resolver()._negative_ttl(make_response(), EXAMPLE, EXAMPLE) is None

    def test_delegation_is_not_cached_without_a_ttl(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        response = make_response(authority=[("example.com.", 0, "NS", ["ns1.example.com."])], aa=False)
        resolver._cache_delegation(EXAMPLE, [], ["9.9.9.9"], response, ValidationState.INSECURE)
        assert resolver.cache.get_delegation(EXAMPLE) is None

    def test_delegation_is_not_cached_without_addresses(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        response = make_response(authority=[("example.com.", 300, "NS", ["ns1.example.com."])], aa=False)
        resolver._cache_delegation(EXAMPLE, [], [], response, ValidationState.INSECURE)
        assert resolver.cache.get_delegation(EXAMPLE) is None

    def test_ns_resolution_stops_when_the_budget_is_gone(self) -> None:
        resolver = offline_resolver(limits=Limits(max_queries=1))
        ctx = resolver._new_context()
        ctx.budget.spend_query("x.", "A")
        assert resolver._resolve_ns_names([dns.name.from_text("ns.example.com.")], ctx, 1) == []

    def test_the_aaaa_lookup_is_skipped_once_the_budget_is_gone(self) -> None:
        """The A lookup can spend the last query; asking for AAAA anyway overruns."""
        resolver = offline_resolver(limits=Limits(max_queries=1), ipv4_only=False)
        ctx = resolver._new_context()
        asked = []

        def resolve(ns_name, rdtype, ctx_, depth, path):
            asked.append(rdtype)
            ctx_.budget.spend_query(str(ns_name), dns.rdatatype.to_text(rdtype))
            raise ServfailError(str(ns_name), dns.rdatatype.to_text(rdtype))

        with patch.object(resolver, "_resolve_iterative", side_effect=resolve):
            assert resolver._resolve_ns_names([dns.name.from_text("ns.example.com.")], ctx, 1) == []
        assert asked == [dns.rdatatype.A], "AAAA was queried with no budget left"

    def test_all_servers_erroring_raises_servfail(self) -> None:
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx):
            return make_response(rcode=dns.rcode.REFUSED, aa=False), nameservers[0]

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(ServfailError):
            resolver.resolve("example.com", "A")


class TestZoneKeyCache:
    def test_expired_keys_are_discarded(self) -> None:
        resolver = RecursiveResolver(dnssec=True)
        zone = dns.name.from_text("example.com.")
        keys = ZoneKeys(zone, None, ValidationState.SECURE)
        resolver._store_keys(keys, 3600)
        assert resolver._cached_keys(zone) is not None
        keys.expiry = time.monotonic() - 1
        assert resolver._cached_keys(zone) is None
        assert zone not in resolver._key_cache

    def test_unknown_zone(self) -> None:
        assert RecursiveResolver(dnssec=True)._cached_keys(dns.name.from_text("nope.test.")) is None


class TestNXDOMAINCaching:
    def test_nxdomain_below_a_cached_nxdomain_is_free(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_nxdomain(dns.name.from_text("gone.example.com."), ttl=300, secure=True)
        with patch.object(resolver, "_send_query") as send, pytest.raises(NXDOMAINError):
            resolver.resolve("a.b.gone.example.com", "MX")
        send.assert_not_called()


class TestFinalBranches:
    """The last few guards, each driven deliberately."""

    def test_module_main_runs_in_process(self) -> None:
        """runpy executes __main__ in-process so the guard itself is exercised."""
        import runpy

        with patch.object(sys, "argv", ["recursive-resolver", "--version"]), pytest.raises(SystemExit) as exc:
            runpy.run_module("recursive_resolver", run_name="__main__")
        assert exc.value.code == 0

    def test_verbose_enables_debug_logging(self) -> None:
        from test_cli import _answer as _cli_answer

        from recursive_resolver.cli import main

        with (
            patch("recursive_resolver.cli.RecursiveResolver") as cls,
            patch("recursive_resolver.cli.logging.basicConfig") as basic_config,
        ):
            cls.return_value.resolve_answer.return_value = _cli_answer()
            main(["-v", "example.com"])
        basic_config.assert_called_once()

    def test_construction_failure_exits_2(self, capsys: pytest.CaptureFixture) -> None:
        from recursive_resolver.cli import main

        with patch("recursive_resolver.cli.RecursiveResolver", side_effect=DNSSECUnavailableError()):
            assert main(["example.com"]) == 2
        assert "DNSSECUnavailableError" in capsys.readouterr().err

    def test_relative_names_are_absolutised(self) -> None:
        """Defensive guard: dnspython normally returns an absolute name."""
        resolver = offline_resolver()
        relative = dns.name.from_text("example.com", origin=None)
        assert not relative.is_absolute()
        with patch("dns.name.from_text", return_value=relative):
            assert resolver._normalize_qname("example.com", "A").is_absolute()

    def test_deadline_expiring_mid_loop(self) -> None:
        """The deadline is re-checked before every query, not just at entry."""
        resolver = offline_resolver()
        expired = iter([False, False, True])

        with (
            patch.object(resolver, "_send_query", return_value=(root_to_com(), "198.41.0.4")),
            patch(
                "recursive_resolver.budget.QueryBudget.expired",
                side_effect=lambda: next(expired, True),
            ),
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver.resolve("example.com", "A")

    def test_an_already_expired_budget_short_circuits(self) -> None:
        """A sub-resolution entered after the deadline must not send anything."""
        resolver = offline_resolver()
        with (
            patch("recursive_resolver.budget.QueryBudget.expired", return_value=True),
            patch.object(resolver, "_send_query") as send,
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver.resolve("example.com", "A")
        send.assert_not_called()

    def test_dead_glue_falls_back_to_a_live_ns_name(self) -> None:
        """Glue that passes the address filter but never answers."""
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx):
            # The in-zone NS name fails cheaply; the sibling one resolves.
            if qname == dns.name.from_text("ns1.example.com."):
                return make_response(rcode=dns.rcode.NXDOMAIN, aa=True), "192.5.6.30"
            if qname == dns.name.from_text("ns2.otherdns.net."):
                return make_response(answer=[("ns2.otherdns.net.", 300, "A", ["9.9.9.9"])]), "1.1.1.1"
            if nameservers and nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers == ["192.5.6.30"]:
                return (
                    referral(
                        "example.com.",
                        ["ns1.example.com.", "ns2.otherdns.net."],
                        {"ns1.example.com.": "5.5.5.5"},  # routable, passes the filter, never answers
                    ),
                    "192.5.6.30",
                )
            if nameservers == ["9.9.9.9"]:
                return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])]), "9.9.9.9"
            return (None, "")  # the dead glue never answers

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("example.com", "A") == ["1.2.3.4"]

    def test_additional_records_for_other_names_are_ignored(self) -> None:
        """Only glue for the referral's own NS names may be used."""
        resolver = offline_resolver()
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("unrelated.example.com.", 300, "A", ["9.9.9.9"])],
            aa=False,
        )
        glue = resolver._select_glue(
            response, [dns.name.from_text("ns1.example.com.")], dns.name.from_text("com."), EXAMPLE
        )
        assert glue == []

    def test_non_address_additional_records_are_ignored(self) -> None:
        resolver = offline_resolver()
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 300, "TXT", ['"not an address"'])],
            aa=False,
        )
        glue = resolver._select_glue(
            response, [dns.name.from_text("ns1.example.com.")], dns.name.from_text("com."), EXAMPLE
        )
        assert glue == []

    def test_aaaa_glue_is_ignored_in_ipv4_only_mode(self) -> None:
        resolver = offline_resolver(ipv4_only=True)
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 300, "AAAA", ["2001:500:2::c"])],
            aa=False,
        )
        glue = resolver._select_glue(
            response, [dns.name.from_text("ns1.example.com.")], dns.name.from_text("com."), EXAMPLE
        )
        assert glue == []

    def test_aaaa_glue_is_used_in_dual_stack_mode(self) -> None:
        resolver = offline_resolver(ipv4_only=False)
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 300, "AAAA", ["2001:500:2::c"])],
            aa=False,
        )
        glue = resolver._select_glue(
            response, [dns.name.from_text("ns1.example.com.")], dns.name.from_text("com."), EXAMPLE
        )
        assert glue == ["2001:500:2::c"]


class TestBranchCompleteness:
    """Remaining conditional arms, each with a real scenario behind it."""

    def test_importing_main_normally_skips_the_cli(self) -> None:
        import importlib

        sys.modules.pop("recursive_resolver.__main__", None)
        module = importlib.import_module("recursive_resolver.__main__")
        assert module.main is not None

    def test_cached_delegation_with_only_filtered_addresses_restarts_from_root(self) -> None:
        """A poisoned cache entry must not strand the resolution."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(
            Delegation(zone=dns.name.from_text("com."), addresses=["127.0.0.1", "10.0.0.1"]), ttl=3600
        )
        zone, servers, _state, _ds, _names = resolver._starting_point(EXAMPLE, dns.rdatatype.A)
        assert zone == dns.name.root
        assert servers == resolver._root_addresses

    def test_explicit_cname_query_skips_cname_chasing(self) -> None:
        """Asking for a CNAME means the CNAME is the answer, not a redirect."""
        resolver = offline_resolver()
        classification = resolver._classify_response(
            make_response(rcode=dns.rcode.NXDOMAIN, aa=True), EXAMPLE, dns.rdatatype.CNAME, EXAMPLE
        )
        assert classification["type"] == "nxdomain"

    def test_delegation_with_no_matching_ns_rrset_is_not_cached(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        response = make_response(
            authority=[
                ("other.com.", 300, "NS", ["ns1.other.com."]),
                ("example.com.", 300, "SOA", ["ns1.example.com. a.example.com. 1 3600 900 604800 86400"]),
            ],
            aa=False,
        )
        resolver._cache_delegation(EXAMPLE, [], ["9.9.9.9"], response, ValidationState.INSECURE)
        assert resolver.cache.get_delegation(EXAMPLE) is None

    def test_negative_ttl_ignores_unrelated_authority_records(self) -> None:
        resolver = offline_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "NS", ["ns1.example.com."]),
                ("other.test.", 300, "SOA", ["ns1.other.test. a.other.test. 1 3600 900 604800 60"]),
            ],
            aa=False,
        )
        assert resolver._negative_ttl(response, EXAMPLE, EXAMPLE) is None


class TestDSQueries:
    """A DS record is published by the parent zone, never by the child."""

    def test_warm_delegation_cache_does_not_route_ds_to_the_child(self) -> None:
        """Regression: an earlier A lookup cached the child's delegation, and the
        DS query was then sent to the child, which correctly answers NODATA."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.5.5.5"]), ttl=3600)
        zone, servers, _state, _ds, _names = resolver._starting_point(EXAMPLE, dns.rdatatype.DS)
        assert zone != EXAMPLE, "a DS query must not start at the child zone"
        assert servers != ["5.5.5.5"]

    def test_a_query_still_uses_the_child_delegation(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.5.5.5"]), ttl=3600)
        zone, servers, _state, _ds, _names = resolver._starting_point(EXAMPLE, dns.rdatatype.A)
        assert zone == EXAMPLE
        assert servers == ["5.5.5.5"]

    def test_ds_query_uses_the_parents_cached_delegation(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(Delegation(zone=dns.name.from_text("com."), addresses=["192.5.6.30"]), ttl=3600)
        resolver.cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.5.5.5"]), ttl=3600)
        zone, servers, _state, _ds, _names = resolver._starting_point(EXAMPLE, dns.rdatatype.DS)
        assert zone == dns.name.from_text("com.")
        assert servers == ["192.5.6.30"]

    def test_ds_at_the_root_has_no_parent_to_climb_to(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        zone, _servers, _state, _ds, _names = resolver._starting_point(dns.name.root, dns.rdatatype.DS)
        assert zone == dns.name.root

    def test_ds_in_a_referral_authority_is_the_answer(self) -> None:
        """Parents that reply with a referral still carry the DS in authority."""
        resolver = offline_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "DS", ["2371 13 2 " + "ab" * 32]),
                ("example.com.", 300, "NS", ["ns1.example.com."]),
            ],
            aa=False,
        )
        classification = resolver._classify_response(response, EXAMPLE, dns.rdatatype.DS, dns.name.from_text("com."))
        assert classification["type"] == "answer"
        assert classification["rrset"].rdtype == dns.rdatatype.DS

    def test_a_ds_query_never_descends_past_the_zone_cut(self) -> None:
        """Without a DS present, the parent has told us there is none."""
        resolver = offline_resolver()
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 300, "A", ["9.9.9.9"])],
            aa=False,
        )
        assert resolver._find_referral(response, EXAMPLE, dns.name.from_text("com."), dns.rdatatype.DS) is None
        # The same response is a normal referral for any other type.
        assert resolver._find_referral(response, EXAMPLE, dns.name.from_text("com."), dns.rdatatype.A) is not None

    def test_a_ds_query_below_the_cut_still_follows_referrals(self) -> None:
        """Only a delegation for the qname itself is off limits."""
        resolver = offline_resolver()
        response = make_response(
            authority=[("example.com.", 300, "NS", ["ns1.example.com."])],
            additional=[("ns1.example.com.", 300, "A", ["9.9.9.9"])],
            aa=False,
        )
        found = resolver._find_referral(
            response, dns.name.from_text("sub.example.com."), dns.name.from_text("com."), dns.rdatatype.DS
        )
        assert found is not None

    def test_ds_query_with_no_ds_in_the_authority(self) -> None:
        """The parent delegates but publishes no DS: the zone is unsigned."""
        resolver = offline_resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "NS", ["ns1.example.com."]),
                ("example.com.", 300, "NSEC3PARAM", ["1 0 10 AABBCCDD"]),
            ],
            aa=True,
        )
        classification = resolver._classify_response(response, EXAMPLE, dns.rdatatype.DS, dns.name.from_text("com."))
        assert classification["type"] == "nodata"


class TestStaleDelegationFallback:
    """A parent that still names a provider which has dropped the zone.

    This is common in the wild, and it is not a timeout: the stale servers
    answer promptly with REFUSED. Without a fallback to the referral's other NS
    names, the zone becomes unresolvable even though a working nameserver is
    named in the very same referral.
    """

    def test_refused_servers_fall_back_to_the_other_ns_names(self) -> None:
        resolver = offline_resolver()
        stale, live = "5.5.5.5", "9.9.9.9"

        def send(qname, rdtype, nameservers, ctx):
            # The out-of-zone NS name resolves to the live server.
            if qname == dns.name.from_text("live.example.net."):
                return make_response(answer=[("live.example.net.", 300, "A", [live])]), "1.1.1.1"
            if nameservers and nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers == ["192.5.6.30"]:
                # Glue only for the in-zone name, which points at the provider
                # that no longer serves the zone.
                return (
                    referral(
                        "example.com.",
                        ["ns-stale.example.com.", "live.example.net."],
                        {"ns-stale.example.com.": stale},
                    ),
                    "192.5.6.30",
                )
            if nameservers == [stale]:
                return make_response(rcode=dns.rcode.REFUSED, aa=False), stale
            if nameservers == [live]:
                return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])]), live
            return (None, "")

        with patch.object(resolver, "_send_query", side_effect=send):
            assert resolver.resolve("example.com", "A") == ["1.2.3.4"]

    def test_the_fallback_never_re_tries_addresses_already_used(self) -> None:
        resolver = offline_resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_ns_addresses", return_value=["9.9.9.9", "1.1.1.1"]):
            fresh = resolver._fallback_nameservers([dns.name.from_text("ns.example.net.")], {"9.9.9.9"}, ctx, 0)
        assert fresh == ["1.1.1.1"]

    def test_no_ns_names_means_no_fallback(self) -> None:
        resolver = offline_resolver()
        ctx = resolver._new_context()
        assert resolver._fallback_nameservers([], set(), ctx, 0) == []


class TestConstructorRejectsOutOfRangeEDNS:
    """Everything leaving this package is a `ResolverError`.

    An OPT record carries the payload size in the class field, so a value
    outside 16 bits reached dnspython as a bad rdclass and came back as a bare
    `ValueError` from inside the query path, long after the caller could tell
    what they had done wrong.
    """

    @pytest.mark.parametrize("payload", [70000, -3, 65536])
    def test_an_out_of_range_payload_is_refused_at_construction(self, payload: int) -> None:
        with pytest.raises(ValueError, match="edns_payload"):
            RecursiveResolver(edns_payload=payload)

    @pytest.mark.parametrize("payload", [0, 512, 1232, 65535])
    def test_the_usable_range_is_accepted(self, payload: int) -> None:
        assert RecursiveResolver(edns_payload=payload, dnssec=False).edns_payload == payload

    def test_nothing_but_a_resolver_error_escapes_resolve(self) -> None:
        """The contract the guard exists to keep."""
        resolver = offline_resolver(edns_payload=1232)
        with patch.object(resolver, "_send_query", return_value=(None, "")), pytest.raises(ResolverError):
            resolver.resolve("example.com", "A")


class TestConstructorArguments:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"timeout": 0},
            {"timeout": -1},
            {"max_resolution_time": 0},
            {"max_depth": 0},
            {"max_retries": -1},
            {"max_cname_chain": -1},
            {"clock_skew": -5},
        ],
    )
    def test_out_of_range_values_are_refused(self, kwargs: dict) -> None:
        """`--timeout -1` used to be accepted and reported every lookup as "all nameservers timed out"."""
        with pytest.raises(ValueError):
            RecursiveResolver(dnssec=False, **kwargs)

    def test_arguments_are_keyword_only(self) -> None:
        with pytest.raises(TypeError):
            RecursiveResolver(2.0)  # type: ignore[misc]

    @pytest.mark.parametrize("field", ["max_queries", "max_ns_per_referral", "max_nx_targets", "max_referrals"])
    def test_limits_are_validated(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            Limits(**{field: 0})
        with pytest.raises(TypeError):
            Limits(64)  # type: ignore[misc]


class TestExceptionsCrossProcessBoundaries:
    """Process pools and task queues pickle exceptions; most of ours used to fail to unpickle."""

    @pytest.mark.parametrize(
        "error",
        [
            NoAnswerError("x.example.", "TXT"),
            NXDOMAINError("x.example.", "A"),
            ServfailError("x.example.", "A", rcode=5, reason="refused"),
            QueryBudgetExceededError(None, None, "signature validations", 96),
            ResolutionTimeoutError("x.example.", "A"),
            MaxDepthError("x.example.", "A", 20),
            CNAMELoopError("x.example.", ["a.", "b."]),
            InvalidNameError("bad..name", "empty label"),
            UnsupportedRdtypeError("NOPE"),
            DNSSECValidationError("x.example.", "A", "RRSIG did not verify"),
            DNSSECInsecureError("x.example.", "A"),
            DNSSECMaterialUnavailableError("x.example.", "DNSKEY"),
            DNSSECUnavailableError(),
        ],
    )
    def test_every_error_survives_a_pickle_round_trip(self, error: ResolverError) -> None:
        import pickle

        error.query_name = "caller.example."
        again = pickle.loads(pickle.dumps(error))
        assert type(again) is type(error)
        assert str(again) == str(error)
        assert again.__dict__ == error.__dict__

    def test_the_callers_query_is_attached(self) -> None:
        """`qname` is where the failure happened; `query_name` is what was asked."""
        resolver = offline_resolver()

        def send(qname, rdtype, nameservers, ctx, usable=None):
            if qname == dns.name.from_text("www.example.com."):
                return make_response(answer=[("www.example.com.", 300, "CNAME", ["gone.example.net."])]), "9.9.9.9"
            return make_response(
                rcode=dns.rcode.NXDOMAIN, authority=[("example.net.", 300, "SOA", [SOA_TEXT])]
            ), "9.9.9.9"

        with patch.object(resolver, "_send_query", side_effect=send), pytest.raises(NXDOMAINError) as caught:
            resolver.resolve("www.example.com", "A")
        assert caught.value.qname == "gone.example.net."
        assert caught.value.query_name == "www.example.com."
        assert caught.value.query_type == "A"

    def test_a_budget_error_names_no_fake_query(self) -> None:
        with pytest.raises(QueryBudgetExceededError) as caught:
            QueryBudget(max_signature_validations=0).spend_signature_validation()
        assert caught.value.qname is None
        assert "<dnssec>" not in str(caught.value)


SOA_TEXT = "ns.example.net. admin.example.net. 1 3600 900 604800 300"


class TestTraceReportsTheOutcome:
    def test_the_error_is_kept_with_the_trace(self) -> None:
        resolver = offline_resolver()
        with patch.object(resolver, "_send_query", return_value=(make_response(rcode=dns.rcode.REFUSED), "9.9.9.9")):
            answer, trace = resolver.trace_answer("example.com", "A")
        assert answer is None
        assert isinstance(trace.error, ServfailError)

    def test_a_bogus_response_is_marked_bogus_in_its_step(self) -> None:
        """The step used to show the chain state it was sent under, "secure", for a forged answer."""
        resolver = RecursiveResolver(cache_enabled=False)
        response = make_response(answer=[("www.example.com.", 300, "A", ["1.2.3.4"])])
        start = (dns.name.from_text("example.com."), ["9.9.9.9", "1.1.1.1"], ValidationState.SECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_send_query", return_value=(response, "9.9.9.9")),
            patch.object(resolver, "_insecurely_delegated", return_value=False),
        ):
            answer, trace = resolver.trace_answer("www.example.com", "A")
        assert answer is None and isinstance(trace.error, DNSSECValidationError)
        assert trace[-1].dnssec == "bogus"


class TestPerResolutionMemory:
    """What one resolution learns about servers and names, it does not pay for twice."""

    ZONE = dns.name.from_text("example.com.")

    def _ctx(self, resolver: RecursiveResolver):
        return resolver._new_context()

    def test_servers_that_refused_the_zone_are_not_asked_again(self) -> None:
        resolver = offline_resolver()
        ctx = self._ctx(resolver)
        ctx.failed_servers.update({(self.ZONE, "9.9.9.9"), (self.ZONE, "1.1.1.1")})
        start = (self.ZONE, ["9.9.9.9", "1.1.1.1"], ValidationState.INSECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_send_query") as send,
            pytest.raises(ServfailError, match="refused"),
        ):
            resolver._resolve_iterative(dns.name.from_text("www.example.com."), dns.rdatatype.A, ctx, 0, [])
        send.assert_not_called()

    def test_their_zone_falls_back_to_its_other_names(self) -> None:
        resolver = offline_resolver()
        ctx = self._ctx(resolver)
        ctx.failed_servers.add((self.ZONE, "9.9.9.9"))
        start = (self.ZONE, ["9.9.9.9"], ValidationState.INSECURE, None, [dns.name.from_text("ns.example.net.")])
        good = make_response(answer=[("www.example.com.", 300, "A", ["1.2.3.4"])])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_ns_addresses", return_value=["8.8.8.8"]),
            patch.object(resolver, "_send_query", return_value=(good, "8.8.8.8")) as send,
        ):
            answer = resolver._resolve_iterative(dns.name.from_text("www.example.com."), dns.rdatatype.A, ctx, 0, [])
        assert answer.records == ["1.2.3.4"]
        assert send.call_args.args[2] == ["8.8.8.8"]

    def test_no_reachable_server_is_a_server_failure_not_a_timeout(self) -> None:
        import errno

        from recursive_resolver.resolver import _FatalServerError

        resolver = offline_resolver()
        start = (self.ZONE, ["9.9.9.9"], ValidationState.INSECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_query_once", side_effect=_FatalServerError("no", errno=errno.EHOSTUNREACH)),
            pytest.raises(ServfailError, match="reachable"),
        ):
            resolver.resolve("www.example.com", "A")

    def test_a_known_ns_address_is_reused(self) -> None:
        resolver = offline_resolver()
        ctx = self._ctx(resolver)
        name = dns.name.from_text("ns.example.net.")
        ctx.ns_addresses[(name, int(dns.rdatatype.A))] = ["8.8.8.8"]
        ctx.ns_addresses[(dns.name.from_text("dead.example.net."), int(dns.rdatatype.A))] = None
        with patch.object(resolver, "_resolve_iterative") as walk:
            assert resolver._ns_addresses(name, dns.rdatatype.A, ctx, 1) == ["8.8.8.8"]
            assert resolver._ns_addresses(dns.name.from_text("dead.example.net."), dns.rdatatype.A, ctx, 1) == []
        walk.assert_not_called()

    def test_nothing_fresh_means_no_fallback(self) -> None:
        resolver = offline_resolver()
        ctx = self._ctx(resolver)
        with patch.object(resolver, "_ns_addresses", return_value=["9.9.9.9"]):
            assert resolver._fallback_nameservers([dns.name.from_text("ns.example.net.")], {"9.9.9.9"}, ctx, 0) == []

    def test_an_unreachable_family_is_not_looked_up(self) -> None:
        resolver = offline_resolver(ipv4_only=False)
        ctx = self._ctx(resolver)
        ctx.unreachable_families.add(4)
        asked: list[int] = []

        def lookup(ns_name, rdtype, ctx_, depth):
            asked.append(rdtype)
            return []

        with patch.object(resolver, "_ns_addresses", side_effect=lookup):
            resolver._resolve_ns_names([dns.name.from_text("ns.example.net.")], ctx, 1)
        assert asked == [dns.rdatatype.AAAA]


class TestDelegationAndKeyLifetimes:
    def test_an_insecure_delegation_lives_no_longer_than_its_no_ds_proof(self) -> None:
        from signed_zone import SignedZone, rrset_of

        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        parent = SignedZone.create("com.")
        nsec = rrset_of("example.com.", "NSEC", "f.com. NS RRSIG NSEC")
        response = make_response(authority=[("example.com.", 3600, "NS", ["ns1.example.com."])], aa=False)
        response.authority += [nsec, parent.sign(nsec, expiration=int(time.time()) + 30)]
        args = (dns.name.from_text("example.com."), [dns.name.from_text("ns1.example.com.")], ["9.9.9.9"])
        resolver._cache_delegation(*args, response, ValidationState.INSECURE)
        entry = resolver.cache._cache[("DG", dns.name.from_text("example.com."), 0, 0)]
        assert entry.expiry - time.monotonic() <= 30

        resolver.cache.clear()
        response.authority[-1] = parent.sign(nsec, expiration=int(time.time()) - 1)
        resolver._cache_delegation(*args, response, ValidationState.INSECURE)
        assert resolver.cache.get_delegation(dns.name.from_text("example.com.")) is None

    @staticmethod
    def _unsigned_cut(proof_seconds: int | None, ns_ttl: int = 3600):
        """A referral to example.com, with a no-DS proof valid that long if asked for."""
        from signed_zone import SignedZone, rrset_of

        response = make_response(authority=[("example.com.", ns_ttl, "NS", ["ns1.example.com."])], aa=False)
        if proof_seconds is not None:
            nsec = rrset_of("example.com.", "NSEC", "f.com. NS RRSIG NSEC")
            signed = SignedZone.create("com.").sign(nsec, expiration=int(time.time()) + proof_seconds)
            response.authority += [nsec, signed]
        return (dns.name.from_text("example.com."), [dns.name.from_text("ns1.example.com.")], ["9.9.9.9"], response)

    @staticmethod
    def _lifetime(resolver: RecursiveResolver, zone: str = "example.com.") -> float:
        return resolver.cache._cache[("DG", dns.name.from_text(zone), 0, 0)].expiry - time.monotonic()

    def test_the_cache_floor_does_not_lift_it_past_that_proof(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True, min_ttl=600)
        resolver._cache_delegation(*self._unsigned_cut(30), ValidationState.INSECURE)
        assert self._lifetime(resolver) <= 30
        assert resolver.cache.get_delegation(dns.name.from_text("example.com.")).secure is False

    def test_the_cache_floor_still_applies_where_nothing_was_proven(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True, min_ttl=600)
        resolver._cache_delegation(*self._unsigned_cut(None, ns_ttl=60), ValidationState.INSECURE)
        assert self._lifetime(resolver) > 590

    def test_a_proof_from_a_ds_response_of_its_own_caps_the_cut_and_those_below(self) -> None:
        """The referral carries none of it, so the walk has to have kept it."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        ctx = resolver._new_context()
        ctx.unsigned_until[dns.name.from_text("example.com.")] = time.monotonic() + 30
        resolver._cache_delegation(*self._unsigned_cut(None), ValidationState.INSECURE, None, ctx)
        assert self._lifetime(resolver) <= 30

        below = make_response(authority=[("sub.example.com.", 3600, "NS", ["ns1.example.com."])], aa=False)
        args = (dns.name.from_text("sub.example.com."), [dns.name.from_text("ns1.example.com.")], ["9.9.9.9"])
        resolver._cache_delegation(*args, below, ValidationState.INSECURE, None, ctx)
        assert self._lifetime(resolver, "sub.example.com.") <= 30

        beside = make_response(authority=[("example.org.", 3600, "NS", ["ns1.example.com."])], aa=False)
        args = (dns.name.from_text("example.org."), [dns.name.from_text("ns1.example.com.")], ["9.9.9.9"])
        resolver._cache_delegation(*args, beside, ValidationState.INSECURE, None, ctx)
        assert self._lifetime(resolver, "example.org.") > 3590

    def test_the_ds_lookup_keeps_how_long_its_denial_holds(self) -> None:
        from signed_zone import SignedZone, rrset_of

        resolver = RecursiveResolver(dnssec=True)
        ctx = resolver._new_context()
        parent = SignedZone.create("com.")
        nsec = rrset_of("example.com.", "NSEC", "f.com. NS RRSIG NSEC")
        denial = make_response()
        denial.authority += [nsec, parent.sign(nsec, expiration=int(time.time()) + 30)]
        keys = ZoneKeys(parent.name, parent.dnskey_rrset, ValidationState.SECURE)
        child = dns.name.from_text("example.com.")
        with patch.object(resolver, "_send_query", return_value=(denial, "9.9.9.9")):
            state, _ds, is_cut = resolver._chain_step(child, keys, ["9.9.9.9"], ctx)
        assert (state, is_cut) == (ValidationState.INSECURE, True)
        assert 0 < ctx.unsigned_until[child] - time.monotonic() <= 30

    def test_a_referral_carrying_its_own_denial_keeps_it_for_the_cuts_below(self) -> None:
        from signed_zone import SignedZone, rrset_of

        resolver = RecursiveResolver(dnssec=True)
        ctx = resolver._new_context()
        parent = SignedZone.create("com.")
        nsec = rrset_of("example.com.", "NSEC", "f.com. NS RRSIG NSEC")
        referral_ = make_response(authority=[("example.com.", 3600, "NS", ["ns1.example.com."])], aa=False)
        referral_.authority += [nsec, parent.sign(nsec, expiration=int(time.time()) + 30)]
        keys = ZoneKeys(parent.name, parent.dnskey_rrset, ValidationState.SECURE)
        child = dns.name.from_text("example.com.")
        with patch.object(resolver, "_get_zone_keys", return_value=keys):
            state, _ds = resolver._advance_dnssec(
                referral_, child, parent.name, ["9.9.9.9"], ValidationState.SECURE, parent.ds_rdataset(parent), ctx
            )
        assert state is ValidationState.INSECURE
        assert 0 < ctx.unsigned_until[child] - time.monotonic() <= 30

    def test_a_lookup_resumed_at_an_unsigned_cut_caches_nothing_below_it_for_longer(self) -> None:
        """The zones below are unsigned on the strength of the same proof."""
        resolver = RecursiveResolver(dnssec=True, cache_enabled=True)
        resolver._cache_delegation(*self._unsigned_cut(30), ValidationState.INSECURE)
        cached = resolver.cache.get_delegation(dns.name.from_text("example.com."))
        assert 0 < cached.unsigned_until - time.monotonic() <= 30

        below = referral("sub.example.com.", ["ns1.sub.example.com."], {"ns1.sub.example.com.": "1.2.3.4"})
        answer = make_response(answer=[("www.sub.example.com.", 300, "A", ["5.6.7.8"])])
        replies = iter([below])
        with patch.object(resolver, "_send_query", side_effect=lambda *a, **k: (next(replies, answer), "9.9.9.9")):
            assert resolver.resolve("www.sub.example.com", "A") == ["5.6.7.8"]
        assert self._lifetime(resolver, "sub.example.com.") <= 30
        deeper = resolver.cache.get_delegation(dns.name.from_text("sub.example.com."))
        assert deeper.unsigned_until == pytest.approx(cached.unsigned_until, abs=1.5)

    def test_time_spent_before_caching_comes_off_what_the_ds_allows(self) -> None:
        """Resolving the NS names of a glueless referral can take seconds."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        ds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        ds.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, "1 13 2 " + "AB" * 32), ttl=30)
        validated = time.monotonic() - 10
        resolver._cache_delegation(*self._unsigned_cut(None), ValidationState.SECURE, ds, None, validated)
        assert self._lifetime(resolver) <= 20

    def test_the_walk_says_when_the_verdict_was_reached(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        answer = make_response(answer=[("www.example.com.", 300, "A", ["1.2.3.4"])])
        replies = iter([root_to_com(), referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"})])
        before = time.monotonic()
        with (
            patch.object(resolver, "_send_query", side_effect=lambda *a, **k: (next(replies, answer), "1.2.3.4")),
            patch.object(resolver, "_cache_delegation", wraps=resolver._cache_delegation) as cached,
        ):
            resolver.resolve("www.example.com", "A")
        assert cached.call_count == 2
        for call in cached.call_args_list:
            assert call.args[6] is not None
            assert before <= call.args[7] <= time.monotonic()

    def test_a_denial_lives_no_longer_than_the_records_proving_it(self) -> None:
        """RFC 4035 §5.3.3 counts the TTL the record arrived with, not only its signature's."""
        from signed_zone import SignedZone, rrset_of

        nsec = rrset_of("example.com.", "NSEC", "f.com. NS RRSIG NSEC", ttl=3600)
        signed = SignedZone.create("com.").sign(nsec)
        nsec.ttl = 20
        assert RecursiveResolver._denial_ttl_cap([nsec, signed]) == 20
        assert RecursiveResolver._denial_ttl_cap([nsec]) is None

    def test_without_dnssec_material_the_ns_ttl_stands(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        response = make_response(authority=[("example.com.", 600, "NS", ["ns1.example.com."])], aa=False)
        zone = dns.name.from_text("example.com.")
        resolver._cache_delegation(
            zone, [dns.name.from_text("ns1.example.com.")], ["9.9.9.9"], response, ValidationState.SECURE
        )
        entry = resolver.cache._cache[("DG", zone, 0, 0)]
        assert 590 < entry.expiry - time.monotonic() <= 600

    def test_keys_whose_signature_has_expired_are_not_cached(self) -> None:
        resolver = RecursiveResolver(dnssec=True)
        resolver._store_keys(ZoneKeys(dns.name.from_text("example.com."), None, ValidationState.SECURE), 0)
        assert resolver._cached_keys(dns.name.from_text("example.com.")) is None


class TestNegativeAnswersWithoutSOA:
    def test_they_are_not_cached(self) -> None:
        """RFC 2308 §5: no SOA, no TTL to cache by. They used to be held for 300 seconds."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        empty = make_response(aa=True)
        start = (dns.name.from_text("example.com."), ["9.9.9.9"], ValidationState.INSECURE, None, [])
        with (
            patch.object(resolver, "_starting_point", return_value=start),
            patch.object(resolver, "_send_query", return_value=(empty, "9.9.9.9")),
            pytest.raises(NoAnswerError),
        ):
            resolver.resolve("www.example.com", "MX")
        assert resolver.cache.get_nodata("www.example.com.", "MX") is None


class TestTheDeadlineIsPerCall:
    def test_a_waiter_that_gives_up_on_the_leader_has_no_time_of_its_own_left(self) -> None:
        """A caller that waited out its whole allowance must not then start a full resolution."""
        resolver = offline_resolver(max_resolution_time=0.2)
        started = threading.Event()
        release = threading.Event()
        calls = {"n": 0}

        def slow_send(qname, rdtype, nameservers, ctx, usable=None):
            calls["n"] += 1
            started.set()
            release.wait(2)
            return None, ""

        with patch.object(resolver, "_send_query", side_effect=slow_send):
            leader = threading.Thread(target=lambda: pytest.raises(ResolverError, resolver.resolve, "example.com"))
            leader.start()
            started.wait(2)
            begun = time.monotonic()
            with pytest.raises(ResolutionTimeoutError):
                resolver.resolve("example.com", "A")
            elapsed = time.monotonic() - begun
            release.set()
            leader.join()
        assert elapsed < 0.5
        assert calls["n"] == 1
