"""Coverage of construction, configuration and the less-travelled error paths.

Error paths in a resolver are exactly the paths a hostile zone drives, so they
are exercised explicitly rather than left to chance.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from unittest.mock import patch

import dns.exception
import dns.name
import dns.rcode
import dns.rdatatype
import pytest
from conftest import make_response, referral, root_to_com

from recursive_resolver import (
    AddressFilter,
    CNAMELoopError,
    DNSSECUnavailableError,
    Limits,
    NXDOMAINError,
    QueryBudgetExceededError,
    RecursiveResolver,
    ResolutionTimeoutError,
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


def _resolver(**kwargs) -> RecursiveResolver:
    kwargs.setdefault("dnssec", False)
    kwargs.setdefault("cache_enabled", False)
    return RecursiveResolver(**kwargs)


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

    def test_idna_2008_is_preferred(self) -> None:
        assert RecursiveResolver._default_idna_codec() is dns.name.IDNA_2008_Practical

    def test_idna_2003_fallback_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """Without the idna package we must say so: the results differ."""
        with patch.object(dns.name, "have_idna_2008", False), caplog.at_level("WARNING"):
            codec = RecursiveResolver._default_idna_codec()
        assert codec is dns.name.IDNA_2003
        assert "IDNA 2008 unavailable" in caplog.text

    def test_ipv6_mode_includes_v6_roots(self) -> None:
        resolver = _resolver(ipv4_only=False)
        assert any(":" in a for a in resolver._root_addresses)


class TestInputValidationEdges:
    def test_meta_rdtypes_are_refused(self) -> None:
        with pytest.raises(UnsupportedRdtypeError) as exc:
            _resolver().resolve("example.com", "AXFR")
        assert "meta" in str(exc.value)

    def test_any_is_permitted(self) -> None:
        assert _resolver()._parse_rdtype("ANY") == dns.rdatatype.ANY

    def test_relative_names_are_made_absolute(self) -> None:
        assert _resolver()._normalize_qname("example.com", "A").is_absolute()

    def test_non_string_input(self) -> None:
        from recursive_resolver import InvalidNameError

        with pytest.raises(InvalidNameError):
            _resolver().resolve(None, "A")  # type: ignore[arg-type]

    def test_idna_failure_is_reported_as_an_invalid_name(self) -> None:
        from recursive_resolver import InvalidNameError

        resolver = _resolver()
        with (
            patch("dns.name.from_text", side_effect=UnicodeError("bad idna")),
            pytest.raises(InvalidNameError) as exc,
        ):
            resolver.resolve("bad­.example", "A")
        assert "IDNA" in str(exc.value)

    def test_other_dns_errors_are_reported_as_invalid_names(self) -> None:
        from recursive_resolver import InvalidNameError

        resolver = _resolver()
        with (
            patch("dns.name.from_text", side_effect=dns.exception.SyntaxError("nope")),
            pytest.raises(InvalidNameError),
        ):
            resolver.resolve("weird.example", "A")


class TestLoopErrorPaths:
    def test_deadline_inside_the_delegation_loop(self) -> None:
        resolver = _resolver(max_resolution_time=0.05)
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
        resolver = _resolver()

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

        resolver = _resolver()
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
        resolver = _resolver(max_cname_chain=2)

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
        resolver = _resolver()
        classification = resolver._classify_response(
            make_response(rcode=dns.rcode.NXDOMAIN, aa=False), EXAMPLE, dns.rdatatype.A, EXAMPLE
        )
        assert classification["type"] == "error"
        assert "AA" in classification["detail"]

    def test_nodata_without_aa_is_not_trusted(self) -> None:
        resolver = _resolver()
        response = make_response(
            authority=[("example.com.", 300, "SOA", ["ns1.example.com. a.example.com. 1 3600 900 604800 86400"])],
            aa=False,
        )
        classification = resolver._classify_response(response, EXAMPLE, dns.rdatatype.A, EXAMPLE)
        assert classification["type"] == "error"

    def test_require_authoritative_can_be_relaxed(self) -> None:
        resolver = _resolver(require_authoritative=False)
        classification = resolver._classify_response(
            make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])], aa=False),
            EXAMPLE,
            dns.rdatatype.A,
            EXAMPLE,
        )
        assert classification["type"] == "answer"

    def test_negative_ttl_without_an_soa(self) -> None:
        assert _resolver()._negative_ttl(make_response(), EXAMPLE) is None

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
        resolver = _resolver(limits=Limits(max_queries=1))
        ctx = resolver._new_context()
        ctx.budget.spend_query("x.", "A")
        assert resolver._resolve_ns_names([dns.name.from_text("ns.example.com.")], ctx, 1, limit=5) == []

    def test_all_servers_erroring_raises_servfail(self) -> None:
        resolver = _resolver()

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
        resolver.cache.put_nxdomain(dns.name.from_text("gone.example.com."), ttl=300)
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
        resolver = _resolver()
        relative = dns.name.from_text("example.com", origin=None)
        assert not relative.is_absolute()
        with patch("dns.name.from_text", return_value=relative):
            assert resolver._normalize_qname("example.com", "A").is_absolute()

    def test_deadline_expiring_mid_loop(self) -> None:
        """The deadline is re-checked before every query, not just at entry."""
        resolver = _resolver()
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
        resolver = _resolver()
        with (
            patch("recursive_resolver.budget.QueryBudget.expired", return_value=True),
            patch.object(resolver, "_send_query") as send,
            pytest.raises(ResolutionTimeoutError),
        ):
            resolver.resolve("example.com", "A")
        send.assert_not_called()

    def test_dead_glue_falls_back_to_a_live_ns_name(self) -> None:
        """Glue that passes the address filter but never answers."""
        resolver = _resolver()

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
        resolver = _resolver()
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
        resolver = _resolver()
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
        resolver = _resolver(ipv4_only=True)
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
        resolver = _resolver(ipv4_only=False)
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
        zone, servers, _state, _ds = resolver._starting_point(EXAMPLE, dns.rdatatype.A)
        assert zone == dns.name.root
        assert servers == resolver._root_addresses

    def test_explicit_cname_query_skips_cname_chasing(self) -> None:
        """Asking for a CNAME means the CNAME is the answer, not a redirect."""
        resolver = _resolver()
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
        resolver = _resolver()
        response = make_response(
            authority=[
                ("example.com.", 300, "NS", ["ns1.example.com."]),
                ("other.test.", 300, "SOA", ["ns1.other.test. a.other.test. 1 3600 900 604800 60"]),
            ],
            aa=False,
        )
        assert resolver._negative_ttl(response, EXAMPLE) is None


class TestDSQueries:
    """A DS record is published by the parent zone, never by the child."""

    def test_warm_delegation_cache_does_not_route_ds_to_the_child(self) -> None:
        """Regression: an earlier A lookup cached the child's delegation, and the
        DS query was then sent to the child, which correctly answers NODATA."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.5.5.5"]), ttl=3600)
        zone, servers, _state, _ds = resolver._starting_point(EXAMPLE, dns.rdatatype.DS)
        assert zone != EXAMPLE, "a DS query must not start at the child zone"
        assert servers != ["5.5.5.5"]

    def test_a_query_still_uses_the_child_delegation(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.5.5.5"]), ttl=3600)
        zone, servers, _state, _ds = resolver._starting_point(EXAMPLE, dns.rdatatype.A)
        assert zone == EXAMPLE
        assert servers == ["5.5.5.5"]

    def test_ds_query_uses_the_parents_cached_delegation(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        resolver.cache.put_delegation(Delegation(zone=dns.name.from_text("com."), addresses=["192.5.6.30"]), ttl=3600)
        resolver.cache.put_delegation(Delegation(zone=EXAMPLE, addresses=["5.5.5.5"]), ttl=3600)
        zone, servers, _state, _ds = resolver._starting_point(EXAMPLE, dns.rdatatype.DS)
        assert zone == dns.name.from_text("com.")
        assert servers == ["192.5.6.30"]

    def test_ds_at_the_root_has_no_parent_to_climb_to(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        zone, _servers, _state, _ds = resolver._starting_point(dns.name.root, dns.rdatatype.DS)
        assert zone == dns.name.root

    def test_ds_in_a_referral_authority_is_the_answer(self) -> None:
        """Parents that reply with a referral still carry the DS in authority."""
        resolver = _resolver()
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
        resolver = _resolver()
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
        resolver = _resolver()
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
        resolver = _resolver()
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
        resolver = _resolver()
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
        resolver = _resolver()
        ctx = resolver._new_context()
        with patch.object(resolver, "_resolve_ns_names", return_value=["9.9.9.9", "1.1.1.1"]):
            fresh = resolver._fallback_nameservers([dns.name.from_text("ns.example.net.")], {"9.9.9.9"}, ctx, 0)
        assert fresh == ["1.1.1.1"]

    def test_no_ns_names_means_no_fallback(self) -> None:
        resolver = _resolver()
        ctx = resolver._new_context()
        assert resolver._fallback_nameservers([], set(), ctx, 0) == []
