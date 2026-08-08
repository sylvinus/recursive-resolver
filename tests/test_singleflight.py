"""Tests for concurrent-resolution deduplication."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest
from conftest import make_response, referral, root_to_com

from recursive_resolver import RecursiveResolver
from recursive_resolver.singleflight import SingleFlight


class TestSingleFlight:
    def test_concurrent_calls_run_once(self) -> None:
        sf: SingleFlight[int] = SingleFlight()
        calls = 0
        started = threading.Event()

        def work() -> int:
            nonlocal calls
            calls += 1
            started.set()
            time.sleep(0.2)
            return 42

        results: list[int] = []
        threads = [threading.Thread(target=lambda: results.append(sf.do("k", work))) for _ in range(8)]
        threads[0].start()
        started.wait(timeout=2)
        for t in threads[1:]:
            t.start()
        for t in threads:
            t.join()

        assert calls == 1
        assert results == [42] * 8

    def test_different_keys_run_independently(self) -> None:
        sf: SingleFlight[str] = SingleFlight()
        assert sf.do("a", lambda: "A") == "A"
        assert sf.do("b", lambda: "B") == "B"

    def test_failure_is_shared_with_waiters(self) -> None:
        sf: SingleFlight[int] = SingleFlight()
        started = threading.Event()
        errors: list[BaseException] = []

        def work() -> int:
            started.set()
            time.sleep(0.15)
            raise ValueError("boom")

        def waiter() -> None:
            try:
                sf.do("k", work)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        leader = threading.Thread(target=waiter)
        leader.start()
        started.wait(timeout=2)
        others = [threading.Thread(target=waiter) for _ in range(3)]
        for t in others:
            t.start()
        for t in [leader, *others]:
            t.join()

        assert len(errors) == 4
        assert all(isinstance(e, ValueError) for e in errors)

    def test_key_is_released_after_completion(self) -> None:
        sf: SingleFlight[int] = SingleFlight()
        sf.do("k", lambda: 1)
        assert sf.in_flight() == 0
        with pytest.raises(ValueError):
            sf.do("k", lambda: (_ for _ in ()).throw(ValueError()))
        assert sf.in_flight() == 0


class TestResolverDeduplication:
    def test_thundering_herd_is_collapsed(self) -> None:
        """24 threads asking for one name must not run 24 independent walks."""
        resolver = RecursiveResolver(dnssec=False, cache_enabled=True)
        queries = 0
        lock = threading.Lock()

        def send(qname, rdtype, nameservers, ctx):
            nonlocal queries
            with lock:
                queries += 1
            time.sleep(0.02)
            if nameservers[0] in resolver._root_addresses:
                return root_to_com(), nameservers[0]
            if nameservers[0] == "192.5.6.30":
                return referral("example.com.", ["ns1.example.com."], {"ns1.example.com.": "1.2.3.4"}), "192.5.6.30"
            return make_response(answer=[("example.com.", 300, "A", ["9.9.9.9"])]), "1.2.3.4"

        results: list[list[str]] = []
        with patch.object(resolver, "_send_query", side_effect=send):
            threads = [
                threading.Thread(target=lambda: results.append(resolver.resolve("example.com", "A"))) for _ in range(24)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert all(r == ["9.9.9.9"] for r in results)
        assert len(results) == 24
        # One full walk is 3 queries; without deduplication this was ~72.
        assert queries <= 12, f"expected the herd to be collapsed, got {queries} queries"
