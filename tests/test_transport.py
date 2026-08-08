"""Transport-layer behaviour: how dnspython failures are translated and retried.

These are the paths a hostile or broken nameserver drives, so each one needs to
be exercised deliberately rather than assumed.
"""

from __future__ import annotations

import errno
from unittest.mock import patch

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import pytest
from conftest import make_response

from recursive_resolver import RecursiveResolver
from recursive_resolver.resolver import _FatalServerError, _MalformedResponseError, _RetryableError

QNAME = dns.name.from_text("example.com.")


def _resolver(**kwargs) -> RecursiveResolver:
    kwargs.setdefault("dnssec", False)
    kwargs.setdefault("cache_enabled", False)
    return RecursiveResolver(**kwargs)


def _query_once(resolver: RecursiveResolver, payload: int | None = 1232):
    ctx = resolver._new_context()
    return resolver._query_once(QNAME, dns.rdatatype.A, "9.9.9.9", payload, 1.0, ctx)


class TestExceptionTranslation:
    """Every dnspython failure must map to a deliberate internal signal."""

    def test_timeout_is_retryable(self) -> None:
        resolver = _resolver()
        with patch("dns.query.udp_with_fallback", side_effect=dns.exception.Timeout), pytest.raises(_RetryableError):
            _query_once(resolver)

    def test_eof_is_retryable(self) -> None:
        """dnspython raises EOFError when a TCP peer closes mid-response."""
        resolver = _resolver()
        with patch("dns.query.udp_with_fallback", side_effect=EOFError("EOF")), pytest.raises(_RetryableError):
            _query_once(resolver)

    @pytest.mark.parametrize("code", [errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL])
    def test_unreachable_errnos_abandon_the_server(self, code: int) -> None:
        """No address family here means retrying is pointless."""
        resolver = _resolver()
        with (
            patch("dns.query.udp_with_fallback", side_effect=OSError(code, "unreachable")),
            pytest.raises(_FatalServerError),
        ):
            _query_once(resolver)

    def test_other_oserrors_are_retryable(self) -> None:
        resolver = _resolver()
        with (
            patch("dns.query.udp_with_fallback", side_effect=OSError(errno.ECONNREFUSED, "refused")),
            pytest.raises(_RetryableError),
        ):
            _query_once(resolver)

    def test_unexpected_source_is_retryable_not_malformed(self) -> None:
        """A stray packet must not be treated as 'this server speaks bad DNS'."""
        resolver = _resolver()
        with (
            patch("dns.query.udp_with_fallback", side_effect=dns.query.UnexpectedSource("bad source")),
            pytest.raises(_RetryableError),
        ):
            _query_once(resolver)

    def test_form_error_is_malformed(self) -> None:
        resolver = _resolver()
        with (
            patch("dns.query.udp_with_fallback", side_effect=dns.exception.FormError("bad wire")),
            pytest.raises(_MalformedResponseError),
        ):
            _query_once(resolver)

    def test_bad_response_is_malformed(self) -> None:
        """BadResponse (ID/question mismatch) is a FormError subclass."""
        resolver = _resolver()
        with (
            patch("dns.query.udp_with_fallback", side_effect=dns.query.BadResponse),
            pytest.raises(_MalformedResponseError),
        ):
            _query_once(resolver)

    def test_other_dns_exceptions_are_malformed(self) -> None:
        resolver = _resolver()
        with (
            patch("dns.query.udp_with_fallback", side_effect=dns.exception.SyntaxError("nope")),
            pytest.raises(_MalformedResponseError),
        ):
            _query_once(resolver)

    def test_truncation_without_tcp_fallback_is_retryable(self) -> None:
        resolver = _resolver(use_tcp_fallback=False)
        truncated = make_response(answer=[("example.com.", 300, "A", ["1.1.1.1"])], tc=True)
        with (
            patch("dns.query.udp", side_effect=dns.message.Truncated(message=truncated)),
            pytest.raises(_RetryableError),
        ):
            _query_once(resolver)

    def test_plain_udp_path_requests_truncation_errors(self) -> None:
        """The no-EDNS path must not silently accept a partial answer."""
        resolver = _resolver(use_tcp_fallback=False)
        good = make_response(answer=[("example.com.", 300, "A", ["1.1.1.1"])])
        with patch("dns.query.udp", return_value=good) as udp:
            _query_once(resolver, payload=None)
        assert udp.call_args.kwargs["raise_on_truncation"] is True

    def test_no_edns_query_carries_no_opt_record(self) -> None:
        resolver = _resolver(use_tcp_fallback=False)
        good = make_response(answer=[("example.com.", 300, "A", ["1.1.1.1"])])
        with patch("dns.query.udp", return_value=good) as udp:
            _query_once(resolver, payload=None)
        assert udp.call_args.args[0].edns == -1, "EDNS should be disabled on the plain path"

    def test_rd_bit_is_always_cleared(self) -> None:
        """We iterate ourselves; asking a server to recurse would be wrong."""
        import dns.flags

        resolver = _resolver()
        good = make_response(answer=[("example.com.", 300, "A", ["1.1.1.1"])])
        with patch("dns.query.udp_with_fallback", return_value=(good, False)) as udp:
            _query_once(resolver)
        assert not (udp.call_args.args[0].flags & dns.flags.RD)


class TestServerRotation:
    def test_fatal_error_moves_to_the_next_server(self) -> None:
        # Server order is normally shuffled; pin it so the assertion is precise.
        resolver = _resolver()
        tried: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            tried.append(server)
            if server == "1.1.1.1":
                raise _FatalServerError("no route")
            return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])

        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            patch("recursive_resolver.resolver.random.shuffle", lambda seq: None),
        ):
            ctx = resolver._new_context()
            response, server = resolver._send_query(QNAME, dns.rdatatype.A, ["1.1.1.1", "9.9.9.9"], ctx)
        assert response is not None
        assert server == "9.9.9.9"
        assert tried.count("1.1.1.1") == 1, "a fatal server must not be retried"

    def test_malformed_response_downgrades_edns_once_then_gives_up(self) -> None:
        resolver = _resolver(max_retries=3)
        payloads: list[int | None] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            payloads.append(payload)
            raise _MalformedResponseError("garbage")

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(QNAME, dns.rdatatype.A, ["9.9.9.9"], ctx)
        assert response is None
        assert payloads == [1232, None], "one EDNS downgrade, then abandon the server"

    def test_deadline_stops_the_send_loop(self) -> None:
        resolver = _resolver(max_resolution_time=0.0)
        ctx = resolver._new_context()
        response, server = resolver._send_query(QNAME, dns.rdatatype.A, ["9.9.9.9"], ctx)
        assert response is None
        assert server == ""

    def test_no_usable_servers_returns_nothing(self) -> None:
        """Every candidate filtered out as non-public."""
        resolver = _resolver()
        ctx = resolver._new_context()
        response, server = resolver._send_query(QNAME, dns.rdatatype.A, ["127.0.0.1", "10.0.0.1"], ctx)
        assert response is None
        assert server == ""


class TestServerOrdering:
    def test_servers_are_shuffled(self) -> None:
        """Deterministic ordering would make one server absorb all first-tries."""
        resolver = _resolver()
        candidates = [f"9.9.9.{i}" for i in range(1, 30)]
        orders = {tuple(resolver._order_servers(candidates)) for _ in range(20)}
        assert len(orders) > 1, "server order should vary between calls"

    def test_ordering_drops_non_public_addresses(self) -> None:
        resolver = _resolver()
        ordered = resolver._order_servers(["9.9.9.9", "127.0.0.1", "10.0.0.1", "1.1.1.1"])
        assert sorted(ordered) == ["1.1.1.1", "9.9.9.9"]


class TestBreadthFirstSweep:
    """Every server is tried once before any is retried.

    Retrying one server to exhaustion before touching the next lets a single
    dead nameserver consume the whole budget while a healthy sibling sits
    unused, which is what made several stale-delegation domains unresolvable.
    """

    def test_a_dead_server_does_not_delay_a_healthy_one(self) -> None:
        resolver = _resolver(max_retries=2)
        order: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            order.append(server)
            if server == "1.1.1.1":
                raise _RetryableError("blackholed")
            return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])

        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            patch("recursive_resolver.resolver.random.shuffle", lambda seq: None),
        ):
            ctx = resolver._new_context()
            response, server = resolver._send_query(QNAME, dns.rdatatype.A, ["1.1.1.1", "9.9.9.9"], ctx)

        assert response is not None and server == "9.9.9.9"
        assert order == ["1.1.1.1", "9.9.9.9"], "the healthy server must be reached on the first sweep"

    def test_all_servers_abandoned_stops_immediately(self) -> None:
        """No point sweeping again when every server is unreachable."""
        resolver = _resolver(max_retries=5)
        calls = 0

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            nonlocal calls
            calls += 1
            raise _FatalServerError("no route to host")

        with patch.object(resolver, "_query_once", side_effect=query_once):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(QNAME, dns.rdatatype.A, ["1.1.1.1", "9.9.9.9"], ctx)

        assert response is None
        assert calls == 2, "each server abandoned once, no further sweeps"

    def test_edns_downgrade_is_remembered_per_server(self) -> None:
        resolver = _resolver(max_retries=2)
        seen: list[tuple[str, int | None]] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            seen.append((server, payload))
            if server == "1.1.1.1" and payload is not None:
                return make_response(rcode=dns.rcode.NOTIMP, aa=False)
            if server == "1.1.1.1":
                return make_response(answer=[("example.com.", 300, "A", ["1.2.3.4"])])
            raise _RetryableError("quiet")

        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            patch("recursive_resolver.resolver.random.shuffle", lambda seq: None),
        ):
            ctx = resolver._new_context()
            response, server = resolver._send_query(QNAME, dns.rdatatype.A, ["1.1.1.1", "9.9.9.9"], ctx)

        assert response is not None and server == "1.1.1.1"
        assert ("1.1.1.1", None) in seen, "the EDNS-less retry must target the same server"

    def test_an_abandoned_server_is_skipped_on_later_sweeps(self) -> None:
        """Once a server is unreachable, later sweeps must not query it again."""
        resolver = _resolver(max_retries=2)
        attempts: list[str] = []

        def query_once(qname, rdtype, server, payload, timeout, ctx):
            attempts.append(server)
            if server == "1.1.1.1":
                raise _FatalServerError("no route to host")
            raise _RetryableError("quiet")

        with (
            patch.object(resolver, "_query_once", side_effect=query_once),
            patch("recursive_resolver.resolver.random.shuffle", lambda seq: None),
        ):
            ctx = resolver._new_context()
            response, _ = resolver._send_query(QNAME, dns.rdatatype.A, ["1.1.1.1", "9.9.9.9"], ctx)

        assert response is None
        assert attempts.count("1.1.1.1") == 1, "the abandoned server must not be retried"
        assert attempts.count("9.9.9.9") == 3, "the quiet server is retried on every sweep"
