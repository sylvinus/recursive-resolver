"""Single-flight deduplication of concurrent identical resolutions.

Without this, N threads asking for the same name at the same moment each run a
full independent walk down the delegation tree: an N-times multiplier on
upstream query load, and on load against the root servers in particular.
Modelled on aiodnsresolver's ``in_progress`` map: the first caller does the
work, the rest wait and share its outcome, including its exception.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class _Call(Generic[T]):
    __slots__ = ("event", "value", "error")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.value: T | None = None
        self.error: BaseException | None = None


class SingleFlight(Generic[T]):
    """Collapse concurrent calls sharing a key into one execution."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[Any, _Call[T]] = {}

    def do(self, key: Any, fn: Callable[[], T], wait_timeout: float | None = None) -> T:
        """Run ``fn`` for ``key``, or wait for an in-flight call with the same key.

        If the leader raises, every waiter receives the same exception: a
        failure is shared, not retried N times in a stampede.
        """
        with self._lock:
            call = self._calls.get(key)
            if call is None:
                call = _Call[T]()
                self._calls[key] = call
                leader = True
            else:
                leader = False

        if leader:
            try:
                call.value = fn()
            except BaseException as exc:  # noqa: BLE001 - re-raised below and to waiters
                call.error = exc
                raise
            finally:
                with self._lock:
                    self._calls.pop(key, None)
                call.event.set()
            return call.value  # type: ignore[return-value]

        if not call.event.wait(timeout=wait_timeout):
            # The leader is taking too long; do the work ourselves rather than
            # blocking indefinitely on it.
            return fn()
        if call.error is not None:
            # Every waiter for this key re-raises the *same* exception object,
            # and each `raise` writes __traceback__ on it. Without this, several
            # threads concurrently append to one traceback and a caller ends up
            # inspecting frames from threads it never ran. Dropping it gives
            # each waiter a traceback rooted at its own call site.
            raise call.error.with_traceback(None)
        return call.value  # type: ignore[return-value]

    def in_flight(self) -> int:
        """Number of distinct keys currently being resolved."""
        with self._lock:
            return len(self._calls)
