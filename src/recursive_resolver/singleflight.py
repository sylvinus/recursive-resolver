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


def _per_waiter(error: BaseException) -> BaseException:
    """A distinct instance of ``error``, so no two threads share one object.

    ``raise`` writes ``__traceback__`` onto the exception it is handed, so
    giving every waiter the leader's instance has several threads appending to
    one traceback at once, and a caller ends up reading frames from threads it
    never ran.

    ``copy.copy`` cannot do this. These exceptions build their message in
    ``__init__`` out of several arguments while ``args`` holds only the
    finished string, so copy re-invokes ``__init__`` with the wrong arity: it
    raises ``TypeError`` for most of them and silently double-wraps the message
    for the rest. Bypassing ``__init__`` and carrying ``args``, ``__dict__``
    and ``__cause__`` across reproduces every :class:`ResolverError` exactly,
    which is all this class is ever asked to transport.

    ``OSError`` keeps ``errno`` and ``strerror`` in C-level state that is
    populated at construction and would not survive, so it is passed through
    untouched: a correct shared object beats a lossy private one. Anything else
    that cannot be rebuilt is returned as-is for the same reason. The leader
    catches ``BaseException``, so what arrives here is not a closed set, and
    the caller must get the real failure rather than an error from this
    function -- which is exactly what disqualified ``copy.copy``.
    """
    if isinstance(error, OSError):
        return error
    try:
        clone = error.__class__.__new__(error.__class__)
        clone.args = error.args
        clone.__dict__.update(error.__dict__)
        clone.__cause__ = error.__cause__
    except Exception:  # noqa: BLE001 - a messy traceback beats losing the error
        return error
    return clone


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
            raise _per_waiter(call.error)
        return call.value  # type: ignore[return-value]

    def in_flight(self) -> int:
        """Number of distinct keys currently being resolved."""
        with self._lock:
            return len(self._calls)
