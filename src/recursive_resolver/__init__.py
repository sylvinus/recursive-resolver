"""recursive-resolver: Pure-Python DNS recursive resolver — iterates from root servers, bypassing all caches."""

from .exceptions import (
    CNAMELoopError,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    ResolutionTimeoutError,
    ResolverError,
    ServfailError,
)
from .resolver import RecursiveResolver, TraceStep

__version__ = "0.1.0"

__all__ = [
    "RecursiveResolver",
    "TraceStep",
    "ResolverError",
    "NXDOMAINError",
    "NoAnswerError",
    "MaxDepthError",
    "ResolutionTimeoutError",
    "CNAMELoopError",
    "ServfailError",
    "__version__",
]
