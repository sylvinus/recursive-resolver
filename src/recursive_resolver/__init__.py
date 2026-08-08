"""recursive-resolver: Pure-Python DNS recursive resolver that iterates from the root servers."""

from .addresses import AddressFilter
from .budget import Limits
from .cache import DNSCache
from .dnssec import ValidationState
from .exceptions import (
    CNAMELoopError,
    DNSSECError,
    DNSSECInsecureError,
    DNSSECUnavailableError,
    DNSSECValidationError,
    InvalidNameError,
    MaxDepthError,
    NoAnswerError,
    NXDOMAINError,
    QueryBudgetExceededError,
    ResolutionTimeoutError,
    ResolverError,
    ServfailError,
    UnsupportedRdtypeError,
)
from .resolver import Answer, RecursiveResolver, TraceStep

__version__ = "0.1.0"

__all__ = [
    "RecursiveResolver",
    "Answer",
    "TraceStep",
    "ValidationState",
    "Limits",
    "DNSCache",
    "AddressFilter",
    # Exceptions
    "ResolverError",
    "NXDOMAINError",
    "NoAnswerError",
    "MaxDepthError",
    "ResolutionTimeoutError",
    "CNAMELoopError",
    "ServfailError",
    "InvalidNameError",
    "UnsupportedRdtypeError",
    "QueryBudgetExceededError",
    "DNSSECError",
    "DNSSECValidationError",
    "DNSSECInsecureError",
    "DNSSECUnavailableError",
    "__version__",
]
