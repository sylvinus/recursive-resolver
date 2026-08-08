"""Per-resolution work budget.

A single ``resolve()`` call fans out: referrals lead to more referrals, and a
glueless referral makes us resolve each NS hostname, each of which is itself a
full resolution that may fan out again.  Bounding only the recursion *depth*
leaves the branching factor unbounded: a hostile zone that answers every
query with a glueless referral to 50 fresh NS names can provoke tens of
thousands of upstream queries from one call, which is the NXNSAttack
(CVE-2020-8616, CVE-2020-12662) and the Non-Responsive Delegation attack
(CVE-2022-3204).

Every production resolver therefore carries a counter that is *shared with
sub-resolutions*.  This module is that counter.  Reference values:

===================  ==================================  =======
Resolver             Setting                             Value
===================  ==================================  =======
BIND 9               ``max-recursion-queries``           32
PowerDNS Recursor    ``max-qperq``                       50
Unbound              ``MAX_TARGET_COUNT``                64
Unbound              ``MAX_TARGET_NX``                   5
PowerDNS Recursor    ``max-ns-per-resolve``              13
Unbound              ``MAX_REFERRAL_COUNT``              130
===================  ==================================  =======
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .exceptions import QueryBudgetExceededError

# Unbound's MAX_TARGET_COUNT. Higher than BIND's 32 because we always walk from
# the root on a cold delegation cache, which costs a few extra queries per name.
DEFAULT_MAX_QUERIES = 64

# Unbound's MAX_TARGET_NX. The core NXNSAttack control: an attacker's NS names
# deliberately do not resolve, so cap how many failures we will absorb.
DEFAULT_MAX_NX_TARGETS = 5

# Unbound's MAX_REFERRAL_COUNT.
DEFAULT_MAX_REFERRALS = 130

# PowerDNS's max-ns-per-resolve.
DEFAULT_MAX_NS_PER_REFERRAL = 13

# DNSSEC crypto work limits (KeyTrap, CVE-2023-50387 / CVE-2023-50868). A
# malicious zone can publish many DNSKEYs and many colliding RRSIGs so that a
# validator performs O(keys x signatures) expensive operations for a single
# answer.
#
# The quadratic blowup is already killed per-RRset by the tag trimming in
# dnssec.py (at most MAX_RRSIGS_PER_RRSET attempts however many keys and
# signatures a zone publishes); this is the defence-in-depth global bound.
#
# PowerDNS uses 30, but it validates against a warm cache. We walk from the
# root on a cold cache, where the measured worst case across deep signed
# chains, including ones reached through a CNAME, is 19.
# 96 leaves ~5x headroom while still bounding an attacker to a few
# milliseconds of CPU per query.
DEFAULT_MAX_SIGNATURE_VALIDATIONS = 96
DEFAULT_MAX_NSEC3_HASHES = 600


@dataclass(frozen=True)
class Limits:
    """Immutable hardening limits, shared by every resolution a resolver runs.

    These exist because of specific attacks rather than because anyone wants to
    tune them, and they move as a set: raising ``max_queries`` without raising
    ``max_referrals`` just moves which counter fires first. Grouping them keeps
    the resolver constructor honest about that, and lets a limit be added for
    the next CVE without changing its signature.

    The defaults are the reference values in the table above. Raise them only
    if you have measured a legitimate name that needs the headroom; every one
    of them is a bound on what a hostile zone can make you do.

    Args:
        max_queries: Total upstream DNS queries allowed for one ``resolve()``,
            including every sub-resolution of an NS hostname.
        max_ns_per_referral: NS hostnames chased when a referral arrives
            without usable glue.
        max_nx_targets: NS-hostname resolutions allowed to fail before the
            call is abandoned. The core NXNSAttack control.
        max_referrals: Referrals allowed to be followed in one call.
        max_signature_validations: RRSIG verifications allowed in one call
            (KeyTrap).
        max_nsec3_hashes: NSEC3 hash computations allowed in one call
            (KeyTrap).
    """

    max_queries: int = DEFAULT_MAX_QUERIES
    max_ns_per_referral: int = DEFAULT_MAX_NS_PER_REFERRAL
    max_nx_targets: int = DEFAULT_MAX_NX_TARGETS
    max_referrals: int = DEFAULT_MAX_REFERRALS
    max_signature_validations: int = DEFAULT_MAX_SIGNATURE_VALIDATIONS
    max_nsec3_hashes: int = DEFAULT_MAX_NSEC3_HASHES

    def budget(self, deadline: float) -> QueryBudget:
        """Return a fresh per-resolution counter enforcing these limits."""
        return QueryBudget(
            max_queries=self.max_queries,
            max_nx_targets=self.max_nx_targets,
            max_referrals=self.max_referrals,
            max_signature_validations=self.max_signature_validations,
            max_nsec3_hashes=self.max_nsec3_hashes,
            deadline=deadline,
        )


@dataclass
class QueryBudget:
    """Mutable work budget shared across a resolution and all its sub-resolutions.

    Args:
        max_queries: Total upstream DNS queries allowed for the whole call.
        max_nx_targets: Total NS-hostname resolutions allowed to fail.
        max_referrals: Total referrals allowed to be followed.
        deadline: Absolute ``time.monotonic()`` value after which the
            resolution is abandoned.
    """

    max_queries: int = DEFAULT_MAX_QUERIES
    max_nx_targets: int = DEFAULT_MAX_NX_TARGETS
    max_referrals: int = DEFAULT_MAX_REFERRALS
    max_signature_validations: int = DEFAULT_MAX_SIGNATURE_VALIDATIONS
    max_nsec3_hashes: int = DEFAULT_MAX_NSEC3_HASHES
    deadline: float = float("inf")

    queries_sent: int = field(default=0, init=False)
    nx_targets: int = field(default=0, init=False)
    referrals_followed: int = field(default=0, init=False)
    signature_validations: int = field(default=0, init=False)
    nsec3_hashes: int = field(default=0, init=False)

    def spend_query(self, qname: str, rdtype: str) -> None:
        """Account for one outgoing query. Raises when the budget is exhausted."""
        if self.queries_sent >= self.max_queries:
            raise QueryBudgetExceededError(qname, rdtype, "queries", self.max_queries)
        self.queries_sent += 1

    def note_referral(self, qname: str, rdtype: str) -> None:
        """Account for one followed referral."""
        if self.referrals_followed >= self.max_referrals:
            raise QueryBudgetExceededError(qname, rdtype, "referrals", self.max_referrals)
        self.referrals_followed += 1

    def note_nx_target(self, qname: str, rdtype: str) -> None:
        """Account for one NS hostname that failed to resolve."""
        self.nx_targets += 1
        if self.nx_targets > self.max_nx_targets:
            raise QueryBudgetExceededError(qname, rdtype, "failed NS targets", self.max_nx_targets)

    def spend_signature_validation(self) -> None:
        """Account for one signature verification (KeyTrap control)."""
        self.signature_validations += 1
        if self.signature_validations > self.max_signature_validations:
            raise QueryBudgetExceededError("<dnssec>", "RRSIG", "signature validations", self.max_signature_validations)

    def spend_nsec3_hash(self) -> None:
        """Account for one NSEC3 hash computation (KeyTrap control)."""
        self.nsec3_hashes += 1
        if self.nsec3_hashes > self.max_nsec3_hashes:
            raise QueryBudgetExceededError("<dnssec>", "NSEC3", "NSEC3 hash computations", self.max_nsec3_hashes)

    def remaining_queries(self) -> int:
        """Number of queries still permitted."""
        return max(0, self.max_queries - self.queries_sent)

    def expired(self) -> bool:
        """True if the wall-clock deadline has passed."""
        return time.monotonic() >= self.deadline

    def time_remaining(self) -> float:
        """Seconds left before the deadline (never negative)."""
        return max(0.0, self.deadline - time.monotonic())
