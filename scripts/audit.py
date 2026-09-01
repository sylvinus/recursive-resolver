#!/usr/bin/env python3
"""Layer 0 of TESTING.md: invariants that must hold for every lookup.

Attaches to a live :class:`RecursiveResolver` instance, records what it did
during one resolution, and checks the properties that make a DNSSEC verdict
trustworthy. Every other layer in the protocol is a way of generating inputs;
this is what turns an input into a test.

The instrumentation is a wrapper around instance methods, not a change to the
resolver: production code carries no test hooks, and the audit cannot drift
from what the resolver actually does because it observes the real calls.

Invariants
----------
I1  A DNSSEC verdict requires retrieved material. If any fetch of validation
    material came back empty-handed, the resolution must not end in a
    ``DNSSECError``; it must end in ``DNSSECMaterialUnavailableError``.
I2  Every query sent while validating carries EDNS0, so it can carry the DO
    bit (RFC 4035 §3.2.1). Without it the answer arrives unsigned and the
    validator can only read that as forged.
I3  No zone is judged on one server's word. A fetch of validation material
    that failed must have asked every usable address in the NS set.
I4  Nothing is accepted from a response the resolver itself classified as
    unusable (non-authoritative answer, wrong class, out of bailiwick).
I5  ``DNSSECMaterialUnavailableError`` is only raised when a fetch really did
    return nothing: it must not become a way to hide a validation failure.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import dns.flags
import dns.rdatatype

# RR_SRC points the harness at a different copy of the package, which is how
# the mutation runs check that these tests actually bite.
sys.path.insert(0, os.environ.get("RR_SRC", str(Path(__file__).resolve().parent.parent / "src")))

from recursive_resolver import DNSSECError, RecursiveResolver  # noqa: E402
from recursive_resolver.exceptions import DNSSECMaterialUnavailableError  # noqa: E402

# Fetches of validation material, as opposed to ordinary data queries.
MATERIAL_TYPES = frozenset({dns.rdatatype.DNSKEY, dns.rdatatype.DS})


@dataclass
class Fetch:
    qname: str
    rdtype: str
    material: bool
    offered: set[str]
    asked: set[str] = field(default_factory=set)
    got_response: bool = False
    # The resolution ran out of budget or wall-clock during this fetch, so the
    # servers it did not reach were not servers it chose to ignore.
    exhausted: bool = False


@dataclass
class Ledger:
    fetches: list[Fetch] = field(default_factory=list)
    queries: list[tuple[str, str, str, int | None, bool]] = field(default_factory=list)
    classifications: list[tuple[str, bool, str]] = field(default_factory=list)

    def failed_material_fetches(self) -> list[Fetch]:
        return [f for f in self.fetches if f.material and not f.got_response]

    def violations(self, outcome: BaseException | None) -> list[str]:
        """Check every invariant against what was recorded."""
        out: list[str] = []
        failed = self.failed_material_fetches()

        # I1
        if isinstance(outcome, DNSSECError) and failed:
            names = ", ".join(f"{f.qname}/{f.rdtype}" for f in failed)
            out.append(f"I1: {type(outcome).__name__} raised while material was unavailable for {names}")

        # I2
        for qname, rdtype, server, payload, dnssec in self.queries:
            if dnssec and payload is None:
                out.append(f"I2: {qname}/{rdtype} sent to {server} without EDNS while validating")

        # I3
        for fetch in failed:
            unasked = [s for s in fetch.offered if s not in fetch.asked]
            if unasked and not fetch.exhausted:
                out.append(
                    f"I3: gave up on {fetch.qname}/{fetch.rdtype} without asking {', '.join(unasked)}"
                    f" (asked {len(fetch.asked)} of {len(fetch.offered)})"
                )

        # I4
        for qname, authoritative, kind in self.classifications:
            if kind in ("answer", "nxdomain", "nodata") and not authoritative:
                out.append(f"I4: accepted a {kind} for {qname} without the AA bit")

        # I5
        if isinstance(outcome, DNSSECMaterialUnavailableError) and not failed:
            out.append("I5: material reported unavailable, but every fetch returned a response")

        return out


@contextmanager
def audited(resolver: RecursiveResolver):
    """Record one resolver's activity. Yields the :class:`Ledger`."""
    ledger = Ledger()
    real_send = resolver._send_query
    real_query = resolver._query_once
    real_classify = resolver._classify_response

    def send_query(qname, rdtype, nameservers, ctx, usable=None):
        # What the resolver itself would consider, not the raw NS set. I3 asks
        # whether every *usable* address was tried, and it is the resolver's own
        # ordering that decides which those are: the address filter drops some,
        # and cassette replay deliberately restricts the set to the servers the
        # recording actually reached. Comparing against the unrestricted list
        # instead reports a violation for every server the replay was never
        # going to use.
        fetch = Fetch(
            qname=str(qname),
            rdtype=dns.rdatatype.to_text(rdtype),
            material=rdtype in MATERIAL_TYPES and ctx.dnssec,
            offered=set(resolver._order_servers(nameservers)),
        )
        ledger.fetches.append(fetch)
        try:
            response, server = real_send(qname, rdtype, nameservers, ctx, usable=usable)
        except Exception:
            fetch.got_response = False
            fetch.exhausted = True
            raise
        fetch.got_response = response is not None
        fetch.exhausted = ctx.budget.expired() or ctx.budget.queries_sent >= ctx.budget.max_queries
        return response, server

    def query_once(qname, rdtype, server, payload, timeout, ctx):
        ledger.queries.append((str(qname), dns.rdatatype.to_text(rdtype), server, payload, ctx.dnssec))
        if ledger.fetches:
            ledger.fetches[-1].asked.add(server)
        return real_query(qname, rdtype, server, payload, timeout, ctx)

    def classify(response, qname, rdtype, current_zone):
        result = real_classify(response, qname, rdtype, current_zone)
        ledger.classifications.append((str(qname), bool(response.flags & dns.flags.AA), result["type"]))
        return result

    # Overriding on the instance and deleting afterwards, rather than assigning
    # the bound methods back: a leftover instance attribute would shadow the
    # class for the rest of the resolver's life, including any later patching.
    wrapped = {"_send_query": send_query, "_query_once": query_once, "_classify_response": classify}
    previous = {name: resolver.__dict__.get(name) for name in wrapped}
    for name, function in wrapped.items():
        setattr(resolver, name, function)
    try:
        yield ledger
    finally:
        for name, original in previous.items():
            if original is None:
                resolver.__dict__.pop(name, None)
            else:
                setattr(resolver, name, original)


def resolve_audited(resolver: RecursiveResolver, qname: str, rdtype: str):
    """Resolve, returning ``(answer, exception, violations)``."""
    with audited(resolver) as ledger:
        try:
            answer = resolver.resolve_answer(qname, rdtype)
        except Exception as exc:  # noqa: BLE001 - the harness classifies it
            return None, exc, ledger.violations(exc)
        return answer, None, ledger.violations(None)
