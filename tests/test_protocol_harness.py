"""The real-world testing protocol's own guards (see TESTING.md).

The harnesses in `scripts/` are what stands between a DNSSEC regression and a
release, so they need to keep working even though they normally run against
live DNS. These tests pin the two pieces of judgement they encode - which
invariant violations count, and which outcome changes a fault may legitimately
cause - and keep the modules importable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype
from conftest import make_response

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from audit import Fetch, Ledger, audited  # noqa: E402
from cassette import apply_fault, transition_allowed  # noqa: E402

from recursive_resolver import DNSSECValidationError, RecursiveResolver  # noqa: E402
from recursive_resolver.exceptions import DNSSECMaterialUnavailableError  # noqa: E402


def _fetch(*, material=True, got=True, offered=("9.9.9.9", "1.1.1.1"), asked=("9.9.9.9", "1.1.1.1")) -> Fetch:
    fetch = Fetch(qname="example.test.", rdtype="DNSKEY", material=material, offered=list(offered))
    fetch.asked = set(asked)
    fetch.got_response = got
    return fetch


class TestInvariants:
    def test_a_clean_resolution_violates_nothing(self) -> None:
        ledger = Ledger(fetches=[_fetch()], queries=[("example.test.", "A", "9.9.9.9", 1232, True)])
        assert ledger.violations(None) == []

    def test_i1_a_dnssec_verdict_while_material_was_unavailable(self) -> None:
        ledger = Ledger(fetches=[_fetch(got=False)])
        outcome = DNSSECValidationError("example.test.", "A", "no valid DNSKEY")
        assert any(v.startswith("I1") for v in ledger.violations(outcome))

    def test_i2_a_query_sent_without_edns_while_validating(self) -> None:
        ledger = Ledger(queries=[("example.test.", "DNSKEY", "9.9.9.9", None, True)])
        assert any(v.startswith("I2") for v in ledger.violations(None))

    def test_i2_ignores_a_resolver_that_is_not_validating(self) -> None:
        ledger = Ledger(queries=[("example.test.", "A", "9.9.9.9", None, False)])
        assert ledger.violations(None) == []

    def test_i3_giving_up_before_every_server_was_asked(self) -> None:
        ledger = Ledger(fetches=[_fetch(got=False, asked=("9.9.9.9",))])
        violations = ledger.violations(DNSSECMaterialUnavailableError("example.test.", "DNSKEY"))
        assert any(v.startswith("I3") for v in violations)

    def test_i4_an_answer_accepted_without_the_aa_bit(self) -> None:
        ledger = Ledger(classifications=[("example.test.", False, "answer")])
        assert any(v.startswith("I4") for v in ledger.violations(None))

    def test_i5_material_reported_unavailable_when_every_fetch_answered(self) -> None:
        ledger = Ledger(fetches=[_fetch()])
        outcome = DNSSECMaterialUnavailableError("example.test.", "DNSKEY")
        assert any(v.startswith("I5") for v in ledger.violations(outcome))

    def test_the_audit_records_what_the_resolver_did_and_leaves_no_trace(self) -> None:
        """A harness that permanently rewires the object under test is a liability."""
        resolver = RecursiveResolver(cache_enabled=False, dnssec=False)
        answer = make_response(answer=[("example.test.", 300, "A", ["198.51.100.9"])])

        # The transport is wired up first, so the audit wraps it rather than
        # being replaced by it: the order the harnesses use.
        transport = resolver._query_once = lambda *a, **k: answer
        with audited(resolver) as ledger:
            resolver._send_query(
                dns.name.from_text("example.test."), dns.rdatatype.A, ["9.9.9.9"], resolver._new_context()
            )
        assert [f.qname for f in ledger.fetches] == ["example.test."]
        assert [f.asked for f in ledger.fetches] == [{"9.9.9.9"}]
        assert resolver._query_once is transport
        assert not {"_send_query", "_classify_response"} & set(resolver.__dict__)


class TestPerturbationRules:
    """Which outcome changes a single-server fault may legitimately cause."""

    def test_an_availability_fault_must_not_change_the_verdict(self) -> None:
        assert not transition_allowed("ok/secure", "bogus", "timeout")
        assert not transition_allowed("ok/secure", "ok/insecure", "empty-answer")

    def test_losing_a_server_may_cost_the_material(self) -> None:
        assert transition_allowed("ok/secure", "unavailable", "servfail")

    def test_stripping_signatures_may_legitimately_look_like_tampering(self) -> None:
        assert transition_allowed("ok/secure", "bogus", "strip-rrsig")

    def test_stripping_signatures_must_not_silently_downgrade(self) -> None:
        assert not transition_allowed("ok/secure", "ok/insecure", "strip-rrsig")

    def test_reordering_alone_must_reproduce_the_outcome(self) -> None:
        assert transition_allowed("ok/secure", "ok/secure", "")
        assert not transition_allowed("ok/insecure", "ok/secure", "")


class TestFaults:
    def test_each_fault_does_what_it_says(self) -> None:
        signed = make_response(
            answer=[
                ("example.test.", 300, "A", ["198.51.100.9"]),
                ("example.test.", 300, "RRSIG", ["A 8 2 300 20990101000000 20200101000000 1 example.test. AAAA"]),
            ]
        )
        assert not apply_fault(make_response(answer=[("a.test.", 300, "A", ["1.2.3.4"])]), "empty-answer", 1232).answer
        stripped = apply_fault(signed, "strip-rrsig", 1232)
        assert [r.rdtype for r in stripped.answer] == [dns.rdatatype.A]
        assert apply_fault(make_response(), "no-aa", 1232).flags & dns.flags.AA == 0
        assert apply_fault(make_response(), "servfail", 1232).rcode() == dns.rcode.SERVFAIL
        # FORMERR emulates a server that dislikes the OPT record, so a query
        # sent without EDNS must come back untouched.
        assert apply_fault(make_response(), "formerr", None).rcode() == dns.rcode.NOERROR
