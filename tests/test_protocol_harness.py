"""The real-world testing protocol's own guards (see TESTING.md).

The harnesses in `scripts/` are what stands between a DNSSEC regression and a
release, so they need to keep working even though they normally run against
live DNS. These tests pin the two pieces of judgement they encode - which
invariant violations count, and which outcome changes a fault may legitimately
cause - and keep the modules importable.
"""

from __future__ import annotations

import ast
import inspect
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype
from conftest import make_response

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from audit import Fetch, Ledger, audited  # noqa: E402
from cassette import apply_fault, outcome_of, transition_allowed  # noqa: E402
from verdict_harness import (  # noqa: E402
    BOGUS,
    FAILED,
    INFORMATIONAL_DISAGREEMENTS,
    INSECURE,
    LEAKED,
    NODATA,
    NXDOMAIN,
    SECURE,
    Outcome,
    compare,
    data_is_unstable,
    gates_release,
    leaked,
    our_outcome,
)

from recursive_resolver import (  # noqa: E402
    DNSSECValidationError,
    RecursiveResolver,
    ServfailError,
)
from recursive_resolver.exceptions import (  # noqa: E402
    DNSSECMaterialUnavailableError,
    MaxDepthError,
)


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

    def test_i4_is_silent_when_the_resolver_does_not_require_authority(self) -> None:
        """`lax-aa` is one of the configurations the verdict harness sweeps.

        Reporting a violation there flags the resolver for doing exactly what
        it was told, and a gating harness that cries wolf gets ignored.
        """
        ledger = Ledger(classifications=[("example.test.", False, "answer")], require_authoritative=False)
        assert ledger.violations(None) == []

    def test_the_ledger_takes_the_policy_from_the_resolver(self) -> None:
        lax = RecursiveResolver(dnssec=False, cache_enabled=False, require_authoritative=False)
        with audited(lax) as ledger:
            pass
        assert ledger.require_authoritative is False
        with audited(RecursiveResolver(dnssec=False, cache_enabled=False)) as ledger:
            pass
        assert ledger.require_authoritative is True

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

    def test_a_leaked_exception_is_never_an_allowed_outcome(self) -> None:
        """README: every failure is a ResolverError, nothing from dnspython escapes.

        `error/` is the escape hatch for resolver errors this harness has no
        bucket for, and a fault may legitimately turn one into another. A
        non-ResolverError is not in that category, and reproducing it under
        every server order does not make it legitimate.
        """
        assert outcome_of(None, MaxDepthError("a.test.", "A", 30)) == "error/MaxDepthError"
        assert outcome_of(None, TypeError("boom")) == "leaked/TypeError"
        assert transition_allowed("error/MaxDepthError", "nodata", "timeout")
        assert not transition_allowed("nodata", "leaked/TypeError", "timeout")
        assert not transition_allowed("leaked/TypeError", "leaked/TypeError", "")


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


class TestReferencePanel:
    """A verdict needs a two-thirds majority of the panel, not one supporter.

    Five public validators do not always agree, and the odd one running a stale
    cache or a negative trust anchor must not be able to ratify our answer on
    its own. These pin the quorum, because the rule is the whole reason the
    differential can fail a release.
    """

    @staticmethod
    def _panel(*verdicts: str) -> dict[str, str]:
        return {f"ref{i}": v for i, v in enumerate(verdicts)}

    def test_a_lone_secure_does_not_ratify_our_secure(self) -> None:
        panel = self._panel(SECURE, "insecure", "insecure", "insecure", "insecure")
        assert compare(Outcome(SECURE, ""), panel) == "we-say-secure-they-do-not"

    def test_a_two_thirds_secure_majority_does(self) -> None:
        panel = self._panel(SECURE, SECURE, SECURE, SECURE, "insecure")
        assert compare(Outcome(SECURE, ""), panel) == ""

    def test_an_evenly_split_panel_decides_nothing(self) -> None:
        panel = self._panel(SECURE, SECURE, "insecure", "insecure")
        assert compare(Outcome(SECURE, ""), panel) == "references-disagree"

    def test_a_secure_majority_against_our_insecure_is_the_dangerous_direction(self) -> None:
        panel = self._panel(SECURE, SECURE, SECURE, SECURE, "bogus")
        assert compare(Outcome("insecure", ""), panel) == "we-say-insecure-they-say-secure"

    def test_a_lone_secure_against_our_insecure_is_not(self) -> None:
        panel = self._panel(SECURE, "insecure", "insecure", "insecure", "insecure")
        assert compare(Outcome("insecure", ""), panel) == ""

    def test_a_bogus_majority_against_our_insecure_is_a_disagreement(self) -> None:
        """We return the data; four of five refuse it. Whatever they caught, we did not."""
        panel = self._panel("bogus", "bogus", "bogus", "servfail", "insecure")
        assert compare(Outcome("insecure", ""), panel) == "we-say-insecure-they-say-bogus"

    def test_a_lone_bogus_against_our_insecure_is_not(self) -> None:
        """One operator's SERVFAIL is an operator, not a finding."""
        panel = self._panel("bogus", "insecure", "insecure", "insecure", "insecure")
        assert compare(Outcome("insecure", ""), panel) == ""


class TestEveryDisagreementIsClassified:
    """A label `compare` can return must be a deliberate gate-or-not decision.

    The labels used to be enumerated in the *gating* set, so one added to
    `compare` and forgotten there was filed under "the internet, not us" and
    let a release through. This reads the labels out of the source, so adding
    one without deciding what it means fails here rather than in six months.
    """

    @staticmethod
    def _labels() -> set[str]:
        source = inspect.getsource(compare)
        tree = ast.parse(textwrap.dedent(source))
        return {
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Return)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and node.value.value
        } | {
            branch.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.IfExp)
            for branch in (node.value.body, node.value.orelse)
            if isinstance(branch, ast.Constant) and isinstance(branch.value, str) and branch.value
        }

    def test_the_labels_are_the_ones_we_think(self) -> None:
        assert self._labels() == {
            "references-disagree",
            "we-say-secure-they-do-not",
            "we-say-insecure-they-say-secure",
            "we-say-insecure-they-say-bogus",
            "false-bogus",
            "we-answered-they-refused",
            "material-unavailable-but-they-resolved",
            "we-failed-they-resolved",
        }

    def test_the_leak_label_is_classified_too(self) -> None:
        """It never comes out of `compare`, so the source scan cannot see it."""
        assert gates_release("we-leaked-a-non-resolver-error")
        assert "we-leaked-a-non-resolver-error" not in INFORMATIONAL_DISAGREEMENTS

    def test_the_ones_that_are_about_us_gate_the_release(self) -> None:
        about_us = self._labels() - INFORMATIONAL_DISAGREEMENTS
        assert about_us, "compare returns nothing that would fail a release"
        for label in about_us:
            assert gates_release(label), f"{label} is reported but does not gate"

    def test_no_disagreement_is_not_a_gate(self) -> None:
        assert not gates_release("")


class TestOnlyRealDataExcusesAFlap:
    """A flap is excused when the zone handed back two different datasets.

    An outcome that leaves as an exception carries no records, and that is the
    absence of evidence about the zone's contents, not evidence that they
    changed. Treating it as a second dataset excused the one flap that matters
    most: `nic.bj` alternating between SECURE and BOGUS on four record types
    was reported across 120,000 lookups as zero verdict flaps.
    """

    def test_secure_alternating_with_bogus_is_a_flap(self) -> None:
        outcomes = [
            Outcome(SECURE, "", ("81.91.239.11",), ()),
            Outcome(BOGUS, "zone is signed but the answer carries no RRSIG"),
            Outcome(SECURE, "", ("81.91.239.11",), ()),
        ]
        assert data_is_unstable(outcomes) is False

    def test_two_different_answers_are_the_zone_being_unstable(self) -> None:
        outcomes = [
            Outcome(SECURE, "", ("192.0.2.1",), ()),
            Outcome(INSECURE, "", ("198.51.100.1",), ()),
        ]
        assert data_is_unstable(outcomes) is True

    def test_the_same_records_down_two_different_cname_chains_are_unstable(self) -> None:
        """The case the rule was written for: a traffic manager landing either side."""
        outcomes = [
            Outcome(SECURE, "", ("192.0.2.1",), ("a.example.test.",)),
            Outcome(INSECURE, "", ("192.0.2.1",), ("b.example.test.",)),
        ]
        assert data_is_unstable(outcomes) is True

    def test_a_retrieval_failure_alongside_one_answer_excuses_nothing(self) -> None:
        outcomes = [Outcome(SECURE, "", ("192.0.2.1",), ()), Outcome(FAILED, "timeout")]
        assert data_is_unstable(outcomes) is False

    def test_two_denials_are_not_two_datasets(self) -> None:
        assert data_is_unstable([Outcome(NXDOMAIN, "gone"), Outcome(NODATA, "none")]) is False


class TestALeakedExceptionFailsTheRun:
    """README: every failure is a ResolverError, nothing from dnspython escapes.

    The cassette layer refuses to call one an outcome. This layer sees far more
    of the real internet, and used to file a leak under `failed` - which reads
    as one more unreachable zone and never gates.
    """

    def test_a_resolver_error_is_a_failure_not_a_leak(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=False)
        with patch.object(resolver, "resolve_answer", side_effect=ServfailError("a.test.", "A")):
            outcome, _violations = our_outcome(resolver, "a.test.", "A")
        assert outcome.kind == "failed"
        assert not leaked([outcome])

    def test_anything_else_is_a_leak(self) -> None:
        resolver = RecursiveResolver(dnssec=False, cache_enabled=False)
        with patch.object(resolver, "resolve_answer", side_effect=TypeError("boom")):
            outcome, _violations = our_outcome(resolver, "a.test.", "A")
        assert outcome.kind == LEAKED
        assert leaked([outcome])

    def test_a_leak_gates_even_when_the_panel_agrees_with_it(self) -> None:
        """No reference verdict excuses it, so it does not go through `compare`."""
        panel = {"ref0": "servfail", "ref1": "servfail", "ref2": "servfail"}
        assert compare(Outcome(LEAKED, ""), panel) == ""
        assert gates_release("we-leaked-a-non-resolver-error")
