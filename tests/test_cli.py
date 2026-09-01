"""Tests for the command-line interface."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from recursive_resolver import Answer, NXDOMAINError, TraceStep, ValidationState, __version__
from recursive_resolver.cli import main


def _answer(records: str = "1.2.3.4", rdtype: str = "A", dnssec=ValidationState.SECURE) -> Answer:
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset

    rdt = dns.rdatatype.from_text(rdtype)
    rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdataclass.IN, rdt)
    rrset.add(dns.rdata.from_text(dns.rdataclass.IN, rdt, records))
    rrset.ttl = 300
    return Answer(
        qname=dns.name.from_text("example.com."),
        canonical_name=dns.name.from_text("example.com."),
        rdtype=rdt,
        rrset=rrset,
        ttl=300,
        dnssec=dnssec,
    )


class TestBasicInvocation:
    def test_plain_output(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer()
            assert main(["example.com"]) == 0
        assert capsys.readouterr().out.strip() == "1.2.3.4"

    def test_json_output(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer()
            assert main(["--json", "example.com"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["records"] == ["1.2.3.4"]
        assert payload["dnssec"] == "secure"
        assert payload["ttl"] == 300

    def test_record_type_argument(self) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer("10 mail.example.com.", "MX")
            assert main(["example.com", "MX"]) == 0
        cls.return_value.resolve_answer.assert_called_once_with("example.com", "MX")

    def test_version(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert __version__ in capsys.readouterr().out

    def test_missing_argument_exits(self) -> None:
        with pytest.raises(SystemExit):
            main([])


class TestErrorHandling:
    def test_resolver_error_returns_1(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.side_effect = NXDOMAINError("nope.com.")
            assert main(["nope.com"]) == 1
        assert "NXDOMAINError" in capsys.readouterr().err

    def test_json_error_output(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.side_effect = NXDOMAINError("nope.com.")
            assert main(["--json", "nope.com"]) == 1
        payload = json.loads(capsys.readouterr().err)
        assert payload["error"] == "NXDOMAINError"

    def test_unknown_rdtype_is_reported_cleanly(self, capsys: pytest.CaptureFixture) -> None:
        """Regression: this used to print a raw dnspython traceback."""
        # --no-dnssec: these three tests build a *real* RecursiveResolver, and
        # with the CLI default of dnssec=True the constructor raises
        # DNSSECUnavailableError wherever cryptography is missing. main() would
        # then return 2 from the constructor handler and the assertion would
        # fail for a reason that has nothing to do with what is under test.
        assert main(["--no-dnssec", "example.com", "BOGUSTYPE"]) == 1
        assert "UnsupportedRdtypeError" in capsys.readouterr().err

    def test_invalid_name_is_reported_cleanly(self, capsys: pytest.CaptureFixture) -> None:
        assert main(["--no-dnssec", "foo..com"]) == 1
        assert "InvalidNameError" in capsys.readouterr().err

    def test_a_closed_pipe_exits_quietly(self) -> None:
        """`recursive-resolver example.com | head -1` must not print a traceback."""
        # Only dup2 is patched: os.open and os.close stay real, so the handler
        # leaking the devnull descriptor would show up as a leak here too.
        with (
            patch("recursive_resolver.cli.RecursiveResolver"),
            patch("recursive_resolver.cli._run_query", side_effect=BrokenPipeError),
            patch("recursive_resolver.cli.os.dup2") as dup2,
        ):
            assert main(["--no-dnssec", "example.com"]) == 0
        assert dup2.called, "stdout was not redirected, so the shutdown flush will raise again"
        devnull_fd = dup2.call_args.args[0]
        with pytest.raises(OSError):
            os.fstat(devnull_fd)  # already closed: the handler did not leak it

    def test_contradictory_dnssec_flags_are_a_usage_error(self, capsys: pytest.CaptureFixture) -> None:
        """Rejected at parse time rather than failing every lookup later."""
        with pytest.raises(SystemExit) as exc:
            main(["--no-dnssec", "--require-dnssec", "example.com"])
        assert exc.value.code == 2
        assert "not allowed with" in capsys.readouterr().err


class TestTextMode:
    def test_text_mode_concatenates_txt_chunks(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer('"part-one" "part-two"', "TXT")
            assert main(["--text", "example.com", "TXT"]) == 0
        assert capsys.readouterr().out.strip() == "part-onepart-two"

    def test_default_mode_keeps_presentation_format(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer('"part-one" "part-two"', "TXT")
            assert main(["example.com", "TXT"]) == 0
        assert '" "' in capsys.readouterr().out

    def test_text_mode_on_non_text_type_errors(self, capsys: pytest.CaptureFixture) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer()
            assert main(["--text", "example.com"]) == 2
        assert "character-string" in capsys.readouterr().err


class TestTrace:
    def test_trace_output(self, capsys: pytest.CaptureFixture) -> None:
        step = TraceStep(
            server="198.41.0.4",
            qname="example.com.",
            rdtype="A",
            response_type="referral",
            detail="NS: a.gtld-servers.net.",
            zone=".",
            dnssec="secure",
        )
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (_answer(), [step])
            assert main(["--trace", "example.com"]) == 0
        out = capsys.readouterr().out
        assert "198.41.0.4" in out and "referral" in out

    def test_trace_json(self, capsys: pytest.CaptureFixture) -> None:
        step = TraceStep(server="1.2.3.4", qname="example.com.", rdtype="A", response_type="answer")
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (_answer(), [step])
            assert main(["--trace", "--json", "example.com"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["trace"][0]["server"] == "1.2.3.4"
        assert payload["records"] == ["1.2.3.4"]

    def test_trace_failure_returns_1(self) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (None, [])
            assert main(["--trace", "nope.com"]) == 1

    def test_trace_json_failure_says_so_in_the_payload(self, capsys: pytest.CaptureFixture) -> None:
        """A failed trace must not emit a success-shaped payload full of nulls."""
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (None, [])
            assert main(["--trace", "--json", "nope.com"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["error"] == "ResolutionIncomplete"
        assert "no response" in payload["message"]
        assert payload["records"] is None and payload["dnssec"] is None

    def test_trace_honours_text_mode(self, capsys: pytest.CaptureFixture) -> None:
        """--text must mean the same thing with --trace as without it."""
        step = TraceStep(server="1.2.3.4", qname="example.com.", rdtype="A", response_type="answer")
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (_answer('"chunk1" "chunk2"', "TXT"), [step])
            assert main(["--trace", "--text", "example.com", "TXT"]) == 0
        out = capsys.readouterr().out
        assert "chunk1chunk2" in out
        assert '" "' not in out

    def test_trace_text_mode_on_a_non_text_type_errors(self, capsys: pytest.CaptureFixture) -> None:
        step = TraceStep(server="1.2.3.4", qname="example.com.", rdtype="A", response_type="answer")
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (_answer(), [step])
            assert main(["--trace", "--text", "example.com"]) == 2
        assert "character-string" in capsys.readouterr().err


class TestOptionPlumbing:
    def test_security_options_reach_the_resolver(self) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer()
            main(
                [
                    "--no-dnssec",
                    "--allow-private",
                    "--no-cache",
                    "--cache-depth",
                    "tld",
                    "--edns-payload",
                    "512",
                    "example.com",
                ]
            )
        kwargs = cls.call_args.kwargs
        assert kwargs["dnssec"] is False
        assert kwargs["allow_private_addresses"] is True
        assert kwargs["cache_enabled"] is False
        assert kwargs["max_delegation_cache_depth"] == "tld"
        assert kwargs["edns_payload"] == 512

    def test_defaults_are_secure(self) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer()
            main(["example.com"])
        kwargs = cls.call_args.kwargs
        assert kwargs["dnssec"] is True
        assert kwargs["allow_private_addresses"] is False
        assert kwargs["cache_enabled"] is True

    def test_cache_depth_accepts_a_plain_number_too(self) -> None:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = _answer()
            main(["--cache-depth", "2", "example.com"])
        assert cls.call_args.kwargs["max_delegation_cache_depth"] == "2"

    def test_an_unknown_cache_depth_is_reported_cleanly(self, capsys: pytest.CaptureFixture) -> None:
        # --no-dnssec for the same reason as above: the DNSSEC availability
        # check runs before cache construction, so without it the message on
        # stderr would be DNSSECUnavailableError, not the cache-depth one.
        assert main(["--no-dnssec", "--cache-depth", "sometimes", "example.com"]) == 2
        assert "unknown cache depth" in capsys.readouterr().err


class TestDNSSECVerdictOnStderr:
    """Plain output must never look validated when it is not.

    The verdict goes to stderr so that stdout stays a clean list of values;
    the wording matches delv, BIND's validating lookup utility.
    """

    def _run(self, argv: list[str], answer: Answer, capsys: pytest.CaptureFixture) -> tuple[str, str]:
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.resolve_answer.return_value = answer
            assert main(argv) == 0
        captured = capsys.readouterr()
        return captured.out, captured.err

    @pytest.mark.parametrize(
        ("state", "note"),
        [
            (ValidationState.SECURE, "; fully validated"),
            (ValidationState.INSECURE, "; unsigned answer"),
            (ValidationState.BOGUS, "; validation failed"),
        ],
    )
    def test_each_state_is_reported(self, state: ValidationState, note: str, capsys: pytest.CaptureFixture) -> None:
        out, err = self._run(["example.com"], _answer(dnssec=state), capsys)
        assert err.strip() == note
        assert out.strip() == "1.2.3.4"

    def test_stdout_carries_only_values(self, capsys: pytest.CaptureFixture) -> None:
        """Piping the output must not require filtering out a comment line."""
        out, _ = self._run(["example.com"], _answer(), capsys)
        assert out == "1.2.3.4\n"

    def test_no_dnssec_says_so_rather_than_claiming_unsigned(self, capsys: pytest.CaptureFixture) -> None:
        """--no-dnssec leaves the default INSECURE state, which is not a proof."""
        _, err = self._run(["--no-dnssec", "example.com"], _answer(dnssec=ValidationState.INSECURE), capsys)
        assert err.strip() == "; dnssec validation disabled"

    def test_json_output_has_no_note(self, capsys: pytest.CaptureFixture) -> None:
        out, err = self._run(["--json", "example.com"], _answer(), capsys)
        assert err == ""
        assert json.loads(out)["dnssec"] == "secure"

    def test_json_says_disabled_rather_than_insecure(self, capsys: pytest.CaptureFixture) -> None:
        """The stderr note gets this right; the JSON payload used to claim "insecure"."""
        out, _ = self._run(["--json", "--no-dnssec", "example.com"], _answer(dnssec=ValidationState.INSECURE), capsys)
        assert json.loads(out)["dnssec"] == "disabled"

    def test_text_mode_still_reports(self, capsys: pytest.CaptureFixture) -> None:
        out, err = self._run(["--text", "example.com", "TXT"], _answer('"v=spf1 -all"', "TXT"), capsys)
        assert err.strip() == "; fully validated"
        assert out.strip() == "v=spf1 -all"

    def test_trace_mode_reports_before_the_records(self, capsys: pytest.CaptureFixture) -> None:
        answer = _answer()
        step = TraceStep(server="1.2.3.4", qname="example.com.", rdtype="A", response_type="answer")
        with patch("recursive_resolver.cli.RecursiveResolver") as cls:
            cls.return_value.trace_answer.return_value = (answer, [step])
            assert main(["--trace", "example.com"]) == 0
        captured = capsys.readouterr()
        assert captured.err.strip() == "; fully validated"
        assert captured.out.strip().endswith("1.2.3.4")
