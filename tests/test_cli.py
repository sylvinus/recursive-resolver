"""Tests for the CLI interface."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from recursive_resolver import NXDOMAINError, __version__
from recursive_resolver.cli import main
from recursive_resolver.resolver import TraceStep


class TestCLIBasic:
    """Test CLI argument parsing and basic output."""

    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit, match="0"):
            main(["--version"])
        assert __version__ in capsys.readouterr().out

    def test_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit, match="0"):
            main(["--help"])
        out = capsys.readouterr().out
        assert "recursive-resolver" in out
        assert "domain" in out

    def test_no_args(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit, match="2"):
            main([])

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_simple_resolve(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve.return_value = ["93.184.216.34"]
        ret = main(["example.com"])
        assert ret == 0
        assert "93.184.216.34" in capsys.readouterr().out
        mock_cls.return_value.resolve.assert_called_once_with("example.com", "A")

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_explicit_rdtype(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve.return_value = ["10 mail.example.com."]
        ret = main(["example.com", "MX"])
        assert ret == 0
        assert "10 mail.example.com." in capsys.readouterr().out
        mock_cls.return_value.resolve.assert_called_once_with("example.com", "MX")

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_multiple_results(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve.return_value = ["1.2.3.4", "5.6.7.8"]
        ret = main(["example.com"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "1.2.3.4" in out
        assert "5.6.7.8" in out


class TestCLIJson:
    """Test JSON output mode."""

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_json_output(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve.return_value = ["93.184.216.34"]
        ret = main(["--json", "example.com"])
        assert ret == 0
        data = json.loads(capsys.readouterr().out)
        assert data == ["93.184.216.34"]

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_json_error(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve.side_effect = NXDOMAINError("no.example.com", "A")
        ret = main(["--json", "no.example.com"])
        assert ret == 1
        data = json.loads(capsys.readouterr().err)
        assert data["error"] == "NXDOMAINError"
        assert "message" in data


class TestCLITrace:
    """Test --trace mode."""

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_trace_text(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve_with_trace.return_value = [
            TraceStep(
                server="198.41.0.4",
                qname="example.com.",
                rdtype="A",
                response_type="referral",
                detail="NS: a.gtld-servers.net.",
                rcode=0,
            ),
            TraceStep(
                server="192.5.6.30",
                qname="example.com.",
                rdtype="A",
                response_type="answer",
                detail="93.184.216.34",
                rcode=0,
            ),
        ]
        ret = main(["--trace", "example.com"])
        assert ret == 0
        out = capsys.readouterr().out
        assert "198.41.0.4" in out
        assert "referral" in out
        assert "answer" in out

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_trace_json(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve_with_trace.return_value = [
            TraceStep(
                server="198.41.0.4",
                qname="example.com.",
                rdtype="A",
                response_type="referral",
                detail="NS: a.gtld-servers.net.",
                rcode=0,
            ),
        ]
        ret = main(["--trace", "--json", "example.com"])
        assert ret == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["server"] == "198.41.0.4"
        assert data[0]["response_type"] == "referral"


class TestCLIErrors:
    """Test error handling."""

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_nxdomain_error(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve.side_effect = NXDOMAINError("no.example.com", "A")
        ret = main(["no.example.com"])
        assert ret == 1
        err = capsys.readouterr().err
        assert "NXDOMAINError" in err

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_trace_error(self, mock_cls: mock.MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_cls.return_value.resolve_with_trace.side_effect = NXDOMAINError("no.example.com", "A")
        ret = main(["--trace", "no.example.com"])
        assert ret == 1
        err = capsys.readouterr().err
        assert "NXDOMAINError" in err


class TestCLIOptions:
    """Test that CLI options are passed through to the resolver."""

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_timeout_option(self, mock_cls: mock.MagicMock) -> None:
        mock_cls.return_value.resolve.return_value = []
        main(["--timeout", "10", "example.com"])
        mock_cls.assert_called_once_with(
            timeout=10.0,
            max_depth=20,
            cache_enabled=True,
            ipv4_only=True,
            max_resolution_time=30.0,
        )

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_no_cache_option(self, mock_cls: mock.MagicMock) -> None:
        mock_cls.return_value.resolve.return_value = []
        main(["--no-cache", "example.com"])
        mock_cls.assert_called_once_with(
            timeout=5.0,
            max_depth=20,
            cache_enabled=False,
            ipv4_only=True,
            max_resolution_time=30.0,
        )

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_ipv6_option(self, mock_cls: mock.MagicMock) -> None:
        mock_cls.return_value.resolve.return_value = []
        main(["--ipv6", "example.com"])
        mock_cls.assert_called_once_with(
            timeout=5.0,
            max_depth=20,
            cache_enabled=True,
            ipv4_only=False,
            max_resolution_time=30.0,
        )

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_max_time_option(self, mock_cls: mock.MagicMock) -> None:
        mock_cls.return_value.resolve.return_value = []
        main(["--max-time", "15", "example.com"])
        mock_cls.assert_called_once_with(
            timeout=5.0,
            max_depth=20,
            cache_enabled=True,
            ipv4_only=True,
            max_resolution_time=15.0,
        )

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_max_depth_option(self, mock_cls: mock.MagicMock) -> None:
        mock_cls.return_value.resolve.return_value = []
        main(["--max-depth", "5", "example.com"])
        mock_cls.assert_called_once_with(
            timeout=5.0,
            max_depth=5,
            cache_enabled=True,
            ipv4_only=True,
            max_resolution_time=30.0,
        )

    @mock.patch("recursive_resolver.cli.RecursiveResolver")
    def test_combined_options(self, mock_cls: mock.MagicMock) -> None:
        mock_cls.return_value.resolve.return_value = []
        main(["--timeout", "8", "--max-depth", "10", "--no-cache", "--ipv6", "--max-time", "20", "example.com"])
        mock_cls.assert_called_once_with(
            timeout=8.0,
            max_depth=10,
            cache_enabled=False,
            ipv4_only=False,
            max_resolution_time=20.0,
        )
