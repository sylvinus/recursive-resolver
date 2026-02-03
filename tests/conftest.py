"""Shared fixtures and CLI options for pytest."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--csv",
        action="store",
        default=None,
        help="Path to a CSV file with domains for bulk testing",
    )
    parser.addoption(
        "--types",
        action="store",
        default="A,MX",
        help="Comma-separated record types to test (default: A,MX)",
    )
    parser.addoption(
        "--sample",
        action="store",
        type=int,
        default=0,
        help="Randomly sample N domains from the CSV (0 = all)",
    )


@pytest.fixture
def csv_path(request: pytest.FixtureRequest) -> str | None:
    return request.config.getoption("--csv")  # type: ignore[return-value]
