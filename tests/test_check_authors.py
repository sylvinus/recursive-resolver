"""The CI check that keeps AI tools out of the author fields.

The hard part is not catching the tools, it is not catching people. Claude,
Jean-Claude, Devin, Gemini and Mistral are all real names, and this project is
French, so a check keyed on given names would reject genuine contributors.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_authors.py"
_spec = importlib.util.spec_from_file_location("check_authors", SCRIPT)
assert _spec is not None and _spec.loader is not None
check_authors = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_authors)


class TestPeopleAreNotBlocked:
    @pytest.mark.parametrize(
        "identity",
        [
            "Claude Dubois <claude.dubois@example.fr>",
            "Claude Monet <claude@monet.example>",
            "Jean-Claude Vandamme <jc@example.be>",
            "Claude Shannon <cshannon@bell-labs.example>",
            "Claude <claude@example.fr>",
            "Devin Smith <devin@example.com>",
            "Frédéric Mistral <f.mistral@example.fr>",
            "Gemini Rossi <g.rossi@example.it>",
            "Cursor Jones <cj@example.org>",
            "Llama Del Rey <l@example.pe>",
        ],
    )
    def test_a_human_name_alone_never_trips_the_check(self, identity: str) -> None:
        assert check_authors.MATCHER.search(identity) is None, identity

    def test_an_ordinary_co_author_trailer_passes(self) -> None:
        message = "Fix a bug\n\nCo-authored-by: Claude Dubois <claude.dubois@example.fr>\n"
        assert check_authors.check_message(message, "test") == []


class TestToolsAreBlocked:
    @pytest.mark.parametrize(
        "identity",
        [
            "Claude Opus 5 <noreply@anthropic.com>",
            "Claude <noreply@anthropic.com>",
            "Claude Code <bot@anthropic.com>",
            "GitHub Copilot <copilot@github.com>",
            "ChatGPT <noreply@openai.com>",
            "openai-codex[bot] <x@users.noreply.github.com>",
            "Cursor Agent <agent@cursor.sh>",
            "Devin AI <devin@cognition.ai>",
            "Gemini CLI <g@example.com>",
            "GPT-4o <x@example.com>",
            "Aider <a@example.com>",
        ],
    )
    def test_a_tool_identity_is_caught(self, identity: str) -> None:
        assert check_authors.MATCHER.search(identity) is not None, identity

    def test_a_tool_co_author_trailer_is_caught(self) -> None:
        message = "Fix a bug\n\nCo-authored-by: Claude Opus 5 <noreply@anthropic.com>\n"
        assert check_authors.check_message(message, "commit") != []

    def test_only_co_author_lines_are_scanned(self) -> None:
        """A subject may legitimately mention a tool."""
        assert check_authors.check_message("Add codex support to the parser", "commit") == []


class TestAgainstARealRepository:
    @staticmethod
    def _repo(tmp_path: Path) -> Path:
        run = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)  # noqa: E731
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
        run("config", "user.name", "Real Person")
        run("config", "user.email", "real@example.com")
        run("commit", "-q", "--allow-empty", "-m", "base")
        return tmp_path

    def _check(self, repo: Path, rev_range: str) -> int:
        result = subprocess.run([sys.executable, str(SCRIPT), rev_range], cwd=repo, capture_output=True, text=True)
        return result.returncode

    def test_a_clean_history_passes(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "--allow-empty", "-m", "good change"],
            check=True,
            capture_output=True,
        )
        assert self._check(repo, "HEAD~1..HEAD") == 0

    def test_a_tool_trailer_fails(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "change\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            ],
            check=True,
            capture_output=True,
        )
        assert self._check(repo, "HEAD~1..HEAD") == 1

    def test_a_tool_author_fails(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Claude Code",
                "-c",
                "user.email=noreply@anthropic.com",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "change",
            ],
            check=True,
            capture_output=True,
        )
        assert self._check(repo, "HEAD~1..HEAD") == 1

    def test_a_contributor_named_claude_passes(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Claude Dubois",
                "-c",
                "user.email=claude.dubois@example.fr",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "a genuine change",
            ],
            check=True,
            capture_output=True,
        )
        assert self._check(repo, "HEAD~1..HEAD") == 0
