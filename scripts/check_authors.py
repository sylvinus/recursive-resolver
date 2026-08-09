#!/usr/bin/env python3
"""Reject commits that credit an AI tool as an author or co-author.

CONTRIBUTING.md says the human submitting a change is its author, whatever wrote
the first draft. This enforces that, because a policy nobody checks is a policy
nobody follows.

Three fields are checked, since naming a tool as the author is just as much a
violation as a trailer: the commit author, the committer, and any
``Co-authored-by:`` trailer.

The matching is deliberately conservative. Claude, Jean-Claude, Devin, Gemini
and Mistral are all real people's names, so a bare given name never trips this;
a vendor address or a product name is required.

Usage:
    python scripts/check_authors.py                      # origin/main..HEAD
    python scripts/check_authors.py <range>              # any git range
    python scripts/check_authors.py --commit-msg <file>  # a single message
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Identifying a tool has to be done without blocking people. "Claude",
# "Jean-Claude", "Devin", "Gemini" and "Mistral" are all real human names, so a
# bare given name is never enough on its own. Two signals are used instead: the
# vendor address the tool commits from, and product names no person is called.

# Domains that only ever belong to a vendor's automation. Matched on the domain,
# never the local part, so devin@example.com stays fine.
AI_EMAIL_DOMAINS = (
    r"@anthropic\.com",
    r"@openai\.com",
    r"@cursor\.(?:sh|com)",
    r"@cognition(?:-ai)?\.(?:ai|com)",
    r"@mistral\.ai",
)

# Product names. Each needs a qualifier where the first word is also a human
# name, and stands alone only where it is not.
AI_NAME_PATTERNS = (
    r"\bclaude[\s-]*(?:code|opus|sonnet|haiku|ai|assistant|bot|\d)",
    r"\bcopilot\b",
    r"\bchatgpt\b",
    r"\bopenai\b",
    r"\banthropic\b",
    r"\bgpt-?[0-9](?:\.\d+)?o?\b",
    r"\bcodex\b",
    r"\baider\b",
    r"\bgemini[\s-]*(?:cli|pro|code|ai|assistant|bot|\d)",
    r"\bcursor[\s-]*(?:agent|ai|bot)",
    r"\bdevin[\s-]*(?:ai|bot)",
    r"\bmistral[\s-]*(?:ai|bot)",
    r"\bllama[\s-]*(?:\d|ai|bot)",
    # The GitHub App convention, e.g. "copilot[bot]" or "openai-codex[bot]".
    # Scoped to the AI apps on purpose: this check runs on every pull request,
    # and a bare `\[bot\]` would fail dependabot[bot], renovate[bot] and
    # github-actions[bot], which the policy is not about.
    r"\b(?:copilot|codex|claude|devin|cursor|gemini|chatgpt|openai|anthropic|aider)[\w.-]*\[bot\]",
)

MATCHER = re.compile("|".join(AI_EMAIL_DOMAINS + AI_NAME_PATTERNS), re.IGNORECASE)

ADVICE = """
CONTRIBUTING.md: the human submitting a change is its author. An AI tool may
have written the first draft, but it is not an author or co-author.

Fix the commit(s):
    git commit --amend            # drop the trailer, or correct the author
    git rebase -i <base>          # for more than the last commit

and check your identity:
    git config user.name
    git config user.email
"""


def _run(args: list[str]) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"git {' '.join(args)} failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return result.stdout


def check_message(text: str, label: str) -> list[str]:
    """Return the offending lines in one commit message."""
    problems = []
    for line in text.splitlines():
        if line.lower().startswith("co-authored-by:") and MATCHER.search(line):
            problems.append(f"{label}: {line.strip()}")
    return problems


def check_range(rev_range: str) -> list[str]:
    """Return every violation across the commits in ``rev_range``."""
    # A record separator keeps multi-line bodies unambiguous.
    raw = _run(["log", "--format=%H%x00%an <%ae>%x00%cn <%ce>%x00%B%x1e", rev_range])
    problems: list[str] = []
    for record in raw.split("\x1e"):
        if not record.strip():
            continue
        sha, author, committer, body = (record.strip().split("\x00") + ["", "", "", ""])[:4]
        short = sha[:12]
        if MATCHER.search(author):
            problems.append(f"{short} author: {author}")
        if MATCHER.search(committer):
            problems.append(f"{short} committer: {committer}")
        problems += check_message(body, f"{short} trailer")
    return problems


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--commit-msg":
        if len(argv) < 2:
            print("--commit-msg needs a path", file=sys.stderr)
            return 2
        # Git writes commit messages as UTF-8; read_text() would otherwise use
        # the platform default and blow up on an accented name in a trailer.
        problems = check_message(Path(argv[1]).read_text(encoding="utf-8"), "commit message")
    else:
        rev_range = argv[0] if argv else "origin/main..HEAD"
        problems = check_range(rev_range)

    if not problems:
        return 0

    print("An AI tool is credited as an author or co-author:\n", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
