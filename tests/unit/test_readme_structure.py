# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""README.md is the front door: its structure, and its ties to the code (#323).

- ``## Quick start`` follows ``## Install`` and shows real text and JSON output: a ``VIOLATION``
  block with its ``fix:`` line, the summary line, the footer and a ``--json`` excerpt.
- Every subcommand and ``--flag`` on a Guardian command line the README shows exists in
  ``cli.build_parser()``. A command line is a code span or fenced line holding the word
  ``ssc-guardian`` (the words after it), or a code span that starts with a Guardian verb
  (``check --repo``). The flags of uv, gh, pip and Python are never read. A word after
  ``ssc-guardian`` that is neither a verb nor an option must have the shape of the output lines
  the quick start shows (``ssc-guardian check: ...``, ``ssc-guardian 1.0.0, exit 1: ...``), so a
  misspelled verb still fails.
- The quick start names no home folder, temporary folder, user name, host name or e-mail
  address: pasted output uses ``~/projects/app`` style placeholders.
- ``## Known limits`` has four groups and no bullet outside them.
- While ``publisher.py`` exempts Guardian's own repository from the young or little-used rule,
  the README says so (enforcement-integrity: every exemption the code applies is disclosed).

Each check has a planted negative control. The checks read files only and change nothing.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from ssc_guardian import cli
from ssc_guardian.plugins.actions import publisher

# doc_content: these tests read README.md.
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
GUARDIAN = "ssc-guardian"
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(`+)(?!`)(?:(?!\n[ \t]*\n)[\s\S])*?(?<!`)\1(?!`)")
SHELL_ENDS = frozenset({";", "&&", "||", "|", "&", "done"})
# The two output lines whose second word is not a verb: the summary's "check:" and the footer's
# "1.0.0,".
OUTPUT_WORD = re.compile(r"^(?:(?:check|protect|install|pin|acknowledge|override):|\d+\.\d+\.\d+(?:\.\w+)?,)$")
KNOWN_LIMITS_GROUPS = ("Scope and platform", "Not yet (planned)", "What Guardian cannot enforce", "Edge cases")
PERSONAL: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/Users/[^/\s`\"]+"), "a macOS home folder"),
    (re.compile(r"/home/[^/\s`\"]+"), "a Linux home folder"),
    (re.compile(r"/private/|/var/folders/|/tmp/"), "a temporary folder"),
    (re.compile(r"[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), "an e-mail address"),
    (re.compile(r"\b[\w-]+\.(?:local|lan|internal)\b"), "a host name"),
    (re.compile(r"^[\w.-]+@[\w.-]+[ :]", re.M), "a shell prompt with a user and host name"),
)


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _prose_and_fenced(text: str) -> tuple[str, list[str]]:
    """*text* without its fenced code blocks, and the lines inside them."""
    prose: list[str] = []
    fenced: list[str] = []
    fence = ""
    for line in text.splitlines():
        match = FENCE.match(line)
        if fence:
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
                fence = ""
            else:
                fenced.append(line)
        elif match:
            fence = match.group(1)
        else:
            prose.append(line)
    return "\n".join(prose), fenced


def _section(text: str, heading: str) -> str:
    """The text under the ``## `` *heading*, up to the next ``## `` heading."""
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert match, f"no section {heading!r}"
    return match.group(1)


def headings(text: str) -> list[str]:
    prose, _ = _prose_and_fenced(text)
    return re.findall(r"^## (.+?)\s*$", prose, re.M)


def quick_start_problems(text: str) -> list[str]:
    """The quick start follows Install and shows real text and JSON output."""
    names = headings(text)
    if "Install" not in names or "Quick start" not in names:
        return ["no Install or no Quick start section"]
    problems: list[str] = []
    if names.index("Quick start") != names.index("Install") + 1:
        problems.append(f"Quick start does not follow Install: {names}")
    _, fenced = _prose_and_fenced(_section(text, "Quick start"))
    shown = "\n".join(fenced)
    wanted = {
        "a VIOLATION block": r"^VIOLATION \S+",
        "a fix: line": r"^  fix: .*\bssc-guardian \w+",
        "the summary line": r"^ssc-guardian check: \d+ violations?, ",
        "the footer": r"^ssc-guardian \d+\.\d+\.\d+, exit [012]: ",
        "a JSON excerpt": r'^\s*"format_version": "\d+\.\d+"',
    }
    problems += [f"the quick start shows no {what}" for what, rx in wanted.items() if not re.search(rx, shown, re.M)]
    return problems


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _options(parser: argparse.ArgumentParser) -> set[str]:
    return {option for action in parser._actions for option in action.option_strings}


def command_lines(text: str) -> list[tuple[str, list[str]]]:
    """Each Guardian command line in *text*: (the line, its words after ``ssc-guardian`` up to the
    end of that shell command). A code span that starts with a verb counts as its words."""
    verbs = set(_subcommands(cli.build_parser()))
    prose, fenced = _prose_and_fenced(text)
    spans = [" ".join(m.group(0).strip("`").split()) for m in CODE_SPAN.finditer(prose)]
    found: list[tuple[str, list[str]]] = []
    for line in [*spans, *fenced]:
        words = line.replace("\\|", "|").split()
        if GUARDIAN in words:
            rest = words[words.index(GUARDIAN) + 1 :]
        elif line in spans and words[:1] and words[0] in verbs and len(words) > 1:
            rest = words
        else:
            continue
        cut = next((i for i, word in enumerate(rest) if word in SHELL_ENDS or word.endswith(";")), len(rest))
        found.append((line, rest[:cut]))
    return found


def cli_problems(text: str) -> list[str]:
    """Each subcommand or flag a Guardian command line in *text* names that the parser lacks."""
    parser = cli.build_parser()
    verbs = _subcommands(parser)
    problems: list[str] = []
    for line, words in command_lines(text):
        if not words:
            continue
        first = words[0]
        if OUTPUT_WORD.match(first):
            continue
        if first.startswith("-"):
            target = parser
        elif first in verbs:
            target = verbs[first]
            nested = _subcommands(target)
            if nested and len(words) > 1 and not words[1].startswith("-"):
                if words[1] not in nested:
                    problems.append(f"{line}: `{first} {words[1]}` is not a command")
                    continue
                target = nested[words[1]]
        else:
            problems.append(f"{line}: {first!r} is not a command")
            continue
        for word in words:
            flag = word.strip("[]()").split("=", 1)[0]
            if flag.startswith("-") and flag != "-" and flag not in _options(target):
                problems.append(f"{line}: {flag} is not an option of {target.prog!r}")
    return problems


def personal_path_problems(text: str) -> list[str]:
    return [f"{what}: {m.group(0)!r}" for rx, what in PERSONAL for m in rx.finditer(text)]


def known_limits_problems(text: str) -> list[str]:
    """Known limits holds exactly the four groups, in order, and every bullet sits under one."""
    section = _section(text, "Known limits")
    groups = re.findall(r"^### (.+?)\s*$", section, re.M)
    problems: list[str] = []
    if tuple(groups) != KNOWN_LIMITS_GROUPS:
        problems.append(f"the groups are {groups}, not {list(KNOWN_LIMITS_GROUPS)}")
    current = ""
    counts = dict.fromkeys(groups, 0)
    for line in section.splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
        elif line.startswith("- "):
            if not current:
                problems.append(f"a bullet sits directly under Known limits: {line[:80]}")
            else:
                counts[current] += 1
    problems += [f"the group {name!r} is empty" for name, count in counts.items() if not count]
    return problems


def exemption_problems(text: str, own_id: int | None) -> list[str]:
    """While the code exempts Guardian's own repository (it has an ID), one README paragraph or
    bullet names the repository, the rule it is exempt from, and the exact-name-and-ID match."""
    if own_id is None:
        return []
    prose, _ = _prose_and_fenced(text)
    items = [" ".join(block.split()) for block in re.split(r"\n[ \t]*\n|\n(?=- )", prose)]
    needed = (publisher.OWN_REPOSITORY, "exempt", "young or little-used", "exact name", "numeric ID")
    if any(all(word in item for word in needed) for item in items):
        return []
    return [f"README.md does not disclose that {publisher.OWN_REPOSITORY} is exempt from the young or little-used rule"]


def test_readme_has_quick_start_after_install() -> None:
    readme = _readme()
    assert quick_start_problems(readme) == []
    # Negative control: the quick start moved after Commands is out of order.
    quick = "## Quick start\n" + _section(readme, "Quick start")
    moved = readme.replace(quick, "").replace("## Settings\n", quick + "## Settings\n")
    assert moved != readme
    assert quick_start_problems(moved) == [f"Quick start does not follow Install: {headings(moved)}"]
    # Negative control: a quick start without its JSON excerpt is caught.
    stripped = re.sub(r'^\s*"format_version".*\n', "", readme, flags=re.M)
    assert quick_start_problems(stripped) == ["the quick start shows no a JSON excerpt"]


def test_readme_flags_exist_in_the_cli() -> None:
    readme = _readme()
    # Idempotency: the check reads the file only; two runs give the same answer.
    assert cli_problems(readme) == cli_problems(readme) == []
    named = {word for _, words in command_lines(readme) for word in words}
    # Not vacuous: the forms the command table leads with, the filters and install's flag are read.
    assert {"--envs", "--path", "--repo", "--language", "--ecosystem", "--venv"} <= named
    # The quick start's output lines are skipped, not read as commands.
    assert cli_problems("```\nssc-guardian check: 1 violation, 0 warnings\nssc-guardian 1.0.0, exit 1: x\n```\n") == []
    # Negative controls: an unknown flag, a misspelled verb, an unknown override verb, and a flag
    # in a code span that starts with a verb.
    assert cli_problems("`ssc-guardian check --no-such-flag --path <p>`") == [
        "ssc-guardian check --no-such-flag --path <p>: --no-such-flag is not an option of 'ssc-guardian check'"
    ]
    assert cli_problems("```\n$ ssc-guardian chek --path ~/projects/app\n```\n") == [
        "$ ssc-guardian chek --path ~/projects/app: 'chek' is not a command"
    ]
    # Only a verb followed by a colon reads as output, so a misspelled one is still caught.
    assert cli_problems("```\nssc-guardian chek: 1 violation\n```\n") == [
        "ssc-guardian chek: 1 violation: 'chek:' is not a command"
    ]
    assert cli_problems("`ssc-guardian override remove`") == [
        "ssc-guardian override remove: `override remove` is not a command"
    ]
    assert cli_problems("Run `install --yes --venv <path>` or `check --repo --bogus`.") == [
        "check --repo --bogus: --bogus is not an option of 'ssc-guardian check'"
    ]
    # A flag that belongs to another command is caught too: `--venv` is install's, not check's.
    assert cli_problems("`ssc-guardian check --venv <p>`") != []
    # Other tools' flags are never read.
    assert cli_problems("`uv venv --python 3.11 --seed` and `python -m venv --copies`") == []


def test_readme_quick_start_has_no_personal_paths() -> None:
    readme = _readme()
    quick = _section(readme, "Quick start")
    assert personal_path_problems(quick) == []
    assert "~/projects/app" in quick
    # Negative control: a planted home-folder line fails, as do an e-mail address and a host prompt.
    assert personal_path_problems(quick + "  place: /Users/someone/projects/app/.venv\n") == [
        "a macOS home folder: '/Users/someone'"
    ]
    assert personal_path_problems("Written: /private/tmp/x/pip.conf") == ["a temporary folder: '/private/'"]
    assert [what for what in personal_path_problems("sent by someone@example.com")] == [
        "an e-mail address: 'someone@example.com'"
    ]
    assert personal_path_problems("someone@laptop ~ % ssc-guardian check --repo .") == [
        "a shell prompt with a user and host name: 'someone@laptop '"
    ]
    # Edge case: an Action reference is not an e-mail address.
    assert personal_path_problems("fix: actions/checkout v4: ssc-guardian pin actions/checkout@v4.2.2") == []


def test_readme_known_limits_has_four_groups() -> None:
    readme = _readme()
    assert known_limits_problems(readme) == []
    assert "Rust" not in _section(readme, "Known limits")
    # Edge case: a bullet planted directly under the heading, before the first group, is caught.
    planted = readme.replace("## Known limits\n", "## Known limits\n\n- An ungrouped limit.\n", 1)
    assert planted != readme
    assert known_limits_problems(planted) == ["a bullet sits directly under Known limits: - An ungrouped limit."]
    # A missing group is caught.
    dropped = readme.replace("### Edge cases\n", "", 1)
    assert dropped != readme
    assert known_limits_problems(dropped)[0].startswith("the groups are ")


def test_readme_names_the_own_repository_exemption() -> None:
    readme = _readme()
    # The code still exempts the repository by exact name and ID, so the README must say so.
    assert publisher.OWN_REPOSITORY_ID is not None
    assert exemption_problems(readme, publisher.OWN_REPOSITORY_ID) == []
    # Error path: removing the disclosure fails while the code still exempts the repository.
    removed = re.sub(r"^- Guardian's own repository .*?(?=^- )", "", readme, count=1, flags=re.M | re.S)
    assert removed != readme
    assert len(exemption_problems(removed, publisher.OWN_REPOSITORY_ID)) == 1
    # With no ID nothing is exempt, so there is nothing to disclose.
    assert exemption_problems(removed, None) == []
