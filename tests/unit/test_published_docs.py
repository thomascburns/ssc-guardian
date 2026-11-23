# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The published documents read as a well-formed public project (#327).

- ``pyproject.toml`` has project URLs, classifiers and keywords, and every URL points at the
  public repository, ``github.com/thomascburns/ssc-guardian``.
- No published document cites a section of the unpublished design plan, an issue number or an
  internal code. Two parts are exempt, each named below with its reason. A link's target (a URL
  or an anchor) is not a citation, so it is not read.
- No prose line of a published document is wider than 100 columns. Tables, fenced code blocks
  and a line whose over-length is one unbreakable token (a long URL, say) are excepted.
- The public changelog names no issue number.
- Every ``ssc-guardian <word>`` in a published document, where the word is a plain lowercase
  word, names a verb the CLI parser has, or is one of a written-out list of ordinary words (a
  title such as "ssc-guardian reference"). The summary line (``ssc-guardian check: ...``) passes
  because ``check`` is a verb, and the footer (``ssc-guardian 1.0.0, exit 0: ...``) because a
  version is not a word. A misspelled verb fails.

Each check is a function that returns the problems it finds: the real files give none, and a
planted copy gives at least one. The checks read files only and give the same result on a re-run.
No network.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

import pytest

from ssc_guardian import cli

# doc_content: these tests read the published documents and pyproject.toml.
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
PYPROJECT = REPO / "pyproject.toml"
CHANGELOG = "docs/changelog.md"
CONTRACTS = "docs/contracts.md"
README = "README.md"
# The Markdown files the public repository holds. A published document that links another
# Markdown file must link one of these (test_published_doc_list_covers_linked_documents).
PUBLISHED_DOCS = (
    README,
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/agent-instructions.md",
    "docs/authority-patterns.md",
    CHANGELOG,
    "docs/claude-code-routing.md",
    CONTRACTS,
    "docs/gate-snippet.md",
    "docs/reference.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
)
# Exempt from the citation check, each with its reason:
# - docs/contracts.md is the frozen design record; its header and its legend decode its codes.
CITATION_EXEMPT_FILES = frozenset({CONTRACTS})
# - README.md "About these documents" explains what such a reference means, with examples.
CITATION_EXEMPT_SECTIONS = {README: "About these documents"}

PUBLIC_URL = "https://github.com/thomascburns/ssc-guardian"
URL_KEYS = ("Homepage", "Source", "Issues", "Security", "Changelog")
MAX_WIDTH = 100

FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
LINK_TARGET = re.compile(r"\]\([^)\s]*\)")
CITATIONS = (
    (re.compile(r"(?i)\bplan\s*§"), "cites the plan"),
    (re.compile(r"(?i)\bv\d+(?:\.\d+)? plan\b"), "cites the plan"),
    # A § that does not follow the name of the published contracts record.
    (
        re.compile(r"(?<!contracts )(?<!contracts\.md )(?<!contracts\.md\] )§"),
        "cites a section of no published document",
    ),
    (re.compile(r"\bfact \d+\b"), "cites a plan fact"),
    (re.compile(r"(?<![\w&/#])#\d+\b"), "cites an issue number"),
    # The codes docs/contracts.md's legend decodes.
    (re.compile(r"\b(?:[DQBNLTM]\d{1,2}|N-\d+|R\d-K\d+|FC-\d+)\b"), "cites an internal code"),
)
ISSUE_NUMBER = re.compile(r"(?<![\w&/#])#\d+\b")
GUARDIAN_WORD = re.compile(r"(?<![\w/.-])ssc-guardian[ \t]+([a-z][a-z-]*)(?![\w-])")
# Ordinary words that follow the name in the published documents without naming a verb: the
# titles "ssc-guardian reference" and "ssc-guardian contracts record", "install ssc-guardian into
# its own venv", "the ssc-guardian repository" and the gate script's "ssc-guardian commit gate" and
# "ssc-guardian gate:" lines.
ORDINARY_WORDS = frozenset({"reference", "contracts", "into", "repository", "commit", "gate"})

Problems = list[str]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def verbs() -> frozenset[str]:
    """The top-level verbs of ``cli.build_parser()``."""
    parser = cli.build_parser()
    found = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    assert len(found) == 1, "the parser has one set of verbs"
    return frozenset(found[0].choices)


def _lines_outside_code(text: str) -> list[tuple[int, str]]:
    """Each (line number, line) of *text* outside fenced code blocks."""
    kept: list[tuple[int, str]] = []
    fence = ""
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if fence:
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
                fence = ""
        elif match:
            fence = match.group(1)
        else:
            kept.append((number, line))
    return kept


def _without_section(text: str, heading: str) -> str:
    """*text* with the lines of its ``## heading`` section blanked, so line numbers stay true."""
    lines = text.splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("## "):
            inside = line == f"## {heading}"
        out.append("" if inside else line)
    return "\n".join(out)


# --- checks ------------------------------------------------------------------------


def pyproject_problems(text: str) -> Problems:
    try:
        project = tomllib.loads(text).get("project")
    except tomllib.TOMLDecodeError as exc:
        return [f"pyproject.toml does not parse: {exc}"]
    if not isinstance(project, dict):
        return ["pyproject.toml has no [project] table"]
    problems: Problems = []
    urls = project.get("urls")
    if not isinstance(urls, dict):
        return ["[project.urls] is missing"]
    problems += [f"[project.urls] has no {key}" for key in URL_KEYS if key not in urls]
    for key, url in urls.items():
        if not isinstance(url, str) or not (url == PUBLIC_URL or url.startswith(PUBLIC_URL + "/")):
            problems.append(f"[project.urls] {key} does not point at the public repository: {url!r}")
        elif url.startswith(PUBLIC_URL + "/blob/main/") and not (REPO / url.split("/blob/main/", 1)[1]).is_file():
            problems.append(f"[project.urls] {key} names a file that does not exist: {url!r}")
    for key in ("classifiers", "keywords"):
        value = project.get(key)
        if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
            problems.append(f"[project] {key} is missing or empty")
    classifiers = project.get("classifiers") or []
    if isinstance(classifiers, list) and any(str(c).startswith("License ::") for c in classifiers):
        problems.append("a License classifier duplicates the license expression")
    return problems


def citation_problems(rel: str, text: str) -> Problems:
    if rel in CITATION_EXEMPT_FILES:
        return []
    if rel in CITATION_EXEMPT_SECTIONS:
        text = _without_section(text, CITATION_EXEMPT_SECTIONS[rel])
    problems: Problems = []
    for number, line in enumerate(text.splitlines(), 1):
        bare = LINK_TARGET.sub("]", line)
        for pattern, what in CITATIONS:
            match = pattern.search(bare)
            if match:
                problems.append(f"{rel}:{number}: {what}: {match.group(0)!r}")
    return problems


def _one_unbreakable_token(line: str) -> bool:
    """The part past the limit is one token that would not fit even on a line of its own."""
    if " " in line[MAX_WIDTH:]:
        return False
    start = line.rfind(" ", 0, MAX_WIDTH) + 1
    indent = len(line) - len(line.lstrip(" "))
    return max(indent, 0) + len(line[start:]) > MAX_WIDTH


def width_problems(rel: str, text: str) -> Problems:
    return [
        f"{rel}:{number}: {len(line)} columns"
        for number, line in _lines_outside_code(text)
        if len(line) > MAX_WIDTH and not line.lstrip().startswith("|") and not _one_unbreakable_token(line)
    ]


def issue_number_problems(rel: str, text: str) -> Problems:
    return [
        f"{rel}:{number}: names an issue number: {match.group(0)!r}"
        for number, line in enumerate(text.splitlines(), 1)
        for match in ISSUE_NUMBER.finditer(LINK_TARGET.sub("]", line))
    ]


def command_problems(rel: str, text: str, known: frozenset[str]) -> Problems:
    return [
        f"{rel}:{number}: 'ssc-guardian {match.group(1)}' names no verb"
        for number, line in enumerate(text.splitlines(), 1)
        for match in GUARDIAN_WORD.finditer(line)
        if match.group(1) not in known and match.group(1) not in ORDINARY_WORDS
    ]


# --- tests ---------------------------------------------------------------------------


def test_published_docs_exist() -> None:
    assert [rel for rel in PUBLISHED_DOCS if not (REPO / rel).is_file()] == []


def test_published_doc_list_covers_linked_documents() -> None:
    """A Markdown file a published document links is itself on the list (fail closed)."""
    listed = {(REPO / rel).resolve() for rel in PUBLISHED_DOCS}
    missing = set()
    for rel in PUBLISHED_DOCS:
        for target in re.findall(r"\]\(([^)\s#]+\.md)(?:#[^)\s]*)?\)", _read(rel)):
            if "://" not in target and (REPO / rel).parent.joinpath(target).resolve() not in listed:
                missing.add(f"{rel} -> {target}")
    assert sorted(missing) == []


def test_pyproject_has_urls_classifiers_and_keywords() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    assert pyproject_problems(text) == []
    # Negative: a URL to another repository, a missing URL, and missing classifiers each fail.
    other = text.replace(f'Issues = "{PUBLIC_URL}/issues"', f'Issues = "{PUBLIC_URL}-fork/issues"')
    assert other != text
    assert pyproject_problems(other) == [
        f"[project.urls] Issues does not point at the public repository: '{PUBLIC_URL}-fork/issues'"
    ]
    no_changelog = re.sub(r"^Changelog = .*\n", "", text, flags=re.M)
    assert no_changelog != text
    assert pyproject_problems(no_changelog) == ["[project.urls] has no Changelog"]
    no_classifiers = re.sub(r"^classifiers = \[\n(?:    .*\n)*\]\n", "", text, flags=re.M)
    assert no_classifiers != text
    assert pyproject_problems(no_classifiers) == ["[project] classifiers is missing or empty"]


@pytest.mark.parametrize("rel", PUBLISHED_DOCS)
def test_published_docs_cite_no_plan_or_issue_numbers(rel: str) -> None:
    assert citation_problems(rel, _read(rel)) == []


@pytest.mark.parametrize(
    ("planted", "what"),
    [
        pytest.param("See plan §5 for the release.", "cites the plan", id="plan-section"),
        pytest.param("They follow the v1.0 plan, §2.2.", "cites the plan", id="v1-plan"),
        pytest.param("As §3 says.", "cites a section of no published document", id="bare-section"),
        pytest.param("Files attach to a draft (fact 16).", "cites a plan fact", id="fact"),
        pytest.param("Fixed in #123.", "cites an issue number", id="issue"),
        pytest.param("Pattern R2-K3 applies.", "cites an internal code", id="code"),
    ],
)
def test_planted_citation_fails(planted: str, what: str) -> None:
    text = _read("docs/agent-instructions.md") + "\n" + planted + "\n"
    problems = citation_problems("docs/agent-instructions.md", text)
    assert problems and all(what in p for p in problems[:1]), problems


def test_citation_check_spares_link_targets_contracts_and_the_about_section() -> None:
    # A link's anchor and a contracts section reference are not citations.
    assert citation_problems("x.md", "See [contracts §2](contracts.md#2-commands-plan-21).\n") == []
    assert citation_problems("x.md", "[docs/contracts.md](docs/contracts.md) §5 gives it.\n") == []
    # The two exempt parts: a citation there passes, and the same text elsewhere fails.
    assert citation_problems(CONTRACTS, "Plan §2.4 (R2-K3).\n") == []
    readme = _read(README)
    about = "## About these documents\n"
    assert citation_problems(README, readme.replace(about, about + "\nplan §5\n")) == []
    assert citation_problems(README, readme.replace("## Install\n", "## Install\n\nplan §5\n"))


@pytest.mark.parametrize("rel", PUBLISHED_DOCS)
def test_published_prose_lines_fit_100_columns(rel: str) -> None:
    assert width_problems(rel, _read(rel)) == []


def test_width_rule_excepts_tables_code_and_one_long_token() -> None:
    long_prose = "word " * 25
    long_url = "[link](https://example.com/" + "a" * 120 + ")."
    text = "\n".join(
        [
            "| " + "cell " * 30 + "|",  # a table row
            "```",
            long_prose,  # in a code block
            "```",
            long_url,  # one unbreakable token
            "Some words, then " + long_url,  # a token that would not fit on its own line either
        ]
    )
    assert width_problems("x.md", text) == []
    # Negative: a long prose line fails, and so does one whose overflow could break at a space.
    assert width_problems("x.md", long_prose) == [f"x.md:1: {len(long_prose)} columns"]
    breakable = "w" * 90 + " " + "x" * 20 + " end"
    assert width_problems("x.md", breakable) == [f"x.md:1: {len(breakable)} columns"]


def test_changelog_has_no_private_issue_numbers() -> None:
    text = _read(CHANGELOG)
    assert issue_number_problems(CHANGELOG, text) == []
    # Error path: a planted issue number fails; a URL's fragment does not.
    planted = text + "\n- Fixed a crash (#123).\n"
    assert issue_number_problems(CHANGELOG, planted) == [
        f"{CHANGELOG}:{len(planted.splitlines())}: names an issue number: '#123'"
    ]
    assert issue_number_problems(CHANGELOG, "See [notes](https://example.com/page#123).\n") == []


@pytest.mark.parametrize("rel", PUBLISHED_DOCS)
def test_published_docs_name_only_real_commands(rel: str) -> None:
    assert command_problems(rel, _read(rel), verbs()) == []


def test_planted_misspelled_command_fails() -> None:
    known = verbs()
    assert {"check", "protect", "install", "pin", "acknowledge", "override"} <= known
    rel = "docs/gate-snippet.md"
    planted = _read(rel) + "\n```sh\nssc-guardian chek --repo .\n```\n"
    assert command_problems(rel, planted, known) == [
        f"{rel}:{len(planted.splitlines()) - 1}: 'ssc-guardian chek' names no verb"
    ]
    # A hyphenated word is read whole: no verb has a hyphen, so it is always a misspelling.
    assert command_problems("x.md", "ssc-guardian chek-repo --repo .\n", known) == [
        "x.md:1: 'ssc-guardian chek-repo' names no verb"
    ]
    # The summary line and the footer the documents show pass.
    output = (
        "ssc-guardian check: 1 violation, 0 warnings, 1 notice; 1 checked\n"
        "ssc-guardian 1.0.0, exit 1: at least one violation.\n"
        "ssc-guardian <version>, exit N: the verdict.\n"
    )
    assert command_problems("x.md", output, known) == []
    # A repository name is not the command.
    assert command_problems("x.md", "gh release download -R thomascburns/ssc-guardian -p x\n", known) == []


def test_checks_are_idempotent() -> None:
    before = {rel: (REPO / rel).read_bytes() for rel in PUBLISHED_DOCS}
    known = verbs()

    def run() -> list[Problems]:
        return [
            pyproject_problems(PYPROJECT.read_text(encoding="utf-8")),
            *(citation_problems(rel, _read(rel)) for rel in PUBLISHED_DOCS),
            *(width_problems(rel, _read(rel)) for rel in PUBLISHED_DOCS),
            *(command_problems(rel, _read(rel), known) for rel in PUBLISHED_DOCS),
            issue_number_problems(CHANGELOG, _read(CHANGELOG)),
        ]

    first, second = run(), run()
    assert first == second == [[] for _ in first]
    assert {rel: (REPO / rel).read_bytes() for rel in PUBLISHED_DOCS} == before
