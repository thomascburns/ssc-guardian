# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The public issue templates hold the wording this project expects (part 5 of #12; #327).

The four files under ``.github/ISSUE_TEMPLATE/`` are read with Guardian's own YAML reader
(``ssc_guardian.yaml_subset``), which keeps every value as text, so ``false`` stays the text
``false``. Each property is a function that returns the problems it finds: the real files must
give none, and a planted copy must give at least one. A planted copy is the real file with one
exact substitution, made only after the test has checked that the text it replaces is there
exactly once, so a negative case can never pass because the file moved on.

The properties: blank issues are off and the only contact link is private vulnerability
reporting; the folder holds exactly the bug, documentation-gap and question forms and the
chooser; the bug form requires the three things CONTRIBUTING.md "Issues" asks for, and the
question form the question; every form opens with the privacy note and sends vulnerabilities to
SECURITY.md; each form carries exactly its one label; each file starts with the copyright and
SPDX lines; and no file names this project's development tooling. The pull-request template
(Markdown, so it carries no comment header) holds CONTRIBUTING.md's two sentences on pull
requests and links CONTRIBUTING.md in the public repository. No network; nothing is written
outside ``tmp_path``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.yaml_subset import parse, to_python

# doc_content: the pull-request template checks read CONTRIBUTING.md (#327).
pytestmark = [pytest.mark.unit, pytest.mark.doc_content]

REPO = Path(__file__).resolve().parents[2]
TEMPLATES = REPO / ".github" / "ISSUE_TEMPLATE"
BUG = TEMPLATES / "bug.yml"
DOCS_GAP = TEMPLATES / "docs-gap.yml"
CONFIG = TEMPLATES / "config.yml"
QUESTION = TEMPLATES / "question.yml"
PR_TEMPLATE = REPO / ".github" / "PULL_REQUEST_TEMPLATE.md"
CONTRIBUTING = REPO / "CONTRIBUTING.md"
TEMPLATE_FILES = frozenset({"bug.yml", "docs-gap.yml", "question.yml", "config.yml"})
CONTRIBUTING_LINK = "[CONTRIBUTING.md](https://github.com/thomascburns/ssc-guardian/blob/main/CONTRIBUTING.md)"

ADVISORY_URL = "https://github.com/thomascburns/ssc-guardian/security/advisories/new"
SECURITY_LINK = "[SECURITY.md](https://github.com/thomascburns/ssc-guardian/blob/main/SECURITY.md)"
PRIVACY_NOTE = (
    "Before you post, remove anything private: tokens, private repository names, paths and package names "
    "you do not want to publish."
)
SECURITY_NOTE = "Do not report a suspected vulnerability here."
HEADER = ("# Copyright 2026 Thomas C. Burns\n", "# SPDX-License-Identifier: Apache-2.0\n")
# The checks that no form names the development repository or one of the owner's private
# repositories run in the development repository, so this published file holds none of those
# names (#325, #332).
BANNED = ("adopt-config", "issue-quality", "audit", "stamp", "TODO")
BUG_REQUIRED = ("version", "command", "output")
DOCS_GAP_REQUIRED = ("document", "gap")
QUESTION_REQUIRED = ("question",)

Problems = list[str]


def _load(text: str, source: str) -> dict[str, Any]:
    data = to_python(parse(text, source))
    assert isinstance(data, dict), f"{source}: top level is not a mapping"
    return data


def _planted(tmp_path: Path, real: Path, old: str, new: str) -> tuple[str, Path]:
    text = real.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"{real.name}: the text to replace is not there exactly once: {old!r}"
    planted = tmp_path / real.name
    planted.write_text(text.replace(old, new), encoding="utf-8")
    return planted.read_text(encoding="utf-8"), planted


# --- properties ---------------------------------------------------------------


def blank_issue_problems(config: dict[str, Any]) -> Problems:
    value = config.get("blank_issues_enabled")
    return [] if value == "false" else [f"blank_issues_enabled is {value!r}, not 'false'"]


def contact_link_problems(config: dict[str, Any]) -> Problems:
    links = config.get("contact_links")
    if not isinstance(links, list) or len(links) != 1:
        return [f"expected exactly one contact link, found {links!r}"]
    link = links[0]
    problems = []
    if not isinstance(link, dict):
        return [f"contact link is not a mapping: {link!r}"]
    if link.get("url") != ADVISORY_URL:
        problems.append(f"contact link URL is {link.get('url')!r}, not {ADVISORY_URL!r}")
    if link.get("name") != "Report a vulnerability privately":
        problems.append(f"contact link name is {link.get('name')!r}")
    about = str(link.get("about", ""))
    if "privately" not in about or "Do not open a public issue" not in about:
        problems.append(f"contact link about line lacks the expected wording: {about!r}")
    return problems


def required_field_problems(form: dict[str, Any], ids: tuple[str, ...]) -> Problems:
    fields = {item.get("id"): item for item in form.get("body", []) if isinstance(item, dict)}
    problems = []
    for field_id in ids:
        field = fields.get(field_id)
        if field is None:
            problems.append(f"required field {field_id!r} is missing")
        elif (field.get("validations") or {}).get("required") != "true":
            problems.append(f"field {field_id!r} is not required")
    return problems


def note_problems(form: dict[str, Any]) -> Problems:
    body = form.get("body") or [{}]
    first = body[0] if isinstance(body[0], dict) else {}
    if first.get("type") != "markdown":
        return ["the form does not open with a markdown note"]
    value = " ".join(str((first.get("attributes") or {}).get("value", "")).split())
    return [f"the note lacks {part!r}" for part in (PRIVACY_NOTE, SECURITY_NOTE, SECURITY_LINK) if part not in value]


def label_problems(form: dict[str, Any], label: str) -> Problems:
    labels = form.get("labels")
    return [] if labels == [label] else [f"labels are {labels!r}, not [{label!r}]"]


def header_problems(text: str) -> Problems:
    lines = tuple(text.splitlines(keepends=True)[:2])
    return [] if lines == HEADER else [f"the file does not start with the licence header: {lines!r}"]


def banned_word_problems(text: str) -> Problems:
    lower = text.lower()
    return [f"names {word!r}" for word in BANNED if word.lower() in lower]


def folder_problems(names: set[str]) -> Problems:
    """The template folder holds exactly the known files: a renamed or extra form is found."""
    missing = sorted(TEMPLATE_FILES - names)
    extra = sorted(names - TEMPLATE_FILES)
    return [f"missing {name}" for name in missing] + [f"unexpected {name}" for name in extra]


def _flat(text: str) -> str:
    return " ".join(text.replace("**", "").split())


def contributing_pr_sentences(contributing: str) -> str:
    """The first paragraph of CONTRIBUTING.md "Pull requests", bold and line breaks removed."""
    marker = "## Pull requests\n"
    if marker not in contributing:
        return ""
    section = contributing.split(marker, 1)[1].lstrip("\n")
    return _flat(section.split("\n\n", 1)[0])


def pr_template_problems(template: str, contributing: str) -> Problems:
    sentences = contributing_pr_sentences(contributing)
    problems = []
    if not sentences:
        problems.append("CONTRIBUTING.md has no Pull requests paragraph")
    elif sentences not in _flat(template):
        problems.append("the template does not hold CONTRIBUTING.md's sentences on pull requests")
    if CONTRIBUTING_LINK not in template:
        problems.append("the template does not link CONTRIBUTING.md in the public repository")
    return problems


# --- the real files -------------------------------------------------------------


def test_templates_read_with_guardians_yaml_reader() -> None:
    for path in (BUG, DOCS_GAP, QUESTION, CONFIG):
        _load(path.read_text(encoding="utf-8"), str(path))


def test_template_folder_holds_exactly_the_known_forms() -> None:
    assert folder_problems({p.name for p in TEMPLATES.iterdir()}) == []
    # Negative: a renamed form is missing under its old name and unexpected under the new one.
    renamed = (TEMPLATE_FILES - {"docs-gap.yml"}) | {"docs.yml"}
    assert folder_problems(set(renamed)) == ["missing docs-gap.yml", "unexpected docs.yml"]
    # Negative: the form's name before #342, restored beside the current one, is unexpected.
    restored = TEMPLATE_FILES | {"feature.yml"}
    assert folder_problems(set(restored)) == ["unexpected feature.yml"]


def test_blank_issues_are_off() -> None:
    assert blank_issue_problems(_load(CONFIG.read_text(encoding="utf-8"), str(CONFIG))) == []


def test_only_contact_link_is_private_vulnerability_reporting() -> None:
    assert contact_link_problems(_load(CONFIG.read_text(encoding="utf-8"), str(CONFIG))) == []


def test_bug_form_requires_version_command_and_output() -> None:
    bug = _load(BUG.read_text(encoding="utf-8"), str(BUG))
    assert bug["name"] == "Bug or wrong verdict"
    assert required_field_problems(bug, BUG_REQUIRED) == []


def test_docs_gap_form_requires_document_and_gap() -> None:
    form = _load(DOCS_GAP.read_text(encoding="utf-8"), str(DOCS_GAP))
    assert form["name"] == "Documentation gap"
    assert required_field_problems(form, DOCS_GAP_REQUIRED) == []


def test_question_form_requires_the_question() -> None:
    form = _load(QUESTION.read_text(encoding="utf-8"), str(QUESTION))
    assert form["name"] == "Question or idea"
    assert required_field_problems(form, QUESTION_REQUIRED) == []


def test_pr_template_holds_contributings_sentences() -> None:
    template = PR_TEMPLATE.read_text(encoding="utf-8")
    contributing = CONTRIBUTING.read_text(encoding="utf-8")
    assert pr_template_problems(template, contributing) == []
    assert banned_word_problems(template) == []


@pytest.mark.parametrize(
    ("which", "old", "new"),
    [
        pytest.param("template", "cannot be merged", "may be merged", id="template-changed"),
        pytest.param(
            "contributing", "while it is\npublished", "at launch while it is\npublished", id="contributing-changed"
        ),
        pytest.param("template", CONTRIBUTING_LINK, "CONTRIBUTING.md", id="link-dropped"),
        pytest.param("contributing", "## Pull requests\n", "## Pulls\n", id="no-section"),
    ],
)
def test_planted_pr_template_drift_fails(which: str, old: str, new: str) -> None:
    texts = {
        "template": PR_TEMPLATE.read_text(encoding="utf-8"),
        "contributing": CONTRIBUTING.read_text(encoding="utf-8"),
    }
    assert texts[which].count(old) == 1, old
    texts[which] = texts[which].replace(old, new)
    assert pr_template_problems(texts["template"], texts["contributing"])


@pytest.mark.parametrize("path", [BUG, DOCS_GAP, QUESTION], ids=["bug", "docs-gap", "question"])
def test_form_opens_with_privacy_and_security_note(path: Path) -> None:
    assert note_problems(_load(path.read_text(encoding="utf-8"), str(path))) == []


@pytest.mark.parametrize(
    ("path", "label"),
    [(BUG, "bug"), (DOCS_GAP, "documentation"), (QUESTION, "question")],
    ids=["bug", "docs-gap", "question"],
)
def test_form_has_its_one_default_label(path: Path, label: str) -> None:
    assert label_problems(_load(path.read_text(encoding="utf-8"), str(path)), label) == []


@pytest.mark.parametrize("path", [BUG, DOCS_GAP, QUESTION, CONFIG], ids=["bug", "docs-gap", "question", "config"])
def test_file_has_licence_header(path: Path) -> None:
    assert header_problems(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "path", [BUG, DOCS_GAP, QUESTION, CONFIG, PR_TEMPLATE], ids=["bug", "docs-gap", "question", "config", "pr"]
)
def test_file_names_no_development_tooling(path: Path) -> None:
    assert banned_word_problems(path.read_text(encoding="utf-8")) == []


# --- planted copies -------------------------------------------------------------

_SECOND_LINK = (
    "  - name: Ask a question\n"
    "    url: https://github.com/thomascburns/ssc-guardian/discussions\n"
    "    about: Ask here.\n"
)


def test_planted_blank_issues_on_fails(tmp_path: Path) -> None:
    text, planted = _planted(tmp_path, CONFIG, "blank_issues_enabled: false", "blank_issues_enabled: true")
    assert blank_issue_problems(_load(text, str(planted)))


def test_planted_second_contact_link_fails(tmp_path: Path) -> None:
    text, planted = _planted(
        tmp_path, CONFIG, "Do not open a public issue for it.\n", "Do not open a public issue for it.\n" + _SECOND_LINK
    )
    assert contact_link_problems(_load(text, str(planted)))


def test_planted_wrong_contact_url_fails(tmp_path: Path) -> None:
    text, planted = _planted(tmp_path, CONFIG, "/security/advisories/new", "/issues/new")
    assert contact_link_problems(_load(text, str(planted)))


def test_planted_contact_links_removed_fails(tmp_path: Path) -> None:
    text = CONFIG.read_text(encoding="utf-8")
    start = text.index("contact_links:\n")
    planted = tmp_path / CONFIG.name
    planted.write_text(text[:start], encoding="utf-8")
    assert contact_link_problems(_load(planted.read_text(encoding="utf-8"), str(planted)))


@pytest.mark.parametrize("field_id", BUG_REQUIRED)
def test_planted_bug_required_field_dropped_fails(tmp_path: Path, field_id: str) -> None:
    text, planted = _planted(tmp_path, BUG, f"    id: {field_id}\n", f"    id: {field_id}-renamed\n")
    assert required_field_problems(_load(text, str(planted)), BUG_REQUIRED)


_ALL_REQUIRED = (
    [(BUG, BUG_REQUIRED, f) for f in BUG_REQUIRED]
    + [(DOCS_GAP, DOCS_GAP_REQUIRED, f) for f in DOCS_GAP_REQUIRED]
    + [(QUESTION, QUESTION_REQUIRED, f) for f in QUESTION_REQUIRED]
)


@pytest.mark.parametrize(("path", "ids", "field_id"), _ALL_REQUIRED, ids=[f for _, _, f in _ALL_REQUIRED])
def test_planted_field_made_optional_fails(tmp_path: Path, path: Path, ids: tuple[str, ...], field_id: str) -> None:
    text = path.read_text(encoding="utf-8")
    start = text.index(f"    id: {field_id}\n")
    end = text.index("      required: true\n", start) + len("      required: true\n")
    old = text[start:end]
    text, planted = _planted(tmp_path, path, old, old.replace("required: true", "required: false"))
    assert required_field_problems(_load(text, str(planted)), ids)


@pytest.mark.parametrize("field_id", DOCS_GAP_REQUIRED)
def test_planted_docs_gap_required_field_dropped_fails(tmp_path: Path, field_id: str) -> None:
    text, planted = _planted(tmp_path, DOCS_GAP, f"    id: {field_id}\n", f"    id: {field_id}-renamed\n")
    assert required_field_problems(_load(text, str(planted)), DOCS_GAP_REQUIRED)


@pytest.mark.parametrize("path", [BUG, DOCS_GAP, QUESTION], ids=["bug", "docs-gap", "question"])
@pytest.mark.parametrize(
    "fragment", ["remove anything private", SECURITY_NOTE, SECURITY_LINK], ids=["privacy", "security", "link"]
)
def test_planted_note_part_removed_fails(tmp_path: Path, path: Path, fragment: str) -> None:
    text, planted = _planted(tmp_path, path, fragment, "")
    assert note_problems(_load(text, str(planted)))


@pytest.mark.parametrize(
    ("path", "label"),
    [(BUG, "bug"), (DOCS_GAP, "documentation"), (QUESTION, "question")],
    ids=["bug", "docs-gap", "question"],
)
def test_planted_extra_label_fails(tmp_path: Path, path: Path, label: str) -> None:
    text, planted = _planted(tmp_path, path, f'labels: ["{label}"]', f'labels: ["{label}", "triage"]')
    assert label_problems(_load(text, str(planted)), label)


@pytest.mark.parametrize("path", [BUG, DOCS_GAP, QUESTION, CONFIG], ids=["bug", "docs-gap", "question", "config"])
def test_planted_header_changed_fails(tmp_path: Path, path: Path) -> None:
    text, _ = _planted(tmp_path, path, HEADER[1], "# License: see LICENSE\n")
    assert header_problems(text)


@pytest.mark.parametrize("path", [BUG, DOCS_GAP, QUESTION, CONFIG], ids=["bug", "docs-gap", "question", "config"])
@pytest.mark.parametrize("word", BANNED)
def test_planted_internal_word_fails(tmp_path: Path, path: Path, word: str) -> None:
    text, planted = _planted(tmp_path, path, HEADER[1], HEADER[1] + f"# See {word}.\n")
    assert banned_word_problems(text) == [f"names {word!r}"]
    _load(text, str(planted))


def test_property_functions_are_total() -> None:
    """Each property returns a list on an empty mapping instead of raising."""
    checks: list[Callable[[dict[str, Any]], Problems]] = [
        blank_issue_problems,
        contact_link_problems,
        note_problems,
        lambda form: required_field_problems(form, BUG_REQUIRED),
        lambda form: label_problems(form, "bug"),
    ]
    for check in checks:
        assert check({})
