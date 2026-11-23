# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""CI reads the default branch's settings and overrides, and fails closed (issues #3, #41; contracts §10.5).
Locally, ``check --repo`` applies the repository's own overrides by advisory (#42, §10.4)."""

from __future__ import annotations

import base64
import io
import json
import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.ci_context import (
    DefaultBranchUnreadableError,
    Fetch,
    in_ci,
    load_repository_context,
    read_default_branch,
)
from ssc_guardian.cli import main
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.findings import Collector, Ecosystem, ExitCode, Finding, Rule, SkipReason, Verb, make_finding
from ssc_guardian.overrides import Facts, release
from ssc_guardian.settings import BlockOn, ConfigFileError
from tests.integration.test_check_repo import MALFORMED_OVERRIDE, VULN, nested_vulnerability, vulnerability_override
from tests.refusal_sites import Refuses, refuses
from tests.unit.test_nested_and_advisories import NODE_ACTION, GitHub, Raw, composite, listed, make_repo, sha
from tests.unit.test_nested_and_advisories import Advisory as ActionAdvisory

pytestmark = [pytest.mark.integration, pytest.mark.doc_content]

TODAY = date(2026, 11, 3)
REPO = "owner/project"
CI = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPO}
OUTER = "0123456789abcdef0123456789abcdef01234567"


def _override(advisory: str) -> str:
    return f"""
[[override]]
ecosystem = "github-actions"
item = "some/action"
version = "{OUTER}"
rule = "known-vulnerability"
reference = "{advisory}"
category = "accepted-risk"
created = 2026-11-01
expiry = 2026-12-01
reason = "reviewed"
"""


def _api(files: Mapping[str, str], *, branch: str = "main") -> dict[str, tuple[int, bytes]]:
    def content(text: str) -> bytes:
        encoded = base64.encodebytes(text.encode()).decode()  # GitHub wraps base64 at 60 columns
        return json.dumps({"type": "file", "encoding": "base64", "content": encoded}).encode()

    listing = [{"name": name, "type": "file"} for name in [*files, "README.md"]]
    responses = {
        f"/repos/{REPO}": (200, json.dumps({"default_branch": branch}).encode()),
        f"/repos/{REPO}/contents/?ref={branch}": (200, json.dumps(listing).encode()),
    }
    responses |= {f"/repos/{REPO}/contents/{name}?ref={branch}": (200, content(text)) for name, text in files.items()}
    return responses


def _fetch(responses: Mapping[str, tuple[int, bytes]], seen: list[str] | None = None) -> Fetch:
    def fetch(path: str) -> tuple[int, bytes]:
        if seen is not None:
            seen.append(path)
        return responses.get(path, (404, b'{"message": "Not Found"}'))

    return fetch


def _repository(tmp_path: Path, settings: str | None = None, overrides: str | None = None) -> str:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    if settings is not None:
        (root / ".ssc-guardian.toml").write_text("format = 1\n" + settings)
    if overrides is not None:
        (root / ".ssc-guardian-overrides.toml").write_text("format = 1\n" + overrides)
    return str(root)


def _finding(advisory: str) -> Finding:
    return make_finding(
        Rule.KNOWN_VULNERABILITY, Ecosystem.GITHUB_ACTIONS, item="some/action", version=OUTER, evidence=[advisory]
    )


FACTS = {a: Facts(kev_listed=False, fix_passes=False) for a in ("GHSA-2222-3333-4444", "GHSA-5555-6666-7777")}


def test_ci_counts_only_default_branch_overrides(tmp_path: Path) -> None:
    # The change adds an override for its own finding; the default branch has another one.
    root = _repository(tmp_path, overrides=_override("GHSA-2222-3333-4444"))
    api = _api({".ssc-guardian-overrides.toml": "format = 1\n" + _override("GHSA-5555-6666-7777")})
    context = load_repository_context(root, environ=CI, fetch=_fetch(api), today=TODAY, home=str(tmp_path))
    assert context.in_ci
    assert [o.reference for o in context.overrides] == ["GHSA-5555-6666-7777"]
    change_finding = _finding("GHSA-2222-3333-4444")
    assert not release(change_finding, context.overrides, today=TODAY, facts=FACTS).released
    assert release(_finding("GHSA-5555-6666-7777"), context.overrides, today=TODAY, facts=FACTS).released
    # Locally, the repository's own overrides apply, with the notice that CI uses only the
    # default branch's.
    local = load_repository_context(root, environ={}, fetch=_fetch({}), today=TODAY, home=str(tmp_path))
    assert release(change_finding, local.overrides, today=TODAY, facts=FACTS).released
    assert [f.rule for f in local.notices] == [Rule.CI_OVERRIDES]


def test_ci_ignores_the_change_overrides_even_without_default_branch_ones(tmp_path: Path) -> None:
    root = _repository(tmp_path, overrides=_override("GHSA-2222-3333-4444"))
    context = load_repository_context(root, environ=CI, fetch=_fetch(_api({})), today=TODAY, home=str(tmp_path))
    assert context.overrides == ()
    assert context.notices == ()


def test_ci_applies_the_stricter_of_default_branch_and_change(tmp_path: Path) -> None:
    # A change that lowers the cooldown, lifts a deny entry or adds an acknowledgment gains nothing.
    ack = '[[acknowledgment]]\nrepository = "new/action"\nrepository_id = 5\ndate = 2026-11-03\n'
    root = _repository(tmp_path, settings="[defaults]\ncooldown_days = 1\n" + ack)
    api = _api(
        {".ssc-guardian.toml": 'format = 1\ndeny = ["github-actions:bad/action"]\n[defaults]\ncooldown_days = 30\n'}
    )
    context = load_repository_context(root, environ=CI, fetch=_fetch(api), today=TODAY, home=str(tmp_path))
    assert context.settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "any/action") == 30
    assert context.settings.denied(Ecosystem.GITHUB_ACTIONS, "Bad/Action")
    assert context.settings.acknowledgments == ()
    assert [(f.rule, f.place) for f in context.notices] == [(Rule.WEAKENED_SETTING, f"{root}/.ssc-guardian.toml")]


def test_ci_with_no_files_on_the_default_branch_lets_the_change_only_tighten(tmp_path: Path) -> None:
    # Q5: the listing proves both files are absent, so the first pull request that adds the
    # settings file can pass; the built-in defaults are its floor in CI (owner ruling B1).
    root = _repository(tmp_path, settings='[defaults]\ncooldown_days = 30\nblock_on = "never"\n')
    seen: list[str] = []
    context = load_repository_context(root, environ=CI, fetch=_fetch(_api({}), seen), today=TODAY, home=str(tmp_path))
    assert context.settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "a/b") == 30
    assert context.settings.block_on is BlockOn.STRONG
    assert seen == [f"/repos/{REPO}", f"/repos/{REPO}/contents/?ref=main"]  # only GETs of listed files
    # Locally the same file applies as written (Q4: built-ins are only the fallback).
    local = load_repository_context(root, environ={}, fetch=_fetch({}), today=TODAY, home=str(tmp_path))
    assert local.settings.block_on is BlockOn.NEVER


@pytest.mark.parametrize(
    "change",
    [
        '[defaults]\nblock_on = "never"\n',
        '[rules]\n"github-actions:evil/act" = { cooldown_days = 0 }\n',
    ],
)
def test_ci_change_cannot_go_below_built_ins_the_default_branch_leaves_unset(tmp_path: Path, change: str) -> None:
    root = _repository(tmp_path, settings=change)
    api = _api({".ssc-guardian.toml": "format = 1\n[defaults]\ncooldown_days = 30\n"})
    settings = load_repository_context(root, environ=CI, fetch=_fetch(api), today=TODAY, home=str(tmp_path)).settings
    assert settings.block_on is BlockOn.STRONG
    assert settings.cooldown_days(Ecosystem.GITHUB_ACTIONS, "evil/act") == 30
    assert settings.weakened  # and the weaker values are reported


@pytest.mark.parametrize("status", [403, 404, 500, None])
@pytest.mark.parametrize(
    "failing",
    [
        f"/repos/{REPO}",
        f"/repos/{REPO}/contents/?ref=main",
        f"/repos/{REPO}/contents/.ssc-guardian.toml?ref=main",
        f"/repos/{REPO}/contents/.ssc-guardian-overrides.toml?ref=main",
    ],
)
def test_ci_fails_with_exit_two_when_default_branch_unreadable(
    tmp_path: Path, status: int | None, failing: str
) -> None:
    root = _repository(tmp_path)
    responses = _api({".ssc-guardian.toml": "format = 1\n", ".ssc-guardian-overrides.toml": "format = 1\n"})
    answer = _fetch(responses)

    def fetch(path: str) -> tuple[int, bytes]:
        if path != failing:
            return answer(path)
        if status is None:
            raise ConnectionError("network down")
        return status, b'{"message": "denied"}'

    collector = Collector(Verb.CHECK)
    with collector.check(Ecosystem.GITHUB_ACTIONS, root):
        load_repository_context(root, environ=CI, fetch=fetch, today=TODAY, home=str(tmp_path))
    result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.reason, s.in_scope) for s in result.skipped] == [(SkipReason.DEFAULT_BRANCH_UNREADABLE, True)]
    assert result.checked == ()
    # The error names the request that failed (text output only).
    with pytest.raises(DefaultBranchUnreadableError, match=re.escape(f"GET {failing} ")):
        load_repository_context(root, environ=CI, fetch=fetch, today=TODAY, home=str(tmp_path))


@pytest.mark.parametrize(
    ("path_suffix", "body", "said", "site"),
    [
        ("", b"not json", "did not return JSON", refuses("ci_context.did-not-return-json")),
        (
            "",
            b'{"default_branch": "bad..name"}',
            "^the repository's default branch is not named$",
            refuses("ci_context.repositorys-default-branch-not-named"),
        ),
        (
            "",
            b"[]",
            "^the repository's default branch is not named$",
            refuses("ci_context.repositorys-default-branch-not-named"),
        ),
        (
            "contents/?ref=main",
            b'{"not": "a list"}',
            "is not a list of entries",
            refuses("ci_context.not-list-entries"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            b'{"type": "file", "encoding": "none", "content": ""}',
            "is not a file the API returns whole",
            refuses("ci_context.not-file-api-returns-whole"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            b'{"type": "dir", "encoding": "base64", "content": ""}',
            "is not a file the API returns whole",
            refuses("ci_context.not-file-api-returns-whole"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            b"[]",
            "is not a file the API returns whole",
            refuses("ci_context.not-file-api-returns-whole"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            b'{"type": "file", "encoding": "base64"}',
            r"^\.ssc-guardian\.toml on main has no content$",
            refuses("ci_context.no-content"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            b'{"type": "file", "encoding": "base64", "content": "!!"}',
            "is not valid base64",
            refuses("ci_context.not-valid-base64"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            json.dumps(
                {"type": "file", "encoding": "base64", "content": base64.b64encode(b"format = 1\n\xff\n").decode()}
            ).encode(),
            r"^\.ssc-guardian\.toml on main: is not UTF-8$",
            refuses("ci_context.file-text-undecodable"),
        ),
        (
            "contents/.ssc-guardian.toml?ref=main",
            json.dumps(
                {"type": "file", "encoding": "base64", "content": base64.b64encode(b"format = 1\nbad = 1\n").decode()}
            ).encode(),
            "^the default branch's copy is malformed: unknown key 'bad' in the file$",
            refuses("ci_context.default-branchs-copy-malformed"),
        ),
    ],
)
def test_malformed_default_branch_answers_are_unreadable(
    tmp_path: Path, path_suffix: str, body: bytes, said: str, site: Refuses
) -> None:
    responses = _api({".ssc-guardian.toml": "format = 1\n"})
    key = f"/repos/{REPO}" + (f"/{path_suffix}" if path_suffix else "")
    responses[key] = (200, body)
    with site, pytest.raises(DefaultBranchUnreadableError, match=said):
        load_repository_context(
            _repository(tmp_path), environ=CI, fetch=_fetch(responses), today=TODAY, home=str(tmp_path)
        )


@pytest.mark.parametrize("value", ["", "missing", "owner", "-owner/repo"])
def test_ci_without_a_valid_repository_name_is_unreadable(value: str) -> None:
    environ = {"GITHUB_ACTIONS": "true"} | ({} if value == "missing" else {"GITHUB_REPOSITORY": value})
    with (
        refuses("ci_context.github-repository-not-set-owner"),
        pytest.raises(DefaultBranchUnreadableError, match="GITHUB_REPOSITORY is not set to OWNER/REPO"),
    ):
        read_default_branch(environ, _fetch({}))


def test_invalid_repository_name_is_refused_before_fetch() -> None:
    seen: list[str] = []
    environ = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "-owner/repo"}
    with (
        refuses("ci_context.github-repository-not-set-owner"),
        pytest.raises(DefaultBranchUnreadableError, match="GITHUB_REPOSITORY is not set to OWNER/REPO"),
    ):
        read_default_branch(environ, _fetch({}, seen))
    assert seen == []


def test_default_branch_non_200_is_refused_by_status() -> None:
    responses = _api({".ssc-guardian.toml": "format = 1\n"})
    responses[f"/repos/{REPO}"] = (500, b"{}")
    with refuses("ci_context.get-json-status"), pytest.raises(DefaultBranchUnreadableError, match="returned 500"):
        read_default_branch(CI, _fetch(responses))


def test_default_branch_partial_base64_is_refused() -> None:
    # An API answer that holds part of a file, or none of it, is never decoded as the whole file.
    responses = _api({".ssc-guardian.toml": "format = 1\n"})
    partial = b'{"type": "file", "encoding": "none", "content": ""}'
    responses[f"/repos/{REPO}/contents/.ssc-guardian.toml?ref=main"] = (200, partial)
    with (
        refuses("ci_context.not-file-api-returns-whole"),
        pytest.raises(DefaultBranchUnreadableError, match="is not a file the API returns whole"),
    ):
        read_default_branch(CI, _fetch(responses))


def test_default_branch_with_an_invalid_name_is_refused() -> None:
    responses = _api({".ssc-guardian.toml": "format = 1\n"})
    responses[f"/repos/{REPO}"] = (200, b'{"default_branch": "bad..name"}')
    with (
        refuses("ci_context.repositorys-default-branch-not-named"),
        pytest.raises(DefaultBranchUnreadableError, match="^the repository's default branch is not named$"),
    ):
        read_default_branch(CI, _fetch(responses))


def test_ci_is_detected_only_by_github_actions_true() -> None:
    assert in_ci({"GITHUB_ACTIONS": "true"})
    for value in ("True", "1", "yes", ""):
        assert not in_ci({"GITHUB_ACTIONS": value})
    assert not in_ci({})


def test_a_malformed_local_file_is_an_unfinished_check(tmp_path: Path) -> None:
    root = _repository(tmp_path, settings='deny = ["requests"]\n')
    with (
        refuses("settings.does-not-name-ecosystem-pypi"),
        refuses("settings.malformed-entry"),
        pytest.raises(ConfigFileError, match="does not name its ecosystem") as caught,
    ):
        load_repository_context(root, environ={}, fetch=_fetch({}), today=TODAY, home=str(tmp_path))
    assert caught.value.place == f"{root}/.ssc-guardian.toml"


@pytest.mark.parametrize(
    ("listing", "said", "site"),
    [
        (
            [{"name": f"file-{n}", "type": "file"} for n in range(1000)],
            "may be truncated",
            refuses("ci_context.listing-may-be-truncated"),
        ),
        ([{"name": ["x"], "type": "file"}], "has an entry with no name", refuses("ci_context.entry-no-name")),
    ],
)
def test_a_listing_that_cannot_prove_absence_is_unreadable(
    listing: list[dict[str, object]], said: str, site: Refuses
) -> None:
    responses = _api({})
    responses[f"/repos/{REPO}/contents/?ref=main"] = (200, json.dumps(listing).encode())
    with site, pytest.raises(DefaultBranchUnreadableError, match=said):
        read_default_branch(CI, _fetch(responses))


def test_ci_change_cannot_narrow_the_scope_and_is_reported(tmp_path: Path) -> None:
    # #255 (owner's ruling of 2026-11-14, option A): no setting chooses what is checked, so a
    # change's [scope] cannot narrow anything: the file is refused (exit 2, naming its line),
    # never read as a narrower scope, and nothing in it applies.
    root = _repository(tmp_path, settings='[scope]\necosystems = ["pypi"]\n')
    said = r"\.ssc-guardian\.toml: line \d+: scope\.ecosystems is no longer read"
    scope_refused, malformed = refuses("settings.scope-refused"), refuses("settings.malformed-entry")
    with scope_refused, malformed, pytest.raises(ConfigFileError, match=said) as raised:
        load_repository_context(root, environ=CI, fetch=_fetch(_api({})), today=TODAY, home=str(tmp_path))
    assert raised.value.skip(Ecosystem.GITHUB_ACTIONS).in_scope  # an unfinished check, never a pass


def test_ci_change_that_only_tightens_raises_no_false_notice(tmp_path: Path) -> None:
    root = _repository(tmp_path, settings="[defaults]\ncooldown_days = 30\n")
    context = load_repository_context(root, environ=CI, fetch=_fetch(_api({})), today=TODAY, home=str(tmp_path))
    assert context.settings.cooldown_days(Ecosystem.PYPI, "requests") == 30
    # The built-in floor is not a file, so a stricter change reports nothing as weakened.
    assert context.notices == ()


def test_ci_ignores_a_malformed_overrides_file_in_the_change(tmp_path: Path) -> None:
    root = _repository(tmp_path, overrides="not = [valid")
    context = load_repository_context(root, environ=CI, fetch=_fetch(_api({})), today=TODAY, home=str(tmp_path))
    assert context.overrides == ()


def test_a_body_that_is_not_bytes_is_unreadable() -> None:
    def fetch(path: str) -> tuple[int, Any]:
        return 200, None

    with (
        refuses("ci_context.did-not-return-json"),
        pytest.raises(DefaultBranchUnreadableError, match="did not return JSON"),
    ):
        read_default_branch(CI, fetch)


def test_default_branch_override_matches_normalized_version(tmp_path: Path) -> None:
    # #41: the default branch's overrides match through the same one spelling of a version as
    # the finding ID (D18). That file holds Action overrides only, whose version is the exact
    # commit: its one spelling is the SHA as given, so the override releases that commit and
    # no other, and a PEP 440 spelling such as 1.0 is still refused for an Action.
    root = _repository(tmp_path)
    api = _api({".ssc-guardian-overrides.toml": "format = 1\n" + _override("GHSA-5555-6666-7777")})
    context = load_repository_context(root, environ=CI, fetch=_fetch(api), today=TODAY, home=str(tmp_path))
    (override,) = context.overrides
    assert override.version == OUTER and override.id == replace(override, reason="other").id
    finding = _finding("GHSA-5555-6666-7777")
    assert release(finding, context.overrides, today=TODAY, facts=FACTS).released
    elsewhere = make_finding(
        Rule.KNOWN_VULNERABILITY,
        Ecosystem.GITHUB_ACTIONS,
        item="some/action",
        version="1" * 40,
        evidence=["GHSA-5555-6666-7777"],
    )
    assert not release(elsewhere, context.overrides, today=TODAY, facts=FACTS).released
    as_a_version = _override("GHSA-5555-6666-7777").replace(OUTER, "1.0")
    api = _api({".ssc-guardian-overrides.toml": "format = 1\n" + as_a_version})
    # A malformed default-branch overrides copy releases nothing and is returned to list (#166).
    with (
        refuses("ci_context.default-branch-overrides-malformed"),
        refuses("overrides.bad-entry-value"),
        refuses("overrides.malformed-entry"),
        refuses("overrides.version-not-valid"),
    ):
        context = load_repository_context(root, environ=CI, fetch=_fetch(api), today=TODAY, home=str(tmp_path))
        skip = context.overrides_unusable.skip(Ecosystem.GITHUB_ACTIONS) if context.overrides_unusable else None
    assert context.overrides == ()
    assert isinstance(context.overrides_unusable, DefaultBranchUnreadableError)
    assert "version is not a valid sha" in str(context.overrides_unusable)
    assert skip is not None and (skip.place, skip.reason) == (None, SkipReason.DEFAULT_BRANCH_UNREADABLE)


@pytest.mark.parametrize(
    ("kev", "age", "applied"),
    [
        ([], 30, True),  # not KEV-listed: the GHSA override releases the advisory
        (["CVE-2025-30066"], 8, False),  # its CVE is KEV-listed and the override is over 7 days old
        (["CVE-2025-30066"], 7, True),
    ],
)
def test_check_repo_override_names_its_advisory_by_any_id_and_follows_its_cves_kev(
    tmp_path: Path, kev: list[str], age: int, applied: bool
) -> None:
    # #42: check --repo groups each advisory's GHSA and CVE, so one override for the GHSA releases
    # a finding whose evidence is both, and its KEV status is the CVE's (Kev.status on the GHSA
    # alone would say "not listed" and keep a KEV-listed vulnerability's override for 90 days).
    # The finding is nested, so no fixed version can be pinned and an override can apply.
    github = GitHub(
        advisories=[ActionAdvisory("GHSA-mrrh-fwg8-r2c3", "t6/vuln", "<= 1.0.0", "1.0.1", "CVE-2025-30066")]
    )
    github.kev = kev
    github.publisher(
        "t5/outer", 105, tags={"v5": sha(50)}, files={(sha(50), "action.yml"): composite(f"t6/vuln@{sha(60)}")}
    )
    github.publisher("t6/vuln", 107, tags={"v1.0.0": sha(60)}, files={(sha(60), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"t5/outer@{sha(50)}", lock=[listed("t5/outer", sha(50), "v5")])
    created = TODAY - timedelta(days=age)
    (root / ".ssc-guardian-overrides.toml").write_text(
        'format = 1\n[[override]]\necosystem = "github-actions"\nitem = "t6/vuln"\n'
        f'version = "{sha(60)}"\nrule = "known-vulnerability"\nreference = "GHSA-mrrh-fwg8-r2c3"\n'
        f'category = "deferred-upgrade"\ncreated = {created.isoformat()}\n'
        f'expiry = {(created + timedelta(days=60)).isoformat()}\nreason = "outer fix pending"\n'
    )
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(home=str(tmp_path / "home"), environ={}, today=TODAY, client=github.client(), stderr=err)
    code = main(["check", "--repo", str(root), "--json"], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    doc = json.loads(out.getvalue())
    vulnerabilities = [f for f in doc["findings"] if f["rule"] == "known-vulnerability"]
    assert [f["evidence"] for f in vulnerabilities] == ([] if applied else [["CVE-2025-30066", "GHSA-mrrh-fwg8-r2c3"]])
    assert [o["reference"] for o in doc["overrides"]["applied"]] == (["GHSA-mrrh-fwg8-r2c3"] if applied else [])
    assert [o["reference"] for o in doc["overrides"]["expired"]] == ([] if applied else ["GHSA-mrrh-fwg8-r2c3"])
    assert code == (0 if applied else 1)


@pytest.mark.parametrize(
    ("copy", "problem"),
    [
        (("format = 1\n" + vulnerability_override(TODAY) + MALFORMED_OVERRIDE).encode(), "override 2 has no ecosystem"),
        (b"format = 1\n\xff\n", "is not UTF-8"),  # decoded with the parse, so it releases nothing too
    ],
)
def test_ci_malformed_default_branch_overrides_release_nothing(tmp_path: Path, copy: bytes, problem: str) -> None:
    # #166, contracts §10.1 and §10.5: in CI the default branch's malformed overrides copy releases
    # nothing, is a default-branch-unreadable skip with no place, and the change is still checked,
    # so its finding gives exit 1. The change's own valid override never counts in CI.
    github, root = nested_vulnerability(tmp_path)
    (root / ".ssc-guardian-overrides.toml").write_text("format = 1\n" + vulnerability_override(TODAY))

    def run(data: bytes) -> tuple[int, dict[str, Any], str]:
        api = _api({".ssc-guardian-overrides.toml": ""})
        content = json.dumps({"type": "file", "encoding": "base64", "content": base64.b64encode(data).decode()})
        api[f"/repos/{REPO}/contents/.ssc-guardian-overrides.toml?ref=main"] = (200, content.encode())
        github.routes |= {key: (status, Raw(body)) for key, (status, body) in api.items()}
        out, err = io.StringIO(), io.StringIO()
        handler = CheckEnvs(home=str(tmp_path / "home"), environ=CI, today=TODAY, client=github.client(), stderr=err)
        code = main(["check", "--repo", str(root), "--json"], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
        return code, json.loads(out.getvalue()), err.getvalue()

    # The control: the default branch's valid copy releases the finding.
    code, doc, _ = run(("format = 1\n" + vulnerability_override(TODAY)).encode())
    assert code == 0 and [o["reference"] for o in doc["overrides"]["applied"]] == [VULN]
    with refuses("ci_context.default-branch-overrides-malformed"), refuses("ci_context.default-branch-copy-skipped"):
        code, doc, err = run(copy)
    assert code == doc["exit_code"] == 1
    vulnerabilities = [f for f in doc["findings"] if f["rule"] == "known-vulnerability"]
    assert [(f["item"], f["evidence"]) for f in vulnerabilities] == [("t6/vuln", ["CVE-2025-30066", VULN])]
    assert doc["overrides"] == {"applied": [], "expired": []}
    assert [(s["place"], s["reason"]) for s in doc["skipped"] if s["in_scope"]] == [(None, "default-branch-unreadable")]
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(root)}]  # no extra skip at the root
    assert f".ssc-guardian-overrides.toml on main is malformed: {problem}" in err


def test_ci_malformed_default_branch_settings_still_stop_the_check(tmp_path: Path) -> None:
    # #166: the settings copy changes what is checked, so it keeps today's stop (exit 2).
    github, root = nested_vulnerability(tmp_path)
    api = _api({".ssc-guardian.toml": "format = 1\nbad = 1\n"})
    github.routes |= {key: (status, Raw(body)) for key, (status, body) in api.items()}
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(home=str(tmp_path / "home"), environ=CI, today=TODAY, client=github.client(), stderr=err)
    with refuses("ci_context.default-branchs-copy-malformed"):
        code = main(["check", "--repo", str(root), "--json"], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    doc = json.loads(out.getvalue())
    assert code == doc["exit_code"] == 2 and doc["findings"] == []
    assert [(s["place"], s["reason"]) for s in doc["skipped"] if s["in_scope"]] == [
        (str(root), "default-branch-unreadable")
    ]
