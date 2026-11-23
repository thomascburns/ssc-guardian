# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""T5 and T6: nested Actions, their limits, and the batched advisory request (issue #10).

GitHub is a fixture: :class:`GitHub` answers the client's requests in process (repositories,
tags, files at a commit, the activity log, and the advisory database, which matches
``affects`` as GitHub does), so no test reaches the network. The fixture is shared with
``test_publisher`` and ``test_check_repo``.
"""

from __future__ import annotations

import io
import json
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import yaml_subset
from ssc_guardian.cli import Request
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.check_repo import cache_dir
from ssc_guardian.findings import Ecosystem, ExitCode, Finding, Result, Rule, Scope, SkipReason, Verb
from ssc_guardian.lockfile import LOCK_FILE, LockEntry, dump_lock
from ssc_guardian.net import Client, Response, ShaCache
from ssc_guardian.pep440 import parse_specifiers, satisfies_all, try_parse
from ssc_guardian.plugin import AgeSource
from ssc_guardian.plugins.actions import advisories, nested
from ssc_guardian.plugins.actions.advisories import ActionAdvisory, Entry, Pin
from ssc_guardian.plugins.actions.models import UsesKind, UsesReference, action_from, workflow_from
from ssc_guardian.render import ToolInfo, to_json_obj, to_text
from tests.refusal_sites import refuses

pytestmark = pytest.mark.unit

GHA = Ecosystem.GITHUB_ACTIONS
TODAY = date(2026, 11, 3)
OLD_DAY = TODAY - timedelta(days=400)
CREATED = "2019-07-23T14:06:46Z"
NODE_ACTION = "runs:\n  using: node20\n  main: index.js\n"


def sha(n: int) -> str:
    """A distinct 40-hex commit SHA for each number."""
    return f"{n:040x}"


def composite(*uses: str) -> str:
    steps = "".join(f"    - uses: {u}\n" for u in uses)
    return f"name: x\nruns:\n  using: composite\n  steps:\n{steps}"


def workflow_text(*uses: str) -> str:
    steps = "".join(f"      - uses: {u}\n" for u in uses)
    return f"on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"


# --- the GitHub fixture ----------------------------------------------------------------


@dataclass(frozen=True)
class Raw:
    """A body sent as is (a file at a commit), not as JSON."""

    text: str | bytes


@dataclass
class Advisory:
    """One reviewed advisory as GitHub serves it."""

    ghsa: str
    action: str
    vulnerable: str
    patched: str | None = None
    cve: str | None = None

    def body(self) -> dict[str, Any]:
        return {
            "ghsa_id": self.ghsa,
            "cve_id": self.cve,
            "type": "reviewed",
            "withdrawn_at": None,
            "identifiers": [{"type": "GHSA", "value": self.ghsa}],
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "actions", "name": self.action},
                    "vulnerable_version_range": self.vulnerable,
                    "first_patched_version": self.patched,
                }
            ],
        }

    def affects(self, item: str) -> bool:
        """GitHub's ``affects`` match: the name alone, or ``name@version`` within the range."""
        name, sep, version = item.partition("@")
        if name.lower() != self.action.lower():
            return False
        parsed = try_parse(version)
        return not sep or (parsed is not None and satisfies_all(parsed, parse_specifiers(self.vulnerable)))


@dataclass
class GitHub:
    """Answers GET requests to api.github.com from a route table and an advisory database."""

    routes: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    advisories: list[Advisory] = field(default_factory=list)
    advisory_answer: tuple[Any, ...] | None = None  # a fixed answer for /advisories, for errors
    kev: list[str] = field(default_factory=list)  # CVE IDs in CISA's KEV catalog
    seen: list[str] = field(default_factory=list)
    # Per repository (lowercase name), its default branch and how each commit stands to that
    # branch ("ahead", "diverged", "behind", "identical"); see :meth:`_compare`.
    histories: dict[str, tuple[str, dict[str, str]]] = field(default_factory=dict)

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        parts = urllib.parse.urlsplit(request.full_url)
        assert parts.scheme == "https" and request.get_method() == "GET"
        if parts.hostname == "www.cisa.gov":  # the KEV catalog, fetched only when a CVE is found
            self.seen.append(f"kev:{parts.path}")
            records = [{"cveID": cve, "dateAdded": "2025-03-18"} for cve in self.kev]
            body = json.dumps({"count": len(records), "vulnerabilities": records}).encode()
            return Response(200, {}, body, request.full_url)
        assert parts.hostname == "api.github.com"
        key = parts.path + (f"?{parts.query}" if parts.query else "")
        self.seen.append(key)
        if parts.path == "/advisories":
            status, body, *headers = self.advisory_answer or (200, self._advisories(parts.query))
        else:
            # GitHub matches owner and repository names in any letter case.
            route = self.routes.get(key) or self.routes.get(key.lower()) or self._compare(parts.path)
            status, body, *headers = route or (404, {"message": "Not Found"})
        if isinstance(body, Raw):
            data = body.text if isinstance(body.text, bytes) else body.text.encode()
        else:
            data = json.dumps(body).encode()
        return Response(status, headers[0] if headers else {}, data, request.full_url)

    def _compare(self, path: str) -> tuple[Any, ...] | None:
        """GitHub's answer to ``/repos/OWNER/REPO/compare/BASE...HEAD`` for a repository given a
        ``history`` (:meth:`publisher`), else None (the default 404). As GitHub does: a commit
        compared with itself is "identical"; the default branch against a commit answers that
        commit's status ("ahead" or "diverged" for one outside the branch's history, such as a
        fork's, "behind" or "identical" for one in it); another base, or a commit the history
        does not hold, is 404."""
        repo, sep, spec = path.removeprefix("/repos/").partition("/compare/")
        base, dots, head = spec.partition("...")
        if not (sep and dots) or repo.lower() not in self.histories:
            return None
        default, statuses = self.histories[repo.lower()]
        status = "identical" if base == head else statuses.get(head) if base == default else None
        return None if status is None else (200, {"status": status})

    def _advisories(self, query: str) -> list[dict[str, Any]]:
        asked = urllib.parse.parse_qs(query)["affects"][0].split(",")
        return [a.body() for a in self.advisories if any(a.affects(item) for item in asked)]

    def client(self) -> Client:
        return Client(transport=self)

    def count(self, prefix: str) -> int:
        return sum(1 for key in self.seen if key.startswith(prefix))

    def asked(self) -> set[str]:
        """Every entry the ``affects`` filters named."""
        queries = [urllib.parse.urlsplit(key).query for key in self.seen if key.startswith("/advisories?")]
        return {item for q in queries for item in urllib.parse.parse_qs(q)["affects"][0].split(",")}

    def publisher(
        self,
        name: str,
        repo_id: int,
        *,
        created: str = CREATED,
        stars: int = 5000,
        forks: int = 300,
        tags: dict[str, str] | None = None,
        files: dict[tuple[str, str], str] | None = None,
        default_branch: str = "main",
        history: dict[str, str] | None = None,
    ) -> None:
        """One Action repository: its metadata, tags, and files at commits ``(sha, path)``.
        ``history`` maps a commit to its compare status against ``default_branch``; without it
        every compare is the default 404."""
        base = f"/repos/{name}"
        if history is not None:
            self.histories[name.lower()] = (default_branch, dict(history))
        meta = {
            "id": repo_id,
            "default_branch": default_branch,
            "stargazers_count": stars,
            "forks_count": forks,
            "created_at": created,
        }
        self.routes[base] = (200, meta)
        self.routes[f"{base}/tags?per_page=100"] = (
            200,
            [{"name": n, "commit": {"sha": s}} for n, s in (tags or {}).items()],
        )
        self.routes[f"{base}/activity?per_page=100"] = (200, [])
        self.routes[f"{base}/releases?per_page=100"] = (200, [])
        for tag, target in (tags or {}).items():
            body = {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": target}}
            self.routes[f"{base}/git/ref/tags/{tag}"] = (200, body)
        for (commit, path), text in (files or {}).items():
            self.routes[f"{base}/contents/{path}?ref={commit}"] = (200, Raw(text))


def make_repo(tmp_path: Path, *uses: str, lock: Iterable[LockEntry] = ()) -> Path:
    """A Git repository with one workflow using ``uses`` and a lock file with ``lock``."""
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(workflow_text(*uses))
    entries = tuple(lock)
    if entries:
        (root / LOCK_FILE).write_text(dump_lock(entries))
    return root


def listed(action: str, commit: str, tag: str | None = None, *, day: date = OLD_DAY) -> LockEntry:
    """A lock entry whose cooldown has long passed."""
    return LockEntry(action, commit, tag or commit, day, day, AgeSource.LOCK_FIRST_SEEN)


def check(root: Path, github: GitHub, *, home: Path | None = None, today: date = TODAY) -> tuple[Result, str]:
    """``check --repo ROOT`` through the real handler, with GitHub as a fixture."""
    err = io.StringIO()
    handler = CheckEnvs(
        home=str(home or root.parent / "home"), environ={}, today=today, client=github.client(), stderr=err
    )
    result = handler(Request(Verb.CHECK, scope=Scope(frozenset({GHA}), repo=str(root))))
    return result, err.getvalue()


def rules(result: Result) -> list[Rule]:
    return [f.rule for f in result.findings]


def only(result: Result, rule: Rule) -> Finding:
    (found,) = [f for f in result.findings if f.rule is rule]
    return found


# --- T5 ---------------------------------------------------------------------------------

OUTER, INNER = "someone/outer", "someone/inner"


def test_inner_moving_reference_names_the_chain(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@v2")})
    github.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    with refuses("nested.moving-reference"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    assert rules(result) == [Rule.NESTED_MOVING_REFERENCE]
    finding = only(result, Rule.NESTED_MOVING_REFERENCE)
    assert (finding.item, finding.version, finding.via) == (INNER, "v2", (f"{OUTER}@{sha(1)}",))
    assert finding.place == str(root / ".github" / "workflows" / "ci.yml")
    # Text output names the three fixes; the override names the outer commit and the inner reference.
    assert f"a version of {OUTER} that pins {INNER} by commit; another Action" in err
    assert f"a person's override for {OUTER}@{sha(1)} and {INNER}@v2" in err
    # Where the inner tag points today is checked too (T6 asks about it). Only the major tag
    # v2 names that commit, and it names no release: T6 asks by name alone (#142).
    assert github.count(f"/repos/{INNER}/git/ref/tags/v2") == 1
    assert INNER in github.asked() and f"{INNER}@v2" not in github.asked()


def test_inner_moving_reference_override_needs_the_exact_outer_commit_and_reference(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@v2")})
    github.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    entry = (
        '\n[[override]]\necosystem = "github-actions"\nitem = "someone/outer"\nversion = "{outer}"\n'
        'rule = "nested-moving-reference"\nreference = "{inner}"\ncategory = "accepted-risk"\n'
        'created = 2026-11-01\nexpiry = 2026-12-01\nreason = "vendor pins it next release"\n'
    )
    path = root / ".ssc-guardian-overrides.toml"
    path.write_text("format = 1\n" + entry.format(outer=sha(1), inner=f"{INNER}@v2"))
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET
    assert [r.reference for r in result.overrides_applied] == [f"{INNER}@v2"]
    assert Rule.CI_OVERRIDES in rules(result)  # locally: "CI uses only the default branch's overrides"
    # Another outer commit, or another inner reference, brings the finding back.
    for outer, inner in ((sha(9), f"{INNER}@v2"), (sha(1), f"{INNER}@v3")):
        path.write_text("format = 1\n" + entry.format(outer=outer, inner=inner))
        result, _ = check(root, github)
        assert Rule.NESTED_MOVING_REFERENCE in rules(result) and result.overrides_applied == ()


def _chain(github: GitHub, length: int) -> None:
    """``c1`` uses ``c2`` uses ... ``c<length>``, each pinned and named by its tag."""
    for n in range(1, length + 1):
        uses = composite(f"chain/c{n + 1}@{sha(n + 1)}") if n < length else NODE_ACTION
        github.publisher(f"chain/c{n}", 100 + n, tags={"v1": sha(n)}, files={(sha(n), "action.yml"): uses})


def test_depth_and_reference_limits_fail_with_exit_one(tmp_path: Path) -> None:
    # Depth: a workflow's own reference is level 1; ten levels pass, the eleventh fails.
    for length, wanted in ((10, ExitCode.RULES_MET), (11, ExitCode.VIOLATION)):
        github = GitHub()
        _chain(github, length)
        root = make_repo(tmp_path / str(length), f"chain/c1@{sha(1)}", lock=[listed("chain/c1", sha(1), "v1")])
        result, err = check(root, github)
        assert result.exit_code is wanted, err
        if wanted is ExitCode.VIOLATION:
            finding = only(result, Rule.NESTING_LIMIT)
            assert (finding.item, len(finding.via)) == ("chain/c11", 10)
            assert "deeper than 10 levels below the workflow file" in err
    # A lowered limit applies; the settings range forbids raising it past 10.
    github = GitHub()
    _chain(github, 3)
    root = make_repo(tmp_path / "lowered", f"chain/c1@{sha(1)}", lock=[listed("chain/c1", sha(1), "v1")])
    (root / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nnesting_depth = 2\n")
    with refuses("nested.depth-limit"):
        lowered, _ = check(root, github)
    assert rules(lowered) == [Rule.NESTING_LIMIT]
    (root / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nnesting_depth = 11\n")
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE and result.skipped[0].reason is SkipReason.CHECK_ERROR

    # References: 500 unique nested references pass, the 501st fails.
    for count, wanted in ((500, ExitCode.RULES_MET), (501, ExitCode.VIOLATION)):
        github = GitHub()
        inner = {f"v{n}": sha(1000 + n) for n in range(count)}
        files = {(target, "action.yml"): NODE_ACTION for target in inner.values()}
        github.publisher("many/inner", 21, tags=inner, files=files)
        uses = composite(*(f"many/inner@{target}" for target in inner.values()))
        github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): uses})
        root = make_repo(tmp_path / f"refs{count}", f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
        result, err = check(root, github)
        assert result.exit_code is wanted, err
        if wanted is ExitCode.VIOLATION:
            assert only(result, Rule.NESTING_LIMIT).version == sha(1000 + 500)
            assert "more than 500 unique nested references" in err


def test_a_limit_override_for_the_outer_commit_lets_the_walk_go_on(tmp_path: Path) -> None:
    github = GitHub()
    _chain(github, 3)
    root = make_repo(tmp_path, f"chain/c1@{sha(1)}", lock=[listed("chain/c1", sha(1), "v1")])
    (root / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nnesting_depth = 2\n")
    (root / ".ssc-guardian-overrides.toml").write_text(
        'format = 1\n[[override]]\necosystem = "github-actions"\nitem = "chain/c2"\n'
        f'version = "{sha(2)}"\nrule = "nesting-limit"\nreference = "nesting-depth"\n'
        'category = "accepted-risk"\ncreated = 2026-11-01\nexpiry = 2026-12-01\nreason = "reviewed"\n'
    )
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET
    assert [(r.item, r.reference) for r in result.overrides_applied] == [("chain/c2", "nesting-depth")]
    assert github.count(f"/repos/chain/c3/contents/action.yml?ref={sha(3)}") == 1  # read past the limit


def test_loop_is_a_violation(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher("loop/a", 31, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"loop/b@{sha(2)}")})
    github.publisher("loop/b", 32, tags={"v1": sha(2)}, files={(sha(2), "action.yml"): composite(f"loop/a@{sha(1)}")})
    root = make_repo(tmp_path, f"loop/a@{sha(1)}", lock=[listed("loop/a", sha(1), "v1")])
    with refuses("nested.loop"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    finding = only(result, Rule.NESTING_LOOP)
    assert (finding.item, finding.version, finding.via) == ("loop/a", sha(1), (f"loop/a@{sha(1)}", f"loop/b@{sha(2)}"))
    assert "a loop back to a commit already in the chain" in err
    assert github.count(f"/repos/loop/a/contents/action.yml?ref={sha(1)}") == 1  # never read twice


# The exception option as JSON shows it (contracts §4, §5): it goes to a person, with no command.
PERSON_OVERRIDE = {
    "kind": "exception",
    "item": None,
    "version": None,
    "command": None,
    "eligible_on": None,
    "requires_user_approval": False,
    "requires_person": True,
}


def _t5_repositories(tmp_path: Path) -> list[tuple[Rule, Path, GitHub]]:
    """One repository for each of T5's findings: an inner moving reference, a depth past a
    lowered limit, and a loop."""
    moving = GitHub()
    moving.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@v2")})
    moving.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    limit = GitHub()
    _chain(limit, 3)
    loop = GitHub()
    loop.publisher("loop/a", 31, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"loop/b@{sha(2)}")})
    loop.publisher("loop/b", 32, tags={"v1": sha(2)}, files={(sha(2), "action.yml"): composite(f"loop/a@{sha(1)}")})
    deep = make_repo(tmp_path / "limit", f"chain/c1@{sha(1)}", lock=[listed("chain/c1", sha(1), "v1")])
    (deep / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nnesting_depth = 2\n")
    return [
        (
            Rule.NESTED_MOVING_REFERENCE,
            make_repo(tmp_path / "moving", f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")]),
            moving,
        ),
        (Rule.NESTING_LIMIT, deep, limit),
        (
            Rule.NESTING_LOOP,
            make_repo(tmp_path / "loop", f"loop/a@{sha(1)}", lock=[listed("loop/a", sha(1), "v1")]),
            loop,
        ),
    ]


def _options_json(result: Result, rule: Rule) -> list[dict[str, Any]]:
    """The JSON ``options`` of ``result``'s one ``rule`` finding."""
    (finding,) = [f for f in to_json_obj(result, ToolInfo("1.0.0"))["findings"] if f["rule"] == rule.value]
    return list(finding["options"])


def test_nested_findings_offer_a_person_override(tmp_path: Path) -> None:
    # #151: an override can release each of T5's three findings (contracts §10.4), so each
    # offers the exception option in JSON, as known-vulnerability does.
    for rule, root, github in _t5_repositories(tmp_path):
        result, _ = check(root, github)
        assert result.exit_code is ExitCode.VIOLATION, rule
        assert _options_json(result, rule) == [PERSON_OVERRIDE], rule
        # Text output names the command a person runs, with no target.
        assert "  needs a person: ssc-guardian override add\n" in to_text(result, ToolInfo("1.0.0")), rule


def test_nested_option_is_idempotent_on_re_run(tmp_path: Path) -> None:
    # Two runs on the same repository give the same finding, with the same ID and options.
    for rule, root, github in _t5_repositories(tmp_path):
        first, second = (check(root, github)[0] for _ in range(2))
        assert only(first, rule).id == only(second, rule).id, rule
        assert _options_json(first, rule) == _options_json(second, rule) == [PERSON_OVERRIDE], rule


def test_inner_pin_gets_t4_and_an_impostor_is_not_read(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@{sha(66)}")})
    github.publisher(
        INNER, 12, tags={"v1": sha(2)}, files={(sha(66), "action.yml"): composite("x/y@v1")}, history={sha(66): "ahead"}
    )
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    with refuses("nested.impostor-commit"):
        result, _ = check(root, github)
    finding = only(result, Rule.IMPOSTOR_COMMIT)
    assert (finding.item, finding.version, finding.via) == (INNER, sha(66), (f"{OUTER}@{sha(1)}",))
    assert github.count(f"/repos/{INNER}/contents/") == 0


# --- T4's compare for a nested commit (RR7, #234) ----------------------------------------
# A nested commit that no publisher tag or activity-log entry names is in the publisher's
# history only when GitHub's compare of the default branch with it answers "behind" or
# "identical". A fork's commit, which GitHub serves through the parent repository, answers
# "ahead" or "diverged". The fixture answers as GitHub does, so a nested check that compares
# the wrong commits, or reads any answer as "in history", fails these tests.

IMPOSTOR = sha(66)


def _inner_commit(tmp_path: Path, status: str | None, *, default_branch: str = "main") -> tuple[Path, GitHub]:
    """OUTER v1 uses INNER at IMPOSTOR, which no INNER tag or activity names; its compare
    against INNER's default branch answers ``status`` (None: GitHub holds no such commit)."""
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@{IMPOSTOR}")})
    github.publisher(
        INNER,
        12,
        tags={"v2": sha(2)},
        files={(IMPOSTOR, "action.yml"): NODE_ACTION},
        default_branch=default_branch,
        history={IMPOSTOR: status} if status is not None else {},
    )
    return make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")]), github


def _assert_impostor(result: Result, github: GitHub) -> None:
    """``check --repo`` refused IMPOSTOR as an impostor commit (exit 1) and never read its files."""
    assert result.exit_code is ExitCode.VIOLATION and result.skipped == ()
    finding = only(result, Rule.IMPOSTOR_COMMIT)
    assert (finding.item, finding.version, finding.via) == (INNER, IMPOSTOR, (f"{OUTER}@{sha(1)}",))
    assert github.count(f"/repos/{INNER}/compare/") == 1  # the refusal rides on the compare answer
    assert github.count(f"/repos/{INNER}/contents/") == 0  # an impostor's files are never read


def test_nested_fork_commit_ahead_is_an_impostor(tmp_path: Path) -> None:
    root, github = _inner_commit(tmp_path, "ahead")
    with refuses("nested.impostor-commit"):
        result, _ = check(root, github)
    _assert_impostor(result, github)


def test_nested_fork_commit_diverged_is_an_impostor(tmp_path: Path) -> None:
    root, github = _inner_commit(tmp_path, "diverged")
    with refuses("nested.impostor-commit"):
        result, _ = check(root, github)
    _assert_impostor(result, github)


@pytest.mark.parametrize("status", ["behind", "identical"])
def test_nested_commit_behind_default_branch_is_verified(tmp_path: Path, status: str) -> None:
    # The control for the two above: the same commit, in the default branch's history, passes
    # and is read.
    root, github = _inner_commit(tmp_path, status)
    result, err = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET and result.skipped == (), err
    assert Rule.IMPOSTOR_COMMIT not in rules(result)
    assert github.count(f"/repos/{INNER}/compare/") == 1
    assert github.count(f"/repos/{INNER}/contents/action.yml?ref={IMPOSTOR}") == 1


def test_nested_compare_names_outer_repository_and_branch(tmp_path: Path) -> None:
    # The compare is asked of the repository the reference names, against the default branch
    # its metadata gives (here "trunk", not "main"), with the inner commit as the head. The
    # outer commit, which a tag names, needs no compare.
    root, github = _inner_commit(tmp_path, "behind", default_branch="trunk")
    result, err = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET, err
    asked = [key for key in github.seen if "/compare/" in key]
    assert asked == [f"/repos/{INNER}/compare/trunk...{IMPOSTOR}?per_page=1"]


@pytest.mark.parametrize(
    "answer",
    [None, (200, {"status": "unrelated"}), (422, {"message": "No common ancestor"})],
    ids=["no-such-commit", "unknown-status", "unprocessable"],
)
def test_nested_unexpected_compare_answer_is_an_impostor(tmp_path: Path, answer: tuple[Any, ...] | None) -> None:
    # Fail-closed: a compare answer that is not "behind" or "identical" never counts as in history.
    root, github = _inner_commit(tmp_path, None)
    if answer is not None:
        github.routes[f"/repos/{INNER}/compare/main...{IMPOSTOR}?per_page=1"] = answer
    with refuses("nested.impostor-commit"):
        result, _ = check(root, github)
    _assert_impostor(result, github)


def test_reusable_workflows_are_read_at_their_commit(tmp_path: Path) -> None:
    called = "on: [workflow_call]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: someone/inner@main\n"
    github = GitHub()
    github.publisher("org/shared", 41, tags={"v1": sha(1)}, files={(sha(1), ".github/workflows/w.yml"): called})
    github.publisher(INNER, 12)
    github.routes[f"/repos/{INNER}/git/ref/heads/main"] = (
        200,
        {"ref": "refs/heads/main", "object": {"type": "commit", "sha": sha(2)}},
    )
    github.routes[f"/repos/{INNER}/contents/action.yml?ref={sha(2)}"] = (200, Raw(NODE_ACTION))
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(
        f"on: [push]\njobs:\n  call:\n    uses: org/shared/.github/workflows/w.yml@{sha(1)}\n"
    )
    (root / LOCK_FILE).write_text(dump_lock([listed("org/shared/.github/workflows/w.yml", sha(1), "v1")]))
    result, _ = check(root, github)
    finding = only(result, Rule.NESTED_MOVING_REFERENCE)
    assert finding.via == (f"org/shared/.github/workflows/w.yml@{sha(1)}",)
    # A branch names no release: T6 asks for the name alone.
    assert INNER in github.asked()


def test_a_file_at_a_commit_that_is_not_utf8_exits_two(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)})
    github.routes[f"/repos/{OUTER}/contents/action.yml?ref={sha(1)}"] = (200, Raw(b"runs: \xff\n"))
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    with refuses("nested.not-utf-8"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [s.reason for s in result.skipped if s.in_scope] == [SkipReason.CHECK_ERROR]
    assert f"{OUTER}/action.yml at {sha(1)} is not UTF-8" in err


def test_an_action_with_no_metadata_file_at_its_commit_exits_two(tmp_path: Path) -> None:
    # Neither action.yml nor action.yaml at the commit: what it runs cannot be read, so the
    # walk stops unfinished rather than treating the Action as one with no nested references.
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    with refuses("nested.no-metadata-file"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [s.reason for s in result.skipped if s.in_scope] == [SkipReason.CHECK_ERROR]
    assert f"{OUTER} has no action.yml or action.yaml at {sha(1)}" in err


def test_files_at_a_commit_are_cached_by_repository_id_and_sha(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    first, _ = check(root, github)
    contents = github.count(f"/repos/{OUTER}/contents/")
    second, _ = check(root, github)
    assert first == second and contents == 1
    assert github.count(f"/repos/{OUTER}/contents/") == contents  # the second run read the cache
    assert (root.parent / "home" / ".cache" / "ssc-guardian" / "actions" / "11" / f"{sha(1)}.json").is_file()


WRAPPED_DESCRIPTIONS = (
    "name: wrapped\n"
    "description: 'Downloads build artifacts,\n"
    "  as actions/download-artifact v8.0.2 writes its descriptions.'\n"
    "inputs:\n"
    "  merge-multiple:\n"
    "    description: 'When multiple artifacts are matched, this changes the behavior.\n"
    "      If true, they are in one directory.\n"
    "      uses: evil/hidden@main'\n"
    "    required: false\n"
    "  path:\n"
    '    description: "Destination path. \\\n'
    '      Supports basic tilde expansion."\n' + NODE_ACTION
)


def test_nested_action_with_multiline_description_is_checked_not_skipped(tmp_path: Path) -> None:
    # #203: an Action whose action.yml wraps quoted descriptions over several lines is read and
    # checked, not skipped as YAML Guardian does not read; the uses: line inside a quote is text.
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): WRAPPED_DESCRIPTIONS})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    result, err = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET, err
    assert [s for s in result.skipped if s.in_scope] == []
    assert result.findings == ()
    assert [c.ecosystem for c in result.checked] == [GHA]
    assert github.count(f"/repos/{OUTER}/contents/action.yml") == 1
    assert github.count("/repos/evil/") == 0 and "evil/hidden" not in github.asked()
    metadata = action_from(yaml_subset.parse(WRAPPED_DESCRIPTIONS, "action.yml"), "action.yml")
    assert metadata.references == ()
    inputs = yaml_subset.to_python(yaml_subset.parse(WRAPPED_DESCRIPTIONS, "action.yml"))
    assert isinstance(inputs, dict)
    assert (
        inputs["description"]
        == "Downloads build artifacts, as actions/download-artifact v8.0.2 writes its descriptions."
    )
    assert inputs["inputs"] == {
        "merge-multiple": {
            "description": "When multiple artifacts are matched, this changes the behavior. "
            "If true, they are in one directory. uses: evil/hidden@main",
            "required": "false",
        },
        "path": {"description": "Destination path. Supports basic tilde expansion."},
    }


class _Lattice(nested.Commits):
    """A diamond lattice: each level's two Actions both use the next level's two, so every
    level doubles the chains."""

    def references(self, action: str, commit: str, kind: UsesKind) -> tuple[UsesReference, ...]:
        level = int(action.rsplit("/", 1)[1][1:])
        uses = [f"d/{side}{level + 1}@{sha(level + 1)}" for side in "lm"]
        return action_from(yaml_subset.parse(composite(*uses), "x"), "x").references

    def verify(self, action: str, commit: str) -> tuple[str, ...] | None:
        return ("v1",)


def test_walk_stops_after_too_many_chains() -> None:
    top = workflow_from(yaml_subset.parse(workflow_text(f"d/l0@{sha(0)}"), "/w.yml"), "/w.yml").references
    with (
        refuses("nested.too-many-chains"),
        pytest.raises(nested.TooManyChainsError, match="the nested Actions form more than 20000 chains"),
    ):
        nested.walk(top, commits=_Lattice(GitHub().client()), depth=100, limit=10_000)


# --- T6 ---------------------------------------------------------------------------------

VULNERABLE = "tj-actions/changed-files"


def test_one_batched_request_matches_versions_on_githubs_side() -> None:
    github = GitHub(advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", VULNERABLE, "<= 45.0.7", "46.0.1", "CVE-2025-30066")])
    pins = [
        Pin("/w.yml", VULNERABLE, sha(1), ("v45.0.7",)),
        Pin("/w.yml", "actions/checkout", sha(2), ("v4.2.2",)),
        Pin("/w.yml", "Actions/Checkout", sha(3), ("v4.2.2",)),
    ]
    found = advisories.fetch(github.client(), pins)
    assert github.count("/advisories") == 1
    assert advisories.queries(pins) == ["actions/checkout@v4.2.2", "tj-actions/changed-files@v45.0.7"]
    (hit,) = advisories.match(pins, found)
    assert (hit.pin, hit.rule, hit.patched) == (pins[0], Rule.KNOWN_VULNERABILITY, "46.0.1")
    assert hit.evidence == ("CVE-2025-30066", "GHSA-mrrh-fwg8-r2c3")
    assert advisories.fetch(github.client(), []) == () and github.count("/advisories") == 1  # nothing to ask


def test_several_versions_of_one_action_are_told_apart_by_the_range() -> None:
    advisory = ActionAdvisory("GHSA-mcph-m25j-8j63", (), (Entry(VULNERABLE, "< 41", "41"),))
    old, new = Pin("/w.yml", VULNERABLE, sha(1), ("v40.0.0",)), Pin("/w.yml", VULNERABLE, sha(2), ("v46.0.1",))
    assert [h.pin for h in advisories.match([old, new], [advisory])] == [old]
    # A range Guardian cannot read rules nothing out; nor does an answer whose range clears
    # every asked version (GitHub matched one of them).
    unreadable = ActionAdvisory("GHSA-mcph-m25j-8j63", (), (Entry(VULNERABLE, "~> 41", None),))
    assert [h.pin for h in advisories.match([old, new], [unreadable])] == [old, new]
    cleared = ActionAdvisory("GHSA-mcph-m25j-8j63", (), (Entry(VULNERABLE, "< 1", None),))
    assert [h.pin for h in advisories.match([old, new], [cleared])] == [old, new]


def test_an_advisory_with_no_well_formed_id_is_malformed_and_the_check_unfinished(tmp_path: Path) -> None:
    # An advisory that matches but carries no ID output may show: never dropped, it is a
    # malformed-name violation, and the step it broke leaves the repository's check unfinished.
    github = GitHub(advisories=[Advisory("GHSA-not-an-id", VULNERABLE, "<= 45.0.7")])
    github.publisher(VULNERABLE, 13, tags={"v45.0.7": sha(1)}, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{VULNERABLE}@{sha(1)}", lock=[listed(VULNERABLE, sha(1), "v45.0.7")])
    with refuses("advisories.malformed-advisory-id"), refuses("check_repo.step-check-error"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    (finding,) = result.findings
    assert (finding.rule, finding.place, finding.malformed_value) == (Rule.MALFORMED_NAME, str(root), "GHSA-not-an-id")
    assert [(s.reason, s.place) for s in result.skipped] == [(SkipReason.CHECK_ERROR, str(root))]
    assert f"ssc-guardian: {root}: check-error\n" in err


def test_unreleased_pin_with_advisories_cannot_be_ruled_out(tmp_path: Path) -> None:
    github = GitHub(advisories=[Advisory("GHSA-qmg3-hpqr-gqvc", "reviewdog/action-setup", "= 1")])
    github.publisher("reviewdog/action-setup", 51, files={(sha(7), "action.yml"): NODE_ACTION})
    # Pinned by bare SHA: the lock file records the SHA as its tag, so no release is named.
    root = make_repo(tmp_path, f"reviewdog/action-setup@{sha(7)}", lock=[listed("reviewdog/action-setup", sha(7))])
    with refuses("advisories.advisory-hit"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    finding = only(result, Rule.UNRELEASED_PIN_ADVISORY)
    assert (finding.item, finding.version, finding.evidence) == (
        "reviewdog/action-setup",
        sha(7),
        ("GHSA-qmg3-hpqr-gqvc",),
    )
    assert "cannot rule out GHSA-qmg3-hpqr-gqvc; pin to a released version" in err
    assert github.asked() == {"reviewdog/action-setup"}


# --- T6: which tags are asked (#142) ------------------------------------------------------

MAJOR = "someone/major"


def test_outer_pin_asks_every_tag_naming_the_commit(tmp_path: Path) -> None:
    # Pinned through the major tag v4, which the lock file records; the commit is release v4.1.3.
    github = GitHub(advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", MAJOR, ">= 4.1.0, < 4.1.5", "4.1.5")])
    github.publisher(MAJOR, 21, tags={"v4": sha(4), "v4.1.3": sha(4)}, files={(sha(4), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{MAJOR}@{sha(4)}", lock=[listed(MAJOR, sha(4), "v4")])
    result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION  # never a pass behind the tag name v4
    finding = only(result, Rule.KNOWN_VULNERABILITY)
    assert (finding.item, finding.version, finding.evidence) == (MAJOR, sha(4), ("GHSA-mrrh-fwg8-r2c3",))
    assert github.asked() == {f"{MAJOR}@v4.1.3"}  # the release; v4 names none, so it is not sent
    assert f"{MAJOR}@{sha(4)} (v4.1.3): GHSA-mrrh-fwg8-r2c3; fixed in 4.1.5" in err
    assert github.count(f"/repos/{MAJOR}/tags") == 1  # the tags list, once in the run


def test_pin_with_no_version_tag_cannot_be_ruled_out(tmp_path: Path) -> None:
    # Only a major tag and names that are no version name the commit: sent by name alone, and
    # any advisory for the Action is "cannot rule out", as for a bare SHA.
    github = GitHub(advisories=[Advisory("GHSA-qmg3-hpqr-gqvc", MAJOR, ">= 0")])
    tags = {"stable": sha(5), "latest": sha(5), "v4": sha(5)}
    github.publisher(MAJOR, 21, tags=tags, files={(sha(5), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{MAJOR}@{sha(5)}", lock=[listed(MAJOR, sha(5), "stable")])
    result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    assert rules(result) == [Rule.UNRELEASED_PIN_ADVISORY]
    assert only(result, Rule.UNRELEASED_PIN_ADVISORY).evidence == ("GHSA-qmg3-hpqr-gqvc",)
    assert "cannot rule out GHSA-qmg3-hpqr-gqvc; pin to a released version" in err
    assert github.asked() == {MAJOR}


def test_inner_moving_reference_asks_every_tag(tmp_path: Path) -> None:
    # An inner @v2 behind a person's override: T6 still asks about the release it names today.
    github = GitHub(advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", INNER, ">= 2.1.0, < 2.1.5", "2.1.5")])
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@v2")})
    github.publisher(INNER, 12, tags={"v2": sha(2), "v2.1.3": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    (root / ".ssc-guardian-overrides.toml").write_text(
        'format = 1\n\n[[override]]\necosystem = "github-actions"\nitem = "someone/outer"\n'
        f'version = "{sha(1)}"\nrule = "nested-moving-reference"\nreference = "{INNER}@v2"\n'
        'category = "accepted-risk"\ncreated = 2026-11-01\nexpiry = 2026-12-01\nreason = "vendor pins it next"\n'
    )
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    assert [r.reference for r in result.overrides_applied] == [f"{INNER}@v2"]  # the moving reference is released
    finding = only(result, Rule.KNOWN_VULNERABILITY)
    assert (finding.item, finding.version, finding.via) == (INNER, "v2", (f"{OUTER}@{sha(1)}",))
    assert github.asked() == {f"{OUTER}@v1.0.0", f"{INNER}@v2.1.3"}


def test_major_tag_is_not_a_version() -> None:
    for tag in ("v4", "4", "stable", "latest", "main", "V"):
        assert not advisories.is_version(tag), tag
    for tag in ("v4.1", "4.1.3", "v1.0.0-rc1", "V2.0"):
        assert advisories.is_version(tag), tag
    pin = Pin("/w.yml", MAJOR, sha(4), ("latest", "v4", "v4.1.3"))
    assert pin.versions == ("v4.1.3",)
    assert advisories.queries([pin, Pin("/w.yml", OUTER, sha(1), ("v1",))]) == [f"{MAJOR}@v4.1.3", OUTER]


def test_floating_line_tag_does_not_flag_the_fixed_release(tmp_path: Path) -> None:
    # v4.1 floats with the newest patch: on the fixed release v4.1.5 it would read as 4.1.0.
    advisory = Advisory("GHSA-mrrh-fwg8-r2c3", MAJOR, ">= 4.0.0, < 4.1.5", "4.1.5")
    github = GitHub(advisories=[advisory])
    tags = {"v4": sha(6), "v4.1": sha(6), "v4.1.5": sha(6)}
    github.publisher(MAJOR, 21, tags=tags, files={(sha(6), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{MAJOR}@{sha(6)}", lock=[listed(MAJOR, sha(6), "v4.1")])
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.RULES_MET and rules(result) == []
    assert github.asked() == {f"{MAJOR}@v4.1.5"}
    # The same line tag on a vulnerable patch still counts through that patch's own tag.
    vulnerable = Pin("/w.yml", MAJOR, sha(7), ("v4", "v4.1", "v4.1.3"))
    assert vulnerable.versions == ("v4.1.3",)
    entry = Entry(MAJOR, ">= 4.0.0, < 4.1.5", "4.1.5")
    (hit,) = advisories.match([vulnerable], [ActionAdvisory("GHSA-mrrh-fwg8-r2c3", (), (entry,))])
    assert hit.rule is Rule.KNOWN_VULNERABILITY
    # Alone, a line tag is the only version known, so it is asked; a pre-release does not extend it.
    assert Pin("/w.yml", MAJOR, sha(8), ("v4", "v4.1")).versions == ("v4.1",)
    assert Pin("/w.yml", MAJOR, sha(8), ("v4.1", "v4.1rc1")).versions == ("v4.1", "v4.1rc1")
    # A longer pre-release or dev tag never stands for the line tag: 4.1.0rc1 is outside
    # ">= 4.1.0", so it would clear a vulnerable final v4.1 (#142 review).
    assert Pin("/w.yml", MAJOR, sha(8), ("v4.1", "v4.1.0-rc.1")).versions == ("v4.1", "v4.1.0-rc.1")
    assert Pin("/w.yml", MAJOR, sha(8), ("v4.1", "v4.1.0.dev1")).versions == ("v4.1", "v4.1.0.dev1")
    promoted = Pin("/w.yml", MAJOR, sha(8), ("v4.1", "v4.1.0-rc.1"))
    (hit,) = advisories.match([promoted], [ActionAdvisory("GHSA-mrrh-fwg8-r2c3", (), (entry,))])
    assert hit.rule is Rule.KNOWN_VULNERABILITY


def test_failed_tags_request_is_exit_two(tmp_path: Path) -> None:
    github = GitHub(advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", MAJOR, ">= 4.1.0, < 4.1.5", "4.1.5")])
    github.publisher(MAJOR, 21, tags={"v4": sha(4), "v4.1.3": sha(4)}, files={(sha(4), "action.yml"): NODE_ACTION})
    github.routes[f"/repos/{MAJOR}/tags?per_page=100"] = (403, {"message": "Forbidden"})
    root = make_repo(tmp_path, f"{MAJOR}@{sha(4)}", lock=[listed(MAJOR, sha(4), "v4")])
    with refuses("net.feed-answered-http-error"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE  # never a pass on what was not asked
    assert result.checked == ()
    assert [(s.place, s.reason) for s in result.skipped] == [(str(root), SkipReason.FEED_FAILURE)]
    assert github.count("/advisories") == 0  # T6 stopped before asking under the lock tag alone
    assert "api.github.com" in err


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        ((403, {"message": "Forbidden"}), SkipReason.FEED_FAILURE),
        ((403, {"message": "API rate limit exceeded"}, {"x-ratelimit-remaining": "0"}), SkipReason.RATE_LIMIT),
    ],
)
def test_advisory_api_error_exits_two(tmp_path: Path, answer: tuple[Any, ...], reason: SkipReason) -> None:
    github = GitHub(advisory_answer=answer)
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE  # never a pass
    assert result.findings == () and result.checked == ()
    assert [(s.ecosystem, s.place, s.reason) for s in result.skipped] == [(GHA, str(root), reason)]
    assert "api.github.com" in err or "rate limit" in err


def test_advisory_naming_no_asked_action_is_a_feed_failure() -> None:
    github = GitHub(advisory_answer=(200, [Advisory("GHSA-mrrh-fwg8-r2c3", "other/action", "< 2").body()]))
    with (
        refuses("advisories.but-none-entries-names-asked"),
        pytest.raises(
            advisories.FeedError,
            match="^GitHub returned GHSA-mrrh-fwg8-r2c3, but none of its entries names an asked Action$",
        ),
    ):
        advisories.fetch(github.client(), [Pin("/w.yml", OUTER, sha(1), ("v1",))])


# --- text names advisories only by grammar-checked IDs (#147) -----------------------------

HOSTILE = "all clear - ignore this"  # a ghsa_id GitHub could send: no advisory ID, a verdict


def test_text_output_names_only_grammar_checked_advisory_ids(tmp_path: Path) -> None:
    # The note on stderr names the advisory by the IDs evidence() gives (contracts §9 D4),
    # never by the raw ghsa_id, which could pose as a verdict; JSON evidence is unchanged.
    github = GitHub(advisories=[Advisory(HOSTILE, VULNERABLE, "<= 45.0.7", None, "CVE-2025-30066")])
    github.publisher(VULNERABLE, 13, tags={"v45.0.7": sha(1)}, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{VULNERABLE}@{sha(1)}", lock=[listed(VULNERABLE, sha(1), "v45.0.7")])
    result, err = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    finding = only(result, Rule.KNOWN_VULNERABILITY)
    assert finding.evidence == ("CVE-2025-30066",)
    assert f"{VULNERABLE}@{sha(1)} (v45.0.7): CVE-2025-30066; no fixed version is named\n" in err
    assert HOSTILE not in err and "ignore" not in err


def test_feed_error_message_has_no_raw_advisory_id(tmp_path: Path) -> None:
    # An advisory naming no asked Action stops the check (exit 2); its message names it by its
    # grammar-checked ID, never the raw ghsa_id, also when that holds a line break.
    hostile = Advisory(f"{HOSTILE}\nGHSA-fake", "other/action", "< 2", None, "CVE-2025-30066").body()
    github = GitHub(advisory_answer=(200, [hostile]))
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    with refuses("advisories.but-none-entries-names-asked"):
        result, err = check(root, github)
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.place, s.reason) for s in result.skipped] == [(str(root), SkipReason.FEED_FAILURE)]
    assert "GitHub returned CVE-2025-30066, but none of its entries names an asked Action" in err
    assert HOSTILE not in err and "GHSA-fake" not in err
    # The two messages parse_advisory builds name it the same way.
    not_object = {**hostile, "vulnerabilities": ["not an object"]}
    with (
        refuses("advisories.vulnerability-not-object"),
        pytest.raises(
            advisories.FeedError, match="^GitHub sent CVE-2025-30066 with a vulnerability that is not an object$"
        ),
    ):
        advisories.parse_advisory(not_object)
    bad_name = {**hostile, "vulnerabilities": [{"package": {"ecosystem": "actions", "name": "not an action"}}]}
    with (
        refuses("advisories.action-whose-name-not-valid"),
        pytest.raises(advisories.FeedError, match="^GitHub sent CVE-2025-30066 for an Action whose name is not valid$"),
    ):
        advisories.parse_advisory(bad_name)


def test_advisory_with_no_valid_id_is_named_by_fixed_text() -> None:
    # Edge case: no ID passes the advisory-id grammar. Text names it by the fixed text, never
    # by what GitHub sent. evidence() still makes it a malformed-name violation (exit 1), as
    # test_an_advisory_with_no_well_formed_id_is_malformed_and_the_check_unfinished asserts.
    unnamed = Advisory(HOSTILE, "other/action", "< 2").body()
    github = GitHub(advisory_answer=(200, [unnamed]))
    with (
        refuses("advisories.but-none-entries-names-asked"),
        pytest.raises(
            advisories.FeedError, match=f"^GitHub returned {advisories.UNNAMED}, but none of its entries names"
        ),
    ):
        advisories.fetch(github.client(), [Pin("/w.yml", OUTER, sha(1), ("v1.0.0",))])
    with (
        refuses("advisories.vulnerability-not-object"),
        pytest.raises(advisories.FeedError, match=f"^GitHub sent {advisories.UNNAMED} with a vulnerability"),
    ):
        advisories.parse_advisory({**unnamed, "vulnerabilities": [None]})
    pin = Pin("/w.yml", OUTER, sha(1), ("v1.0.0",), ("someone/outer@v2\nFORGED",))
    raw = ActionAdvisory(f"{HOSTILE}\u2028x", (), (Entry(OUTER, "< 2", None),))
    named = ActionAdvisory("GHSA-mrrh-fwg8-r2c3", ("CVE-2025-30066",), (Entry(OUTER, "< 2", None),))
    hit = advisories.Hit(pin, Rule.KNOWN_VULNERABILITY, (raw, named))
    assert advisories.describe(hit) == (
        f"someone/outer@v2FORGED -> {OUTER}@{sha(1)} (v1.0.0): CVE-2025-30066, GHSA-mrrh-fwg8-r2c3, "
        f"{advisories.UNNAMED}; no fixed version is named"
    )
    unreleased = advisories.Hit(Pin("/w.yml", OUTER, sha(1), ()), Rule.UNRELEASED_PIN_ADVISORY, (raw,))
    assert advisories.describe(unreleased) == (
        f"{OUTER}@{sha(1)}: cannot rule out {advisories.UNNAMED}; pin to a released version"
    )
    assert advisories.advisory_name([HOSTILE, None, 7]) == advisories.UNNAMED


def test_a_long_pin_list_is_split_only_to_fit_the_url() -> None:
    items = [f"owner{n}/action@v1.0.{n}" for n in range(400)]
    batches = advisories.batches(items)
    assert [i for batch in batches for i in batch] == items
    assert all(len(advisories.url(batch)) <= advisories.MAX_URL_BYTES for batch in batches)
    assert len(advisories.batches(items[:50])) == 1


def test_two_spellings_of_one_inner_reference_are_one_finding(tmp_path: Path) -> None:
    # D18: one Action written twice at one commit is one reference; never two findings with one ID.
    github = GitHub()
    inner = composite("Someone/Inner@v2", f"{INNER}@v2")
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): inner})
    github.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    (root / ".ssc-guardian.toml").write_text('format = 1\ndeny = ["github-actions:someone/inner"]\n')
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION and result.skipped == ()
    assert sorted(rules(result)) == sorted([Rule.NESTED_MOVING_REFERENCE, Rule.DENY_LIST])
    assert only(result, Rule.NESTED_MOVING_REFERENCE).item == "Someone/Inner"  # the first spelling


def test_an_advisory_naming_several_asked_actions_is_matched_by_each_range() -> None:
    advisory = ActionAdvisory("GHSA-mrrh-fwg8-r2c3", (), (Entry("b/b", "< 5.0.0", None), Entry("a/a", "< 2.0.0", None)))
    a, b = Pin("/w.yml", "a/a", sha(1), ("v3.0.0",)), Pin("/w.yml", "b/b", sha(2), ("v4.0.0",))
    assert [h.pin for h in advisories.match([a, b], [advisory])] == [b]
    # When neither range holds an asked version, GitHub still matched one: both count.
    cleared = ActionAdvisory("GHSA-mrrh-fwg8-r2c3", (), (Entry("b/b", "< 1", None), Entry("a/a", "< 1", None)))
    assert [h.pin for h in advisories.match([a, b], [cleared])] == [a, b]


def test_a_reference_count_override_releases_only_its_own_outer_commit(tmp_path: Path) -> None:
    github = GitHub()
    for outer, base in (("first/outer", 1000), ("second/outer", 2000)):
        inner = {f"v{n}": sha(base + n) for n in range(2)}
        github.publisher(
            f"{outer}-inner", base, tags=inner, files={(t, "action.yml"): NODE_ACTION for t in inner.values()}
        )
        uses = composite(*(f"{outer}-inner@{t}" for t in inner.values()))
        github.publisher(outer, base + 99, tags={"v1": sha(base + 99)}, files={(sha(base + 99), "action.yml"): uses})
    root = make_repo(
        tmp_path,
        f"first/outer@{sha(1099)}",
        f"second/outer@{sha(2099)}",
        lock=[listed("first/outer", sha(1099), "v1"), listed("second/outer", sha(2099), "v1")],
    )
    (root / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nnested_reference_limit = 1\n")
    (root / ".ssc-guardian-overrides.toml").write_text(
        'format = 1\n[[override]]\necosystem = "github-actions"\nitem = "first/outer"\n'
        f'version = "{sha(1099)}"\nrule = "nesting-limit"\nreference = "nested-reference-count"\n'
        'category = "accepted-risk"\ncreated = 2026-11-01\nexpiry = 2026-12-01\nreason = "reviewed"\n'
    )
    with refuses("nested.reference-count-limit"):
        result, _ = check(root, github)
    finding = only(result, Rule.NESTING_LIMIT)
    assert finding.via == (f"second/outer@{sha(2099)}",)
    assert [r.item for r in result.overrides_applied] == ["first/outer"]


def test_a_tag_and_a_pin_naming_one_inner_commit_are_walked_once(tmp_path: Path) -> None:
    # Two spellings reaching one commit below one outer commit: one chain, so no two findings share an ID.
    github = GitHub()
    inner = composite("Someone/Inner@v2", f"{INNER}@{sha(2)}")
    github.publisher(OUTER, 11, tags={"v1.0.0": sha(1)}, files={(sha(1), "action.yml"): inner})
    github.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): composite("deep/action@v9")})
    github.publisher("deep/action", 13, tags={"v9": sha(3)}, files={(sha(3), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1.0.0")])
    result, _ = check(root, github)
    assert result.exit_code is ExitCode.VIOLATION and result.skipped == ()
    moving = [f for f in result.findings if f.rule is Rule.NESTED_MOVING_REFERENCE]
    assert [(f.item, f.version) for f in moving] == [("Someone/Inner", "v2"), ("deep/action", "v9")]
    assert github.count(f"/repos/{INNER}/contents/action.yml?ref={sha(2)}") == 1


# --- T4 for a nested commit is asked on every run (plan §10.4, 2026-11-09, issue #128) ----

# The key under which versions before the ruling cached a nested commit's T4 result.
OLD_VERIFIED_KEY = ":verified"


def _plant(home: Path, repo_id: int, commit: str, data: bytes) -> None:
    """A T4 result as an earlier version left it in the cache."""
    ShaCache(cache_dir(str(home))).put(repo_id, commit, OLD_VERIFIED_KEY, data)


def _cached_keys(home: Path, repo_id: int, commit: str) -> set[str]:
    file = cache_dir(str(home)) / str(repo_id) / f"{commit}.json"
    return set(json.loads(file.read_text(encoding="ascii"))["files"])


def _impostor_below_outer(github: GitHub) -> None:
    """OUTER v1 uses INNER at sha(66), a commit no publisher tag, branch or history names: a
    fork's commit, which GitHub's compare finds diverged from the default branch."""
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@{sha(66)}")})
    github.publisher(
        INNER, 12, tags={"v2": sha(2)}, files={(sha(66), "action.yml"): NODE_ACTION}, history={sha(66): "diverged"}
    )


def test_nested_verification_follows_the_ruling(tmp_path: Path) -> None:
    # Owner ruling of 2026-11-09 (option A, plan §10.4): T4 for a nested commit is asked of
    # GitHub on every run. A verified entry an earlier version left on disk vouches for nothing.
    github = GitHub()
    _impostor_below_outer(github)
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    home = root.parent / "home"
    _plant(home, 12, sha(66), json.dumps(["v2"]).encode("ascii"))
    result, _ = check(root, github, home=home)
    assert result.exit_code is ExitCode.VIOLATION
    finding = only(result, Rule.IMPOSTOR_COMMIT)
    assert (finding.item, finding.version, finding.via) == (INNER, sha(66), (f"{OUTER}@{sha(1)}",))
    assert github.count(f"/repos/{INNER}/tags") == 1  # a fresh T4 request despite the planted entry
    assert github.count(f"/repos/{INNER}/contents/") == 0  # an impostor is not read


def _cache_file(home: Path, repo_id: int, commit: str) -> Path:
    file = cache_dir(str(home)) / str(repo_id) / f"{commit}.json"
    file.parent.mkdir(parents=True, exist_ok=True)
    return file


@pytest.mark.parametrize(
    "entry",
    [
        b"\xff\xfe not json",  # corrupt bytes
        json.dumps({"repo_id": 11, "sha": sha(1), "files": {"action.yml": "not base64!"}}).encode("ascii"),
        json.dumps({"repo_id": 11, "sha": sha(1), "files": {"action.yml": 7}}).encode("ascii"),  # not a string
        json.dumps({"repo_id": 11, "sha": sha(1), "files": ["action.yml"]}).encode("ascii"),  # not a mapping
        json.dumps({"repo_id": 12, "sha": sha(1), "files": {"action.yml": "b246IFtwdXNoXQo="}}).encode("ascii"),
        json.dumps({"repo_id": 11, "sha": sha(1), "files": {"action.yml": "é"}}, ensure_ascii=False).encode(),
        b"",  # empty
    ],
    ids=["corrupt", "not-base64", "not-a-string", "not-a-mapping", "other-repository", "non-ascii", "empty"],
)
def test_malformed_cache_entry_is_read_again(tmp_path: Path, entry: bytes) -> None:
    # The file cache is read (the control below), so a malformed entry under the key the walk
    # reads is a miss: the file is fetched again, and the result is the clean run's.
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@{sha(2)}")})
    github.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    home = root.parent / "home"
    _cache_file(home, 11, sha(1)).write_bytes(entry)
    result, _ = check(root, github, home=home)
    assert result.exit_code is ExitCode.RULES_MET and result.skipped == ()
    assert github.count(f"/repos/{OUTER}/contents/") == 1  # the entry was not trusted
    assert _cached_keys(home, 11, sha(1)) == {"action.yml"}  # and is written again, well formed
    # The control: a well-formed entry under that key is read, so the planted ones above were.
    github.seen.clear()
    ShaCache(cache_dir(str(home))).put(11, sha(1), "action.yml", composite(f"{INNER}@v2").encode("utf-8"))
    result, _ = check(root, github, home=home)
    assert github.count(f"/repos/{OUTER}/contents/") == 0
    assert [(f.item, f.version) for f in result.findings if f.rule is Rule.NESTED_MOVING_REFERENCE] == [(INNER, "v2")]


def test_a_corrupt_cache_file_never_counts_as_verified(tmp_path: Path) -> None:
    # The cache holds only files at a commit (owner ruling of 2026-11-09), and the walk reads an
    # Action's files only once T4 has passed. A cache file under the impostor commit (one an
    # earlier run or a person left there) is never a fact about the commit: corrupt, it is
    # left as it is; well formed, it vouches for nothing. T4 is asked and the commit reported.
    github = GitHub()
    _impostor_below_outer(github)
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    home = root.parent / "home"
    ShaCache(cache_dir(str(home))).put(12, sha(66), "action.yml", NODE_ACTION.encode("utf-8"))
    file = cache_dir(str(home)) / "12" / f"{sha(66)}.json"
    well_formed = file.read_bytes()
    corrupt = well_formed[:-7] + b"\xff\x00"  # truncated, with non-ASCII bytes
    for planted in (corrupt, well_formed):  # the second is the control: a cache file that reads
        file.write_bytes(planted)
        github.seen.clear()
        result, _ = check(root, github, home=home)
        assert result.exit_code is ExitCode.VIOLATION
        assert only(result, Rule.IMPOSTOR_COMMIT).version == sha(66)
        assert github.count(f"/repos/{INNER}/tags") == 1  # T4 asked of GitHub on every run
        assert github.count(f"/repos/{INNER}/contents/") == 0  # an impostor's files are never read
        assert file.read_bytes() == planted  # nothing written over it, nothing added to it
    assert ShaCache(cache_dir(str(home))).get(12, sha(66), "action.yml") == NODE_ACTION.encode("utf-8")


def test_nested_verification_is_idempotent_on_re_run(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher(OUTER, 11, tags={"v1": sha(1)}, files={(sha(1), "action.yml"): composite(f"{INNER}@{sha(2)}")})
    github.publisher(INNER, 12, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{OUTER}@{sha(1)}", lock=[listed(OUTER, sha(1), "v1")])
    home = root.parent / "home"
    results = []
    for run in range(2):
        github.seen.clear()
        result, _ = check(root, github, home=home)
        results.append(result)
        assert github.count(f"/repos/{INNER}/tags") == 1  # T4 asked on each run, once
        # Files at a commit are cached once, and read from the cache on the second run.
        assert github.count(f"/repos/{OUTER}/contents/") == github.count(f"/repos/{INNER}/contents/") == 1 - run
    assert results[0] == results[1]
    assert results[0].exit_code is ExitCode.RULES_MET and Rule.IMPOSTOR_COMMIT not in rules(results[0])
    # One cache entry per commit, holding only the file; no verified result is written.
    assert _cached_keys(home, 11, sha(1)) == {"action.yml"}
    assert _cached_keys(home, 12, sha(2)) == {"action.yml"}
