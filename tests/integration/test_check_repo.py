# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""``check --repo`` end to end: the CLI, the six Actions threats on fixtures, the batched
advisory request and ``acknowledge``'s refusals (issue #10). No live network: GitHub and the
KEV catalog are the in-process fixture from ``test_nested_and_advisories``.
"""

from __future__ import annotations

import dataclasses
import io
import json
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.cli import Request, main
from ssc_guardian.commands import check_repo
from ssc_guardian.commands.acknowledge import Acknowledge
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.commands.pin import Reading
from ssc_guardian.findings import ExitCode, Level, Result, Rule, Verb
from ssc_guardian.lockfile import LockEntry
from ssc_guardian.net import Response
from ssc_guardian.plugin import AgeSource
from ssc_guardian.plugins.actions import publisher
from ssc_guardian.plugins.actions.models import UsesReference
from ssc_guardian.render import ToolInfo, to_json
from tests.refusal_sites import refuses
from tests.unit.test_nested_and_advisories import (
    NODE_ACTION,
    TODAY,
    Advisory,
    GitHub,
    composite,
    listed,
    make_repo,
    only,
    sha,
    workflow_text,
)
from tests.unit.test_nested_and_advisories import (
    check as check_run,  # check_repo names the module
)
from tests.unit.test_pinning import CHANGED_FILES, GHSA, V45, changed_files_github, mac_disk

pytestmark = pytest.mark.integration


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _six_threats() -> tuple[GitHub, list[str], list[LockEntry]]:
    """One workflow reference for each threat, and the GitHub that answers for them."""
    github = GitHub(
        advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", "t6/vuln", "<= 1.0.0", "1.0.1", "CVE-2025-30066")],
        kev=["CVE-2025-30066"],
    )
    young = (TODAY - timedelta(days=10)).isoformat() + "T00:00:00Z"
    node = NODE_ACTION
    github.publisher("t1/moving", 101)
    github.publisher("t2/waiting", 102, files={(sha(20), "action.yml"): node})
    github.publisher("t3/young", 103, created=young, files={(sha(30), "action.yml"): node})
    github.publisher("t4/unlisted", 104, files={(sha(40), "action.yml"): node})
    github.publisher("t5/outer", 105, files={(sha(50), "action.yml"): composite("t5/inner@v2")})
    github.publisher("t5/inner", 106, tags={"v2": sha(51)}, files={(sha(51), "action.yml"): node})
    github.publisher("t6/vuln", 107, tags={"v1.0.0": sha(60), "v1.0.1": sha(61)}, files={(sha(60), "action.yml"): node})
    uses = [
        "t1/moving@v1",  # T1: a tag; and T3's first-use notice, since the lock file has no entry
        f"t2/waiting@{sha(20)}",  # T2: inside its cooldown
        f"t3/young@{sha(30)}",  # T3: created 10 days ago
        f"t4/unlisted@{sha(40)}",  # T4: a SHA the lock file does not list
        f"t5/outer@{sha(50)}",  # T5: uses t5/inner@v2
        f"t6/vuln@{sha(60)}",  # T6: v1.0.0, fixed in v1.0.1
    ]
    waiting = TODAY - timedelta(days=5)
    lock = [
        LockEntry("t2/waiting", sha(20), "v2.0.0", waiting, waiting, AgeSource.LOCK_FIRST_SEEN),
        listed("t3/young", sha(30), "v3.0.0"),
        listed("t5/outer", sha(50), "v5.0.0"),
        listed("t6/vuln", sha(60), "v1.0.0"),
    ]
    return github, uses, lock


def _check_json(root: Path, github: GitHub, *argv: str, home: Path | None = None) -> tuple[int, dict[str, Any], str]:
    out, err = io.StringIO(), io.StringIO()
    home = home or root.parent / "home"
    handler = CheckEnvs(home=str(home), environ={}, today=TODAY, client=github.client(), stderr=err)
    code = main(["check", "--repo", str(root), *argv], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    text = out.getvalue()
    return code, (json.loads(text) if "--json" in argv else {"text": text}), err.getvalue()


def test_check_repo_runs_all_six_threats(tmp_path: Path) -> None:
    github, uses, lock = _six_threats()
    root = make_repo(tmp_path, *uses, lock=lock)
    code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 1
    found = {(f["rule"], f["item"]) for f in doc["findings"]}
    assert found == {
        ("moving-reference", "t1/moving"),  # T1
        ("first-use-publisher", "t1/moving"),  # T3 notice
        ("first-use-publisher", "t4/unlisted"),
        ("cooldown-wait", "t2/waiting"),  # T2
        ("young-repository", "t3/young"),  # T3
        ("unverified-pin", "t4/unlisted"),  # T4
        ("nested-moving-reference", "t5/inner"),  # T5
        ("known-vulnerability", "t6/vuln"),  # T6
    }
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(root)}]
    assert [s for s in doc["skipped"] if s["in_scope"]] == []
    by_rule = {f["rule"]: f for f in doc["findings"]}
    assert by_rule["nested-moving-reference"]["via"] == [f"t5/outer@{sha(50)}"]
    vulnerable = by_rule["known-vulnerability"]
    assert vulnerable["evidence"] == ["CVE-2025-30066", "GHSA-mrrh-fwg8-r2c3"]
    assert vulnerable["labels"] == ["actively-exploited"]
    fix, person = vulnerable["options"]
    # The fix goes through T2's cooldown: v1.0.1 is new to the lock file, so it waits 21 days.
    assert (fix["kind"], fix["version"], fix["command"]) == ("replace", "v1.0.1", None)
    assert fix["eligible_on"] == (TODAY + timedelta(days=21)).isoformat()
    assert (person["kind"], person["command"], person["requires_person"]) == ("exception", None, True)
    young = by_rule["young-repository"]["options"]
    assert [(o["kind"], o["command"], o["requires_person"]) for o in young] == [
        ("exception", None, True),
        ("remove", None, False),
    ]
    assert "fix t6/vuln@v1.0.1 is eligible on" in err


def test_one_advisory_request_per_run_and_idempotent(tmp_path: Path) -> None:
    github, uses, lock = _six_threats()
    root = make_repo(tmp_path, *uses, lock=lock)
    outputs = []
    for run in range(2):
        github.seen.clear()
        code, doc, _ = _check_json(root, github, "--json")
        outputs.append(doc)
        assert code == 1
        # One batched request holds every pin read, workflow and nested.
        assert github.count("/advisories") == 1
        # A major tag (v1, v2) names no release, so those are asked by name alone (#142).
        assert github.asked() == {
            "t1/moving",
            "t3/young@v3.0.0",
            "t2/waiting@v2.0.0",
            "t4/unlisted",
            "t5/outer@v5.0.0",
            "t5/inner",
            "t6/vuln@v1.0.0",
        }
        assert len(github.seen) == len(set(github.seen)), "no request is sent twice in a run"
        # Files at a commit come from the cache on the second run; tags are asked again.
        assert github.count("/repos/t5/outer/contents/") == (1 if run == 0 else 0)
        assert github.count("/repos/t5/inner/git/ref/tags/v2") == 1
    assert outputs[0] == outputs[1]  # the same findings, with the same IDs
    # Nothing in the repository changed: check never writes.
    assert sorted(p.name for p in root.iterdir()) == [".git", ".github", ".ssc-guardian.lock"]


def test_check_repo_t6_is_idempotent_on_re_run(tmp_path: Path) -> None:
    # #142: a pin recorded under the major tag v4 is asked as the release v4.1.3 on every run,
    # with the same answer, and the lock file is left byte for byte as it was.
    action = "someone/major"
    github = GitHub(advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", action, ">= 4.1.0, < 4.1.5", "4.1.5")])
    github.publisher(action, 21, tags={"v4": sha(4), "v4.1.3": sha(4)}, files={(sha(4), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{action}@{sha(4)}", lock=[listed(action, sha(4), "v4")])
    lock = (root / ".ssc-guardian.lock").read_bytes()
    outputs = []
    for _ in range(2):
        github.seen.clear()
        code, doc, _ = _check_json(root, github, "--json")
        assert code == 1
        assert [(f["rule"], f["item"]) for f in doc["findings"] if f["level"] == "violation"] == [
            ("known-vulnerability", action)
        ]
        assert github.asked() == {f"{action}@v4.1.3"}
        assert github.count(f"/repos/{action}/tags") == 1  # asked again each run, once
        outputs.append(doc)
    assert outputs[0] == outputs[1]
    assert (root / ".ssc-guardian.lock").read_bytes() == lock


def test_acknowledge_refuses_yes_and_is_absent_from_json(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher("someone/new-action", 61, stars=3, files={(sha(1), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"someone/new-action@{sha(1)}", lock=[listed("someone/new-action", sha(1), "v1")])
    home = str(root.parent / "home")
    handler = Acknowledge(
        stdin=Tty("y\n"), stderr=io.StringIO(), cwd=str(root), home=home, today=TODAY, client=github.client()
    )
    for flag in ("--yes", "--json"):
        err = io.StringIO()
        code = main(["acknowledge", "someone/new-action", flag], handlers={Verb.ACKNOWLEDGE: handler}, stderr=err)
        assert code == 2 and f"refuses {flag}" in err.getvalue()
    assert github.seen == [] and not (root / ".ssc-guardian.toml").exists()  # refused before anything ran
    # check --json names the exception for a person, never the acknowledge command.
    code, doc, _ = _check_json(root, github, "--json")
    assert code == 1
    (young,) = doc["findings"]
    assert young["rule"] == "young-repository"
    assert all(option["command"] is None for option in young["options"])
    dumped = json.dumps(doc)  # (the test folder's own name holds the word, so look for the command)
    assert '"acknowledge"' not in dumped and "ssc-guardian acknowledge" not in dumped
    # The text output names it, for a person.
    code, text, _ = _check_json(root, github)
    assert "needs a person: ssc-guardian acknowledge someone/new-action" in text["text"]
    # The renderer refuses JSON for the command itself.
    with pytest.raises(ValueError, match="acknowledge output is text only"):
        to_json(Result(Verb.ACKNOWLEDGE), ToolInfo("1.0"))
    # A person at a terminal records it, and the next check passes.
    assert handler(Request(Verb.ACKNOWLEDGE, repository="someone/new-action")).exit_code == 0
    assert _check_json(root, github, "--json")[0] == 0


def test_a_folder_that_is_not_a_repository_never_passes(tmp_path: Path) -> None:
    # A mistyped CI gate (--repo ./reop) or a subfolder has no workflows and the wrong settings.
    github = GitHub()
    root = make_repo(tmp_path, "someone/action@v1")
    for folder in (tmp_path.resolve() / "reop", root / ".github"):
        with refuses("check_repo.not-a-repository"):
            code, doc, err = _check_json(folder, github, "--json")
        assert code == doc["exit_code"] == 2
        assert doc["checked"] == [] and "is not the top level of a Git repository" in err
    assert github.seen == []


def test_a_nested_vulnerability_can_be_overridden(tmp_path: Path) -> None:
    # Its fix is a new release of the outer Action, which Guardian cannot pin, so an override applies.
    github = GitHub(advisories=[Advisory("GHSA-mrrh-fwg8-r2c3", "t6/vuln", "<= 1.0.0", "1.0.1")])
    github.publisher(
        "t5/outer", 105, tags={"v5": sha(50)}, files={(sha(50), "action.yml"): composite(f"t6/vuln@{sha(60)}")}
    )
    github.publisher("t6/vuln", 107, tags={"v1.0.0": sha(60)}, files={(sha(60), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"t5/outer@{sha(50)}", lock=[listed("t5/outer", sha(50), "v5")])
    code, doc, _ = _check_json(root, github, "--json")
    assert code == 1
    (finding,) = doc["findings"]
    assert (finding["rule"], finding["via"]) == ("known-vulnerability", [f"t5/outer@{sha(50)}"])
    (root / ".ssc-guardian-overrides.toml").write_text(
        'format = 1\n[[override]]\necosystem = "github-actions"\nitem = "t6/vuln"\n'
        f'version = "{sha(60)}"\nrule = "known-vulnerability"\nreference = "GHSA-mrrh-fwg8-r2c3"\n'
        'category = "deferred-upgrade"\ncreated = 2026-11-01\nexpiry = 2026-12-01\nreason = "outer fix pending"\n'
    )
    code, doc, _ = _check_json(root, github, "--json")
    assert code == 0
    assert [o["reference"] for o in doc["overrides"]["applied"]] == ["GHSA-mrrh-fwg8-r2c3"]


# --- every uses: reference accounted for (#127) ----------------------------------------

DIGEST = "0123456789abcdef" * 4


def _in_scope(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in doc["skipped"] if s["in_scope"]]


def _docker_action(image: str) -> str:
    return f"name: d\nruns:\n  using: docker\n  image: {image}\n"


def _images_github() -> GitHub:
    github = GitHub()
    github.publisher("t7/docker", 108, files={(sha(70), "action.yml"): _docker_action("docker://ghcr.io/x/y:latest")})
    github.publisher("t7/built", 109, files={(sha(71), "action.yml"): _docker_action("Dockerfile")})
    github.publisher(
        "t7/outer",
        110,
        files={(sha(72), "action.yml"): composite("docker://alpine:3.20", f"docker://alpine@sha256:{DIGEST}")},
    )
    return github


def _images_repo(tmp_path: Path) -> Path:
    uses = [
        "docker://alpine:latest",  # in the workflow
        f"docker://alpine@sha256:{DIGEST}",  # pinned by digest: no finding
        f"t7/docker@{sha(70)}",  # a pinned Docker Action whose image has a tag
        f"t7/built@{sha(71)}",  # built from a Dockerfile at the pinned commit: no finding
        f"t7/outer@{sha(72)}",  # a composite Action with a Docker step
    ]
    lock = [listed("t7/docker", sha(70), "v1"), listed("t7/built", sha(71), "v1"), listed("t7/outer", sha(72), "v1")]
    return make_repo(tmp_path, *uses, lock=lock)


def test_check_repo_reports_unpinned_image_in_workflow_and_nested_action(tmp_path: Path) -> None:
    root = _images_repo(tmp_path)
    code, doc, _ = _check_json(root, _images_github(), "--json")
    assert code == doc["exit_code"] == 0  # warnings only
    workflow = str(root / ".github" / "workflows" / "ci.yml")
    found = sorted((f["rule"], f["level"], f["place"], f["item"], f["version"], f["via"]) for f in doc["findings"])
    assert found == [
        ("unpinned-image", "warning", workflow, "alpine:3.20", None, [f"t7/outer@{sha(72)}"]),
        ("unpinned-image", "warning", workflow, "alpine:latest", None, []),
        ("unpinned-image", "warning", workflow, "ghcr.io/x/y:latest", None, [f"t7/docker@{sha(70)}"]),
    ]
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(root)}]
    assert _in_scope(doc) == []


def test_check_repo_lists_unread_local_action(tmp_path: Path) -> None:
    github = GitHub()
    root = make_repo(tmp_path, "./tools/setup", "./tools/read", "./tools/setup")
    (root / "tools" / "read").mkdir(parents=True)
    (root / "tools" / "read" / "action.yaml").write_text(composite("docker://alpine:latest"))
    workflow = str(root / ".github" / "workflows" / "ci.yml")
    with refuses("check_repo.unread-local-action"), refuses("check_repo.references-not-all-checked"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 2
    # Listed once though used twice, under the workflow that names it; the repository is unfinished.
    assert _in_scope(doc) == [
        {"ecosystem": "github-actions", "place": workflow, "reason": "check-error", "in_scope": True},
        {"ecosystem": "github-actions", "place": str(root), "reason": "check-error", "in_scope": True},
    ]
    assert doc["checked"] == []
    # The local Action that is there is read: its image is checked.
    assert [(f["rule"], f["place"], f["item"]) for f in doc["findings"]] == [
        ("unpinned-image", str(root / "tools" / "read" / "action.yaml"), "alpine:latest")
    ]
    assert "a uses: reference was not checked" in err
    code, text, _ = _check_json(root, github)
    assert code == 2
    assert text["text"].count("./tools/setup: no action.yml or action.yaml there in the repository") == 1
    assert "no check, finding or listed skip" not in text["text"]  # listed by its own rule, not by accounting
    assert github.seen == []


def _plant(monkeypatch: pytest.MonkeyPatch, raw: str, kind: str) -> None:
    """Add to the workflow a reference of a kind no check handles, as a future kind would be."""
    planted = object.__new__(UsesReference)
    for name, value in (("raw", raw), ("kind", kind), ("line", 99), ("job", "build"), ("step", 9)):
        object.__setattr__(planted, name, value)
    object.__setattr__(planted, "action", None)
    object.__setattr__(planted, "ref", None)
    read = check_repo.read_each

    def with_planted(root: str) -> Reading:
        reading = read(root)
        first, *rest = reading.sources
        object.__setattr__(planted, "file", first.path)
        planted_first = dataclasses.replace(first, references=(*first.references, planted))
        return dataclasses.replace(reading, sources=(planted_first, *rest))

    monkeypatch.setattr(check_repo, "read_each", with_planted)


def test_unaccounted_reference_is_check_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    github = GitHub()
    root = make_repo(tmp_path, f"docker://alpine@sha256:{DIGEST}")
    assert _check_json(root, github, "--json")[0] == 0
    _plant(monkeypatch, "future://thing", "future-kind")
    with refuses("check_repo.unaccounted-reference"), refuses("check_repo.references-not-all-checked"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 2  # never 0
    workflow = str(root / ".github" / "workflows" / "ci.yml")
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [
        (workflow, "check-error"),
        (str(root), "check-error"),
    ]
    assert doc["checked"] == []
    code, text, _ = _check_json(root, github)
    assert "a reference (line 99): no check, finding or listed skip accounts for this reference" in text["text"]
    assert "future://thing" not in text["text"]  # a value no grammar passed is never echoed


def test_a_local_reference_inside_another_repositorys_action_is_check_error(tmp_path: Path) -> None:
    # Not followed (it names whatever the calling workflow checked out), so it is listed.
    github = GitHub()
    github.publisher("t8/outer", 111, files={(sha(80), "action.yml"): composite("./inner")})
    root = make_repo(tmp_path, f"t8/outer@{sha(80)}", lock=[listed("t8/outer", sha(80), "v1")])
    with refuses("check_repo.unaccounted-reference"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == 2 and doc["checked"] == []
    workflow = str(root / ".github" / "workflows" / "ci.yml")
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [
        (workflow, "check-error"),
        (str(root), "check-error"),
    ]
    code, text, _ = _check_json(root, github)
    assert f"t8/outer@{sha(80)} -> ./inner: no check, finding or listed skip" in text["text"]


def test_accounting_is_idempotent_on_re_run(tmp_path: Path) -> None:
    github = _images_github()
    github.publisher("t8/outer", 111, files={(sha(80), "action.yml"): composite("./inner", "./inner")})
    root = make_repo(
        tmp_path,
        "docker://alpine:latest",
        "docker://alpine:latest",
        "./tools/setup",
        "./tools/setup",
        f"t7/outer@{sha(72)}",
        f"t8/outer@{sha(80)}",
        f"t8/outer@{sha(80)}",
        lock=[listed("t7/outer", sha(72), "v1"), listed("t8/outer", sha(80), "v1")],
    )
    before = sorted(str(p) for p in root.rglob("*"))
    (_, first, _), (_, second, _), (_, text, _) = [_check_json(root, github, *a) for a in (["--json"], ["--json"], [])]
    assert first == second  # the same report, the same IDs
    assert first["exit_code"] == 2
    skipped = [(s["place"], s["reason"]) for s in _in_scope(first)]
    assert len(skipped) == len(set(skipped)) + 1  # the workflow's two skips differ in their text only
    assert len(first["findings"]) == len({f["id"] for f in first["findings"]}) == 2
    assert text["text"].count("./tools/setup: no action.yml") == 1
    assert text["text"].count("-> ./inner: no check") == 1
    assert sorted(str(p) for p in root.rglob("*")) == before  # check writes nothing


def test_a_walk_stopped_at_its_limit_lists_no_unread_reference(tmp_path: Path) -> None:
    # The nesting-limit violation names where the walk stopped; the references after it were
    # never read, so the accounting does not list them as dropped.
    github = GitHub()
    inner = {f"t9/inner-{n}": sha(90 + n) for n in range(3)}
    for n, (name, commit) in enumerate(inner.items()):
        github.publisher(name, 120 + n, tags={"v1": commit}, files={(commit, "action.yml"): NODE_ACTION})
    uses = composite(*(f"{name}@{commit}" for name, commit in inner.items()))
    github.publisher("t9/outer", 119, files={(sha(99), "action.yml"): uses})
    root = make_repo(tmp_path, f"t9/outer@{sha(99)}", lock=[listed("t9/outer", sha(99), "v1")])
    (root / ".ssc-guardian.toml").write_text("format = 1\n[defaults]\nnested_reference_limit = 1\n")
    code, doc, _ = _check_json(root, github, "--json")
    assert code == 1
    assert [(f["rule"], f["item"]) for f in doc["findings"]] == [("nesting-limit", "t9/inner-1")]
    assert _in_scope(doc) == [] and doc["checked"] == [{"ecosystem": "github-actions", "place": str(root)}]


def test_moved_inner_tag_local_and_fresh_cache(tmp_path: Path) -> None:
    # Issue #128, owner ruling of 2026-11-09 (option A, plan §10.4): T4 for a nested commit is
    # asked on every run, so a laptop with a warm cache and a fresh CI runner agree.
    github = GitHub()
    github.publisher("t10/outer", 131, files={(sha(100), "action.yml"): composite(f"t10/inner@{sha(101)}")})
    github.publisher("t10/inner", 132, tags={"v2": sha(101)}, files={(sha(101), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"t10/outer@{sha(100)}", lock=[listed("t10/outer", sha(100), "v1")])
    laptop = tmp_path / "laptop"
    code, doc, _ = _check_json(root, github, "--json", home=laptop)
    assert code == doc["exit_code"] == 0  # run 1: tag v2 names the inner commit M
    assert "impostor-commit" not in {f["rule"] for f in doc["findings"]}
    # The publisher moves v2 away; M is on no branch and not in the default branch's history.
    github.publisher("t10/inner", 132, tags={"v2": sha(102)}, files={(sha(101), "action.yml"): NODE_ACTION})
    results = {}
    for name, home in (("laptop", laptop), ("fresh runner", tmp_path / "runner")):
        code, doc, _ = _check_json(root, github, "--json", home=home)
        results[name] = doc
        assert code == doc["exit_code"] == 1, name
        impostor = [f for f in doc["findings"] if f["rule"] == "impostor-commit"]
        assert [(f["item"], f["version"], f["via"]) for f in impostor] == [
            ("t10/inner", sha(101), [f"t10/outer@{sha(100)}"])
        ], name
    assert results["laptop"] == results["fresh runner"]  # one input, one result


def _decoy_repo(tmp_path: Path) -> Path:
    """A harmless ``act/Action.yml`` beside a hostile ``act/action.yaml`` (#143): GitHub's runner
    finds no ``action.yml`` and runs ``action.yaml``; a Mac's disk answers for ``action.yml``."""
    root = make_repo(tmp_path, "./act")
    (root / "act").mkdir()
    (root / "act" / "Action.yml").write_text(NODE_ACTION)
    (root / "act" / "action.yaml").write_text(composite("evil/x@main"))
    return root


def test_check_repo_case_decoy_is_not_a_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    github = GitHub()
    github.publisher("evil/x", 130, tags={"main": sha(130)}, files={(sha(130), "action.yml"): NODE_ACTION})
    root = _decoy_repo(tmp_path)
    mac_disk(monkeypatch)  # on Linux CI too, the disk answers for 'action.yml' as a Mac's does
    code, doc, _ = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 1  # never 0: evil/x is seen
    found = {(f["rule"], f["place"], f["item"]) for f in doc["findings"]}
    assert ("moving-reference", str(root / "act" / "action.yaml"), "evil/x") in found
    assert all(f["place"] != str(root / "act" / "Action.yml") for f in doc["findings"])
    # With the decoy alone, the runner finds no metadata: the Action is listed unread, exit 2.
    (root / "act" / "action.yaml").unlink()
    with refuses("check_repo.unread-local-action"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 2 and doc["checked"] == []


def test_check_repo_case_rules_are_idempotent_on_re_run(tmp_path: Path) -> None:
    github = GitHub()
    github.publisher("evil/x", 130, tags={"main": sha(130)}, files={(sha(130), "action.yml"): NODE_ACTION})
    root = _decoy_repo(tmp_path)
    before = sorted(str(p) for p in root.rglob("*"))
    first, second = (_check_json(root, github, "--json")[1] for _ in range(2))
    assert first == second and first["exit_code"] == 1  # the same findings, skips and IDs
    # A refused workflow (its extension in another case) is listed by name the same way twice, and
    # the other workflow's finding is still reported: 1 wins over 2 (#146).
    (root / ".github" / "workflows" / "deploy.YML").write_text("name: d\n")
    added = str(root / ".github" / "workflows" / "deploy.YML")
    with refuses("pin.workflow-extension-in-another-case"):
        runs = [_check_json(root, github, "--json") for _ in range(2)]
    assert runs[0] == runs[1] and runs[0][0] == 1
    assert [(s["place"], s["reason"]) for s in _in_scope(runs[0][1])] == [
        (added, "check-error"),
        (str(root), "check-error"),
    ]
    assert ("moving-reference", "evil/x") in {(f["rule"], f["item"]) for f in runs[0][1]["findings"]}
    assert "deploy.YML: a workflow's extension is .yml or .yaml only when letter case is ignored" in runs[0][2]
    assert sorted(str(p) for p in root.rglob("*")) == sorted([*before, added])  # check writes nothing


# --- one file at a time, config skips named, --path keeps what a workflow runs (#146) ---

ANCHOR = "a: &x 1\n"  # an anchor: outside the YAML subset, so the reader refuses the file


def _moving_github(*names: str) -> GitHub:
    github = GitHub()
    for n, name in enumerate(names):
        github.publisher(name, 140 + n, tags={"main": sha(140 + n)}, files={(sha(140 + n), "action.yml"): NODE_ACTION})
    return github


def _workflows(root: Path) -> Path:
    return root / ".github" / "workflows"


def test_unreadable_workflow_still_reports_other_findings(tmp_path: Path) -> None:
    github = _moving_github("t1/moving")
    root = make_repo(tmp_path, "t1/moving@v1")
    z = _workflows(root) / "z.yml"
    z.write_text(ANCHOR)
    with refuses("check_repo.file-not-read"), refuses("check_repo.files-not-all-read"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 1  # the finding in ci.yml wins over the unread z.yml
    assert ("moving-reference", "t1/moving") in {(f["rule"], f["item"]) for f in doc["findings"]}
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [
        (str(z), "unsupported-yaml"),
        (str(root), "check-error"),
    ]
    assert doc["checked"] == []
    assert f"{z}:1:" in err  # the reader's own message names the file and line
    code, text, _ = _check_json(root, github)
    assert f"{z}: the file uses YAML Guardian does not read (line 1:" in text["text"]
    # A malformed uses: value is a violation of its own, at its file, and that file is unread.
    bad = _workflows(root) / "bad.yml"
    bad.write_text(workflow_text("no-at-sign"))
    with refuses("models.malformed-action-step"), refuses("check_repo.file-not-read"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == 1
    found = {(f["rule"], f["place"]) for f in doc["findings"]}
    assert ("malformed-name", str(bad)) in found and ("moving-reference", str(_workflows(root) / "ci.yml")) in found
    assert (str(bad), "check-error") in [(s["place"], s["reason"]) for s in _in_scope(doc)]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (".ssc-guardian.lock", "format = 1\n[[pin]]\naction = 5\n"),
        (".ssc-guardian.toml", "format = 1\nno_such_key = 1\n"),
    ],
)
def test_malformed_lock_and_settings_files_still_stop_the_check(tmp_path: Path, name: str, text: str) -> None:
    # Settings and the lock file change what is checked, so a malformed one stops the check
    # (contracts §10.1, §11.3): t1/moving is not reported, and the repository is unfinished.
    github = _moving_github("t1/moving")
    root = make_repo(tmp_path, "t1/moving@v1")
    (root / name).write_text(text)
    with refuses("settings.file-unusable"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 2
    assert doc["findings"] == []
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [
        (str(root / name), "check-error"),
        (str(root), "check-error"),
    ]
    assert doc["checked"] == [] and f"{root / name}: " in err


# --- a malformed overrides file releases nothing and the run goes on (#166, contracts §10.1) ---

MALFORMED_OVERRIDE = "[[override]]\nitem = 5\n"
VULN = "GHSA-mrrh-fwg8-r2c3"


def nested_vulnerability(tmp_path: Path) -> tuple[GitHub, Path]:
    """A repository whose locked t5/outer runs t6/vuln, which has a reviewed advisory: a nested
    ``known-vulnerability`` finding with no fixed version to pin, the kind an override releases."""
    github = GitHub(advisories=[Advisory(VULN, "t6/vuln", "<= 1.0.0", "1.0.1", "CVE-2025-30066")])
    github.publisher(
        "t5/outer", 105, tags={"v5": sha(50)}, files={(sha(50), "action.yml"): composite(f"t6/vuln@{sha(60)}")}
    )
    github.publisher("t6/vuln", 107, tags={"v1.0.0": sha(60)}, files={(sha(60), "action.yml"): NODE_ACTION})
    return github, make_repo(tmp_path, f"t5/outer@{sha(50)}", lock=[listed("t5/outer", sha(50), "v5")])


def vulnerability_override(today: date) -> str:
    """A valid override releasing :func:`nested_vulnerability`'s finding on ``today``."""
    created = today - timedelta(days=30)
    return (
        f'[[override]]\necosystem = "github-actions"\nitem = "t6/vuln"\nversion = "{sha(60)}"\n'
        f'rule = "known-vulnerability"\nreference = "{VULN}"\ncategory = "deferred-upgrade"\n'
        f"created = {created.isoformat()}\nexpiry = {(created + timedelta(days=60)).isoformat()}\n"
        'reason = "outer fix pending"\n'
    )


def test_malformed_overrides_file_releases_nothing_and_the_run_goes_on(tmp_path: Path) -> None:
    github = _moving_github("t1/moving")
    root = make_repo(tmp_path, "t1/moving@v1")
    overrides = root / ".ssc-guardian-overrides.toml"
    overrides.write_text("format = 1\n" + MALFORMED_OVERRIDE)
    with refuses("settings.file-unusable"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 1  # the finding wins over the unfinished check
    assert ("moving-reference", "t1/moving") in {(f["rule"], f["item"]) for f in doc["findings"]}
    # The overrides file is listed, naming it; the repository root gets no skip of its own.
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [(str(overrides), "check-error")]
    assert doc["checked"] == [{"ecosystem": "github-actions", "place": str(root)}]  # every workflow was read
    assert f"{overrides}: " in err
    code, text, _ = _check_json(root, github)
    assert code == 1 and str(overrides) in text["text"]


def test_malformed_overrides_file_never_releases_a_finding(tmp_path: Path) -> None:
    github, root = nested_vulnerability(tmp_path)
    overrides = root / ".ssc-guardian-overrides.toml"
    overrides.write_text("format = 1\n" + vulnerability_override(TODAY))
    code, doc, _ = _check_json(root, github, "--json")
    # The control: on its own, the override releases the finding.
    assert code == 0 and [o["reference"] for o in doc["overrides"]["applied"]] == [VULN]
    # The same valid override, followed by a malformed entry: the whole file releases nothing,
    # never the entries that parse.
    overrides.write_text("format = 1\n" + vulnerability_override(TODAY) + MALFORMED_OVERRIDE)
    with refuses("settings.file-unusable"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 1
    vulnerabilities = [f for f in doc["findings"] if f["rule"] == "known-vulnerability"]
    assert [(f["item"], f["evidence"]) for f in vulnerabilities] == [("t6/vuln", ["CVE-2025-30066", VULN])]
    assert doc["overrides"] == {"applied": [], "expired": []}
    assert "ci-overrides" not in {f["rule"] for f in doc["findings"]}  # no override counted
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [(str(overrides), "check-error")]


def test_malformed_overrides_report_is_idempotent_on_re_run(tmp_path: Path) -> None:
    github, root = nested_vulnerability(tmp_path)
    overrides = root / ".ssc-guardian-overrides.toml"
    overrides.write_text("format = 1\n" + vulnerability_override(TODAY) + MALFORMED_OVERRIDE)
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    runs = []
    for _ in range(2):
        with refuses("settings.file-unusable"):
            code, doc, err = _check_json(root, github, "--json")
        runs.append((code, doc["findings"], doc["skipped"], doc["overrides"], err))
    assert runs[0] == runs[1] and runs[0][0] == 1
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before  # check --repo writes nothing


def _local_chain(root: Path) -> tuple[Path, Path, Path]:
    """ci.yml runs the local Action setup, which runs the local Action inner, and calls a local
    reusable workflow; each of the three uses a moving reference."""
    workflows = _workflows(root)
    (workflows / "ci.yml").write_text(
        "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: ./.github/actions/setup\n"
        "  call:\n    uses: ./.github/workflows/reusable.yml\n"
    )
    reusable = workflows / "reusable.yml"
    reusable.write_text(
        "on:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: evil/called@main\n"
    )
    setup = root / ".github" / "actions" / "setup" / "action.yml"
    inner = root / ".github" / "actions" / "inner" / "action.yml"
    for action, text in ((setup, composite("./.github/actions/inner")), (inner, composite("evil/action@main"))):
        action.parent.mkdir(parents=True)
        action.write_text(text)
    return reusable, setup, inner


def test_path_filter_checks_local_actions_a_selected_workflow_runs(tmp_path: Path) -> None:
    github = _moving_github("evil/action", "evil/called", "evil/other")
    root = make_repo(tmp_path)
    reusable, _, inner = _local_chain(root)
    other = _workflows(root) / "other.yml"
    other.write_text(workflow_text("evil/other@main"))
    ci = _workflows(root) / "ci.yml"
    code, doc, _ = _check_json(root, github, "--json", "--path", str(ci))
    assert code == doc["exit_code"] == 1  # never 0: what ci.yml runs is checked, at any depth
    found = {(f["rule"], f["place"], f["item"]) for f in doc["findings"] if f["level"] == "violation"}
    assert found == {
        ("moving-reference", str(inner), "evil/action"),  # ci.yml -> setup -> inner
        ("moving-reference", str(reusable), "evil/called"),  # ci.yml calls reusable.yml
    }
    # Only what nothing selected reaches is out of scope.
    assert [s["place"] for s in doc["skipped"] if s["reason"] == "filtered" and s["place"]] == [str(other)]
    assert _in_scope(doc) == []
    # The workflows folder as the path: the Actions outside it are still checked.
    code, doc, _ = _check_json(root, github, "--json", "--path", str(_workflows(root)))
    assert code == 1
    assert ("moving-reference", str(inner), "evil/action") in {
        (f["rule"], f["place"], f["item"]) for f in doc["findings"]
    }
    assert [s for s in doc["skipped"] if s["reason"] == "filtered" and s["place"]] == []


def test_relative_path_filter_is_read_inside_the_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Contracts §2: a relative --path is made absolute against the current folder (owner's
    # ruling, 2026-11-10, #146). From the repository's top level it names the repository's file.
    github = _moving_github("evil/action", "evil/called")
    root = make_repo(tmp_path)
    _, _, inner = _local_chain(root)
    monkeypatch.chdir(root)
    code, doc, _ = _check_json(root, github, "--json", "--path", ".github/workflows/ci.yml")
    assert code == 1
    assert ("moving-reference", str(inner), "evil/action") in {
        (f["rule"], f["place"], f["item"]) for f in doc["findings"]
    }
    assert {"ecosystem": "github-actions", "place": str(_workflows(root) / "ci.yml")} in doc["checked"]
    # From another folder the same text names a place outside the repository: it matches no
    # workflow, so it is unreported and the run is unfinished, never a pass.
    monkeypatch.chdir(tmp_path)
    with refuses("cli.path-not-reported"):
        code, doc, _ = _check_json(root, github, "--json", "--path", ".github/workflows/ci.yml")
    assert code == doc["exit_code"] == 2
    assert (str(tmp_path.resolve() / ".github" / "workflows" / "ci.yml"), "check-error") in [
        (s["place"], s["reason"]) for s in _in_scope(doc)
    ]


@pytest.mark.parametrize("link", [".github/workflows", ".github"])
def test_dangling_workflows_link_is_check_error(tmp_path: Path, link: str) -> None:
    github = GitHub()
    root = tmp_path.resolve() / "repo"
    (root / ".git").mkdir(parents=True)
    (root / link).parent.mkdir(parents=True, exist_ok=True)
    (root / link).symlink_to(tmp_path / "missing")
    with refuses("pin.workflows-link-target-missing"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 2  # never "no workflows", exit 0
    assert doc["checked"] == [] and "is a link to a missing place" in err
    assert github.seen == []


def test_a_refused_local_action_lookup_is_listed_under_its_workflow(tmp_path: Path) -> None:
    github = _moving_github("t1/moving")
    root = make_repo(tmp_path, "t1/moving@v1", "./../outside")
    ci = str(_workflows(root) / "ci.yml")
    with refuses("pin.leaves-folder-pin-reads-only"), refuses("check_repo.local-action-refused"):
        code, doc, err = _check_json(root, github, "--json")
    assert code == 1  # the workflow's other reference is still checked
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [(ci, "check-error"), (str(root), "check-error")]
    assert "./../outside leaves its folder" in err
    code, text, _ = _check_json(root, github)
    assert "./../outside: its metadata could not be looked up" in text["text"]
    assert "no check, finding or listed skip" not in text["text"]  # listed by its own skip


def test_per_file_report_is_idempotent_on_re_run(tmp_path: Path) -> None:
    github = _moving_github("t1/moving", "evil/action", "evil/called")
    root = make_repo(tmp_path, "t1/moving@v1", "./../outside")
    _local_chain(root)
    (_workflows(root) / "z.yml").write_text(ANCHOR)
    (root / ".github" / "actions" / "broken").mkdir(parents=True)
    (root / ".github" / "actions" / "broken" / "action.yml").write_text(ANCHOR)
    (_workflows(root) / "uses-broken.yml").write_text(workflow_text("./.github/actions/broken"))
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    for argv in ([], ["--path", str(_workflows(root) / "uses-broken.yml")]):
        first, second = (_check_json(root, github, "--json", *argv)[1] for _ in range(2))
        assert first == second  # the same findings, skips and IDs
        assert first["exit_code"] == (1 if not argv else 2)  # t1/moving wins unless filtered
        places = [(s["place"], s["reason"]) for s in _in_scope(first)]
        assert (str(root / ".github" / "actions" / "broken" / "action.yml"), "unsupported-yaml") in places
        assert len(places) == len(set(places))
    assert first["exit_code"] == 2  # the selected workflow's Action was not read; nothing else ran
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before  # check writes nothing


def test_unreadable_overrides_file_releases_nothing_and_the_run_goes_on(tmp_path: Path) -> None:
    # A local overrides file that cannot be read (here a dangling link) is used no more than a
    # malformed one (§10.1): listed, naming it, and the finding still gives exit 1.
    github = _moving_github("t1/moving")
    root = make_repo(tmp_path, "t1/moving@v1")
    overrides = root / ".ssc-guardian-overrides.toml"
    overrides.symlink_to(root / "missing.toml")
    with refuses("settings.file-unusable"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 1
    assert ("moving-reference", "t1/moving") in {(f["rule"], f["item"]) for f in doc["findings"]}
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [(str(overrides), "check-error")]


# --- #144: each safety decision has a test that fails when the decision is weakened ----------


def _vulnerability_override(reference: str = GHSA) -> str:
    """A valid repository override for the changed-files advisory at V45 (§10.4)."""
    return (
        f'format = 1\n[[override]]\necosystem = "github-actions"\nitem = "{CHANGED_FILES}"\nversion = "{V45}"\n'
        f'rule = "known-vulnerability"\nreference = "{reference}"\ncategory = "accepted-risk"\n'
        'created = 2026-10-20\nexpiry = 2026-12-31\nreason = "reviewed; vendor fix pending"\n'
    )


def _overridden_v45(tmp_path: Path, reference: str = GHSA) -> Path:
    root = make_repo(tmp_path, f"{CHANGED_FILES}@{V45}", lock=[listed(CHANGED_FILES, V45, "v45.0.7")])
    (root / ".ssc-guardian-overrides.toml").write_text(_vulnerability_override(reference))
    return root


def test_actions_override_ends_when_a_fix_is_eligible(tmp_path: Path) -> None:
    # §10.4: an override on a vulnerable pin ends once a fixed version passes every rule. v46.0.1
    # was pushed long ago, so its cooldown has passed: the override expires and the finding counts.
    github = changed_files_github(Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", "46.0.1"))
    root = _overridden_v45(tmp_path)
    result, err = check_run(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    assert [s for s in result.skipped if s.reason.in_scope] == []
    finding = only(result, Rule.KNOWN_VULNERABILITY)
    assert finding.options[0].command == ("ssc-guardian", "pin", f"{CHANGED_FILES}@v46.0.1")
    assert [r.reference for r in result.overrides_expired] == [GHSA]
    assert result.overrides_applied == ()
    assert f"{CHANGED_FILES}@{V45} (v45.0.7): {GHSA}; fixed in 46.0.1" in err


def test_actions_override_not_applied_when_fix_or_kev_unknown(tmp_path: Path) -> None:
    # Unknown is never a pass (§10.4): when the fixed version cannot be dated, or CISA's KEV
    # catalog cannot be reached, the override is not applied and the vulnerability counts.
    github = changed_files_github(Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", "46.0.1"))
    github.routes[f"/repos/{CHANGED_FILES}/releases?per_page=100"] = (503, {"message": "Service Unavailable"})
    result, err = check_run(_overridden_v45(tmp_path / "undated"), github)
    assert result.exit_code is ExitCode.VIOLATION
    assert [s for s in result.skipped if s.reason.in_scope] == []
    assert only(result, Rule.KNOWN_VULNERABILITY).evidence == (GHSA,)
    assert (result.overrides_applied, result.overrides_expired) == ((), ())
    assert f"the fixed version {CHANGED_FILES}@v46.0.1 could not be dated" in err
    assert "not applied: the fixed-version check did not finish, so the vulnerability counts" in err

    # KEV unreachable: no fixed version is named, so only KEV's answer could stop the override.
    github = _KevDown(advisories=[Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", cve=CVE)])
    github.routes.update(changed_files_github().routes)
    result, err = check_run(_overridden_v45(tmp_path / "kev"), github)
    assert result.exit_code is ExitCode.VIOLATION
    assert [s for s in result.skipped if s.reason.in_scope] == []
    assert only(result, Rule.KNOWN_VULNERABILITY).evidence == (CVE, GHSA)
    kev = only(result, Rule.KEV_UNAVAILABLE)  # the warning that the vulnerability's KEV status is unknown
    assert (kev.item, kev.version) == (CHANGED_FILES, V45)
    assert (result.overrides_applied, result.overrides_expired) == ((), ())
    assert "not applied: KEV could not be reached, so the vulnerability counts" in err
    assert github.count("kev:") >= 1


CVE = "CVE-2025-30066"


@dataclasses.dataclass
class _KevDown(GitHub):
    """GitHub as the fixture serves it, with CISA's KEV catalog unreachable."""

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        if urllib.parse.urlsplit(request.full_url).hostname == "www.cisa.gov":
            self.seen.append("kev:down")
            return Response(503, {}, b"", request.full_url)
        return super().__call__(request, timeout, limit)


def test_override_tests_are_idempotent_on_re_run(tmp_path: Path) -> None:
    # Two runs, one result: the same findings and decisions, and nothing written.
    github = changed_files_github(Advisory(GHSA, CHANGED_FILES, "<= 45.0.7", "46.0.1"))
    root = _overridden_v45(tmp_path)
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    (first, _), (second, _) = check_run(root, github), check_run(root, github)
    assert first == second
    assert first.exit_code is ExitCode.VIOLATION and [r.reference for r in first.overrides_expired] == [GHSA]
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize(
    "called",
    ["./.github/workflows/missing.yml", "./../outside.yml", "./.github/workflows/../../outside.yml"],
    ids=["missing", "parent", "climbs-out"],
)
def test_missing_local_reusable_workflow_is_check_error(tmp_path: Path, called: str) -> None:
    # A job's local reusable workflow is read with the workflows; one that is not among them (a
    # missing file, or one outside the repository) was not checked, so the run is unfinished.
    root = make_repo(tmp_path)
    workflows = root / ".github" / "workflows"
    callee = "on: [workflow_call]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n"
    (root.parent / "outside.yml").write_text(callee)
    (workflows / "ci.yml").write_text(f"on: [push]\njobs:\n  call:\n    uses: {called}\n")
    with refuses("check_repo.unaccounted-reference"):
        code, doc, _ = _check_json(root, GitHub(), "--json")
    assert code == doc["exit_code"] == 2  # never 0
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [
        (str(workflows / "ci.yml"), "check-error"),
        (str(root), "check-error"),
    ]
    _, text, _ = _check_json(root, GitHub())
    assert f"{called}: no check, finding or listed skip accounts for this reference" in text["text"]
    # The control: the same call to a workflow that is read is accounted for.
    (workflows / "other.yml").write_text(callee)
    (workflows / "ci.yml").write_text("on: [push]\njobs:\n  call:\n    uses: ./.github/workflows/other.yml\n")
    assert _check_json(root, GitHub(), "--json")[0] == 0


MOVING = "someone/moving"


@pytest.mark.parametrize(
    ("ref", "rule", "asked"),
    [
        ("v4", Rule.UNRELEASED_PIN_ADVISORY, MOVING),  # a major tag names no release
        ("v4.1.3", Rule.KNOWN_VULNERABILITY, f"{MOVING}@v4.1.3"),  # asked as written
    ],
)
def test_advisory_on_an_outer_moving_reference_is_reported(tmp_path: Path, ref: str, rule: Rule, asked: str) -> None:
    # From #142: T6 runs on an outer moving reference too. Its moving-reference violation is not
    # the only finding: the advisory is reported beside it, with its ID.
    github = GitHub(advisories=[Advisory(GHSA, MOVING, ">= 4.0.0, < 4.1.5", "4.1.5")])
    github.publisher(MOVING, 41)
    root = make_repo(tmp_path, f"{MOVING}@{ref}")
    result, err = check_run(root, github)
    assert result.exit_code is ExitCode.VIOLATION
    assert [s for s in result.skipped if s.reason.in_scope] == []
    assert only(result, Rule.MOVING_REFERENCE).version == ref
    advisory = only(result, rule)
    assert (advisory.item, advisory.version, advisory.evidence) == (MOVING, ref, (GHSA,))
    assert github.asked() == {asked}
    assert GHSA in err


BARE = "someone/bare"


@pytest.mark.parametrize(
    ("tags", "rule"),
    [
        ({"v1": sha(91), "v1.0.0": sha(91)}, Rule.KNOWN_VULNERABILITY),  # its release is in the range
        ({"v1": sha(91), "v1.2.0": sha(91)}, None),  # its release is outside the range: cleared
        ({"v1": sha(91)}, Rule.UNRELEASED_PIN_ADVISORY),  # no release names it: cannot be ruled out
    ],
    ids=["in-range", "out-of-range", "no-release"],
)
def test_bare_sha_named_by_a_release_is_checked_against_the_range(
    tmp_path: Path, tags: dict[str, str], rule: Rule | None
) -> None:
    # From #142: a commit pinned and recorded bare is asked under the release tags that name it
    # today, so the advisory's range decides; with no release tag it cannot be ruled out.
    github = GitHub(advisories=[Advisory(GHSA, BARE, "<= 1.0.0", "1.0.1")])
    github.publisher(BARE, 42, tags=tags, files={(sha(91), "action.yml"): NODE_ACTION})
    root = make_repo(tmp_path, f"{BARE}@{sha(91)}", lock=[listed(BARE, sha(91))])  # recorded as a bare SHA
    result, _ = check_run(root, github)
    assert [s for s in result.skipped if s.reason.in_scope] == []
    found = [(f.rule, f.item, f.version, f.evidence) for f in result.findings if f.level is Level.VIOLATION]
    assert found == ([(rule, BARE, sha(91), (GHSA,))] if rule is not None else [])
    assert result.exit_code is (ExitCode.VIOLATION if rule is not None else ExitCode.RULES_MET)
    releases = [t for t in tags if t != "v1"]
    assert github.asked() == ({f"{BARE}@{t}" for t in releases} or {BARE})


def test_own_repository_young_is_not_blocked(tmp_path: Path) -> None:
    # From #233: Guardian's own repository, by exact name and its recorded ID, is exempt from
    # T3 only; a planted repository with the same name and another ID still blocks, and the
    # deny list still applies to the real one.
    own, own_id = publisher.OWN_REPOSITORY, publisher.OWN_REPOSITORY_ID
    assert own_id is not None
    young = (TODAY - timedelta(days=1)).isoformat() + "T00:00:00Z"
    lock = [listed(own, sha(1), "v1.0.0")]
    for repo_id, blocked in ((own_id, False), (own_id + 1, True)):
        github = GitHub()
        github.publisher(own, repo_id, created=young, stars=0, files={(sha(1), "action.yml"): NODE_ACTION})
        root = make_repo(tmp_path / str(repo_id), f"{own}@{sha(1)}", lock=lock)
        written = (root / ".ssc-guardian.lock").read_bytes()
        code, doc, _ = _check_json(root, github, "--json")
        found = [(f["rule"], f["item"]) for f in doc["findings"]]
        assert (code, found) == ((1, [("young-repository", own)]) if blocked else (0, []))
        assert (root / ".ssc-guardian.lock").read_bytes() == written  # the check writes nothing
    root = make_repo(tmp_path / "denied", f"{own}@{sha(1)}", lock=lock)
    (root / ".ssc-guardian.toml").write_text(f'format = 1\ndeny = ["github-actions:{own}"]\n')
    github = GitHub()
    github.publisher(own, own_id, created=young, stars=0, files={(sha(1), "action.yml"): NODE_ACTION})
    with refuses("publisher.denied-action"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == 1 and [(f["rule"], f["item"]) for f in doc["findings"]] == [("deny-list", own)]


# --- #284: the repository skip names the file, stderr lines once, the exemption note ----------


def _repository_lines(text: str, root: Path) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(f"  github-actions {root}:")]


def test_refused_config_line_gives_no_bare_check_failed_line(tmp_path: Path) -> None:
    github = _moving_github("t1/moving")
    root = make_repo(tmp_path, "t1/moving@v1")
    settings = root / ".ssc-guardian.toml"
    settings.write_text("format = 1\nno_such_key = 1\n")
    with refuses("settings.file-unusable"), refuses("check_repo.file-unusable"):
        code, doc, _ = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 2
    # The JSON is unchanged: the file's skip, then the repository's.
    assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [
        (str(settings), "check-error"),
        (str(root), "check-error"),
    ]
    code, text, _ = _check_json(root, github)
    assert code == 2
    assert f"  github-actions {settings}: the check failed (unknown key 'no_such_key' in the file) [in scope]" in (
        text["text"].splitlines()
    )
    assert _repository_lines(text["text"], root) == [
        f"  github-actions {root}: the check failed (see {settings}) [in scope]"
    ]
    # A workflow that could not be read: the repository line points at it too.
    settings.unlink()
    z = _workflows(root) / "z.yml"
    z.write_text(ANCHOR)
    with refuses("check_repo.file-not-read"), refuses("check_repo.files-not-all-read"):
        code, text, _ = _check_json(root, github)
    assert code == 1  # the finding in ci.yml wins, as before
    assert _repository_lines(text["text"], root) == [f"  github-actions {root}: the check failed (see {z}) [in scope]"]
    # Negative: a repository with no file problem has no "see" pointer.
    z.unlink()
    code, text, _ = _check_json(root, github)
    assert code == 1 and "(see " not in text["text"] and _repository_lines(text["text"], root) == []


@dataclasses.dataclass
class _RateLimited(GitHub):
    """GitHub with the hourly limit used up: every request answers 403 with no requests left."""

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        self.seen.append(request.full_url)
        headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1794900000"}
        return Response(403, headers, b'{"message": "API rate limit exceeded"}', request.full_url)


def test_rate_limit_message_is_printed_once_per_run(tmp_path: Path) -> None:
    uses = [f"t{n}/listed@{sha(n)}" for n in range(1, 4)]
    root = make_repo(tmp_path, *uses, lock=[listed(f"t{n}/listed", sha(n), "v1.0.0") for n in range(1, 4)])
    said = "GitHub's hourly rate limit is used up: it resets at 2026-11-17 07:20 UTC; log in with gh or set GH_TOKEN"
    runs = []
    for _ in range(2):
        with refuses("net.githubs-hourly-rate-limit-used"):
            code, doc, err = _check_json(root, _RateLimited(), "--json")
        assert code == doc["exit_code"] == 2
        assert [(s["place"], s["reason"]) for s in _in_scope(doc)] == [(str(root), "rate-limit")]
        assert err.count(said) == 1, err
        runs.append(err)
    assert runs[0] == runs[1]  # idempotent: the same stderr on a re-run


EXEMPT = "exempt from the young or little-used repository rule (Guardian's own repository)"


def _young_publisher(tmp_path: Path, name: str, repo_id: int) -> tuple[GitHub, Path]:
    young = (TODAY - timedelta(days=1)).isoformat() + "T00:00:00Z"
    github = GitHub()
    github.publisher(name, repo_id, created=young, stars=0, files={(sha(1), "action.yml"): NODE_ACTION})
    return github, make_repo(tmp_path / str(repo_id), f"{name}@{sha(1)}", lock=[listed(name, sha(1), "v1.0.0")])


def test_own_repository_exemption_prints_one_note(tmp_path: Path) -> None:
    own, own_id = publisher.OWN_REPOSITORY, publisher.OWN_REPOSITORY_ID
    assert own_id is not None
    github, root = _young_publisher(tmp_path, own, own_id)
    code, doc, err = _check_json(root, github, "--json")
    assert code == doc["exit_code"] == 0
    assert doc["findings"] == [] and _in_scope(doc) == []
    assert EXEMPT not in json.dumps(doc)  # stderr only: the JSON is unchanged
    assert err.count(f"ssc-guardian: {own}: {EXEMPT}\n") == 1
    code, text, err = _check_json(root, github)
    assert code == 0 and err.count(EXEMPT) == 1 and EXEMPT not in text["text"]


def test_other_young_repository_is_not_exempt(tmp_path: Path) -> None:
    own, own_id = publisher.OWN_REPOSITORY, publisher.OWN_REPOSITORY_ID
    assert own_id is not None
    for name, repo_id in ((own, own_id + 1), ("someone/young", own_id)):
        github, root = _young_publisher(tmp_path, name, repo_id)
        with refuses("publisher.young-repository"):
            code, doc, err = _check_json(root, github, "--json")
        assert (code, [(f["rule"], f["item"]) for f in doc["findings"]]) == (1, [("young-repository", name)])
        assert EXEMPT not in err
