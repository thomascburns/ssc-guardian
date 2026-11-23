# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The network client: GET only, token handling, gh boundary, rate limits, SHA cache (issue #4)."""

from __future__ import annotations

import json
import logging
import os
import pickle
import re
import stat
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.client import IncompleteRead
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian import net
from ssc_guardian.findings import Collector, Ecosystem, ExitCode, SkipReason, Verb
from ssc_guardian.net import (
    GH_MAX_LINKS,
    GH_PATHS,
    OSV_QUERYBATCH_URL,
    Client,
    FeedError,
    RateLimitError,
    Response,
    ShaCache,
    Token,
    TokenError,
    find_token,
)
from ssc_guardian.render import ToolInfo, to_json, to_text
from tests.refusal_sites import refuses

pytestmark = pytest.mark.unit

# Built from pieces, so a secret scanner reading this file finds no token (#325).
SECRET = "ghp_" + "TopSecretToken0123456789abcdefABCDEF"
GH = "https://api.github.com/advisories?type=malware"
TOOL = ToolInfo("1.0.0.dev0", None)


@dataclass
class Sent:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


Reply = Response | BaseException


def reply(status: int = 200, body: object = None, **headers: str) -> Response:
    data = body if isinstance(body, bytes) else json.dumps([] if body is None else body).encode()
    return Response(status, {k.replace("_", "-").lower(): v for k, v in headers.items()}, data, "")


@dataclass
class Recorder:
    """A transport that answers from a script per URL and records every request it is sent.
    The last scripted answer for a URL repeats."""

    routes: dict[str, list[Reply]] = field(default_factory=dict)
    sent: list[Sent] = field(default_factory=list)

    def route(self, url: str, *answers: Reply) -> Recorder:
        self.routes[url] = list(answers)
        return self

    def __call__(self, request: urllib.request.Request, timeout: float, limit: int) -> Response:
        headers = {k.lower(): v for k, v in request.header_items()}
        body = request.data if isinstance(request.data, bytes) else None
        self.sent.append(Sent(request.get_method(), request.full_url, headers, body))
        answers = self.routes[request.full_url]
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, BaseException):
            raise answer
        return Response(answer.status, answer.headers, answer.body, request.full_url)


@dataclass
class Clock:
    now: float = 1000.0
    slept: list[float] = field(default_factory=list)

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


def client(transport: Recorder, clock: Clock | None = None, token: Token | None = None) -> Client:
    clock = clock or Clock()
    return Client(token, transport=transport, sleep=clock.sleep, monotonic=clock.monotonic)


# --- read only --------------------------------------------------------------------


def test_client_sends_only_get_requests() -> None:
    urls = [
        GH,
        "https://api.osv.dev/v1/vulns/PYSEC-2024-1",
        "https://pypi.org/simple/requests/",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ]
    transport = Recorder()
    for url in [*urls, OSV_QUERYBATCH_URL]:
        transport.route(url, reply())
    c = client(transport, token=Token(SECRET, "GH_TOKEN"))
    for url in urls:
        c.get(url, accept="application/json", limit=1000)
    c.osv_querybatch({"queries": []}, limit=1000)
    # Every GitHub request is a GET; the one other method is the POST to OSV's batch query.
    assert [s.method for s in transport.sent if "api.github.com" in s.url] == ["GET"]
    assert [(s.method, s.url) for s in transport.sent if s.method != "GET"] == [("POST", OSV_QUERYBATCH_URL)]

    # No other method, and no POST anywhere else, can be sent at all.
    for method, url in [
        ("POST", GH),
        ("PUT", GH),
        ("PATCH", GH),
        ("DELETE", GH),
        ("POST", "https://api.osv.dev/v1/query"),
        ("POST", "https://pypi.org/simple/requests/"),
        ("HEAD", GH),
    ]:
        with refuses("net.refused-method"), pytest.raises(ValueError, match="refused"):
            c._send(method, url, b"{}", "application/json", 1000, frozenset())
    assert len(transport.sent) == 5


def test_post_is_never_redirected() -> None:
    transport = Recorder().route(OSV_QUERYBATCH_URL, reply(307, location="https://api.osv.dev/v1/other"))
    with (
        refuses("net.sent-redirect-not-followed"),
        pytest.raises(FeedError, match=re.escape("api.osv.dev sent a redirect that is not followed")),
    ):
        client(transport).osv_querybatch({"queries": []}, limit=1000)
    assert len(transport.sent) == 1


def test_redirect_without_a_location_is_not_followed() -> None:
    transport = Recorder().route(PYPI_URL, reply(302))
    with (
        refuses("net.sent-redirect-not-followed"),
        pytest.raises(FeedError, match=re.escape("pypi.org sent a redirect that is not followed")),
    ):
        client(transport).get(PYPI_URL, accept="*/*", limit=100)
    assert [s.url for s in transport.sent] == [PYPI_URL]


def test_redirect_loop_stops_after_five_redirects() -> None:
    other = "https://api.github.com/repositories/1"
    transport = Recorder().route(GH, reply(302, location=other)).route(other, reply(302, location=GH))
    with (
        refuses("net.sent-too-many-redirects"),
        pytest.raises(FeedError, match=re.escape("api.github.com sent too many redirects")),
    ):
        client(transport).get(GH, accept="*/*", limit=100)
    assert len(transport.sent) == net.MAX_REDIRECTS + 1


def test_body_that_is_not_json_is_a_feed_failure() -> None:
    transport = Recorder().route(PYPI_URL, reply(200, b"<html>not json</html>"))
    response = client(transport).get(PYPI_URL, accept="application/json", limit=100)
    with (
        refuses("net.sent-response-not-json"),
        pytest.raises(FeedError, match=re.escape("pypi.org sent a response that is not JSON")),
    ):
        response.json()


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/advisories",
        "https://example.com/advisories",
        "https://api.github.com.example.com/x",
        "https://user@api.github.com/advisories",
        "https://api.github.com" + ":8443/advisories",  # in pieces: a secret scanner reads it as a key
        "https://api.github.com/advisories#frag",
        "https://api.github.com/a b",
        "file:///etc/passwd",
    ],
)
def test_client_refuses_other_hosts_and_schemes(url: str) -> None:
    transport = Recorder()
    with refuses("net.refused-url"), pytest.raises(ValueError, match="refused URL"):
        client(transport).get(url, accept="*/*", limit=10)
    assert transport.sent == []


@pytest.mark.parametrize("url", ["https://[::1", "https://[not-an-address]/advisories"])
def test_client_refuses_a_url_it_cannot_parse(url: str) -> None:
    transport = Recorder()
    with refuses("net.refused-url-unparsable"), pytest.raises(ValueError, match="refused URL: it cannot be parsed"):
        client(transport).get(url, accept="*/*", limit=10)
    assert transport.sent == []


# --- token ------------------------------------------------------------------------


def test_token_never_sent_after_cross_host_redirect() -> None:
    first = "https://api.github.com/repos/a/b"
    same_host = "https://api.github.com/repositories/1"
    other_host = "https://pypi.org/simple/x/"
    back = "https://api.github.com/repositories/2"
    transport = (
        Recorder()
        .route(first, reply(301, location=same_host))
        .route(same_host, reply(302, location=other_host))
        .route(other_host, reply(302, location=back))
        .route(back, reply(200, {"ok": True}))
    )
    response = client(transport, token=Token(SECRET, "GH_TOKEN")).get(first, accept="application/json", limit=100)
    assert response.json() == {"ok": True}
    sent_auth = [(s.url, "authorization" in s.headers) for s in transport.sent]
    # A redirect within api.github.com keeps the token; once one leaves it, it is never sent
    # again, not even when a later redirect comes back.
    assert sent_auth == [(first, True), (same_host, True), (other_host, False), (back, False)]
    assert transport.sent[0].headers["authorization"] == f"Bearer {SECRET}"


def test_token_goes_only_to_github() -> None:
    urls = ["https://pypi.org/simple/x/", "https://api.osv.dev/v1/vulns/X", OSV_QUERYBATCH_URL]
    transport = Recorder()
    for url in urls:
        transport.route(url, reply())
    c = client(transport, token=Token(SECRET, "GH_TOKEN"))
    c.get(urls[0], accept="*/*", limit=100)
    c.get(urls[1], accept="*/*", limit=100)
    c.osv_querybatch({"queries": []}, limit=100)
    assert all("authorization" not in s.headers for s in transport.sent)


def test_pythonhosted_files_are_fetched_with_get_only_and_no_token() -> None:
    # The pinned pip wheel (#6): files.pythonhosted.org is a known host, for GET only.
    url = "https://files.pythonhosted.org/packages/de/f0/abc/pip-26.0.1-py3-none-any.whl"
    transport = Recorder().route(url, reply(body=b"wheel bytes"))
    c = client(transport, token=Token(SECRET, "GH_TOKEN"))
    assert c.get(url, accept="application/octet-stream", limit=100).body == b"wheel bytes"
    assert [(s.method, s.url) for s in transport.sent] == [("GET", url)]
    assert "authorization" not in transport.sent[0].headers
    with refuses("net.refused-method"), pytest.raises(ValueError, match="refused POST"):
        c._send("POST", url, b"{}", "*/*", 100, frozenset())
    assert len(transport.sent) == 1


def test_redirect_to_an_unknown_host_is_refused() -> None:
    transport = Recorder().route(GH, reply(302, location="https://evil.example/steal"))
    with (
        refuses("net.redirected-outside-known-services"),
        refuses("net.refused-url"),
        pytest.raises(FeedError, match=re.escape("api.github.com redirected outside the known services")),
    ):
        client(transport, token=Token(SECRET, "GH_TOKEN")).get(GH, accept="*/*", limit=100)
    assert [s.url for s in transport.sent] == [GH]


def test_token_never_in_output_log_or_json(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    token = Token(SECRET, "GH_TOKEN")
    transport = (
        Recorder()
        .route(GH, reply(500, b"oops"))
        .route(GH + "&page=2", reply(403, b"{}", x_ratelimit_remaining="0", x_ratelimit_reset="1793736000"))
        .route(GH + "&page=3", OSError("connection reset"))
    )
    c = client(transport, token=token)
    collector = Collector(Verb.CHECK)
    errors: list[BaseException] = []
    for url in (GH, GH + "&page=2", GH + "&page=3"):
        with collector.check(Ecosystem.PYPI, "/venv"):
            try:
                c.get(url, accept="*/*", limit=100)
            except FeedError as exc:
                errors.append(exc)
                logging.getLogger("ssc_guardian").exception("feed failed: %s", exc)
                raise
    result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    texts = [repr(token), str(token), repr(c), to_json(result, TOOL), to_text(result, TOOL), caplog.text]
    texts += [f"{e!s} {e!r} {e.__cause__!r}" for e in errors]
    print(*texts)
    captured = capsys.readouterr()
    for text in [*texts, captured.out, captured.err]:
        assert SECRET not in text
    assert "GH_TOKEN" in repr(token)  # it names its source, never its value
    with pytest.raises(TypeError, match="a token is never serialized"):
        pickle.dumps(token)
    with pytest.raises(TypeError, match="not JSON serializable"):
        json.dumps(token)


@pytest.mark.parametrize("value", ["has space", "line\nbreak", "tab\t", "é", "x" * 1025, "a\r\nX-Injected: 1"])
def test_token_that_could_break_a_header_is_refused(value: str) -> None:
    with refuses("net.does-not-hold-token"), pytest.raises(TokenError, match="GH_TOKEN") as raised:
        find_token({"GH_TOKEN": value})
    assert value not in str(raised.value)


# --- token search and the gh boundary ------------------------------------------------


# Every gh case names its own candidate paths under tmp_path, so no test runs a real gh.
GH_SECRET = "gho_FromFakeGh0123456789abcdefABCDEF"


def fake_gh(folder: Path, body: str = f"echo {GH_SECRET}", mode: int = 0o755) -> tuple[Path, Path]:
    """A gh script at ``folder/gh`` that appends its arguments to ``folder/ran``, then runs
    ``body``; returns the script and that record."""
    folder.mkdir(parents=True, exist_ok=True)
    gh, record = folder / "gh", folder / "ran"
    gh.write_text(f"#!/bin/sh\necho \"$*\" >> '{record}'\n{body}\n")
    gh.chmod(mode)
    return gh, record


def runs(record: Path) -> list[str]:
    return record.read_text().splitlines() if record.exists() else []


def trusted_chain(tmp_path: Path) -> Callable[[str], os.stat_result]:
    """An lstat that reports ``/`` and every folder down to ``tmp_path`` as user-owned 0o755
    folders, and anything under ``tmp_path`` as it is. On GitHub's runner ``/tmp`` is
    ``drwxrwxrwt``, which the real walk refuses, so every gh test walks through this."""
    chain = {str(folder) for folder in (tmp_path, *tmp_path.parents)}

    def lstat_path(path: str) -> os.stat_result:
        info = os.lstat(path)
        if path not in chain:
            return info
        fields = list(info[:10])
        fields[0], fields[4] = stat.S_IFDIR | 0o755, os.getuid()
        return os.stat_result(fields)

    return lstat_path


@dataclass
class GhRuns:
    """A gh runner that records the file it was asked to run and answers ``output``."""

    output: bytes | None = GH_SECRET.encode() + b"\n"
    paths: list[str] = field(default_factory=list)

    def __call__(self, path: str) -> bytes | None:
        self.paths.append(path)
        return self.output


def owned_by(uid: int) -> Callable[[str], os.stat_result]:
    """A stat that reports the real file with another owner."""

    def gh_stat(path: str) -> os.stat_result:
        fields = list(os.stat(path)[:10])
        fields[4] = uid
        return os.stat_result(fields)

    return gh_stat


def test_gh_from_path_is_never_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    walk = trusted_chain(tmp_path)
    assert GH_PATHS == ("/opt/homebrew/bin/gh", "/usr/local/bin/gh")  # the plan's two, nothing else
    on_path, path_record = fake_gh(tmp_path / "bin")
    _, here_record = fake_gh(tmp_path / "here")
    monkeypatch.setenv("PATH", f"{on_path.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.chdir(tmp_path / "here")
    # PATH, a bare name and relative paths: none is run, though each names an existing gh.
    for paths in ((str(tmp_path / "none" / "gh"),), ("gh",), ("./gh", "../here/gh", "../bin/gh")):
        assert find_token({}, lstat_path=walk, gh_paths=paths) is None
    assert runs(path_record) == runs(here_record) == []

    # The positive control: the same kind of file at a fixed absolute path is run, once,
    # with the fixed arguments.
    control, control_record = fake_gh(tmp_path / "fixed")
    token = find_token({}, lstat_path=walk, gh_paths=(str(control),))
    assert token is not None and token.source == "gh auth token"
    assert token._authorization() == f"Bearer {GH_SECRET}"
    assert GH_SECRET not in f"{token!r} {token!s}"
    assert runs(control_record) == ["auth token --hostname github.com"]
    assert runs(path_record) == runs(here_record) == []


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777, 0o4775, 0o720, 0o702])
def test_gh_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    walk = trusted_chain(tmp_path)
    gh, record = fake_gh(tmp_path / "gh-dir", mode=mode)
    assert find_token({}, lstat_path=walk, gh_paths=(str(gh),)) is None
    assert runs(record) == []
    gh.chmod(0o755)  # the same file, writable by its owner only, is run
    assert find_token({}, lstat_path=walk, gh_paths=(str(gh),)) is not None
    assert len(runs(record)) == 1


def test_gh_owner_and_symlink_target_are_checked(tmp_path: Path) -> None:
    walk = trusted_chain(tmp_path)
    gh, _ = fake_gh(tmp_path / "cellar")
    for uid, trusted in ((os.getuid(), True), (0, True), (os.getuid() + 1, False), (65534, False)):
        runner = GhRuns()
        found = find_token({}, lstat_path=walk, gh_paths=(str(gh),), gh_stat=owned_by(uid), run_gh=runner)
        assert (found is not None) is trusted and len(runner.paths) == int(trusted), uid

    # A symlink is followed: its target is what is checked and what is run.
    links = tmp_path / "links"
    links.mkdir()
    (links / "gh").symlink_to(gh)
    runner, seen = GhRuns(), []

    def seeing(path: str) -> os.stat_result:
        seen.append(path)
        return os.stat(path)

    found = find_token({}, lstat_path=walk, gh_paths=(str(links / "gh"),), gh_stat=seeing, run_gh=runner)
    assert found is not None
    assert runner.paths == seen == [os.path.realpath(gh)]

    open_to_all, _ = fake_gh(tmp_path / "open", mode=0o777)
    (links / "to-open").symlink_to(open_to_all)  # a safe-looking link to a file others can write
    (links / "to-folder").symlink_to(tmp_path / "cellar")
    (links / "dangling").symlink_to(tmp_path / "missing")
    (links / "loop").symlink_to(links / "loop")
    for name in ("to-open", "to-folder", "dangling", "loop"):
        runner = GhRuns()
        assert find_token({}, lstat_path=walk, gh_paths=(str(links / name),), run_gh=runner) is None, name
        assert runner.paths == [], name

    # An untrusted first candidate moves the search on to the next; gh runs once.
    runner = GhRuns()
    assert (
        find_token({}, lstat_path=walk, gh_paths=(str(links / "to-open"), str(links / "gh")), run_gh=runner) is not None
    )
    assert runner.paths == [os.path.realpath(gh)]


def brew_gh(tmp_path: Path) -> tuple[Path, Path]:
    """Homebrew's shape under ``tmp_path/brew``: ``bin/gh`` links to
    ``../Cellar/gh/2.88.1/bin/gh``. Returns the link and the file."""
    brew = tmp_path / "brew"
    gh, _ = fake_gh(brew / "Cellar" / "gh" / "2.88.1" / "bin")
    (brew / "bin").mkdir()
    (brew / "bin" / "gh").symlink_to("../Cellar/gh/2.88.1/bin/gh")
    return brew / "bin" / "gh", gh


def test_gh_path_is_walked_from_root_through_each_link(tmp_path: Path) -> None:
    walk = trusted_chain(tmp_path)
    link, gh = brew_gh(tmp_path)
    seen: list[str] = []

    def recording(path: str) -> os.stat_result:
        seen.append(path)
        return walk(path)

    runner = GhRuns()
    assert find_token({}, gh_paths=(str(link),), lstat_path=recording, run_gh=runner) is not None
    assert runner.paths == [str(gh)]
    # One lstat per folder from /, for the link, then for each part of its relative target.
    brew = tmp_path / "brew"
    chain = [str(folder) for folder in reversed((tmp_path, *tmp_path.parents))]
    cellar = [brew / "Cellar", brew / "Cellar" / "gh", brew / "Cellar" / "gh" / "2.88.1", gh.parent, gh]
    assert seen == [*chain, str(brew), str(brew / "bin"), str(link), *map(str, cellar)]


def test_gh_path_with_an_untrusted_folder_or_link_is_refused(tmp_path: Path) -> None:
    walk = trusted_chain(tmp_path)
    link, gh = brew_gh(tmp_path)
    cellar = tmp_path / "brew" / "Cellar"
    paths = (str(link),)
    group = os.stat(cellar).st_gid

    def token(lstat_path: Callable[[str], os.stat_result] = walk, admin: int | None = None) -> bool:
        runner = GhRuns()
        found = find_token({}, gh_paths=paths, lstat_path=lstat_path, admin_gid=lambda: admin, run_gh=runner)
        assert len(runner.paths) == int(found is not None)  # gh runs only when found trusted
        return found is not None

    assert token()  # the control

    # A folder on the link's target others can write: the gh file itself is fine.
    for mode in (0o777, 0o1777, 0o757):
        cellar.chmod(mode)
        assert not token(admin=group), oct(mode)
    # Group write is trusted only for the admin group, and never with other write.
    cellar.chmod(0o775)
    assert not token() and not token(admin=group + 1)
    assert token(admin=group)
    cellar.chmod(0o755)

    # A folder or a link another user owns.
    def owned_by_other(place: Path) -> Callable[[str], os.stat_result]:
        def lstat_path(path: str) -> os.stat_result:
            info = walk(path)
            if path != str(place):
                return info
            fields = list(info[:10])
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)

        return lstat_path

    for place in (cellar, cellar.parent, link, gh.parent):
        assert not token(owned_by_other(place)), place

    # A link's own mode bits mean nothing (Linux reports 0777): only its owner counts.
    def open_link(path: str) -> os.stat_result:
        info = walk(path)
        if path != str(link):
            return info
        fields = list(info[:10])
        fields[0] = stat.S_IFLNK | 0o777
        return os.stat_result(fields)

    assert token(open_link)


def test_gh_link_chain_is_bounded(tmp_path: Path) -> None:
    walk = trusted_chain(tmp_path)
    gh, _ = fake_gh(tmp_path / "cellar")
    links = tmp_path / "links"
    links.mkdir()
    previous = gh
    for number in range(GH_MAX_LINKS + 1):  # link 0 points at gh; link N at link N-1
        (links / str(number)).symlink_to(previous)
        previous = links / str(number)
    runner = GhRuns()
    within = str(links / str(GH_MAX_LINKS - 1))
    assert find_token({}, gh_paths=(within,), lstat_path=walk, run_gh=runner) is not None
    beyond = str(links / str(GH_MAX_LINKS))
    assert find_token({}, gh_paths=(beyond,), lstat_path=walk, run_gh=runner) is None
    assert runner.paths == [str(gh)]


def test_gh_runs_only_when_both_token_variables_are_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    walk = trusted_chain(tmp_path)
    gh, _ = fake_gh(tmp_path)
    paths = (str(gh),)
    for environ, source in (
        ({"GH_TOKEN": ""}, None),  # set but empty counts as set
        ({"GITHUB_TOKEN": ""}, None),
        ({"GH_TOKEN": "", "GITHUB_TOKEN": ""}, None),
        ({"GH_TOKEN": "ghp_a"}, "GH_TOKEN"),
        ({"GITHUB_TOKEN": "ghs_b"}, "GITHUB_TOKEN"),
        ({"GH_TOKEN": "", "GITHUB_TOKEN": "ghs_b"}, "GITHUB_TOKEN"),
    ):
        runner = GhRuns()
        found = find_token(environ, lstat_path=walk, gh_paths=paths, run_gh=runner)
        assert (found.source if found else None) == source, environ
        assert runner.paths == [], environ

    runner = GhRuns()
    found = find_token({"PATH": "/usr/bin"}, lstat_path=walk, gh_paths=paths, run_gh=runner)
    assert found is not None and found.source == "gh auth token" and len(runner.paths) == 1

    # With no mapping given, the search reads the process environment.
    monkeypatch.setenv("GH_TOKEN", "")
    runner = GhRuns()
    assert find_token(lstat_path=walk, gh_paths=paths, run_gh=runner) is None and runner.paths == []
    monkeypatch.delenv("GH_TOKEN")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert find_token(lstat_path=walk, gh_paths=paths, run_gh=runner) is not None and len(runner.paths) == 1


@pytest.mark.parametrize(
    "output",
    [
        None,  # the runner's answer for a failed gh
        b"",
        b"\n",
        b"has space\n",
        b"two\nlines\n",
        b"\tghp_tab\n",
        b"a\r\nX-Injected: 1\n",
        b"ghp_carriage\r\n",
        "é-not-ascii\n".encode(),
        b"\xff\xfe\n",
        b"x" * 1025 + b"\n",
    ],
)
def test_gh_output_that_is_not_a_token_is_ignored(
    tmp_path: Path, output: bytes | None, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    walk = trusted_chain(tmp_path)
    caplog.set_level(logging.DEBUG)
    gh, _ = fake_gh(tmp_path)
    runner = GhRuns(output)
    assert find_token({}, lstat_path=walk, gh_paths=(str(gh),), run_gh=runner) is None
    assert len(runner.paths) == 1
    captured = capsys.readouterr()
    assert captured.out == captured.err == caplog.text == ""


@pytest.mark.parametrize(
    ("body", "mode"),
    [
        (f"echo {GH_SECRET}\nexit 1", 0o755),  # a token, but a failed exit
        (f"echo {GH_SECRET} >&2\nexit 4", 0o755),  # gh's own error output is dropped unread
        ("exec sleep 30", 0o755),  # times out
        (f"echo {GH_SECRET}", 0o644),  # cannot start: OSError
    ],
)
def test_gh_that_fails_gives_no_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], body: str, mode: int
) -> None:
    walk = trusted_chain(tmp_path)
    monkeypatch.setattr("ssc_guardian.net.GH_TIMEOUT_SECONDS", 2.0)
    gh, record = fake_gh(tmp_path, body, mode)
    started = time.monotonic()
    assert find_token({}, lstat_path=walk, gh_paths=(str(gh),)) is None
    assert time.monotonic() - started < 10  # the timeout stopped the sleeping gh
    assert len(runs(record)) == (0 if mode == 0o644 else 1)
    captured = capsys.readouterr()
    assert GH_SECRET not in captured.out + captured.err


def test_token_search_is_idempotent_on_re_run(tmp_path: Path) -> None:
    walk = trusted_chain(tmp_path)
    gh, record = fake_gh(tmp_path)
    first, second = (
        find_token({}, lstat_path=walk, gh_paths=(str(gh),)),
        find_token({}, lstat_path=walk, gh_paths=(str(gh),)),
    )
    assert first is not None and second is not None
    assert (first.source, first._authorization()) == (second.source, second._authorization())
    assert len(runs(record)) == 2  # once per search
    for environ in ({"GH_TOKEN": "ghp_a"}, {"GH_TOKEN": ""}):
        assert repr(find_token(environ, lstat_path=walk, gh_paths=(str(gh),))) == repr(
            find_token(environ, lstat_path=walk, gh_paths=(str(gh),))
        )
    assert len(runs(record)) == 2
    missing = (str(tmp_path / "missing" / "gh"),)
    assert (
        find_token({}, lstat_path=walk, gh_paths=missing) is None
        and find_token({}, lstat_path=walk, gh_paths=missing) is None
    )


def test_token_search_order(tmp_path: Path) -> None:
    first = find_token({"GH_TOKEN": "ghp_a", "GITHUB_TOKEN": "ghs_b"})
    assert first is not None and first.source == "GH_TOKEN"
    for environ in ({"GITHUB_TOKEN": "ghs_b"}, {"GH_TOKEN": "", "GITHUB_TOKEN": "ghs_b"}):
        found = find_token(environ)
        assert found is not None and found.source == "GITHUB_TOKEN"
    assert find_token({"GH_TOKEN": "", "GITHUB_TOKEN": ""}) is None
    assert find_token({}, gh_paths=(str(tmp_path / "gh"),)) is None  # no gh there: no login


# --- rate limits ---------------------------------------------------------------------


def test_hourly_rate_limit_exits_two_with_reset_time() -> None:
    reset = int(datetime(2026, 11, 3, 18, 0, tzinfo=UTC).timestamp())
    limited = reply(
        403, {"message": "API rate limit exceeded"}, x_ratelimit_remaining="0", x_ratelimit_reset=str(reset)
    )
    transport = Recorder().route(GH, limited).route(GH + "&page=2", reply())
    clock = Clock()
    c = client(transport, clock)
    said = (
        "GitHub's hourly rate limit is used up: it resets at 2026-11-03 18:00 UTC; "
        "log in with gh or set GH_TOKEN for a higher limit"
    )
    with refuses("net.githubs-hourly-rate-limit-used"), pytest.raises(RateLimitError, match=re.escape(said)) as raised:
        c.get(GH, accept="*/*", limit=100)
    assert raised.value.reason is SkipReason.RATE_LIMIT
    assert raised.value.reset_at == datetime(2026, 11, 3, 18, 0, tzinfo=UTC)
    assert "resets at 2026-11-03 18:00 UTC" in str(raised.value)
    assert "log in with gh or set GH_TOKEN" in str(raised.value)  # the fix, for a run with no login
    assert clock.slept == []  # the hourly limit is never waited out
    # The client stops: later GitHub requests fail at once, without being sent.
    collector = Collector(Verb.CHECK)
    with refuses("net.github-stopped"), collector.check(Ecosystem.GITHUB_ACTIONS, "/repo/.github/workflows/ci.yml"):
        c.get(GH + "&page=2", accept="*/*", limit=100)
    assert len(transport.sent) == 1
    result = collector.result()
    assert result.exit_code is ExitCode.INCOMPLETE
    assert [(s.reason, s.in_scope) for s in result.skipped] == [(SkipReason.RATE_LIMIT, True)]


def test_hourly_limit_on_429_without_a_reset_still_stops() -> None:
    transport = Recorder().route(GH, reply(429, b"{}", x_ratelimit_remaining="0"))
    with refuses("net.githubs-hourly-rate-limit-used"), pytest.raises(RateLimitError, match="did not say when"):
        client(transport).get(GH, accept="*/*", limit=100)


@pytest.mark.parametrize(
    ("wait", "outcome", "slept"),
    [("60", "ok", [60.0]), ("61", "stopped", []), ("3600", "stopped", []), ("0", "ok", [0.0])],
)
def test_secondary_limit_over_sixty_seconds_exits_two(wait: str, outcome: str, slept: list[float]) -> None:
    transport = Recorder().route(GH, reply(403, {"message": "secondary"}, retry_after=wait), reply(200))
    clock = Clock()
    c = client(transport, clock)
    if outcome == "ok":
        assert c.get(GH, accept="*/*", limit=100).status == 200
    else:
        said = f"GitHub's secondary rate limit asks for a {wait} s wait, over the 60 s Guardian waits; run again later"
        with refuses("net.githubs-secondary-rate-limit-asks"), pytest.raises(RateLimitError, match=re.escape(said)):
            c.get(GH, accept="*/*", limit=100)
    assert clock.slept == slept


@pytest.mark.parametrize(("limited", "succeeds"), [(3, True), (4, False)])
def test_secondary_limit_retries_at_most_three_times(limited: int, succeeds: bool) -> None:
    answers = [reply(429, b"{}", retry_after="1")] * limited + [reply(200)]
    transport = Recorder().route(GH, *answers)
    clock = Clock()
    c = client(transport, clock)
    if succeeds:
        assert c.get(GH, accept="*/*", limit=100).status == 200
    else:
        said = "GitHub's secondary rate limit held after 3 retries; run again later"
        with refuses("net.githubs-secondary-rate-limit-held"), pytest.raises(RateLimitError, match=re.escape(said)):
            c.get(GH, accept="*/*", limit=100)
    assert clock.slept == [1.0, 1.0, 1.0]
    assert len(transport.sent) == 4


def test_secondary_limit_without_retry_after_waits_one_minute() -> None:
    body = b'{"message": "You have exceeded a secondary rate limit."}'
    transport = Recorder().route(GH, reply(403, body), reply(200))
    clock = Clock()
    assert client(transport, clock).get(GH, accept="*/*", limit=100).status == 200
    assert clock.slept == [60.0]


def test_plain_403_is_a_failure_not_a_rate_limit() -> None:
    transport = Recorder().route(GH, reply(403, {"message": "Resource not accessible"}))
    clock = Clock()
    with refuses("net.feed-answered-http-error"), pytest.raises(FeedError, match="answered HTTP 403") as raised:
        client(transport, clock).get(GH, accept="*/*", limit=100)
    assert not isinstance(raised.value, RateLimitError)
    assert raised.value.reason is SkipReason.FEED_FAILURE
    assert clock.slept == [] and len(transport.sent) == 1


# --- feed retries ----------------------------------------------------------------------

PYPI_URL = "https://pypi.org/simple/requests/"


@pytest.mark.parametrize("failure", [TimeoutError("timed out"), OSError("reset"), reply(503), reply(429)])
def test_feed_retries_twice_then_fails(failure: Reply) -> None:
    transport = Recorder().route(PYPI_URL, failure)
    clock = Clock()
    with refuses("net.feed-retries-exhausted"), pytest.raises(FeedError, match="after 2 retries") as raised:
        client(transport, clock).get(PYPI_URL, accept="*/*", limit=100)
    assert raised.value.reason is SkipReason.FEED_FAILURE
    assert len(transport.sent) == 3
    assert clock.slept == [1.0, 4.0]


def test_feed_retry_must_fit_in_sixty_seconds() -> None:
    transport = Recorder().route(PYPI_URL, reply(503, retry_after="30"), reply(503, retry_after="31"), reply(200))
    clock = Clock()
    with (
        refuses("net.no-retry-fits-deadline"),
        pytest.raises(FeedError, match=re.escape("pypi.org answered HTTP 503; no retry fits in 60 s")),
    ):
        client(transport, clock).get(PYPI_URL, accept="*/*", limit=100)
    assert clock.slept == [30.0]


def test_feed_errors_other_than_retryable_fail_at_once() -> None:
    transport = Recorder().route(PYPI_URL, reply(400))
    clock = Clock()
    with refuses("net.feed-answered-http-error"), pytest.raises(FeedError, match="HTTP 400"):
        client(transport, clock).get(PYPI_URL, accept="*/*", limit=100)
    assert len(transport.sent) == 1


@pytest.mark.parametrize("value", ["\u00b2", "1e3", "-5", "99999999999999999999999"])
def test_header_numbers_that_are_not_plain_numbers_are_ignored(value: str) -> None:
    # str.isdigit() accepts a superscript two; a huge reset time cannot be a date.
    transport = Recorder().route(GH, reply(403, b"{}", x_ratelimit_remaining="0", x_ratelimit_reset=value))
    with refuses("net.githubs-hourly-rate-limit-used"), pytest.raises(RateLimitError, match="did not say when"):
        client(transport).get(GH, accept="*/*", limit=100)
    feed = Recorder().route(PYPI_URL, reply(503, retry_after=value))
    clock = Clock()
    with refuses("net.feed-retries-exhausted"), pytest.raises(FeedError, match="after 2 retries"):
        client(feed, clock).get(PYPI_URL, accept="*/*", limit=100)
    assert clock.slept == [1.0, 4.0]  # the backoff, not the header


def test_broken_http_response_is_a_feed_failure() -> None:
    # http.client errors are not OSErrors; the transport turns them into one, so they are
    # retried and end as a feed failure, never as an unexpected exception.
    def broken(request: urllib.request.Request, timeout: float, limit: int) -> Response:
        try:
            raise IncompleteRead(b"partial")
        except IncompleteRead as exc:
            raise OSError("broken HTTP response (IncompleteRead)") from exc

    clock = Clock()
    c = Client(transport=broken, sleep=clock.sleep, monotonic=clock.monotonic)
    with refuses("net.feed-retries-exhausted"), pytest.raises(FeedError, match="could not be reached"):
        c.get(PYPI_URL, accept="*/*", limit=100)


def test_github_network_failure_is_not_retried() -> None:
    transport = Recorder().route(GH, TimeoutError())
    with (
        refuses("net.could-not-reached"),
        pytest.raises(FeedError, match=re.escape("api.github.com could not be reached (TimeoutError)")),
    ):
        client(transport).get(GH, accept="*/*", limit=100)
    assert len(transport.sent) == 1


# --- cache -----------------------------------------------------------------------------

SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    "sha",
    [
        "v4.2.2",
        "main",
        "../../../etc/passwd",
        SHA.upper(),
        SHA[:-1],
        SHA + "0",
        SHA + "\n",
        SHA[:-1] + "/",
        "",
        None,
        int(SHA[:15], 16),
    ],
)
def test_cache_key_rejects_non_sha_input(tmp_path: Path, sha: Any) -> None:
    cache = ShaCache(tmp_path / "cache")
    with refuses("grammars.malformed-value"), pytest.raises(ValueError, match="malformed sha"):
        cache.put(1, sha, "action.yml", b"x")
    with refuses("grammars.malformed-value"), pytest.raises(ValueError, match="malformed sha"):
        cache.get(1, sha, "action.yml")
    assert not (tmp_path / "cache").exists()


@pytest.mark.parametrize("repo_id", [0, -1, True, "123", "../1", 1.0, 2**63, None])
def test_cache_key_rejects_non_id_repository(tmp_path: Path, repo_id: Any) -> None:
    cache = ShaCache(tmp_path / "cache")
    with pytest.raises(ValueError, match="a repository ID is a positive integer"):
        cache.put(repo_id, SHA, "action.yml", b"x")
    assert not (tmp_path / "cache").exists()


def test_cache_names_files_by_repository_id_and_sha_only(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    cache = ShaCache(root)
    assert cache.get(42, SHA, "action.yml") is None
    cache.put(42, SHA, "action.yml", b"runs: {}\n")
    cache.put(42, SHA, "../../escape/action.yml", b"\x00\xff")  # a path is content, never a file name
    assert cache.get(42, SHA, "action.yml") == b"runs: {}\n"
    assert cache.get(42, SHA, "../../escape/action.yml") == b"\x00\xff"
    assert sorted(str(p.relative_to(root)) for p in root.rglob("*")) == ["42", f"42/{SHA}.json"]
    assert cache.get(43, SHA, "action.yml") is None


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"repo_id": 7, "sha": "' + SHA + '", "files": {"a": "%%%"}}',
        '{"repo_id": 8, "sha": "' + SHA + '", "files": {"a": "eA=="}}',
    ],
)
def test_cache_file_that_cannot_be_read_back_is_a_miss(tmp_path: Path, content: str) -> None:
    file = tmp_path / "7" / f"{SHA}.json"
    file.parent.mkdir()
    file.write_text(content)
    assert ShaCache(tmp_path).get(7, SHA, "a") is None


def test_fifo_in_the_sha_cache_is_a_miss_not_a_hang(tmp_path: Path) -> None:
    file = tmp_path / "7" / f"{SHA}.json"
    file.parent.mkdir()
    os.mkfifo(file)
    cache = ShaCache(tmp_path)
    assert cache.get(7, SHA, "a") is None  # must not hang the run
    cache.put(7, SHA, "a", b"x")  # the entry replaces the FIFO
    assert cache.get(7, SHA, "a") == b"x"


def test_read_refuses_a_body_over_the_size_cap() -> None:
    # The Recorder stands in for the transport, so this drives the cap directly.
    class Endless:
        def read(self, size: int) -> bytes:
            return b"x" * size

    response: Any = Endless()
    with refuses("net.response-too-large"), pytest.raises(FeedError, match="pypi.org sent more than 10 bytes"):
        net._read(response, "https://pypi.org/simple/x/", 10)
