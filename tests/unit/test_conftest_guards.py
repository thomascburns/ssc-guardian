# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""The hermetic test base in ``tests/conftest.py`` holds (issue #7).

Every address a test here tries to reach is in a documentation range (192.0.2.0/24,
2001:db8::/32) or ``example.com``, and the guard refuses it before any packet is sent.
Where a test must show what the guard does to a whole test (a caught attempt still fails
it; a ``requires_network`` test is exempt, or skipped offline), it runs pytest on a small
test file in a subprocess, with this conftest and a probe that never touches the network.
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from xml.etree import ElementTree

import pytest

from tests import conftest
from tests.conftest import (
    GH_LOGIN_VARS,
    NO_PROXY,
    PROXY_VARS,
    REAL_HOME,
    XDG_HOMES,
    FixtureServer,
    Hermetic,
    serve_folder,
)

pytestmark = pytest.mark.unit


def _create_connection(host: str, port: int) -> None:
    socket.create_connection((host, port), timeout=1).close()


def _socket_call(family: int, kind: int, call: Callable[[socket.socket], object]) -> Callable[[], None]:
    def attempt() -> None:
        with contextlib.closing(socket.socket(family, kind)) as sock:
            call(sock)

    return attempt


def _urlopen_without_proxy(url: str) -> None:
    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=1).close()


def _urlopen_with_env_proxies(url: str) -> None:
    urllib.request.build_opener().open(url, timeout=1).close()


TCP, UDP, V4, V6 = socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.AF_INET, socket.AF_INET6

ATTEMPTS = [
    pytest.param(lambda: _create_connection("192.0.2.1", 443), "connect to 192.0.2.1:443", id="ipv4"),
    pytest.param(
        _socket_call(V6, TCP, lambda s: s.connect(("2001:db8::1", 443, 0, 0))),
        "connect to [2001:db8::1]:443",
        id="ipv6",
    ),
    pytest.param(
        _socket_call(V6, TCP, lambda s: s.connect(("::ffff:192.0.2.1", 80, 0, 0))),
        "connect to [::ffff:192.0.2.1]:80",
        id="ipv4-mapped",
    ),
    pytest.param(
        _socket_call(V4, TCP, lambda s: s.connect_ex(("192.0.2.1", 80))), "connect to 192.0.2.1:80", id="connect-ex"
    ),
    pytest.param(
        _socket_call(V4, TCP, lambda s: s.connect(("example.com", 80))), "connect to example.com:80", id="name"
    ),
    pytest.param(lambda: _create_connection("example.com", 443), "a name lookup for example.com", id="lookup"),
    pytest.param(lambda: socket.gethostbyname("example.com"), "a name lookup for example.com", id="gethostbyname"),
    pytest.param(lambda: socket.gethostbyaddr("192.0.2.1"), "a reverse name lookup for 192.0.2.1", id="reverse-lookup"),
    pytest.param(
        _socket_call(V4, UDP, lambda s: s.sendto(b"x", ("192.0.2.1", 53))), "datagram to 192.0.2.1:53", id="udp"
    ),
    pytest.param(
        _socket_call(V4, UDP, lambda s: s.sendmsg([b"x"], [], 0, ("192.0.2.1", 53))),
        "datagram to 192.0.2.1:53",
        id="udp-sendmsg",
    ),
    pytest.param(
        lambda: socket.getnameinfo(("192.0.2.1", 80), 0), "a reverse name lookup for 192.0.2.1", id="getnameinfo"
    ),
    pytest.param(lambda: _urlopen_without_proxy("http://192.0.2.1/"), "connect to 192.0.2.1:80", id="urllib"),
    pytest.param(
        lambda: _urlopen_with_env_proxies("http://192.0.2.1/"), "the closed proxy port", id="urllib-through-proxy"
    ),
]


@pytest.mark.parametrize(("attempt", "named"), ATTEMPTS)
def test_live_network_access_fails_the_test(hermetic: Hermetic, attempt: Callable[[], object], named: str) -> None:
    assert hermetic.guard is not None
    with pytest.raises(pytest.fail.Exception) as raised:  # the guard's own text, asserted below
        attempt()
    assert named in str(raised.value)
    blocked = hermetic.guard.take()  # taken, or the guard would fail this test after it returns
    assert len(blocked) == 1 and named in blocked[0]


def test_loopback_and_unix_sockets_are_allowed(
    hermetic: Hermetic, fixture_server: FixtureServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (fixture_server.root / "a.txt").write_text("a")
    port = fixture_server.url.rsplit(":", 1)[1]
    for host in ("127.0.0.1", "localhost", "LOCALHOST"):
        with urllib.request.urlopen(f"http://{host}:{port}/a.txt", timeout=5) as answer:
            assert answer.read() == b"a"
    # An [::1] URL goes direct too (NO_PROXY names it with brackets), never to the closed proxy port.
    with pytest.raises(urllib.error.URLError) as direct:  # urllib's error: no Guardian message
        _urlopen_with_env_proxies(f"http://[::1]:{port}/a.txt")
    assert isinstance(direct.value.reason, OSError)
    assert socket.getnameinfo(("127.0.0.1", 80), socket.NI_NUMERICHOST | socket.NI_NUMERICSERV) == ("127.0.0.1", "80")
    # ::1 is loopback: nothing listens there, so the system refuses it (or has no IPv6); the
    # guard's refusal is no OSError and would fail this test. The system's error: no Guardian message.
    with pytest.raises(OSError), contextlib.closing(socket.socket(socket.AF_INET6)) as sock:
        sock.connect(("::1", int(port), 0, 0))
    monkeypatch.chdir(tmp_path)  # a short relative path: AF_UNIX paths are limited to about 100 bytes
    with (
        contextlib.closing(socket.socket(socket.AF_UNIX)) as server,
        contextlib.closing(socket.socket(socket.AF_UNIX)) as client,
    ):
        server.bind("s")
        server.listen()
        client.connect("s")
    assert hermetic.guard is not None and hermetic.guard.take() == []


def test_home_folder_is_temporary(hermetic: Hermetic) -> None:
    home = hermetic.home
    assert os.environ["HOME"] == str(home)
    assert Path.home() == home and Path("~").expanduser() == home and os.path.expanduser("~") == str(home)
    # Fresh: nothing from another test, only (d)'s empty gh config folder.
    assert sorted(str(path.relative_to(home)) for path in home.rglob("*")) == [".config", ".config/gh"]
    assert home != Path(REAL_HOME) and not str(home).startswith(REAL_HOME.rstrip("/") + "/")
    assert not any(name in os.environ for name in XDG_HOMES)  # their defaults fall under HOME

    written = Path("~/.config/ssc-guardian/settings.toml").expanduser()
    written.parent.mkdir(parents=True)
    written.write_text("")
    assert written.is_relative_to(home)

    child = subprocess.run(
        [sys.executable, "-c", "import pathlib; print(pathlib.Path.home())"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert child.stdout == f"{home}\n"


def test_no_test_sees_a_github_login(hermetic: Hermetic) -> None:
    assert not any(name in os.environ for name in GH_LOGIN_VARS)
    config = Path(os.environ["GH_CONFIG_DIR"])
    assert config == hermetic.home / ".config" / "gh" and list(config.iterdir()) == []


def test_subprocesses_reach_loopback_and_nothing_else(fixture_server: FixtureServer) -> None:
    assert {name: os.environ[name] for name in PROXY_VARS} == dict.fromkeys(PROXY_VARS, "http://127.0.0.1:9")
    assert os.environ["NO_PROXY"] == os.environ["no_proxy"] == NO_PROXY
    (fixture_server.root / "a.txt").write_text("a")
    child = (
        "import sys, urllib.request\n"
        "print(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())\n"
        "try:\n"
        "    urllib.request.urlopen('http://192.0.2.1/', timeout=5)\n"
        "except OSError as exc:\n"
        "    print(type(getattr(exc, 'reason', exc)).__name__)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", child, fixture_server.url_for("a.txt")], capture_output=True, text=True, check=True
    )
    # Loopback directly (NO_PROXY); anything else to the closed port, which refuses it.
    assert proc.stdout == "a\nConnectionRefusedError\n"


def _fetch(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=5) as answer:
        return answer.status, answer.read()


def test_fixture_server_is_idempotent_across_re_run(fixture_server: FixtureServer) -> None:
    root = fixture_server.root
    assert list(root.iterdir()) == []  # a fresh folder for each test
    (root / "simple").mkdir()
    (root / "simple" / "index.json").write_bytes(b'{"projects": []}')
    before = sorted(root.rglob("*"))

    first, second = (
        _fetch(fixture_server.url_for("simple/index.json")),
        _fetch(fixture_server.url_for("simple/index.json")),
    )
    assert first == second == (200, b'{"projects": []}')
    with pytest.raises(urllib.error.HTTPError) as missing:  # urllib's error: no Guardian message
        _fetch(fixture_server.url_for("absent.json"))
    assert missing.value.code == 404

    # A re-run over the same folder serves the same answer on a fresh port, and its
    # teardown leaves nothing listening.
    with serve_folder(root) as again:
        assert again.url != fixture_server.url
        assert _fetch(again.url_for("simple/index.json")) == first
    port = int(again.url.rsplit(":", 1)[1])
    with pytest.raises(ConnectionRefusedError):  # the system's error: no Guardian message
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    assert sorted(root.rglob("*")) == before  # serving wrote nothing


# --- what the guard does to a whole test, in a pytest subprocess -------------

INNER_TESTS = """
import os
import socket
import subprocess
import sys
import threading

import pytest

import conftest


def test_caught_by_except_exception():
    try:
        socket.create_connection(("192.0.2.1", 443), timeout=1)
    except Exception:
        pass


def test_caught_by_except_base_exception():
    try:
        socket.create_connection(("192.0.2.2", 443), timeout=1)
    except BaseException:
        pass


def test_in_a_thread():
    thread = threading.Thread(target=lambda: socket.create_connection(("192.0.2.3", 443), timeout=1))
    thread.start()
    thread.join()


def test_loopback_only():
    socket.getaddrinfo("localhost", 80)


def test_caught_then_skipped():
    try:
        socket.create_connection(("192.0.2.4", 443), timeout=1)
    except BaseException:
        pass
    pytest.skip("skipping after the attempt")


@pytest.mark.xfail(reason="an expected failure must not hide the attempt")
def test_caught_in_an_xfail_test():
    try:
        socket.create_connection(("192.0.2.5", 443), timeout=1)
    except BaseException:
        pass
    assert False


@pytest.mark.xfail(reason="the guard's own refusal is not an expected failure")
def test_refused_in_an_xfail_test():
    socket.create_connection(("192.0.2.6", 443), timeout=1)


@pytest.mark.xfail(strict=True, reason="a strict xfail that passes")
def test_caught_in_a_strict_xfail_test():
    try:
        socket.create_connection(("192.0.2.7", 443), timeout=1)
    except BaseException:
        pass


@pytest.fixture
def hides_in_setup():
    try:
        socket.create_connection(("192.0.2.8", 443), timeout=1)
    except BaseException:
        pass


def test_caught_in_fixture_setup(hides_in_setup):
    pass


@pytest.fixture
def hides_in_teardown():
    yield
    try:
        socket.create_connection(("192.0.2.9", 443), timeout=1)
    except BaseException:
        pass


def test_caught_in_fixture_teardown(hides_in_teardown):
    pass


def test_caught_then_refused():
    try:
        socket.create_connection(("192.0.2.10", 443), timeout=1)
    except BaseException:
        pass
    socket.create_connection(("192.0.2.11", 443), timeout=1)


def test_caught_then_failed_quoting_it():
    try:
        socket.create_connection(("192.0.2.13", 443), timeout=1)
    except BaseException:
        pass
    pytest.fail("connect to 192.0.2.13:443", pytrace=False)


def test_refused():
    socket.create_connection(("192.0.2.14", 443), timeout=1)


def test_refused_then_hidden_attempt():
    try:
        socket.create_connection(("192.0.2.15", 443), timeout=1)
    except BaseException:
        thread = threading.Thread(target=lambda: socket.create_connection(("192.0.2.16", 443), timeout=1))
        thread.start()
        thread.join()
        raise


@pytest.fixture(scope="session")
def session_environment():
    return {name: os.environ.get(name) for name in (*conftest.GH_LOGIN_VARS, "GH_CONFIG_DIR", "HOME")}


def test_session_fixtures_see_no_gh_login(session_environment):
    assert all(session_environment[name] is None for name in conftest.GH_LOGIN_VARS)
    config = session_environment["GH_CONFIG_DIR"]
    assert config == os.path.join(session_environment["HOME"], conftest.GH_CONFIG) and os.listdir(config) == []


def _gh_login_hidden(hermetic):
    assert not any(name in os.environ for name in conftest.GH_LOGIN_VARS)
    config = os.environ["GH_CONFIG_DIR"]
    assert config == str(hermetic.home / conftest.GH_CONFIG) and os.listdir(config) == []
    child = subprocess.run(
        [sys.executable, "-c", "import os, sys; print(sorted(set(os.environ) & set(sys.argv[1:])))"]
        + list(conftest.GH_LOGIN_VARS),
        capture_output=True,
        text=True,
        check=True,
    )
    assert child.stdout == "[]\\n"


def test_gh_login_hidden(hermetic):
    _gh_login_hidden(hermetic)


def test_caught_keeps_tmp_path(tmp_path):
    (tmp_path / "kept").write_text("")
    try:
        socket.create_connection(("192.0.2.12", 443), timeout=1)
    except BaseException:
        pass


@pytest.mark.requires_network
def test_exempt_first(hermetic):
    assert hermetic.guard is None
    assert "connect" not in vars(socket.socket) and not hasattr(socket.getaddrinfo, "__wrapped__")
    assert os.environ["HOME"] == str(hermetic.home) != conftest.REAL_HOME
    assert not any(name in os.environ for name in conftest.PROXY_VARS)
    _gh_login_hidden(hermetic)


@pytest.mark.requires_network
def test_exempt_second():
    pass


def test_probed_once_per_session():
    assert conftest.PROBES == ["probe"]
"""

# Replaces the probe: never the network; the answer comes from the run's environment.
INNER_PROBE = """

PROBES = []


def _probe_online():
    PROBES.append("probe")
    return os.environ["INNER_ONLINE"] == "1"
"""


# A login for every variable conftest's (d) unsets; fake values, never a real token.
OWNER_LOGIN = dict.fromkeys(conftest.GH_LOGIN_VARS, "owner-login")


def _inner_run(folder: Path, *, online: bool) -> dict[str, tuple[str, str]]:
    """Each inner test's outcomes (``passed``, or ``failure``, ``skipped`` and ``error`` joined
    by ``+`` in report order) and their messages joined by `` | ``."""
    folder.mkdir()
    (folder / "conftest.py").write_text(Path(conftest.__file__).read_text() + INNER_PROBE)
    (folder / "test_inner.py").write_text(INNER_TESTS)
    (folder / "pytest.ini").write_text(
        "[pytest]\ntmp_path_retention_policy = failed\nmarkers =\n    requires_network: reaches the network\n"
    )
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PYTEST_", "COV_CORE_")) and name not in PROXY_VARS
    }
    env["INNER_ONLINE"] = "1" if online else "0"
    env.update(OWNER_LOGIN)  # as if exported in the owner's shell: the inner conftest must hide it
    (folder / "owner-gh").mkdir()
    (folder / "owner-gh" / "hosts.yml").write_text("github.com:\n    user: owner\n")
    env["GH_CONFIG_DIR"] = str(folder / "owner-gh")
    report = folder / "report.xml"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--basetemp", str(folder / "tmp")]
        + ["--junitxml", str(report)],
        cwd=folder,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert report.is_file(), proc.stdout + proc.stderr
    outcomes: dict[str, tuple[str, str]] = {}
    for case in ElementTree.parse(report).iter("testcase"):
        results = [child for child in case if child.tag in {"failure", "skipped", "error"}]
        tags = "+".join(child.tag for child in results) or "passed"
        outcomes[case.attrib["name"]] = (tags, " | ".join(child.attrib.get("message", "") for child in results))
    return outcomes


def test_caught_live_network_access_still_fails_the_test(tmp_path: Path) -> None:
    folder = tmp_path / "online"
    outcomes = _inner_run(folder, online=True)
    for name, address in [
        ("test_caught_by_except_exception", "192.0.2.1:443"),
        ("test_caught_by_except_base_exception", "192.0.2.2:443"),
        ("test_in_a_thread", "192.0.2.3:443"),
    ]:
        outcome, message = outcomes[name]
        assert outcome == "failure", outcomes
        assert f"live network access in a hermetic test: connect to {address}" in message
    assert outcomes["test_loopback_only"] == ("passed", ""), outcomes
    # A skip or an expected failure after the attempt does not hide it.
    for name, address in [
        ("test_caught_then_skipped", "192.0.2.4:443"),
        ("test_caught_in_an_xfail_test", "192.0.2.5:443"),
        ("test_refused_in_an_xfail_test", "192.0.2.6:443"),
        ("test_caught_in_a_strict_xfail_test", "192.0.2.7:443"),
        ("test_caught_keeps_tmp_path", "192.0.2.12:443"),
    ]:
        outcome, message = outcomes[name]
        assert outcome == "failure", outcomes
        assert f"live network access in a hermetic test: connect to {address}" in message
    # In any phase: an attempt hidden in a fixture's setup or teardown errors the test.
    for name, address in [
        ("test_caught_in_fixture_setup", "192.0.2.8:443"),
        ("test_caught_in_fixture_teardown", "192.0.2.9:443"),
    ]:
        outcome, message = outcomes[name]
        assert outcome.endswith("error"), outcomes
        assert f"connect to {address}" in message
    # A hidden attempt is named even when a later one is refused.
    outcome, message = outcomes["test_caught_then_refused"]
    assert outcome == "failure" and "192.0.2.10:443" in message and "192.0.2.11:443" in message, outcomes
    # A test's own failure that quotes a hidden attempt is still named as live network access:
    # only the guard's own refusal is left as it is, and it is named once.
    outcome, message = outcomes["test_caught_then_failed_quoting_it"]
    assert outcome == "failure" and "live network access in a hermetic test: connect to 192.0.2.13:443" in message
    outcome, message = outcomes["test_refused"]
    assert outcome == "failure" and message.count("live network access in a hermetic test") == 1, outcomes
    # The guard's own refusal followed by a hidden attempt names both.
    outcome, message = outcomes["test_refused_then_hidden_attempt"]
    assert outcome == "failure" and "192.0.2.15:443" in message and "192.0.2.16:443" in message, outcomes
    # The owner's exported login and gh config never reach a test, a session fixture or a subprocess.
    assert outcomes["test_gh_login_hidden"] == ("passed", ""), outcomes
    assert outcomes["test_session_fixtures_see_no_gh_login"] == ("passed", ""), outcomes
    # The failed test's tmp_path is kept: tmp_path_retention_policy "failed" sees the failure.
    assert list((folder / "tmp").glob("test_caught_keeps_tmp_path*/kept")), outcomes


def test_requires_network_tests_are_exempt_and_skipped_offline(tmp_path: Path) -> None:
    exempt = ("test_exempt_first", "test_exempt_second", "test_probed_once_per_session")
    online = _inner_run(tmp_path / "online", online=True)
    assert [online[name] for name in exempt] == [("passed", "")] * 3, online

    offline = _inner_run(tmp_path / "offline", online=False)
    skip = ("skipped", "the host is offline: pypi.org:443 cannot be reached")
    assert [offline[name] for name in exempt] == [skip, skip, ("passed", "")], offline
