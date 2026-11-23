# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Every test is hermetic: a temporary home and no live network (issue #7, plan §5).

For every test, autouse:

(a) ``HOME`` is a fresh folder from pytest's temporary area, empty but for (d)'s
    ``.config/gh``, so ``Path.home()`` and ``~`` never reach the real home, and
    ``XDG_CONFIG_HOME``, ``XDG_DATA_HOME``, ``XDG_CACHE_HOME`` and ``XDG_STATE_HOME`` are
    unset so their defaults fall under it. The
    folder sits beside the test's ``tmp_path``, not inside it, because tests assert exactly
    what ``tmp_path`` holds. A test that sets ``HOME`` itself, or passes its own environment
    to a subprocess, keeps its own.
(b) An in-process socket guard: a connection or datagram to anything but loopback
    (127.0.0.0/8, ``::1``, the name ``localhost``) or a Unix socket, and a name lookup for any
    other host, fails the test with a message naming the address. The attempt raises at
    once, and it still fails the test when the code under test catches that exception. The
    guard covers the test and its function-scoped fixtures; a module- or session-scoped
    fixture is set up before it and gets only (c), (d) and a temporary home shared by the
    session.
    Looking up this host's own name (``socket.getfqdn()``, ``email.utils.make_msgid()``, a
    server bound to ``""``) is refused too: it can ask DNS or mDNS. A test that skips, or is
    marked xfail, still fails on an attempt it hid.
(c) For subprocesses, ``HTTP_PROXY``, ``HTTPS_PROXY`` and ``ALL_PROXY`` (and their lowercase
    forms) point at a closed loopback port, 127.0.0.1:9, and ``NO_PROXY`` is
    ``localhost,127.0.0.1,::1,[::1]``, so
    a child's HTTP client reaches loopback directly and nothing else. In process, a
    connection to that port is reported as live network access.
(d) No test, and no subprocess it starts, sees the owner's GitHub login: ``GH_TOKEN``,
    ``GITHUB_TOKEN``, ``GH_ENTERPRISE_TOKEN``, ``GITHUB_ENTERPRISE_TOKEN`` and ``GH_HOST`` are
    unset, and ``GH_CONFIG_DIR`` is an empty folder under the temporary home. With (a), which
    also hides gh's keychain login on macOS, a real ``gh auth token`` finds no login.

A test marked ``requires_network`` is exempt from (b) and (c) and keeps (a) and (d). It is
skipped when the host is offline, which one probe per test process decides (a short-timeout
direct connection to pypi.org:443; under xdist, one per worker). With
``SSC_GUARDIAN_REQUIRE_NETWORK=1`` (CI sets it, plan §10.4) an offline host fails the test
instead: the real-install tests never pass by skipping. The variable is read once, here, and
removed from the environment, so no test or subprocess inherits it; xdist workers get it from
the controller.

``fixture_server`` serves a fresh folder over HTTP on 127.0.0.1, on an ephemeral port, and
shuts down at teardown.
"""

from __future__ import annotations

import contextlib
import functools
import ipaddress
import os
import socket
import threading
import urllib.parse
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

# Read before any fixture changes HOME: the home every test must stay out of.
REAL_HOME = os.path.expanduser("~")

XDG_HOMES = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME")
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
NO_PROXY_VARS = ("NO_PROXY", "no_proxy")
# "[::1]" too: urllib compares a URL's host with its brackets, so "::1" alone misses http://[::1]/.
NO_PROXY = "localhost,127.0.0.1,::1,[::1]"
# The discard port: closed on any host that runs no discard service, and outside every
# ephemeral range, so no fixture server bound to port 0 can take it. (A port bound but not
# listening is no sink: macOS drops the connection silently and the client waits it out.)
CLOSED_PORT = 9
PROXY = f"http://127.0.0.1:{CLOSED_PORT}"
# The host's own proxy settings, restored for a requires_network test.
ORIGINAL_PROXIES = {name: os.environ[name] for name in (*PROXY_VARS, *NO_PROXY_VARS) if name in os.environ}

# (d): the variables gh and net.find_token read a login or its host from.
GH_LOGIN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST")
GH_CONFIG = ".config/gh"  # GH_CONFIG_DIR, under the temporary home: gh's default place, empty

ONLINE_PROBE = ("pypi.org", 443)
ONLINE_PROBE_TIMEOUT = 3.0
# Read once and removed, so the inner pytest runs that test this file start without it.
REQUIRE_NETWORK = os.environ.pop("SSC_GUARDIAN_REQUIRE_NETWORK", "") == "1"
_WORKER_REQUIRE_NETWORK = "ssc_guardian_require_network"

REQUIRES_NETWORK = "requires_network"


# --- (b) the socket guard ----------------------------------------------------


@dataclass
class Guard:
    """The live-network attempts made during one test."""

    blocked: list[str] = field(default_factory=list)
    # The exception each refusal raised, so a report can tell the guard's own from a test's.
    raised: list[BaseException] = field(default_factory=list)

    def take(self) -> list[str]:
        """The attempts so far, which are then forgotten (a guard test checks and clears them)."""
        taken, self.blocked[:], self.raised[:] = list(self.blocked), [], []
        return taken

    def refuse(self, what: str) -> None:
        self.blocked.append(what)
        refusal = pytest.fail.Exception(_message([what]), pytrace=False)
        self.raised.append(refusal)
        raise refusal

    def is_own_refusal(self, call: pytest.CallInfo[None]) -> bool:
        """Whether ``call`` ended with the guard's one refusal, which names the only attempt."""
        return call.excinfo is not None and len(self.raised) == 1 and call.excinfo.value is self.raised[0]


_PREFIX = "live network access in a hermetic test: "


def _message(blocked: list[str]) -> str:
    return (
        _PREFIX
        + "; ".join(blocked)
        + f". Tests reach only loopback; a test that must reach the network is marked {REQUIRES_NETWORK}."
    )


def _is_loopback_name(host: str) -> bool:
    return host.lower().rstrip(".") == "localhost"


def _loopback_address(host: str) -> bool | None:
    """Whether numeric ``host`` is a loopback address; None when ``host`` is not numeric."""
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def _host(value: object) -> str:
    return value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)


def _refusal(family: int, address: Any) -> str | None:
    """What a connection or datagram to ``address`` would reach that is not allowed, or None."""
    if family == getattr(socket, "AF_UNIX", None):
        return None
    if family not in (socket.AF_INET, socket.AF_INET6):
        return f"a socket of family {family} to {address!r}"
    host, port = _host(address[0]), address[1]
    shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    loopback = _loopback_address(host)
    if loopback is None:  # a name, resolved by the system without socket.getaddrinfo
        loopback = _is_loopback_name(host)
    if not loopback:
        return shown
    if port == CLOSED_PORT:
        return f"{shown}, the closed proxy port: a request for a host other than loopback went through *_PROXY"
    return None


def _lookup_refusal(host: object, *, reverse: bool = False) -> str | None:
    """A lookup that would ask DNS about a host other than loopback, or None.

    A forward lookup of a numeric address asks nothing (its connection is checked); a
    reverse lookup asks DNS about any address but a loopback one.
    """
    if host is None:
        return None
    name = _host(host)
    loopback = _loopback_address(name)
    if loopback or _is_loopback_name(name) or (loopback is not None and not reverse):
        return None
    return f"a {'reverse ' if reverse else ''}name lookup for {name}"


def _install_guard(monkeypatch: pytest.MonkeyPatch, guard: Guard) -> None:
    connect, connect_ex, sendto = socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto
    sendmsg = socket.socket.sendmsg
    getnameinfo = socket.getnameinfo

    def guarded_connect(self: socket.socket, address: Any) -> None:
        if (refused := _refusal(self.family, address)) is not None:
            guard.refuse(f"connect to {refused}")
        return connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        if (refused := _refusal(self.family, address)) is not None:
            guard.refuse(f"connect to {refused}")
        return connect_ex(self, address)

    def guarded_sendto(self: socket.socket, data: Any, *args: Any) -> int:
        address = args[-1]  # sendto(data, address) or sendto(data, flags, address)
        if (refused := _refusal(self.family, address)) is not None:
            guard.refuse(f"datagram to {refused}")
        return sendto(self, data, *args)

    def guarded_sendmsg(self: socket.socket, buffers: Any, *args: Any) -> int:
        address = args[2] if len(args) >= 3 else None  # sendmsg(buffers, ancdata, flags, address)
        if address is not None and (refused := _refusal(self.family, address)) is not None:
            guard.refuse(f"datagram to {refused}")
        return sendmsg(self, buffers, *args)

    def guarded_getnameinfo(sockaddr: Any, flags: int) -> Any:
        if (refused := _lookup_refusal(sockaddr[0], reverse=True)) is not None:
            guard.refuse(refused)
        return getnameinfo(sockaddr, flags)

    def guarded_lookup(lookup: Callable[..., Any], *, reverse: bool = False) -> Callable[..., Any]:
        @functools.wraps(lookup)
        def guarded(host: object, *args: Any, **kwargs: Any) -> Any:
            if (refused := _lookup_refusal(host, reverse=reverse)) is not None:
                guard.refuse(refused)
            return lookup(host, *args, **kwargs)

        return guarded

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    monkeypatch.setattr(socket.socket, "sendmsg", guarded_sendmsg)
    monkeypatch.setattr(socket, "getnameinfo", guarded_getnameinfo)
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, guarded_lookup(getattr(socket, name)))
    monkeypatch.setattr(socket, "gethostbyaddr", guarded_lookup(socket.gethostbyaddr, reverse=True))


_GUARD = pytest.StashKey[Guard]()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Fail a test whose live-network attempt was caught and hidden, in any phase.

    A conftest wrapper sits outside the skipping plugin's, so it sees the report after xfail
    and skip are applied (an attempt hidden by a test that then skips, or by an xfail test,
    still fails it), and inside tmpdir's ``tryfirst`` one, so ``tmp_path`` retention sees the
    failure and keeps the folder.
    """
    report = yield
    guard = item.stash.get(_GUARD, None)
    if guard is None or not guard.blocked:
        return report
    own = report.failed and guard.is_own_refusal(call)
    message = _message(guard.take())
    if own:
        return report  # the guard's own refusal, which names the one attempt already
    report.longrepr = f"{message}\n\n{report.longrepr}" if report.failed else message
    report.outcome = "failed"
    if hasattr(report, "wasxfail"):
        del report.wasxfail
    return report


# --- the online probe for requires_network -----------------------------------

_online: bool | None = None


def _probe_online() -> bool:
    try:
        with socket.create_connection(ONLINE_PROBE, timeout=ONLINE_PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def host_is_online() -> bool:
    """Whether the host reaches the network: probed once per session, then cached."""
    global _online
    if _online is None:
        _online = _probe_online()
    return _online


def require_online() -> None:
    """For a ``requires_network`` test: nothing when the host is online; otherwise a skip, or
    a failure when ``SSC_GUARDIAN_REQUIRE_NETWORK=1``."""
    if host_is_online():
        return
    offline = f"the host is offline: {ONLINE_PROBE[0]}:{ONLINE_PROBE[1]} cannot be reached"
    if REQUIRE_NETWORK:
        pytest.fail(f"{offline}, and SSC_GUARDIAN_REQUIRE_NETWORK=1 forbids skipping", pytrace=False)
    pytest.skip(offline)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    """xdist's controller: a worker starts after this file removed the variable, so it is sent."""
    node.workerinput[_WORKER_REQUIRE_NETWORK] = REQUIRE_NETWORK


def pytest_configure(config: pytest.Config) -> None:
    """An xdist worker takes the controller's ``SSC_GUARDIAN_REQUIRE_NETWORK``."""
    global REQUIRE_NETWORK
    workerinput = getattr(config, "workerinput", None)
    if workerinput is not None:
        REQUIRE_NETWORK = bool(workerinput.get(_WORKER_REQUIRE_NETWORK, REQUIRE_NETWORK))


# --- the autouse fixtures ----------------------------------------------------


@dataclass(frozen=True)
class Hermetic:
    """What the autouse fixture set up for one test."""

    home: Path
    guard: Guard | None  # None for a requires_network test


def _without_gh_login(patch: pytest.MonkeyPatch, home: Path) -> None:
    """(d) for ``home``."""
    for name in GH_LOGIN_VARS:
        patch.delenv(name, raising=False)
    config = home / GH_CONFIG
    config.mkdir(parents=True)
    patch.setenv("GH_CONFIG_DIR", str(config))


@pytest.fixture(scope="session", autouse=True)
def _session_hermetic(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """(a), (c) and (d) for the fixtures shared across tests, set up before any per-test fixture."""
    with pytest.MonkeyPatch.context() as patch:
        home = tmp_path_factory.mktemp("session-home")
        patch.setenv("HOME", str(home))
        _without_gh_login(patch, home)
        for name in XDG_HOMES:
            patch.delenv(name, raising=False)
        for name in PROXY_VARS:
            patch.setenv(name, PROXY)
        for name in NO_PROXY_VARS:
            patch.setenv(name, NO_PROXY)
        yield


@pytest.fixture(autouse=True)
def hermetic(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    _session_hermetic: None,
) -> Iterator[Hermetic]:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    _without_gh_login(monkeypatch, home)
    if request.node.get_closest_marker(REQUIRES_NETWORK) is not None:
        require_online()
        for name in (*PROXY_VARS, *NO_PROXY_VARS):  # the host's own settings, as before the session
            if name in ORIGINAL_PROXIES:
                monkeypatch.setenv(name, ORIGINAL_PROXIES[name])
            else:
                monkeypatch.delenv(name, raising=False)
        yield Hermetic(home, None)
        return
    guard = Guard()
    request.node.stash[_GUARD] = guard
    _install_guard(monkeypatch, guard)
    yield Hermetic(home, guard)


# --- the fixture HTTP server -------------------------------------------------


@dataclass(frozen=True)
class FixtureServer:
    """A folder served over HTTP on 127.0.0.1."""

    root: Path
    url: str  # http://127.0.0.1:<port>, no trailing slash

    def url_for(self, name: str) -> str:
        return f"{self.url}/{urllib.parse.quote(name)}"


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return


@contextlib.contextmanager
def serve_folder(root: Path) -> Iterator[FixtureServer]:
    """Serve ``root`` (GET and HEAD) on 127.0.0.1 on an ephemeral port until the block ends."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(_QuietHandler, directory=str(root)))
    thread = threading.Thread(target=server.serve_forever, name="fixture-server", daemon=True)
    thread.start()
    try:
        yield FixtureServer(root, f"http://127.0.0.1:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.fixture
def fixture_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FixtureServer]:
    """A fresh, empty folder served on 127.0.0.1; put the files a test needs in ``root``."""
    with serve_folder(tmp_path_factory.mktemp("served")) as server:
        yield server
