# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The network client: standard-library ``urllib`` only (plan §2.3, R1-K9.1, N21).

- **Hosts.** HTTPS to the five outside services only: ``api.github.com``, ``api.osv.dev``,
  ``pypi.org``, ``files.pythonhosted.org`` (Guardian's pinned pip wheel, plan §3.1 step 3) and
  ``www.cisa.gov``. Any other URL, a redirect included, is refused.
- **Read only.** Every request is a GET, except one: the OSV ``querybatch`` query, a POST of
  package names to one fixed URL (plan §10.3). Nothing else is ever sent with another method,
  and GitHub and ``files.pythonhosted.org`` receive GET requests only.
- **Token.** :func:`find_token` searches ``GH_TOKEN``, then ``GITHUB_TOKEN``, then
  ``gh auth token`` (plan §2.3 execution boundary item 3). gh runs only when both variables
  are unset, only from :data:`GH_PATHS` (never through ``PATH`` or a relative path), only
  when every folder from ``/`` down, every link on the way and the file itself are owned by
  root or the user and writable by no other user (group write only for ``admin``), and only
  when the file the path resolves to is a regular file owned by root or the user and
  writable by no one else; that checked file is the one run, from ``/``, with fixed
  arguments, no shell and a short timeout. A gh that fails, times out or prints something that cannot be a token
  gives no token. The token goes only to ``api.github.com`` over HTTPS, is never sent again
  once a redirect leaves that host, and never appears on screen, in a log or in JSON:
  :class:`Token` hides it from ``str``, ``repr`` and pickling, and no error message carries
  request headers or gh's output.
- **GitHub rate limits.** At the hourly limit the client stops: :class:`RateLimitError`
  (exit 2) names the reset time, and every later GitHub request fails at once without being
  sent. A secondary limit waits the time GitHub gives, at most 60 s and at most 3 retries.
- **OSV, PyPI, CISA.** A fixed timeout per request; at most 2 retries within 60 s. A failed
  request raises :class:`FeedError` (exit 2), never an empty answer.
- **Cache.** :class:`ShaCache` keeps only content addressed by a commit: its file names come
  from a repository ID and a validated 40-hex SHA, and from nothing else.
"""

from __future__ import annotations

import base64
import grp
import json
import os
import re
import stat

# Runs only gh auth token (plan §2.3 boundary item 3); owner-approved, issue #39.
import subprocess  # nosec B404
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import Message
from http.client import HTTPException, HTTPResponse
from pathlib import Path

from ssc_guardian.findings import IncompleteCheckError, SkipReason, record_site
from ssc_guardian.grammars import Field, check

GITHUB_API = "api.github.com"
OSV_API = "api.osv.dev"
PYPI = "pypi.org"
PYPI_FILES = "files.pythonhosted.org"  # GET only: the pinned pip wheel
CISA = "www.cisa.gov"
HOSTS = frozenset({GITHUB_API, OSV_API, PYPI, PYPI_FILES, CISA})

# The one request that is not a GET: OSV's batch query takes its package list as a POST body.
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

TOKEN_VARIABLES = ("GH_TOKEN", "GITHUB_TOKEN")

# The only places gh is run from (plan §2.3 boundary item 3), in this order; never PATH.
GH_PATHS = ("/opt/homebrew/bin/gh", "/usr/local/bin/gh")
GH_ARGUMENTS = ("auth", "token", "--hostname", "github.com")
GH_TIMEOUT_SECONDS = 10.0
GH_MAX_LINKS = 32  # links followed on the way to gh (macOS follows at most 32)

TIMEOUT_SECONDS = 30.0
FEED_RETRIES = 2
FEED_RETRY_BUDGET_SECONDS = 60.0
FEED_BACKOFF_SECONDS = (1.0, 4.0)
SECONDARY_LIMIT_MAX_WAIT_SECONDS = 60.0
SECONDARY_LIMIT_DEFAULT_WAIT_SECONDS = 60.0  # GitHub: "wait at least one minute" (§8 fact 14)
SECONDARY_LIMIT_RETRIES = 3
MAX_REDIRECTS = 5

_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# A token goes into an HTTP header: printable ASCII with no space, so it cannot add a header.
_TOKEN = re.compile(r"[\x21-\x7e]{1,1024}", re.ASCII)


class FeedError(IncompleteCheckError):
    """A request to an outside service failed: the check is unfinished (exit 2), never a pass.

    The message names the service and the cause, never a header or the token.
    """

    def __init__(self, message: str, reason: SkipReason = SkipReason.FEED_FAILURE, *, site: str | None = None) -> None:
        super().__init__(reason, site=site)
        self.message = message

    def __str__(self) -> str:
        return self.message


class RateLimitError(FeedError):
    """GitHub's rate limit stopped the run (exit 2, ``rate-limit``).

    ``reset_at`` is when the hourly limit resets (None for a secondary limit, or when GitHub
    did not say).
    """

    def __init__(self, message: str, reset_at: datetime | None = None, *, site: str | None = None) -> None:
        super().__init__(message, SkipReason.RATE_LIMIT, site=site)
        self.reset_at = reset_at


class RefusedRequestError(ValueError):
    """A request Guardian never sends: a URL that is not HTTPS to a known service, or a method
    other than GET and OSV's one POST. A ValueError, so callers that catch one are unchanged."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


class TokenError(ValueError):
    """A token variable holds a value no token can have. The message names the variable only."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


class Token:
    """A GitHub token. ``str`` and ``repr`` never show it, so a log line or a message built
    from one cannot carry it; only :class:`Client` reads it, to build the header."""

    __slots__ = ("__value", "source")

    def __init__(self, value: str, source: str) -> None:
        if not _TOKEN.fullmatch(value):
            raise TokenError(f"{source} does not hold a token", site="net.does-not-hold-token")
        self.__value = value
        self.source = source

    def __repr__(self) -> str:
        return f"Token(source={self.source!r})"

    __str__ = __repr__

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("a token is never serialized")

    def _authorization(self) -> str:
        return f"Bearer {self.__value}"


# --- token search ---------------------------------------------------------------


# Runs one checked gh: (the file it resolved to) -> its standard output, or None when it failed.
GhRunner = Callable[[str], bytes | None]


def gh_is_trusted(info: os.stat_result) -> bool:
    """A regular file owned by root or the user and writable by no one else (boundary item 3)."""
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid in (0, os.getuid())
        and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _admin_gid() -> int | None:
    """The ``admin`` group's ID, or None where there is no such group (GitHub's Linux runner)."""
    try:
        return grp.getgrnam("admin").gr_gid
    except KeyError:
        return None


def _step_is_trusted(info: os.stat_result, admin: int | None) -> bool:
    """One folder, link or file on gh's path: owned by root or the user and writable by no
    other user. A symlink's own mode bits mean nothing (Linux reports 0777), so only its owner
    counts. Group write is trusted only for the ``admin`` group, whose members can already
    become root with sudo (Homebrew's folders are ``drwxrwxr-x`` owner:admin)."""
    if info.st_uid not in (0, os.getuid()):
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    if info.st_mode & stat.S_IWOTH:
        return False
    return not info.st_mode & stat.S_IWGRP or (admin is not None and info.st_gid == admin)


def _trusted_walk(path: str, lstat_path: Callable[[str], os.stat_result], admin: int | None) -> str | None:
    """The file absolute ``path`` resolves to, when every folder from ``/`` down, every link
    on the way and the file itself pass :func:`_step_is_trusted`; else None. A link's target
    is walked from ``/`` (absolute) or from the link's folder (relative), and at most
    :data:`GH_MAX_LINKS` links are followed."""
    here = "/"
    if not _step_is_trusted(lstat_path(here), admin):
        return None
    pending = [part for part in path.split("/") if part]
    links = 0
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            here = os.path.dirname(here)  # ``here`` holds no link, so its parent is real
            continue
        step = os.path.join(here, part)
        info = lstat_path(step)
        if not _step_is_trusted(info, admin):
            return None
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > GH_MAX_LINKS:
                return None
            target = os.readlink(step)
            if target.startswith("/"):
                here = "/"
            pending[:0] = [p for p in target.split("/") if p]
            continue
        if pending and not stat.S_ISDIR(info.st_mode):
            return None
        here = step
    return here


def _trusted_gh(
    paths: Sequence[str],
    gh_stat: Callable[[str], os.stat_result],
    lstat_path: Callable[[str], os.stat_result],
    admin: Callable[[], int | None],
) -> str | None:
    """The file the first trusted gh in ``paths`` resolves to, or None. A path that is not
    absolute is never used; the path is walked from ``/`` (:func:`_trusted_walk`), and the
    file it resolves to must pass :func:`gh_is_trusted` too."""
    for path in paths:
        if not os.path.isabs(path):
            continue
        try:
            resolved = _trusted_walk(path, lstat_path, admin())
            if resolved is None:
                continue
            info = gh_stat(resolved)
        except (OSError, ValueError):
            continue
        if gh_is_trusted(info):
            return resolved
    return None


def _run_gh(path: str) -> bytes | None:
    """``gh auth token`` from the checked file ``path``, run in ``/`` so no file in the current
    folder is read: its standard output when it exits 0, else None. gh inherits Guardian's
    environment; its error output is dropped unread."""
    try:
        # A fixed argument list, no shell, the checked gh only; owner-approved, issue #39.
        done = subprocess.run(  # nosec B603
            [path, *GH_ARGUMENTS],
            cwd="/",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=GH_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _gh_token(output: bytes | None) -> Token | None:
    """The token gh printed (one line), or None when its output cannot be one. Nothing here
    names the output: the :class:`TokenError` is dropped, never raised."""
    if output is None:
        return None
    try:
        return Token(output.decode("ascii").removesuffix("\n"), "gh auth token")
    except (UnicodeDecodeError, TokenError):
        return None


def find_token(
    environ: Mapping[str, str] | None = None,
    *,
    gh_paths: Sequence[str] = GH_PATHS,
    gh_stat: Callable[[str], os.stat_result] = os.stat,
    lstat_path: Callable[[str], os.stat_result] = os.lstat,
    admin_gid: Callable[[], int | None] = _admin_gid,
    run_gh: GhRunner = _run_gh,
) -> Token | None:
    """The GitHub token, or None for no login (plan §2.3).

    Order: ``GH_TOKEN``, then ``GITHUB_TOKEN``, then ``gh auth token`` (execution boundary
    item 3). An empty variable moves the search on to the next variable; a set value that
    cannot be a token raises :class:`TokenError`. gh runs only when both variables are unset
    (one that is set but empty counts as set, and gives None), at most once per search, from
    the first of ``gh_paths`` whose every folder from ``/``, every link on the way and the
    file itself are trusted (:func:`_trusted_walk`) and whose resolved file
    :func:`gh_is_trusted` passes; the resolved file is the one run, from ``/``. A gh that
    exits non-zero, times out, cannot start or prints something that cannot be a token gives
    None, never an error that names its output. gh runs in the process environment, not in
    ``environ``, which only decides whether it runs.

    ``gh_paths``, ``gh_stat``, ``lstat_path``, ``admin_gid`` and ``run_gh`` are injectable so
    tests never stat or run a real gh.
    """
    environ = os.environ if environ is None else environ
    for name in TOKEN_VARIABLES:
        value = environ.get(name)
        if value:
            return Token(value, name)
    if any(name in environ for name in TOKEN_VARIABLES):
        return None
    gh = _trusted_gh(gh_paths, gh_stat, lstat_path, admin_gid)
    return None if gh is None else _gh_token(run_gh(gh))


# --- transport ------------------------------------------------------------------


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]  # names lowercased
    body: bytes
    url: str

    def json(self) -> object:
        """The body as JSON; a body that is not raises :class:`FeedError`."""
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise FeedError(
                f"{_host(self.url)} sent a response that is not JSON", site="net.sent-response-not-json"
            ) from exc


# One HTTP exchange: (request, timeout, byte limit) -> response. It never follows a redirect;
# it raises OSError (urllib.error.URLError, TimeoutError) when no response arrives.
Transport = Callable[[urllib.request.Request, float, int], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are returned, not followed: :class:`Client` decides each one itself."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _read(response: HTTPResponse | urllib.error.HTTPError, url: str, limit: int) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise FeedError(f"{_host(url)} sent more than {limit} bytes", site="net.response-too-large")
    return bytes(body)


def urllib_transport(request: urllib.request.Request, timeout: float, limit: int) -> Response:
    """The real transport: one HTTPS exchange through ``urllib``, redirects not followed."""
    url = request.full_url
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return Response(response.status, _lowered(response.headers), _read(response, url, limit), url)
    except urllib.error.HTTPError as exc:
        with exc:
            try:
                return Response(exc.code, _lowered(exc.headers), _read(exc, url, limit), url)
            except HTTPException as broken:
                raise OSError(f"broken HTTP response ({type(broken).__name__})") from broken
    except HTTPException as exc:
        # A malformed status line or a body cut short: no response arrived.
        raise OSError(f"broken HTTP response ({type(exc).__name__})") from exc


def _lowered(headers: Message | None) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or "the service"


def _checked_url(url: str) -> urllib.parse.SplitResult:
    """Only HTTPS to one of :data:`HOSTS`, on the default port, with no user name or fragment."""
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
    except ValueError:
        raise RefusedRequestError("refused URL: it cannot be parsed", site="net.refused-url-unparsable") from None
    if (
        parts.scheme != "https"
        or hostname not in HOSTS
        or parts.netloc != hostname
        or parts.fragment
        or not url.isascii()
        or any(ch.isspace() or not ch.isprintable() for ch in url)
    ):
        raise RefusedRequestError(
            f"refused URL for {hostname or 'an unknown host'}: not HTTPS to a known service", site="net.refused-url"
        )
    return parts


# --- client -----------------------------------------------------------------------


class Client:
    """Sends Guardian's requests. One client serves one run.

    ``transport``, ``sleep``, ``monotonic`` and ``now`` are injectable so tests drive every
    path without the network or a real clock.
    """

    def __init__(
        self,
        token: Token | None = None,
        *,
        user_agent: str = "ssc-guardian",
        transport: Transport = urllib_transport,
        timeout: float = TIMEOUT_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if token is not None and not isinstance(token, Token):
            raise TypeError("a token is a Token")
        self._token = token
        self._user_agent = user_agent
        self._transport = transport
        self._timeout = timeout
        self._sleep = sleep
        self._monotonic = monotonic
        self._now = now
        self._github_stopped: RateLimitError | None = None

    def get(self, url: str, *, accept: str, limit: int, allow: frozenset[int] = frozenset()) -> Response:
        """GET ``url``. A 2xx response, or one whose status is in ``allow``, is returned; any
        other outcome raises :class:`FeedError` (or :class:`RateLimitError` for GitHub)."""
        return self._send("GET", url, None, accept, limit, allow)

    def osv_querybatch(self, payload: Mapping[str, object], *, limit: int) -> Response:
        """The one POST: OSV's batch query of package names (plan §10.3)."""
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return self._send("POST", OSV_QUERYBATCH_URL, body, "application/json", limit, frozenset())

    def _send(
        self, method: str, url: str, body: bytes | None, accept: str, limit: int, allow: frozenset[int]
    ) -> Response:
        parts = _checked_url(url)
        if method != "GET" and (method, url) != ("POST", OSV_QUERYBATCH_URL):
            raise RefusedRequestError(
                f"refused {method}: Guardian sends only GET, and one POST to OSV's batch query",
                site="net.refused-method",
            )
        if parts.hostname == GITHUB_API:
            return self._github(url, accept, limit, allow)
        return self._feed(method, url, body, accept, limit, allow)

    def _request(
        self, method: str, url: str, body: bytes | None, accept: str, with_token: bool
    ) -> urllib.request.Request:
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("User-Agent", self._user_agent)
        request.add_header("Accept", accept)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        host = urllib.parse.urlsplit(url).hostname
        if host == GITHUB_API:
            request.add_header("X-GitHub-Api-Version", "2022-11-28")
        if with_token and self._token is not None and host == GITHUB_API:
            # Unredirected: even a redirect that urllib followed on its own would not carry it.
            request.add_unredirected_header("Authorization", self._token._authorization())
        return request

    def _exchange(self, method: str, url: str, body: bytes | None, accept: str, limit: int) -> Response:
        """One request and its redirects. The token is dropped for good once a redirect
        leaves ``api.github.com``; a POST is never redirected."""
        with_token = True
        for _ in range(MAX_REDIRECTS + 1):
            response = self._transport(self._request(method, url, body, accept, with_token), self._timeout, limit)
            if response.status not in _REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            if method != "GET" or not location:
                raise FeedError(
                    f"{_host(url)} sent a redirect that is not followed", site="net.sent-redirect-not-followed"
                )
            try:
                target = urllib.parse.urljoin(url, location)
                _checked_url(target)
            except ValueError as exc:
                raise FeedError(
                    f"{_host(url)} redirected outside the known services", site="net.redirected-outside-known-services"
                ) from exc
            if _host(target) != _host(url):
                with_token = False
            url = target
        raise FeedError(f"{_host(url)} sent too many redirects", site="net.sent-too-many-redirects")

    # GitHub: no retries for failures; only the rate-limit rules below.
    def _github(self, url: str, accept: str, limit: int, allow: frozenset[int]) -> Response:
        if self._github_stopped is not None:
            raise RateLimitError(str(self._github_stopped), self._github_stopped.reset_at, site="net.github-stopped")
        retries = 0
        while True:
            try:
                response = self._exchange("GET", url, None, accept, limit)
            except OSError as exc:
                raise FeedError(
                    f"{GITHUB_API} could not be reached ({type(exc).__name__})", site="net.could-not-reached"
                ) from exc
            if response.status not in {403, 429}:
                return _accepted(response, allow)
            if response.headers.get("x-ratelimit-remaining") == "0":
                self._github_stopped = self._hourly_limit(response)
                raise self._github_stopped
            wait = _secondary_wait(response)
            if wait is None:
                return _accepted(response, allow)
            if wait > SECONDARY_LIMIT_MAX_WAIT_SECONDS:
                raise RateLimitError(
                    f"GitHub's secondary rate limit asks for a {wait:.0f} s wait, over the "
                    f"{SECONDARY_LIMIT_MAX_WAIT_SECONDS:.0f} s Guardian waits; run again later",
                    site="net.githubs-secondary-rate-limit-asks",
                )
            if retries >= SECONDARY_LIMIT_RETRIES:
                raise RateLimitError(
                    f"GitHub's secondary rate limit held after {SECONDARY_LIMIT_RETRIES} retries; run again later",
                    site="net.githubs-secondary-rate-limit-held",
                )
            self._sleep(wait)
            retries += 1

    def _hourly_limit(self, response: Response) -> RateLimitError:
        reset_at = _timestamp(response.headers.get("x-ratelimit-reset"))
        when = f"it resets at {reset_at:%Y-%m-%d %H:%M} UTC" if reset_at else "GitHub did not say when it resets"
        login = "" if self._token else "; log in with gh or set GH_TOKEN for a higher limit"
        return RateLimitError(
            f"GitHub's hourly rate limit is used up: {when}{login}", reset_at, site="net.githubs-hourly-rate-limit-used"
        )

    # OSV, PyPI, CISA: at most 2 retries within 60 s.
    def _feed(
        self, method: str, url: str, body: bytes | None, accept: str, limit: int, allow: frozenset[int]
    ) -> Response:
        deadline = self._monotonic() + FEED_RETRY_BUDGET_SECONDS
        for attempt in range(FEED_RETRIES + 1):
            wait: float | None = None
            try:
                response = self._exchange(method, url, body, accept, limit)
            except OSError as exc:
                cause = f"{_host(url)} could not be reached ({type(exc).__name__})"
            else:
                if response.status not in _RETRYABLE_STATUSES:
                    return _accepted(response, allow)
                cause = f"{_host(url)} answered HTTP {response.status}"
                wait = _retry_after(response.headers.get("retry-after"))
            if attempt == FEED_RETRIES:
                break
            wait = FEED_BACKOFF_SECONDS[attempt] if wait is None else wait
            if self._monotonic() + wait > deadline:
                raise FeedError(
                    f"{cause}; no retry fits in {FEED_RETRY_BUDGET_SECONDS:.0f} s", site="net.no-retry-fits-deadline"
                )
            self._sleep(wait)
        raise FeedError(f"{cause} after {FEED_RETRIES} retries", site="net.feed-retries-exhausted")


def _accepted(response: Response, allow: frozenset[int]) -> Response:
    if 200 <= response.status < 300 or response.status in allow:
        return response
    raise FeedError(f"{_host(response.url)} answered HTTP {response.status}", site="net.feed-answered-http-error")


def _whole_number(value: str | None) -> int | None:
    """An ASCII whole number from a header, or None (``str.isdigit`` alone accepts ``²``)."""
    text = (value or "").strip()
    return int(text) if text and text.isascii() and text.isdigit() and len(text) <= 18 else None


def _retry_after(value: str | None) -> float | None:
    """A ``Retry-After`` in whole seconds; None when absent or not a number."""
    seconds = _whole_number(value)
    return None if seconds is None else float(seconds)


def _timestamp(value: str | None) -> datetime | None:
    """A Unix time from a header as an aware datetime, or None when it is not one."""
    seconds = _whole_number(value)
    try:
        return None if seconds is None else datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _secondary_wait(response: Response) -> float | None:
    """The wait a secondary limit asks for, or None when the 403 is not a rate limit."""
    retry_after = _retry_after(response.headers.get("retry-after"))
    if retry_after is not None:
        return retry_after
    if response.status == 429 or b"secondary rate limit" in response.body.lower():
        return SECONDARY_LIMIT_DEFAULT_WAIT_SECONDS
    return None


# --- cache --------------------------------------------------------------------------


class ShaCache:
    """Content addressed by a commit, kept between runs (plan §2.3).

    A file name is made only of a repository ID (a positive integer GitHub assigns) and a
    validated 40-hex commit SHA, so no other input reaches the file system: not a tag, a
    branch, a path or a name. What one commit holds never changes, so an entry never goes
    stale; tag-to-commit answers are never cached. A file that cannot be read back exactly
    is a miss.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def _file(self, repo_id: int, sha: str) -> Path:
        if type(repo_id) is not int or not 0 < repo_id < 2**63:
            raise ValueError("a repository ID is a positive integer")
        return self._root / str(repo_id) / f"{check(Field.SHA, sha)}.json"

    def _entries(self, file: Path, repo_id: int, sha: str) -> dict[str, str]:
        try:
            # Non-blocking and a regular file only, so a FIFO in the entry's place is a miss.
            fd = os.open(file, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    return {}
                data = json.loads(handle.read().decode("ascii"))
        except (OSError, UnicodeDecodeError, ValueError):
            return {}
        if not isinstance(data, dict) or data.get("repo_id") != repo_id or data.get("sha") != sha:
            return {}
        files = data.get("files")
        if not isinstance(files, dict) or not all(isinstance(v, str) for v in files.values()):
            return {}
        return files

    def get(self, repo_id: int, sha: str, path: str) -> bytes | None:
        """The bytes stored for ``path`` at that commit, or None."""
        file = self._file(repo_id, sha)
        encoded = self._entries(file, repo_id, sha).get(path)
        if encoded is None:
            return None
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError:
            return None

    def put(self, repo_id: int, sha: str, path: str, data: bytes) -> None:
        """Store ``data`` for ``path`` at that commit; the file is replaced in one step."""
        file = self._file(repo_id, sha)
        entries = self._entries(file, repo_id, sha)
        entries[path] = base64.b64encode(data).decode("ascii")
        file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        text = json.dumps({"repo_id": repo_id, "sha": sha, "files": entries}, sort_keys=True, ensure_ascii=True)
        handle, temp = tempfile.mkstemp(dir=file.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="ascii") as out:
                out.write(text)
            os.replace(temp, file)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
