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

"""Command-line frame (plan §2.1): flat verbs, filters, ``--json`` and the ``--yes`` rules.

The frame parses and validates every argument against its field grammar,
builds the check scope from the filters, calls the verb's handler and renders
its result. A malformed argument is a malformed-name violation (exit 1). A
handler that raises gives exit 2, never Python's default exit 1, which would
read as a violation. Each verb has its handler (``check``, ``protect``,
``install``, ``pin``, ``acknowledge`` and ``override add``); an area or a
``--path`` the handler did not report is an unfinished check (exit 2), never
a pass.
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from typing import Any, NoReturn, TextIO

from ssc_guardian.commands import acknowledge, check_envs, install, override_add, pin, protect
from ssc_guardian.feeds import osv
from ssc_guardian.feeds.kev import Kev, KevStatus
from ssc_guardian.findings import (
    Ecosystem,
    ExitCode,
    FindingField,
    Installer,
    Result,
    Scope,
    Skip,
    SkipReason,
    Verb,
    incomplete_exit,
    item_field,
    malformed,
    malformed_from,
    record_site,
    version_field,
)
from ssc_guardian.grammars import Field, MalformedValueError, matches
from ssc_guardian.net import Client, FeedError
from ssc_guardian.plugin import Requirement
from ssc_guardian.render import ToolInfo, strip_controls, to_json, to_text, use_color
from ssc_guardian.version import VersionAction, git_commit

# --language values and the ecosystems each one selects (later: javascript, typescript, rust).
LANGUAGES: Mapping[str, frozenset[Ecosystem]] = {"python": frozenset({Ecosystem.PYPI})}

_VERB_ECOSYSTEM: Mapping[Verb, Ecosystem | None] = {
    Verb.PROTECT: Ecosystem.PYPI,
    Verb.INSTALL: Ecosystem.PYPI,
    Verb.PIN: Ecosystem.GITHUB_ACTIONS,
    Verb.ACKNOWLEDGE: Ecosystem.GITHUB_ACTIONS,
    Verb.OVERRIDE_ADD: None,
}


@dataclass(frozen=True)
class Request:
    """One parsed, grammar-checked command. Only the fields of ``verb`` are set.

    What ``check`` and ``protect`` act on comes only from their arguments (#255): ``check``'s
    ``scope``, and ``protect``'s ``paths`` (each ``--path``, resolved)."""

    verb: Verb
    scope: Scope | None = None
    paths: tuple[str, ...] = ()
    venv: str | None = None
    requirements: tuple[Requirement, ...] = ()
    action: str | None = None
    ref: str | None = None
    installer: Installer | None = None
    repository: str | None = None
    yes: bool = False


Handler = Callable[[Request], Result]


def not_available(request: Request) -> Result:
    """The handler for a verb that is not built yet: its area is an in-scope skip (exit 2)."""
    if request.scope is not None:
        ecosystems: Sequence[Ecosystem | None] = sorted(request.scope.ecosystems)
    else:
        ecosystems = [_VERB_ECOSYSTEM[request.verb]]
    return Result(
        request.verb,
        skipped=tuple(Skip(e, None, SkipReason.NOT_AVAILABLE, site="cli.not-available") for e in ecosystems),
    )


@dataclass(frozen=True)
class KevCatalogLookup:
    """``override add``'s KEV lookup over CISA's catalog, which needs no token: True when the
    reference is KEV-listed, False when it is not, None when that is unknown. KEV lists CVEs,
    so a reference that is not a CVE (a GHSA or PYSEC ID) is looked up in OSV and checked over
    its advisory's aliases, as the run does (§10.4). A feed error, or a withdrawn record, is
    unknown, never "not listed"."""

    client: Client | None = None

    def __call__(self, reference: str) -> bool | None:
        client = self.client or Client()
        ids = {reference}
        if not reference.startswith("CVE-"):
            url = osv.VULN_URL + urllib.parse.quote(reference, safe="")
            try:
                response = client.get(url, accept="application/json", limit=osv.RECORD_LIMIT)
                record = osv.parse_record(response.json(), reference)
            except FeedError:  # a rate limit is one too
                return None
            if record is None:
                return None
            ids.update(record.aliases)
        status = Kev(client).status(ids)
        return {KevStatus.LISTED: True, KevStatus.NOT_LISTED: False}.get(status)


DEFAULT_HANDLERS: Mapping[Verb, Handler] = {
    **{verb: not_available for verb in Verb},
    Verb.INSTALL: install.handle,
    Verb.CHECK: check_envs.handle,  # the Python environments, and the repository's workflows (check_repo)
    Verb.PROTECT: protect.handle,
    Verb.OVERRIDE_ADD: override_add.OverrideAdd(kev_lookup=KevCatalogLookup()),
    Verb.PIN: pin.handle,
    Verb.ACKNOWLEDGE: acknowledge.handle,
}


def tool_version() -> str:
    try:
        version = metadata.version("ssc-guardian")
    except metadata.PackageNotFoundError:
        return "0+unknown"
    return version if matches(Field.PEP440_VERSION, version) else "0+unknown"


# The only command lines on which --help and --version exit 0 (contracts §2).
_ALONE = (["--help"], ["-h"], ["--version"])


class UsageError(Exception):
    """A command line that names nothing to check, or is otherwise unusable (exit 2)."""

    def __init__(self, *args: object, site: str | None = None) -> None:
        super().__init__(*args)
        record_site(site)


class _Parser(argparse.ArgumentParser):
    """argparse with its help and usage text on the streams given to ``main`` (subparsers get
    them through ``add_parser``), and control characters stripped from its error messages,
    which echo argv."""

    def __init__(self, *args: Any, stdout: TextIO | None = None, stderr: TextIO | None = None, **kwargs: Any) -> None:
        # No prefix matching: "--h" must not act as "--help", and abbreviations are not part
        # of the command contract.
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
        self._stdout = stdout
        self._stderr = stderr

    def _out(self) -> TextIO | None:
        return self._stdout if self._stdout is not None else sys.stdout

    def _err(self) -> TextIO | None:
        return self._stderr if self._stderr is not None else sys.stderr

    def print_usage(self, file: Any = None) -> None:
        super().print_usage(file if file is not None else self._out())

    def print_help(self, file: Any = None) -> None:
        super().print_help(file if file is not None else self._out())

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            self._print_message(message, self._err())
        super().exit(status)

    def error(self, message: str) -> NoReturn:
        err = self._err()
        if err is not None:  # argparse would print usage to stdout instead
            self.print_usage(err)
        self.exit(int(ExitCode.INCOMPLETE), f"{self.prog}: error: {strip_controls(message)}\n")


def _language(value: str) -> str:
    """A supported ``--language`` value; any other is refused, never skipped (D11)."""
    if value not in LANGUAGES:
        raise argparse.ArgumentTypeError(
            f"unsupported language {value!r}: this version checks {', '.join(sorted(LANGUAGES))}; "
            "GitHub Actions are checked with --repo or --ecosystem github-actions"
        )
    return value


def build_parser(*, stdout: TextIO | None = None, stderr: TextIO | None = None) -> argparse.ArgumentParser:
    streams: dict[str, Any] = {"stdout": stdout, "stderr": stderr}
    parser = _Parser(
        prog="ssc-guardian",
        description="Software Supply Chain Guardian: checks Python environments and GitHub Actions.",
        **streams,
    )
    parser.add_argument(
        "--version", action=VersionAction, version=tool_version(), help="show the version and exit", **streams
    )
    verbs = parser.add_subparsers(dest="verb", required=True, metavar="command")

    output = _Parser(add_help=False)
    output.add_argument("--json", action="store_true", help="JSON output (the versioned contract)")
    confirm_flag = _Parser(add_help=False)
    confirm_flag.add_argument("--yes", action="store_true", help="confirm the shown change in advance")

    check = verbs.add_parser(
        "check", parents=[output], help="check what --path or --repo names; changes nothing", **streams
    )
    where = check.add_mutually_exclusive_group()
    where.add_argument("--envs", action="store_true", help="only the Python environments")
    where.add_argument("--repo", nargs="?", const=".", metavar="DIR", help="only one repository's workflows")
    check.add_argument("--language", action="append", type=_language, help="filter by language (python)")
    check.add_argument("--ecosystem", action="append", choices=[e.value for e in Ecosystem], help="filter by ecosystem")
    check.add_argument("--path", action="append", metavar="PATH", help="a place to check (repeatable)")

    protect = verbs.add_parser(
        "protect", parents=[output, confirm_flag], help="write the installers' cooldown under --path", **streams
    )
    protect.add_argument(
        "installer",
        nargs="?",
        choices=[i.value for i in Installer],
        help="which installer's setting to write (pip or uv); when omitted, pip, and uv where a --path covers "
        "its config",
    )
    protect.add_argument(
        "--path", action="append", required=True, metavar="PATH", help="a place to protect (repeatable, required)"
    )

    install = verbs.add_parser("install", parents=[output, confirm_flag], help="checked install into a venv", **streams)
    install.add_argument("--venv", required=True, metavar="PATH", help="the virtual environment to install into")
    install.add_argument("packages", nargs="+", metavar="package", help="NAME or NAME==VERSION")

    pin = verbs.add_parser("pin", parents=[output, confirm_flag], help="verify and pin an Action version", **streams)
    pin.add_argument("action", metavar="action", help="OWNER/REPO[/PATH]@REF")

    # The exception commands parse --yes and --json only to refuse them by name, so their help
    # does not list them: it offers only what the command accepts (contracts §2, D2; #180).
    refused = _Parser(add_help=False)
    refused.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    refused.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    acknowledge = verbs.add_parser(
        "acknowledge",
        parents=[refused],
        help="record a person's acceptance of an Action repository",
        **streams,
    )
    acknowledge.add_argument("repository", metavar="OWNER/REPO")
    override = verbs.add_parser("override", help="manage overrides", **streams)
    override_verbs = override.add_subparsers(dest="override_verb", required=True, metavar="command")
    override_verbs.add_parser("add", parents=[refused], help="write one override entry", **streams)
    return parser


def _abspath(raw: str) -> str | None:
    """``raw`` made absolute against the current directory, or None if it cannot be taken as
    written: empty (which ``abspath`` would turn into the current directory) or containing a
    ``..`` component. ``.`` components are dropped."""
    expanded = os.path.expanduser(raw)
    if not expanded or ".." in expanded.split("/"):
        return None
    # abspath keeps exactly two leading slashes (POSIX leaves "//" implementation-defined;
    # on macOS it names "/"), so collapse them to one: the same place, one spelling.
    return "/" + os.path.abspath(expanded).lstrip("/")


def _resolved(typed: str) -> str:
    """``typed`` (absolute, no ``.`` or ``..``) with its symlinks resolved as the system follows
    them, never by guessing. The longest part that resolves strictly is resolved; the parts after
    it, which do not exist yet (a new venv) or sit under a folder that cannot be searched, are
    kept as typed. ``realpath`` collapses a ``..`` in a link target as text, even when strict, so
    it can name a place the system would never open; its answer is used only if the system
    opens the typed part and the answer as the same file. Otherwise, and at a symlink the system
    cannot follow (dangling, in a loop, or in too long a chain), ``typed`` is returned unchanged."""
    head, rest = typed, list[str]()
    while True:
        try:
            base = os.path.realpath(head, strict=True)
        except (OSError, RecursionError):  # realpath recurses once per link in a chain
            if head == "/" or os.path.islink(head):
                return typed
            head, name = os.path.split(head)
            rest.insert(0, name)
            continue
        try:
            if not os.path.samestat(os.stat(head), os.stat(base)):
                return typed
        except OSError:
            return typed
        break
    # One leading slash, whatever realpath returns: "//" must never survive as a second spelling.
    return "/" + os.path.join(base, *rest).lstrip("/")


def _place(raw: str) -> tuple[str | None, str]:
    """A place argument (or None), and the form a malformed-place finding shows.

    Both the typed path, made absolute, and that path with its symlinks resolved must match
    the path grammar: the typed form so a refused name never runs, the resolved form so one
    place has one spelling and one finding ID (``/tmp/x`` is ``/private/tmp/x`` on macOS;
    D18). The finding shows the form that failed, which names the cause ("." or a symlink to
    a folder named ``odd#dir`` would not). Letter case is kept, except where a symlink is
    replaced by its target. Each argument is resolved once, and the form checked is the form used.
    """
    typed = _abspath(raw)
    if typed is None or not matches(Field.PATH, typed):
        return None, typed or raw
    resolved = _resolved(typed)
    return (resolved if matches(Field.PATH, resolved) else None), resolved


# A bare check names nothing: refused from the arguments alone, before anything is read (#255).
NOTHING_NAMED = (
    "check names nothing to check: pass --path PATH (repeatable), or --repo [DIR]; "
    "for the Python environments, check --envs --path PATH"
)


def _places(raw_places: Sequence[str], verb: Verb, ecosystem: Ecosystem | None) -> list[str] | Result:
    """Each place argument resolved once (a second read of the file system could disagree),
    or the malformed-name result for the first that fails the path grammar."""
    places: list[str] = []
    for raw in raw_places:
        place, shown = _place(raw)
        if place is None:
            return Result(verb, findings=(malformed(FindingField.PLACE, shown, ecosystem=ecosystem),))
        places.append(place)
    return places


def _ecosystems(args: argparse.Namespace) -> set[Ecosystem]:
    """The ecosystems the scope flags and filters select, from the arguments alone."""
    ecosystems = set(Ecosystem)
    if args.envs:
        ecosystems = {Ecosystem.PYPI}
    if args.repo is not None:
        ecosystems = {Ecosystem.GITHUB_ACTIONS}
    if args.ecosystem:
        ecosystems &= {Ecosystem(e) for e in args.ecosystem}
    if args.language:
        ecosystems &= set().union(*(LANGUAGES[lang] for lang in args.language))
    return ecosystems


def _nothing_left() -> UsageError:
    # Exit 0 with nothing checked would let a mistyped CI gate always pass.
    return UsageError("the scope and filters leave nothing to check", site="cli.scope-filters-leave-nothing-check")


def _check_request(args: argparse.Namespace) -> Request | Result:
    ecosystems = _ecosystems(args)
    if not args.path and args.repo is None:  # refused from the arguments, before anything is read
        raise _nothing_left() if not ecosystems else UsageError(NOTHING_NAMED, site="cli.check-names-nothing")
    raw_places = [*(args.path or ()), *([args.repo] if args.repo is not None else [])]
    places = _places(raw_places, Verb.CHECK, None)
    if isinstance(places, Result):
        return places
    count = len(args.path or ())
    paths = tuple(places[:count])
    repo = places[count] if args.repo is not None else None
    if not ecosystems:
        raise _nothing_left()
    return Request(Verb.CHECK, scope=Scope(frozenset(ecosystems), paths, repo))


def _protect_request(args: argparse.Namespace) -> Request | Result:
    """``protect [pip|uv] --path PATH...``: argparse already refused a run with no ``--path`` (exit 2),
    and the handler refuses one that reaches it without any."""
    places = _places(args.path or (), Verb.PROTECT, Ecosystem.PYPI)
    if isinstance(places, Result):
        return places
    installer = Installer(args.installer) if args.installer else None
    return Request(Verb.PROTECT, paths=tuple(dict.fromkeys(places)), installer=installer, yes=args.yes)


def _install_request(args: argparse.Namespace) -> Request | Result:
    venv, shown = _place(args.venv)
    if venv is None:
        return Result(Verb.INSTALL, findings=(malformed(FindingField.PLACE, shown, ecosystem=Ecosystem.PYPI),))
    requirements = []
    for raw in args.packages:
        name, sep, version = raw.partition("==")
        if not matches(Field.PYPI_NAME, name):
            bad = malformed(FindingField.ITEM, raw, ecosystem=Ecosystem.PYPI, place=venv)
            return Result(Verb.INSTALL, findings=(bad,))
        if sep and not matches(Field.PEP440_VERSION, version):
            bad = malformed(FindingField.VERSION, raw, ecosystem=Ecosystem.PYPI, place=venv, item=name)
            return Result(Verb.INSTALL, findings=(bad,))
        requirements.append(Requirement(Ecosystem.PYPI, name, version if sep else None))
    return Request(Verb.INSTALL, venv=venv, requirements=tuple(requirements), yes=args.yes)


def _pin_request(args: argparse.Namespace) -> Request | Result:
    action, sep, ref = args.action.rpartition("@")
    if not sep:
        action, ref = args.action, ""
    gha = Ecosystem.GITHUB_ACTIONS
    if not matches(item_field(gha), action):
        return Result(Verb.PIN, findings=(malformed(FindingField.ITEM, args.action, ecosystem=gha),))
    if sep and not matches(version_field(gha), ref):
        return Result(Verb.PIN, findings=(malformed(FindingField.VERSION, args.action, ecosystem=gha, item=action),))
    return Request(Verb.PIN, action=action, ref=ref or None, yes=args.yes)


def _request(verb: Verb, args: argparse.Namespace) -> Request | Result:
    if verb is Verb.CHECK:
        return _check_request(args)
    if verb is Verb.INSTALL:
        return _install_request(args)
    if verb is Verb.PIN:
        return _pin_request(args)
    if verb is Verb.PROTECT:
        return _protect_request(args)
    if verb is Verb.ACKNOWLEDGE:
        if not matches(Field.OWNER_REPO, args.repository):
            bad = malformed(FindingField.ITEM, args.repository, ecosystem=Ecosystem.GITHUB_ACTIONS)
            return Result(Verb.ACKNOWLEDGE, findings=(bad,))
        return Request(Verb.ACKNOWLEDGE, repository=args.repository)
    return Request(Verb.OVERRIDE_ADD)


def _with_coverage(result: Result, request: Request) -> Result:
    """Make every area the request covers that the handler did not report an unfinished check.

    For ``check`` the area is the scope's ecosystems, and each ecosystem the scope and filters
    left out is listed as out of scope (never clean). For ``install``, ``pin``, ``protect`` and
    ``acknowledge`` it is the verb's ecosystem. A handler reports an area with a ``Checked``
    entry or an in-scope skip; an out-of-scope skip does not count, so a handler cannot mark
    its own area out of scope and exit 0, and an area a person or CI asked for is never passed
    over. No setting leaves an area out (#255).

    For ``check`` and ``protect``, each ``--path`` value must be reported too, by an in-scope
    ecosystem whose ``Checked`` entry or in-scope skip has that place or one inside it; one that
    none reports (a handler that ignored it, or a value that matched nothing) is an unfinished
    check there.
    """
    if request.scope is not None:
        required: Sequence[Ecosystem] = sorted(request.scope.ecosystems)
        left_out = tuple(Skip(e, None, SkipReason.FILTERED) for e in Ecosystem if e not in request.scope.ecosystems)
        paths: Sequence[str] = tuple(dict.fromkeys(request.scope.paths))
    else:
        verb_ecosystem = _VERB_ECOSYSTEM[request.verb]
        required = [verb_ecosystem] if verb_ecosystem is not None else []
        left_out = ()
        paths = tuple(dict.fromkeys(request.paths))
    reports: list[tuple[Ecosystem | None, str | None]] = [(c.ecosystem, c.place) for c in result.checked]
    reports += [(s.ecosystem, s.place) for s in result.skipped if s.in_scope]
    reported = {ecosystem for ecosystem, _ in reports}
    unreported = tuple(
        Skip(e, None, SkipReason.CHECK_ERROR, detail="not reported", site="cli.area-not-reported")
        for e in required
        if e not in reported
    )
    places = [place for ecosystem, place in reports if ecosystem in required and place is not None]
    unreported += tuple(
        Skip(None, path, SkipReason.CHECK_ERROR, detail="not reported", site="cli.path-not-reported")
        for path in paths
        if not any(os.path.commonpath([place, path]) == path for place in places)
    )
    return Result(
        result.command,
        result.findings,
        result.checked,
        left_out + result.skipped + unreported,
        result.overrides_applied,
        result.overrides_expired,
    )


def confirm(change: str, *, verb: Verb, yes: bool, stdin: TextIO | None, stdout: TextIO | None) -> bool:
    """Show before write (plan §2.1, N23): show ``change``, then write only on a yes.

    ``--yes`` confirms in advance, except for the exception commands, which a
    person confirms at a terminal. Without a terminal there is no confirmation,
    and no stdin (``sys.stdin`` is None when fd 0 was closed) is no terminal: the
    change is still shown, so a person or script sees what ``--yes`` would do, but
    no question is asked and stdin is never read (#284). A change or prompt that
    cannot be shown (a closed or broken stream, or none: ``sys.stderr`` is None when
    fd 2 was closed) is not confirmed either, and stdin is not read: a question the
    person could not see is never a yes (contracts §3).

    ``change`` is shown line by line as the caller built it: each value from a file, a file
    name or the network must already be stripped of line breaks (``strip_controls``) before it
    goes into ``change`` (contracts §5; #147), since stripping the finished text here cannot
    tell a value's line break from the caller's own. Each line is stripped again of controls.
    """
    if yes and not verb.person_only:
        return True
    shown = "\n".join(strip_controls(line) for line in change.splitlines())
    if stdin is None or not stdin.isatty():
        _show(stdout, shown + "\n")  # shown or not, there is no confirmation without a terminal
        return False
    if not _show(stdout, shown + "\nProceed? [y/N] "):
        return False
    return stdin.readline().strip().lower() in {"y", "yes"}


def main(
    argv: Sequence[str] | None = None,
    *,
    handlers: Mapping[Verb, Handler] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Run one command and return its exit code: 0, 1 or 2 (plan §2.2)."""
    try:
        return _main(argv, handlers=handlers, stdout=stdout, stderr=stderr, environ=environ)
    finally:
        _settle_streams()


def _settle_streams() -> None:
    """Flush the process's own stdout and stderr now, inside main.

    Text left in a stream's buffer after a failed write (a broken pipe) would be flushed
    again at interpreter shutdown, fail again, and make Python exit 120 instead of the code
    main returned. A stream that cannot be flushed is pointed at the null device, the
    pattern Python's documentation gives for SIGPIPE, so the shutdown flush succeeds.
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            _flush_or_silence(stream)


def _flush_or_silence(stream: TextIO) -> None:
    try:
        stream.flush()
    except KeyboardInterrupt:
        raise
    except BaseException:
        _point_at_null_device(stream)


def _point_at_null_device(stream: TextIO) -> None:
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, stream.fileno())
        os.close(null)
    except KeyboardInterrupt:
        raise
    except BaseException:  # nothing more can be done; the exit code is already decided
        return


def _main(
    argv: Sequence[str] | None,
    *,
    handlers: Mapping[Verb, Handler] | None,
    stdout: TextIO | None,
    stderr: TextIO | None,
    environ: Mapping[str, str] | None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err: TextIO | None = stderr if stderr is not None else sys.stderr
    env = environ if environ is not None else os.environ
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        args = build_parser(stdout=out, stderr=err).parse_args(arguments)
    except SystemExit as exc:  # usage errors (2), --help and --version (0)
        code = exc.code if isinstance(exc.code, int) else int(ExitCode.INCOMPLETE)
        if code == 0 and arguments not in _ALONE:
            # "check --help" or "--version check" in a CI gate checks nothing: never a pass.
            _say(err, "ssc-guardian: --help, -h and --version exit 0 only on their own; nothing was checked.")
            return incomplete_exit(site="cli.help-not-alone")
        if code == int(ExitCode.INCOMPLETE):  # argparse's usage error: a refusal like any other
            return incomplete_exit(site="cli.argparse-usage-error")
        return code
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # for example unreadable package metadata
        _say(err, f"ssc-guardian: internal error ({type(exc).__name__}); nothing was checked or written.")
        return incomplete_exit(site="cli.parse-failed")

    verb = Verb.OVERRIDE_ADD if args.verb == "override" else Verb(args.verb)
    if verb.person_only:
        for flag, given in (("--yes", args.yes), ("--json", args.json)):
            if given:
                _say(
                    err,
                    f"ssc-guardian: {verb.value} refuses {flag}: a person confirms it at a terminal, "
                    "and its output is text only.",
                )
                return incomplete_exit(site="cli.person-only-flag")

    # Everything after parsing is inside one try: any failure, in the handler, the
    # renderer or the write, exits 2 and never Python's default 1, which reads as a violation.
    try:
        result = _run(verb, args, handlers if handlers is not None else DEFAULT_HANDLERS)
        tool = ToolInfo(tool_version(), git_commit(lambda line: _say(err, line)))
        text = to_json(result, tool) if args.json else to_text(result, tool, color=use_color(out, env))
    except UsageError as exc:
        _say(err, f"ssc-guardian: {exc}")
        return incomplete_exit(site="cli.usage-error")
    except KeyboardInterrupt:
        raise
    # Every BaseException but KeyboardInterrupt: sys.exit(0) in a handler must not read as
    # "rules met", and asyncio.CancelledError must not become Python's exit 1.
    except BaseException as exc:  # a failed command never exits 0, and never 1 by accident
        _say(err, f"ssc-guardian: internal error ({type(exc).__name__}); nothing was checked or written.")
        return incomplete_exit(site="cli.internal-error")
    try:
        _write(out, text)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # for example a closed pipe
        _say(err, f"ssc-guardian: could not write output ({type(exc).__name__}).")
        return incomplete_exit(site="cli.output-not-written")
    return int(result.exit_code)


def _run(verb: Verb, args: argparse.Namespace, handlers: Mapping[Verb, Handler]) -> Result:
    parsed = _request(verb, args)
    if isinstance(parsed, Result):
        return parsed
    try:
        result = handlers[verb](parsed)
        if not isinstance(result, Result) or result.command is not verb:
            raise TypeError("a handler returns a Result for its own verb")
    except MalformedValueError as exc:
        ecosystem = _VERB_ECOSYSTEM.get(verb)
        skip = Skip(
            ecosystem, None, SkipReason.CHECK_ERROR, detail=type(exc).__name__, site="cli.handler-malformed-value"
        )
        finding = malformed_from(exc, ecosystem=ecosystem)
        result = Result(verb, findings=(finding,) if finding is not None else (), skipped=(skip,))
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # a failed command never exits 0, and never 1 by accident
        skip = Skip(
            _VERB_ECOSYSTEM.get(verb),
            None,
            SkipReason.CHECK_ERROR,
            detail=type(exc).__name__,
            site="cli.handler-failed",
        )
        result = Result(verb, skipped=(skip,))
    return _with_coverage(result, parsed)


def _say(err: TextIO | None, message: str) -> None:
    """Write one line to stderr, control characters stripped (it can carry an exception's
    type name). A closed or broken stderr (``sys.stderr`` is None when fd 2 was closed at
    start) is ignored, so it can never turn exit 2 into Python's exit 1."""
    _show(err, strip_controls(message) + "\n")


def _show(out: TextIO | None, text: str) -> bool:
    """Write and flush ``text`` as given; False when it could not be shown. A missing stream
    (``sys.stderr`` is None when fd 2 was closed at start), a closed or a broken one is never
    an error here: the caller decides what an unseen line means. A KeyboardInterrupt still
    propagates."""
    if out is None:
        return False
    try:
        out.write(text)
        out.flush()
    except KeyboardInterrupt:
        raise
    except BaseException:  # nothing else to report to; the caller's result stands
        return False
    return True


def _write(out: TextIO, text: str) -> None:
    """Write ``text``; a stream that cannot encode a character gets an ASCII escape for it."""
    try:
        out.write(text)
    except UnicodeEncodeError:
        out.write(text.encode("ascii", "backslashreplace").decode("ascii"))
    out.flush()  # a closed pipe fails here, inside main's guard, not at interpreter shutdown
