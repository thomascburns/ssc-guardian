# Copyright 2026 Thomas C. Burns
# SPDX-License-Identifier: Apache-2.0
"""Every refusal has a negative test; the reference case and the bypass lists fail (issues #11, #117, #131, #164).

A refusal is a rule of level violation, an in-scope skip reason, a call of one of :data:`REFUSALS`
(with every subclass, at any depth), a refusal built by hand (:data:`HAND_BUILT`, issue #131):
a ``Skip(...)`` whose reason is in scope, or not spelt as a ``SkipReason`` member, and the exit 2 a
command sets itself, ``return incomplete_exit(site=...)`` in place of ``return
int(ExitCode.INCOMPLETE)``, and a call that builds a violation finding (:data:`FINDING_BUILDERS`,
issue #164): one whose rule is a violation, or is chosen by a variable. Each such call in
``src/ssc_guardian`` passes ``site="<module>.<slug>"``,
a string literal unique across the source, and the refusal records it when it is built
(``findings.record_site``). A negative test names the site it targets with
``refuses("<site>")`` (``tests/refusal_sites.py``), which fails unless that site's refusal fired
inside the block and reached the test (issue #148); the test still asserts the outcome. This file
reads both lists by AST and compares them:

- a refusal call with no ``site=``, one that is not a string literal, a bare ``raise`` of a refusal
  class, a ``return int(ExitCode.INCOMPLETE)`` outside ``incomplete_exit`` (:data:`EXIT_HELPER`),
  and a duplicate ID fail. The two calls that pass on a site built elsewhere are named in
  :data:`FORWARDS`, by module, function and argument, never by line, and the one function that
  builds a finding only as a lookup key, which never reaches a result, in :data:`NOT_RESULTS`;
- a site that no ``refuses("...")`` literal names fails, unless ``refusal_baseline.txt`` or
  ``refusal_exemptions.txt`` holds it; an entry there that no longer exists, or that a test now
  names, fails, and both files are sorted;
- a ``refuses`` call whose argument is not a literal, or that names no site in the source, fails;
- a ``refuses`` block inside something that would swallow its "did not fire" AssertionError fails:
  a ``.check(...)`` context (``Collector.check``), a ``try`` or ``try``/``except*`` whose handler is
  bare or names ``Exception``, ``BaseException`` or ``AssertionError`` (alone or in a tuple), and a
  ``pytest.raises`` or ``suppress`` of one of those. The block goes outside it. A ``with`` on a
  plain variable (a parametrize column of ``refuses`` objects) counts as a ``refuses`` block, and a
  planted ``inline.`` ID does not. The guard reads one function's own statements: a catch-all
  bound to a variable first, or a helper holding the block that is called inside one, is not seen;
- a catch of any type inside a ``refuses`` block fails (issue #234): a ``try`` with an ``except``
  clause, or a ``suppress(...)`` entered inside the block, would stop the refusal in a test frame,
  which ``refuses`` reads as reaching the test. ``pytest.raises`` asserts the raise and is allowed.
  A refusal a test helper catches is not seen here.

The baseline holds the sites no test names yet. It was rebuilt once, as IDs, when the site IDs
replaced the text keys (issue #117); it may only shrink, and it is empty before the M2 audit
runs (owner's ruling, 2026-11-07). An exemption is ``id: reason``, for a site normal input cannot
reach; each needs the owner's approval. Rules, in-scope skip reasons and the forms of
``yaml_subset._RefusalError`` count where a test asserts them (:func:`asserted`, issue #148). A rule
built at several places has a site at each, so each place needs its own test that reaches it; a
count of the tests that assert the rule is not that proof (issue #164). A test that may
not run (skip, skipif, xfail, ``pytest.skip``) names nothing and asserts nothing. Planted IDs in
tests start with ``inline.``, and are not counted. The scan reads the source and writes nothing;
a file it cannot parse fails it.

No live network: GitHub is the in-process fixture from ``test_nested_and_advisories``, and the
feeds are the local server of ``test_check_envs``.
"""

from __future__ import annotations

import ast
import io
import json
import os
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from ssc_guardian.cli import main
from ssc_guardian.commands import install
from ssc_guardian.commands.check_envs import CheckEnvs
from ssc_guardian.findings import Level, Rule, SkipReason, Verb
from ssc_guardian.net import Client
from tests.integration import test_check_envs as envs
from tests.integration.test_pin_command import GENUINE, MALICIOUS, REVIEWDOG
from tests.refusal_sites import refuses
from tests.unit.test_nested_and_advisories import TODAY, GitHub, listed, make_repo, sha

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "ssc_guardian"
TESTS = ROOT / "tests"
BASELINE = Path(__file__).with_name("refusal_baseline.txt")
EXEMPTIONS = Path(__file__).with_name("refusal_exemptions.txt")
FIXTURES = TESTS / "fixtures" / "actions"
YAML_SUBSET = SOURCE / "yaml_subset.py"
HELPER = TESTS / "refusal_sites.py"

# The modelled outer Action of the reference case, and the reusable workflow's file.
CHANGED_FILES = "tj-actions/changed-files"
OUTER_COMMIT = sha(45)
SHARED_FILE = ".github/workflows/w.yml"

# The baseline's length, exact: lower it with each site a test comes to name, and never raise it.
BASELINE_SIZE = 0
# A test's planted site, which the check leaves out.
PLANTED = "inline."
# A site ID: the module's last name, a dot, and a lowercase slug.
SITE_ID = re.compile(r"[a-z0-9_]+\.[a-z0-9]+(?:-[a-z0-9]+)*")
# Forms a variable holds. These counts pin the source's shape today: the calls that name a form by
# variable (_check_indicators' table and two choices), the bindings of ``form``, and the values
# they give it (three rows, two sides of each choice). A change to any of them fails its test, so
# a person looks at _form_values. It pins a shape and proves nothing more: an alias or a subclass
# of _RefusalError is not followed.
VARIABLE_FORM_CALLS = 3
FORM_BINDINGS = 3
FORM_VALUES = 7

# Every class below is a refusal with its subclasses, found by name in the source. _StopError is
# one name in three commands: override add's inherits from Exception, and ends its command the
# same way as the other two, so it counts as well. _refuse is the function that builds the
# Actions models' refusals; _RefusalError is a YAML refusal before parse() names its file.
REFUSALS = frozenset(
    {
        "IncompleteCheckError",
        "MalformedValueError",
        "UsageError",
        "RefusedError",
        "RefusedRequestError",
        "DirectUrlError",
        "LocalInstallRefusedError",
        "TokenError",
        "MalformedEntryError",
        "_RefusalError",
        "_refuse",
    }
)
# The only refusal calls whose site is not a literal: each passes on a site that was recorded
# where it was built (a _RefusalError, a _refuse call), with recorded=True so it is not recorded
# twice. (module, function, the site argument as written.)
FORWARDS = frozenset(
    {
        ("yaml_subset", "parse", "r.site"),
        ("plugins.actions.models", "_refuse", "site"),
        ("findings", "make_finding", "site"),
        ("plugins.actions.nested", "_limit", "site"),
    }
)
# The calls that build a finding (issue #164): a violation, or a rule chosen by a variable, is a
# refusal and names its site. Each (module, function) of FINDING_HELPERS is a helper of one module
# whose callers name the site, and which passes it on (its call in FORWARDS).
FINDING_BUILDERS = frozenset({"make_finding", "Finding"})
FINDING_HELPERS = frozenset({("plugins.actions.nested", "_limit")})
VIOLATIONS = frozenset(rule.name for rule in Rule if rule.level is Level.VIOLATION)
# Where a finding is built only as a lookup key for overrides.release, never listed in a result, so
# no test can see it reach one (owner's ruling, 2026-11-11). (module, function.)
NOT_RESULTS = frozenset({("commands.check_repo", "_release_at")})
# Refusals built by hand (issue #131): a Skip whose reason is in scope, or one whose reason the
# scan cannot read as a SkipReason member (fail-closed), and incomplete_exit, which sets exit 2
# outside a Result. A Skip whose reason is spelt as an out-of-scope member is no refusal.
HAND_BUILT = frozenset({"Skip", "incomplete_exit"})
OUT_OF_SCOPE = frozenset(reason.name for reason in SkipReason if not reason.in_scope)
# The one place that may spell the hand-set exit 2 itself: incomplete_exit, which records a site.
# (module, function.) The argparse parser's own exit is not this form (a ``self.exit(...)`` call):
# cli.main returns the usage error it ends in through incomplete_exit (cli.argparse-usage-error, #148).
EXIT_HELPER = ("findings", "incomplete_exit")


# --- the scanner ------------------------------------------------------------------------


@dataclass(frozen=True)
class Site:
    """One refusal call in the source. ``site`` is its ID, or None with ``problem`` saying why."""

    module: str
    function: str
    name: str
    line: int
    site: str | None
    problem: str | None = None

    @property
    def where(self) -> str:
        return f"{self.module}:{self.line} {self.name}"


def _name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    return node.attr if isinstance(node, ast.Attribute) else None


def _refusal_names(trees: Iterable[ast.Module]) -> frozenset[str]:
    """:data:`REFUSALS`, :data:`HAND_BUILT` and every class that inherits from one, at any depth."""
    bases: dict[str, set[str | None]] = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases.setdefault(node.name, set()).update(_name(base) for base in node.bases)
    names = set(REFUSALS | HAND_BUILT)
    while grown := {name for name, parents in bases.items() if name not in names and parents & names}:
        names |= grown
    return frozenset(names)


def _nodes(tree: ast.AST, function: str = "") -> Iterable[tuple[ast.AST, str]]:
    """Every node under ``tree`` with the name of the innermost function that holds it."""
    for child in ast.iter_child_nodes(tree):
        inner = child.name if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) else function
        yield child, inner
        yield from _nodes(child, inner)


def _is_hand_set_exit(node: ast.Return) -> bool:
    """``return int(ExitCode.INCOMPLETE)``: exit 2 set by hand, outside a Result."""
    value = node.value
    if not (isinstance(value, ast.Call) and _name(value.func) == "int" and len(value.args) == 1):
        return False
    (code,) = value.args
    return isinstance(code, ast.Attribute) and code.attr == "INCOMPLETE" and _name(code.value) == "ExitCode"


def _out_of_scope_skip(node: ast.Call) -> bool:
    """A ``Skip`` whose reason is spelt ``SkipReason.<member>`` with an out-of-scope member."""
    given = node.args[2:3] or [keyword.value for keyword in node.keywords if keyword.arg == "reason"]
    reason = given[0] if given else None
    return isinstance(reason, ast.Attribute) and _name(reason.value) == "SkipReason" and reason.attr in OUT_OF_SCOPE


def _builds_finding(module: str, function: str, node: ast.Call) -> bool:
    """A call that builds a violation finding, or one whose rule a variable chooses (issue #164)."""
    name = _name(node.func)
    if name not in FINDING_BUILDERS and (module, name) not in FINDING_HELPERS:
        return False
    if (module, function) in NOT_RESULTS:
        return False
    given = node.args[:1] or [keyword.value for keyword in node.keywords if keyword.arg == "rule"]
    rule = given[0] if given else None
    spelt = isinstance(rule, ast.Attribute) and _name(rule.value) == "Rule"
    return not spelt or (isinstance(rule, ast.Attribute) and rule.attr in VIOLATIONS)


def _site(module: str, function: str, node: ast.AST, names: frozenset[str]) -> Site | None:
    if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Name | ast.Attribute) and _name(node.exc) in names:
        return Site(module, function, str(_name(node.exc)), node.lineno, None, "a bare raise names no site")
    if isinstance(node, ast.Return) and _is_hand_set_exit(node) and (module, function) != EXIT_HELPER:
        return Site(module, function, "exit 2", node.lineno, None, "a hand-set exit 2 names no site")
    if not isinstance(node, ast.Call):
        return None
    if not (_name(node.func) in names or _builds_finding(module, function, node)):
        return None
    if _name(node.func) == "Skip" and _out_of_scope_skip(node):
        return None
    name, line = str(_name(node.func)), node.lineno
    given = [keyword.value for keyword in node.keywords if keyword.arg == "site"]
    if any(keyword.arg is None for keyword in node.keywords):
        return Site(module, function, name, line, None, "**keywords can hide the site")
    if not given:
        return Site(module, function, name, line, None, "no site=")
    (value,) = given
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        if not SITE_ID.fullmatch(value.value):
            return Site(module, function, name, line, None, f"site {value.value!r} is not module.slug")
        return Site(module, function, name, line, value.value)
    if (module, function, ast.unparse(value)) in FORWARDS:
        return None  # passes on a site recorded where it was built
    return Site(module, function, name, line, None, "site is not a string literal")


def scan(sources: Mapping[str, str]) -> list[Site]:
    """Every refusal call in ``sources`` (module name to text), in module order."""
    trees = {module: ast.parse(text) for module, text in sources.items()}
    names = _refusal_names(trees.values())
    return [
        site
        for module, tree in sorted(trees.items())
        for node, function in _nodes(tree)
        if (site := _site(module, function, node, names)) is not None
    ]


def problems(sites: Sequence[Site]) -> list[str]:
    """A refusal call with no usable site, and each ID used twice."""
    found = [f"{s.where}: {s.problem}" for s in sites if s.problem is not None]
    counts = Counter(s.site for s in sites if s.site is not None)
    return found + [f"{site} is used {n} times" for site, n in sorted(counts.items()) if n > 1]


# A test that may not run proves nothing: one marked skip, skipif or xfail (itself, its class or
# its module's ``pytestmark``), or one whose body can call pytest.skip, pytest.xfail or
# pytest.importorskip (#148). A requires_network test runs on CI, which forbids skipping it. Not
# seen: a skip reached through a helper or fixture, a ``pytest.param(..., marks=...)`` skip, and a
# module-level importorskip; nothing in the suite uses them around a refusal or an assert today.
_SKIP_MARKS = frozenset({"skip", "skipif", "xfail"})
_SKIP_CALLS = frozenset({"skip", "xfail", "importorskip"})


def _marks(decorators: Iterable[ast.expr]) -> set[str]:
    """The pytest mark names in ``decorators`` (``pytest.mark.skip`` and ``pytest.mark.skip(...)``)."""
    found = set()
    for node in decorators:
        node = node.func if isinstance(node, ast.Call) else node
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) and node.value.attr == "mark":
            found.add(node.attr)
    return found


def _module_marks(tree: ast.Module) -> set[str]:
    """The marks a module's ``pytestmark`` applies to every test in it."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(_name(t) == "pytestmark" for t in node.targets):
            value = node.value
            return _marks(value.elts if isinstance(value, ast.List | ast.Tuple) else [value])
    return set()


def _may_skip(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> bool:
    if _marks(node.decorator_list) & _SKIP_MARKS:
        return True
    if isinstance(node, ast.ClassDef):
        return False
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in _SKIP_CALLS
        and _name(call.func.value) == "pytest"
        for call in ast.walk(node)
    )


def _counted_nodes(tree: ast.Module) -> Iterable[ast.AST]:
    """Every node of a test file outside a test that may not run (decorators included)."""
    if _module_marks(tree) & _SKIP_MARKS:
        return
    pending: list[ast.AST] = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and _may_skip(node):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def named_sites(files: Mapping[str, str]) -> tuple[set[str], list[str]]:
    """The IDs that ``refuses("...")`` calls name in ``files`` (path to text), planted IDs and
    tests that may not run left out, and each ``refuses`` call whose argument is not one string
    literal."""
    named: set[str] = set()
    bad: list[str] = []
    for path, text in sorted(files.items()):
        for node in _counted_nodes(ast.parse(text)):
            if not (isinstance(node, ast.Call) and _name(node.func) == "refuses"):
                continue
            argument = node.args[0] if len(node.args) == 1 and not node.keywords else None
            if not (isinstance(argument, ast.Constant) and isinstance(argument.value, str)):
                bad.append(f"{path}:{node.lineno}")
            elif not argument.value.startswith(PLANTED):
                named.add(argument.value)
    return named, bad


# The exceptions whose handler also catches refuses' AssertionError.
_SWALLOWS = frozenset({"Exception", "BaseException", "AssertionError"})


def _swallows(node: ast.expr | None) -> bool:
    """An except clause's type, or a raises/suppress argument, that catches an AssertionError."""
    if node is None:
        return True  # a bare except
    return any(_name(e) in _SWALLOWS for e in (node.elts if isinstance(node, ast.Tuple) else [node]))


def _catches_everything(node: ast.AST) -> bool:
    """A context that turns refuses' failure into a result: ``x.check(...)``, a broad ``try``, or a
    ``pytest.raises`` or ``suppress`` of a broad type."""
    if isinstance(node, ast.Try | ast.TryStar):
        return any(_swallows(h.type) for h in node.handlers)
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Attribute) and node.func.attr == "check":
        return True
    arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
    return _name(node.func) in {"raises", "suppress"} and any(_swallows(a) for a in arguments)


def _is_refuses_item(item: ast.withitem) -> bool:
    expr = item.context_expr
    if isinstance(expr, ast.Name):
        return True
    if not (isinstance(expr, ast.Call) and _name(expr.func) == "refuses"):
        return False
    planted = expr.args and isinstance(expr.args[0], ast.Constant) and str(expr.args[0].value).startswith(PLANTED)
    return not planted


def swallowed(files: Mapping[str, str]) -> list[str]:
    """Each ``refuses`` block that sits inside a context catching every exception, as path:line."""
    found: list[str] = []

    def visit(path: str, node: ast.AST, catching: bool) -> None:
        if isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:  # a later item runs inside an earlier one
                if _is_refuses_item(item) and catching:
                    found.append(f"{path}:{node.lineno}")
                catching = catching or _catches_everything(item.context_expr)
            body: Iterable[ast.AST] = node.body
        elif isinstance(node, ast.Try | ast.TryStar) and _catches_everything(node):
            for part in (*node.handlers, *node.orelse, *node.finalbody):
                visit(path, part, catching)
            body, catching = node.body, True
        else:
            body = ast.iter_child_nodes(node)
        for child in body:
            visit(path, child, catching)

    for path, text in sorted(files.items()):
        visit(path, ast.parse(text), False)
    return found


def caught_in_block(files: Mapping[str, str]) -> list[str]:
    """Each catch inside a ``refuses`` block, as path:line: a ``try`` or ``try``/``except*`` with an
    ``except`` clause of any type, or a ``suppress(...)`` entered after the ``refuses`` item. A
    refusal such a catch stops ends in a test frame, which ``refuses`` reads as reaching the test,
    though nothing asserted it (#234, L4-12). ``pytest.raises`` asserts the raise, so it is not one.
    Everything under the block is read, nested functions too."""
    found: list[str] = []

    def visit(path: str, node: ast.AST, inside: bool) -> None:
        if inside and isinstance(node, ast.Try | ast.TryStar) and node.handlers:
            found.append(f"{path}:{node.lineno}")
        if isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:  # a later item runs inside an earlier one
                expr = item.context_expr
                if inside and isinstance(expr, ast.Call) and _name(expr.func) == "suppress":
                    found.append(f"{path}:{node.lineno}")
                inside = inside or _is_refuses_item(item)
            children: Iterable[ast.AST] = node.body
        else:
            children = ast.iter_child_nodes(node)
        for child in children:
            visit(path, child, inside)

    for path, text in sorted(files.items()):
        visit(path, ast.parse(text), False)
    return found


def unnamed(sites: Iterable[Site], named: Iterable[str], listed: Iterable[str] = ()) -> list[str]:
    """The IDs of ``sites`` that neither a test names nor a list holds, sorted."""
    return sorted({s.site for s in sites if s.site is not None} - set(named) - set(listed))


def _source_modules() -> dict[str, str]:
    paths = sorted(SOURCE.rglob("*.py"))
    return {".".join(p.relative_to(SOURCE).with_suffix("").parts): p.read_text() for p in paths}


def _test_files() -> dict[str, str]:
    """Every test file but the helper, by path; this file's own refuses calls count."""
    return {str(p.relative_to(ROOT)): p.read_text() for p in sorted(TESTS.rglob("*.py")) if p != HELPER}


def _form_arguments(source: str) -> list[ast.expr]:
    """The form argument of each refusal in ``source``."""
    tree = ast.parse(source)
    return [n.args[1] for n in ast.walk(tree) if isinstance(n, ast.Call) and _name(n.func) == "_RefusalError"]


def _form_values(source: str) -> list[ast.expr]:
    """What a variable called ``form`` is given: a table's column, or the two sides of a choice."""
    values: list[ast.expr] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple) and isinstance(node.iter, ast.Tuple):
            names = [_name(element) for element in node.target.elts]
            if "form" in names:
                rows = [row for row in node.iter.elts if isinstance(row, ast.Tuple)]
                values += [row.elts[names.index("form")] for row in rows]
        elif isinstance(node, ast.Assign) and _name(node.targets[0]) == "form" and isinstance(node.value, ast.IfExp):
            values += [node.value.body, node.value.orelse]
    return values


def _yaml_forms(source: str) -> set[str]:
    """Every form of the refusals in ``source``, whether a call or a variable holds it."""
    values = [*_form_arguments(source), *_form_values(source)]
    return {str(value.value) for value in values if isinstance(value, ast.Constant)}


# --- rules, skip reasons and YAML forms: counted where a test asserts them (#148) ----------


def _spellings(node: ast.AST, *, calls: bool = True) -> set[str]:
    """The strings and ``Name.attribute`` spellings (``Rule.COOLDOWN``) under ``node``. Without
    ``calls``, nothing inside a call is read, but a ``pytest.param``: a value a test passes to a
    function is its input, not what it expects."""
    found: set[str] = set()
    pending = [node]
    while pending:
        here = pending.pop()
        if isinstance(here, ast.Constant) and isinstance(here.value, str):
            found.add(here.value)
        elif isinstance(here, ast.Attribute) and isinstance(here.value, ast.Name):
            found.add(f"{here.value.id}.{here.attr}")
        if not calls and isinstance(here, ast.Call) and _name(here.func) != "param":
            continue
        pending.extend(ast.iter_child_nodes(here))
    return found


def _read(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _bindings(nodes: Iterable[ast.AST]) -> dict[str, set[str]]:
    """What each name is given in ``nodes``: an assignment's or a loop's literal values."""
    given: dict[str, set[str]] = {}
    for top in nodes:
        for node in ast.walk(top):
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                targets, value = (node.targets if isinstance(node, ast.Assign) else [node.target]), node.value
            elif isinstance(node, ast.For | ast.comprehension):
                targets, value = [node.target], node.iter
            else:
                continue
            for target in targets:
                for name in _read(target):
                    given.setdefault(name, set()).update(_spellings(value, calls=False))
    return given


def _parametrized(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, set[str]]:
    """Each parametrize argument's values."""
    given: dict[str, set[str]] = {}
    for decorator in function.decorator_list:
        if isinstance(decorator, ast.Call) and _name(decorator.func) == "parametrize" and len(decorator.args) >= 2:
            names = [n.value for n in ast.walk(decorator.args[0]) if isinstance(n, ast.Constant)]
            for name in (part.strip() for value in names if isinstance(value, str) for part in value.split(",")):
                given.setdefault(name, set()).update(_spellings(decorator.args[1], calls=False))
    return given


def _expectations(function: ast.AST) -> list[ast.expr]:
    """What ``function`` asserts: each ``assert``'s test, each ``pytest.raises``'s ``match=``, and
    the value of a one-element unpacking (``(found,) = [f for f in ... if f.rule is rule]``),
    which fails unless exactly one is there."""
    found: list[ast.expr] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            found.append(node.test)
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Tuple | ast.List)
            and len(node.targets[0].elts) == 1
        ):
            found.append(node.value)
        elif isinstance(node, ast.Call) and _name(node.func) == "raises":
            found += [keyword.value for keyword in node.keywords if keyword.arg == "match"]
    return found


def _imports_guardian(tree: ast.Module) -> bool:
    """Whether a test file imports Guardian: a test of a script asserts the script's output."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "ssc_guardian":
            return True
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "ssc_guardian" for a in node.names):
            return True
    return False


def asserted(files: Mapping[str, str]) -> dict[str, set[str]]:
    """Each string or ``Name.attribute`` spelling a test asserts, with the tests (``path::name``)
    that assert it. A spelling counts in an ``assert`` or a ``pytest.raises`` ``match=``: written
    there, given to a name read there (an assignment, a loop or a parametrize argument), or passed
    to a helper of the same file whose parameter is asserted. A mention anywhere else, a test
    that may not run and a file that imports no Guardian module count for nothing."""
    found: dict[str, set[str]] = {}
    for path, text in sorted(files.items()):
        tree = ast.parse(text)
        if not _imports_guardian(tree):
            continue
        module = _bindings(
            n for n in tree.body if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        )
        functions = {n.name: n for n in _counted_nodes(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
        given = {name: {**module, **_bindings(f.body), **_parametrized(f)} for name, f in functions.items()}
        checked: dict[str, set[int]] = {}  # each helper's parameters that are asserted, by position
        params = {name: [a.arg for a in (*f.args.posonlyargs, *f.args.args)] for name, f in functions.items()}

        def spellings(function: str, expr: ast.AST, given: dict[str, dict[str, set[str]]] = given) -> set[str]:
            names = given[function]
            return _spellings(expr) | {s for read in _read(expr) for s in names.get(read, set())}

        for name, function in functions.items():
            for expr in _expectations(function):
                for spelling in spellings(name, expr):
                    found.setdefault(spelling, set()).add(f"{path}::{name}")
                checked.setdefault(name, set()).update(
                    i for i, param in enumerate(params[name]) if param in _read(expr)
                )
        while True:  # a value passed to an asserted parameter, through as many helpers as there are
            grown = False
            for name, function in functions.items():
                for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
                    helper = _name(call.func) if isinstance(call.func, ast.Name) else None
                    if helper not in checked:
                        continue
                    passed = [*enumerate(call.args)]
                    passed += [(params[helper].index(k.arg), k.value) for k in call.keywords if k.arg in params[helper]]
                    for index, value in passed:
                        if index not in checked[helper]:
                            continue
                        for spelling in spellings(name, value):
                            found.setdefault(spelling, set()).add(f"{path}::{name}")
                        mine = {i for i, param in enumerate(params[name]) if param in _read(value)}
                        if not mine <= checked.setdefault(name, set()):
                            checked[name] |= mine
                            grown = True
            if not grown:
                break
    return found


def unnamed_codes(files: Mapping[str, str], sources: Mapping[str, str] | None = None) -> list[str]:
    """The violation rules, in-scope skip reasons and YAML forms (of ``sources``' ``yaml_subset``,
    Guardian's when None) that no test in ``files`` (path to text) asserts. One test each: each
    place that builds a rule has its own site, which a test names (issue #164)."""
    sources = _source_modules() if sources is None else sources
    tests = asserted(files)
    codes = [*(r for r in Rule if r.level is Level.VIOLATION), *(s for s in SkipReason if s.in_scope)]
    missing = [
        code.value
        for code in codes
        if not tests.get(code.value, set()) | tests.get(f"{type(code).__name__}.{code.name}", set())
    ]
    forms = _yaml_forms(sources.get("yaml_subset", YAML_SUBSET.read_text()))
    return missing + sorted(form for form in forms if not tests.get(form))


def uncovered(sources: Mapping[str, str], files: Mapping[str, str], listed: Iterable[str] = ()) -> list[str]:
    """The whole check: each site in ``sources`` that no ``refuses`` literal in ``files`` names and
    ``listed`` does not hold, then each rule, skip reason and YAML form that no test asserts."""
    named, _ = named_sites(files)
    return unnamed(scan(sources), named, listed) + unnamed_codes(files, sources)


def _baseline() -> list[str]:
    return BASELINE.read_text().splitlines()


def _exemptions() -> list[str]:
    return EXEMPTIONS.read_text().splitlines()


def _exempt_ids(lines: Iterable[str]) -> list[str]:
    """The ID of each ``id: reason`` line; a line without a reason fails."""
    ids = []
    for line in lines:
        site, _, reason = line.partition(": ")
        assert SITE_ID.fullmatch(site) and reason.strip(), f"an exemption is 'id: reason': {line!r}"
        ids.append(site)
    return ids


# --- every refusal has a negative test --------------------------------------------------

# The negative control: a planted site that no test names. The check must report it every run.
PLANTED_SOURCE = 'def unmentioned():\n    raise UsageError("planted", site="planted.no-test-names-this")\n'


def test_every_refusal_site_is_named_by_a_test() -> None:
    sites = scan(_source_modules())
    named, bad = named_sites(_test_files())
    listed = [*_baseline(), *_exempt_ids(_exemptions())]
    print(f"{len(sites)} sites, {len(named)} named by a test, {len(_baseline())} in the baseline")
    assert bad == [], "refuses takes one string literal"
    assert swallowed(_test_files()) == [], "a refuses block inside a catch-all: move it outside"
    assert caught_in_block(_test_files()) == [], "a catch inside a refuses block: assert with pytest.raises"
    assert uncovered(_source_modules(), _test_files(), listed) == [], (
        "a refusal, rule, skip reason or form no test covers"
    )
    assert sorted(named - {s.site for s in sites}) == [], "a test names a site the source does not have"
    # The negative control fires: a planted site with no test is reported on every run.
    planted = scan({**_source_modules(), "planted": PLANTED_SOURCE})
    assert unnamed(planted, named, listed) == ["planted.no-test-names-this"]


def test_every_refusal_call_carries_a_literal_unique_site() -> None:
    sites = scan(_source_modules())
    assert problems(sites) == []
    # The real source holds known sites, so the scan is reading it.
    assert {
        "cli.scope-filters-leave-nothing-check",
        "yaml_subset.reserved-indicator",
        "models.file-empty",
        "net.refused-method",
    } <= {s.site for s in sites}
    # Every module that refuses is read: a scan that found nothing would pass the test above.
    assert len({s.module for s in sites}) >= 30 and len(sites) >= 290


INLINE = """
class LocalError(UsageError):
    pass

def unnamed():
    raise LocalError("a refusal", site="inline.unnamed")

def named(name):
    raise UsageError(f"{name} is named", site="inline.named")

def built_elsewhere():
    return MalformedValueError(None, "a value", site="inline.built-elsewhere")

def missing():
    raise UsageError("no site at all")

def computed(name):
    raise UsageError("computed", site=f"inline.{name}")

def from_a_variable(site):
    raise LocalError("a variable", site=site)

def by_keywords(options):
    raise UsageError("hidden", **options)

def class_alone():
    raise LocalError

def twice():
    raise UsageError("again", site="inline.named")

def misspelt():
    raise UsageError("not an ID", site="Inline Named")

def parse():
    raise UsageError("not the forward", site=r.site)

def not_a_refusal():
    raise ValueError("a plain error that is no refusal of Guardian's")
"""


def test_scanner_reports_a_missing_computed_or_duplicate_site() -> None:
    sites = scan({"inline": INLINE})
    assert [(s.function, s.site) for s in sites if s.site] == [
        ("unnamed", "inline.unnamed"),
        ("named", "inline.named"),
        ("built_elsewhere", "inline.built-elsewhere"),
        ("twice", "inline.named"),
    ]
    assert problems(sites) == [
        "inline:15 UsageError: no site=",
        "inline:18 UsageError: site is not a string literal",
        "inline:21 LocalError: site is not a string literal",
        "inline:24 UsageError: **keywords can hide the site",
        "inline:27 LocalError: a bare raise names no site",
        "inline:33 UsageError: site 'Inline Named' is not module.slug",
        # A function called parse in another module is not yaml_subset's forward.
        "inline:36 UsageError: site is not a string literal",
        "inline.named is used 2 times",
    ]
    # The two forwards are accepted by module, function and argument, and nowhere else.
    forward = (
        "class UnsupportedYamlError(IncompleteCheckError):\n    pass\n"
        "def parse():\n    raise UnsupportedYamlError(s, 1, 'f', 'd', site=r.site, recorded=True)\n"
    )
    assert scan({"yaml_subset": forward}) == []
    for module, text in (("yaml_subset", forward.replace("r.site", "other")), ("other", forward)):
        assert problems(scan({module: text})) == [f"{module}:4 UnsupportedYamlError: site is not a string literal"]
    # A file the scan cannot parse fails it: nothing is skipped.
    with pytest.raises(SyntaxError):
        scan({"broken": "raise UsageError(site=\n"})


def test_a_refuses_block_inside_a_catch_all_is_reported() -> None:
    test = """
with collector.check(PYPI, place):
    with refuses("site.swallowed"):
        run()
with collector.check(PYPI, place), refuses("site.inner-item"):
    run()
with refuses("site.outside"), collector.check(PYPI, place):
    run()
try:
    with site:
        run()
except Exception:
    pass
try:
    with refuses("site.narrow-try"):
        run()
except KeyError:
    pass
try:
    with refuses("site.tuple"):
        run()
except (KeyError, Exception):
    pass
try:
    with refuses("site.assertion"):
        run()
except AssertionError:
    pass
try:
    with refuses("site.star"):
        run()
except* Exception:
    pass
with pytest.raises(AssertionError), refuses("site.raises-assertion"):
    run()
with contextlib.suppress(BaseException), refuses("site.suppressed"):
    run()
with pytest.raises(ValueError), refuses("site.narrow-raises"):
    run()
with pytest.raises(AssertionError), refuses("inline.planted"):
    run()
with pytest.raises(expected_exception=Exception), refuses("site.keyword"):
    run()
"""
    assert swallowed({"t.py": test}) == [
        "t.py:3",
        "t.py:5",
        "t.py:10",
        "t.py:20",
        "t.py:25",
        "t.py:30",
        "t.py:34",
        "t.py:36",
        "t.py:42",
    ]


def test_specific_exception_catch_in_block_is_swallowing() -> None:
    # #234 (L4-12): a catch of any type inside a refuses block stops the refusal in a test frame,
    # which refuses reads as reaching the test; the scan reports it. pytest.raises asserts the raise.
    test = """
with refuses("site.narrow"):
    try:
        run()
    except KeyError:
        pass
with site:
    try:
        run()
    except (KeyError, ValueError):
        pass
with refuses("site.star"):
    try:
        run()
    except* OSError:
        pass
with refuses("site.later-item"), contextlib.suppress(KeyError):
    run()
with refuses("site.nested"):
    if ready:
        with contextlib.suppress(OSError):
            run()
with refuses("site.raises"), pytest.raises(UsageError, match="x"):
    run()
with refuses("site.finally-only"):
    try:
        run()
    finally:
        tidy()
try:
    with refuses("site.outside-narrow"):
        run()
except KeyError:
    pass
with contextlib.suppress(KeyError), refuses("site.before"):
    run()
with refuses("inline.planted"):
    try:
        run()
    except KeyError:
        pass
"""
    assert caught_in_block({"t.py": test}) == ["t.py:3", "t.py:8", "t.py:13", "t.py:17", "t.py:21"]
    # A narrow catch around a block sees the refusal only after refuses has judged it: not reported.
    assert swallowed({"t.py": test}) == []


def test_coverage_scan_is_idempotent_on_re_run() -> None:
    # The scan reads only: two runs over the real source and tests give the same answers, and
    # no file it read changed.
    before = {**_source_modules(), **_test_files()}
    runs = [
        (
            [s.site for s in scan(_source_modules())],
            named_sites(_test_files()),
            swallowed(_test_files()),
            caught_in_block(_test_files()),
        )
        for _ in range(2)
    ]
    assert runs[0] == runs[1]
    assert {**_source_modules(), **_test_files()} == before
    assert "findings.duplicate-finding-id" in runs[0][1][0]  # the scan is reading the real tests


HAND_BUILT_SOURCE = """
def no_site(place):
    return Skip(None, place, SkipReason.CHECK_ERROR, detail="planted")

def named(place):
    return Skip(None, place, SkipReason.FEED_FAILURE, site="inline.named-skip")

def by_keyword(place):
    return Skip(None, place, reason=SkipReason.NOT_AVAILABLE)

def from_a_variable(reason):
    return Skip(None, None, reason)

def computed(name):
    return Skip(None, None, SkipReason.CHECK_ERROR, site=f"inline.{name}")

def out_of_scope():
    return Skip(None, None, SkipReason.FILTERED)

def out_of_scope_by_keyword():
    return Skip(None, None, reason=SkipReason.LOCAL_INSTALL, detail="a local install")

def hand_set():
    return int(ExitCode.INCOMPLETE)

def through_the_helper():
    return incomplete_exit(site="inline.named-exit")

def helper_without_a_site():
    return incomplete_exit()

def twice():
    return incomplete_exit(site="inline.named-skip")

def not_this_form(parser):
    parser.exit(int(ExitCode.INCOMPLETE), "usage")
    code = int(ExitCode.INCOMPLETE)
    return ExitCode.VIOLATION
"""


def test_hand_built_refusal_without_site_fails_the_scan() -> None:
    # The negative control (issue #131): a hand-built in-scope skip or exit 2 with no site, or
    # with one that is not a literal, is reported; an out-of-scope skip is no refusal.
    sites = scan({"inline": HAND_BUILT_SOURCE})
    assert [(s.function, s.site) for s in sites if s.site] == [
        ("named", "inline.named-skip"),
        ("through_the_helper", "inline.named-exit"),
        ("twice", "inline.named-skip"),
    ]
    assert problems(sites) == [
        "inline:3 Skip: no site=",
        "inline:9 Skip: no site=",
        "inline:12 Skip: no site=",
        "inline:15 Skip: site is not a string literal",
        "inline:24 exit 2: a hand-set exit 2 names no site",
        "inline:30 incomplete_exit: no site=",
        "inline.named-skip is used 2 times",
    ]
    # The helper alone may spell the exit 2 itself, and only in findings.
    helper = "def incomplete_exit(*, site):\n    record_site(site)\n    return int(ExitCode.INCOMPLETE)\n"
    assert scan({"findings": helper}) == []
    assert problems(scan({"cli": helper})) == ["cli:3 exit 2: a hand-set exit 2 names no site"]
    # In the real source, each planted form is reported when it joins it, and no test names it.
    named, _ = named_sites(_test_files())
    listed = [*_baseline(), *_exempt_ids(_exemptions())]
    planted = scan({**_source_modules(), "planted": HAND_BUILT_SOURCE})
    assert len(problems(planted)) == 7
    assert unnamed(planted, named, listed) == ["inline.named-exit", "inline.named-skip"]
    # The real source's hand-built refusals are read: the collector's, a command's and the CLI's.
    live = {s.site for s in scan(_source_modules())}
    assert {"findings.check-raised", "pin.not-confirmed", "cli.help-not-alone", "discovery.dangling-link"} <= live


def test_scan_is_idempotent_and_baseline_does_not_grow() -> None:
    before = {path: path.read_bytes() for path in (BASELINE, EXEMPTIONS, *sorted(SOURCE.rglob("*.py")))}
    runs = [(scan(_source_modules()), named_sites(_test_files())) for _ in range(2)]
    assert runs[0] == runs[1]  # the same sites and the same names, run after run
    assert {path: path.read_bytes() for path in before} == before  # the scan writes nothing
    # The baseline only shrinks: no hand-built site joined it; each one is named by a test.
    sites, (named, _) = runs[0]
    assert len(_baseline()) <= BASELINE_SIZE
    hand_built = {s.site for s in sites if s.name in HAND_BUILT and s.site is not None}
    assert len(hand_built) >= 37
    assert sorted(hand_built & set(_baseline())) == []
    assert sorted(hand_built - named) == []


def test_only_a_refuses_literal_names_a_site() -> None:
    sites = scan({"inline": INLINE})
    test = """
'''inline.unnamed in a docstring names nothing'''
# inline.unnamed in a comment names nothing
text = "inline.unnamed in a string names nothing"
with refuses("site.named-by-a-test"):
    pass
CASES = [refuses("site.in-a-parametrize-list")]
with refuses(computed_id):
    pass
"""
    named, bad = named_sites({"tests/unit/test_x.py": test})
    assert named == {"site.named-by-a-test", "site.in-a-parametrize-list"}
    assert bad == ["tests/unit/test_x.py:8"]
    assert unnamed(sites, named) == ["inline.built-elsewhere", "inline.named", "inline.unnamed"]
    # Planted IDs are left out, so a test of the helper names no real site by accident.
    assert named_sites({"t.py": 'refuses("inline.unnamed")'})[0] == set()
    assert unnamed([Site("m", "f", "UsageError", 1, "real.site")], {"real.site"}) == []


_CODES = [
    *(rule.value for rule in Rule if rule.level is Level.VIOLATION),
    *(reason.value for reason in SkipReason if reason.in_scope),
]


def _yaml_only() -> dict[str, str]:
    """A source with no rule built at a known place: each code then needs one test."""
    return {"yaml_subset": YAML_SUBSET.read_text()}


def test_rule_named_only_as_a_string_is_not_covered() -> None:
    # The negative control (#148): every code mentioned, and none asserted. Each is reported;
    # the name-anywhere count this replaced reported none of them.
    forms = sorted(_yaml_forms(YAML_SUBSET.read_text()))
    every = [*_CODES, *forms]
    mentions = (
        "from ssc_guardian.findings import Rule\n"
        f"NAMES = {every!r}  # a list no assert reads\n"
        "def test_mentions(run):\n"
        f"    run({every!r}, Rule.COOLDOWN)  # given to a call: input, not an expectation\n"
        "    expected = 'cooldown'\n"
        "    assert run() == 0\n"
    )
    assert unnamed_codes({"tests/unit/test_planted.py": mentions}, _yaml_only()) == [*_CODES, *forms]
    # A test of a script, which imports no Guardian module, asserts the script's output.
    script = f"from scripts import parity_report\ndef test_script():\n    assert parity_report.rows() == {every!r}\n"
    assert unnamed_codes({"tests/unit/test_script.py": script}, _yaml_only()) == [*_CODES, *forms]
    # Asserted on a result, each code is covered: written in the assert, given to a name it
    # reads, a parametrize value, or passed to a helper whose parameter is asserted.
    asserts = (
        "import pytest\nfrom ssc_guardian.findings import Rule\n"
        f"EXPECTED = {_CODES[:4]!r}\n"
        "def _has(result, code):\n    assert code in result.codes\n"
        "def test_direct(result):\n"
        f"    assert result.codes == {_CODES[4:8]!r}\n"
        "def test_named(result):\n    assert result.codes == EXPECTED\n"
        f"@pytest.mark.parametrize('code', {_CODES[8:12]!r})\n"
        "def test_parametrized(result, code):\n    assert code in result.codes\n"
        "def test_helper(result):\n" + "".join(f"    _has(result, {code!r})\n" for code in [*_CODES[12:], *forms])
    )
    assert unnamed_codes({"tests/unit/test_asserts.py": asserts}, _yaml_only()) == []
    # The real suite: every code is asserted somewhere.
    assert unnamed_codes(_test_files()) == []


# --- each place that builds a violation finding has its own site (issue #164) ----------------

# Two places that build one rule: a count of the tests that assert it would pass with both tests
# reaching the first place, and the second place untested.
TWO_PLACES = {
    "pin": "def plan():\n    return make_finding(Rule.IMPOSTOR_COMMIT, GHA, place=root, site='planted.first-place')\n",
    "nested": (
        "def inner():\n    return make_finding(rule=Rule.IMPOSTOR_COMMIT, ecosystem=GHA, site='planted.second-place')\n"
    ),
}


def _impostor_suite(*sites: str) -> dict[str, str]:
    """Two tests that assert ``impostor-commit``, each in a ``refuses`` block naming one of ``sites``."""
    body = "".join(
        f"def test_{n}(run):\n    with refuses({site!r}):\n        result = run()\n"
        "    assert 'impostor-commit' in result.rules\n"
        for n, site in enumerate(sites)
    )
    return {"tests/unit/test_impostor.py": "from ssc_guardian import findings\n" + body}


def _planted(sources: Mapping[str, str], files: Mapping[str, str]) -> list[str]:
    """What the whole check reports about the planted places and their rule."""
    return [gap for gap in uncovered(sources, files) if gap.startswith("planted.") or gap == "impostor-commit"]


def test_each_place_that_builds_a_rule_has_its_own_site() -> None:
    # The negative control: two tests assert the rule, but both name the first place, so the
    # planted second place is reported. The count this replaced (one test per place) passed it.
    sources = {**TWO_PLACES, "yaml_subset": ""}
    assert _planted(sources, _impostor_suite("planted.first-place", "planted.first-place")) == ["planted.second-place"]
    assert _planted(sources, _impostor_suite("planted.first-place", "planted.second-place")) == []
    # A rule asserted by no test is still reported, even when each place is named.
    unasserted = _impostor_suite("planted.first-place", "planted.second-place")
    unasserted["tests/unit/test_impostor.py"] = unasserted["tests/unit/test_impostor.py"].replace(
        "'impostor-commit' in", "'other' in"
    )
    assert _planted(sources, unasserted) == ["impostor-commit"]
    # The real source: the places #148 counted each have a site of their own.
    by_rule: dict[str, set[str]] = {}
    for site in scan(_source_modules()):
        if site.name in FINDING_BUILDERS or site.name == "_limit":
            by_rule.setdefault(site.module, set()).add(str(site.site))
    sites = {s for found in by_rule.values() for s in found}
    assert {"policy.cooldown", "install.file-cooldown"} <= sites
    assert {"check_envs.denied-installed", "install.denied-requested", "install.denied-resolved"} <= sites
    assert {"publisher.denied-action", "pin.impostor-commit", "nested.impostor-commit"} <= sites
    assert {"nested.depth-limit", "nested.reference-count-limit"} <= sites


FINDINGS_SOURCE = """
def no_site(place):
    return make_finding(Rule.COOLDOWN, PYPI, place=place)

def named(place):
    return make_finding(Rule.DENY_LIST, PYPI, place=place, site="inline.named-finding")

def by_keyword(place):
    return make_finding(rule=Rule.UNPROTECTED, ecosystem=PYPI, place=place)

def built_directly():
    return Finding(Rule.MALFORMED_NAME, None, malformed_field=PLACE, malformed_value="x")

def computed(name):
    return make_finding(Rule.COOLDOWN, PYPI, site=f"inline.{name}")

def a_notice(place):
    return make_finding(Rule.CI_OVERRIDES, GHA, place=place)

def a_warning():
    return make_finding(Rule.UNPINNED_IMAGE, GHA)

def by_keywords(options):
    return make_finding(Rule.COOLDOWN, PYPI, **options)

def twice(place):
    return make_finding(Rule.COMPROMISE, PYPI, place=place, site="inline.named-finding")

def make_finding(rule, ecosystem, site=None):
    return Finding(rule, ecosystem, site=site)

def _release_at(rule):
    return make_finding(rule, GHA)

def _limit(rule, ref, node, *, site):
    return make_finding(rule, GHA, site=site)

def walk(ref, node):
    return _limit(Rule.NESTING_LIMIT, ref, node)
"""


def test_finding_built_without_a_site_fails_the_scan() -> None:
    # The error path: a violation finding with no site, a computed one or a hidden one is reported;
    # a warning or a notice is no refusal. The forwards, the lookup key and the nested helper are
    # accepted only in their own module.
    sites = scan({"inline": FINDINGS_SOURCE})
    assert [(s.function, s.site) for s in sites if s.site] == [
        ("named", "inline.named-finding"),
        ("twice", "inline.named-finding"),
    ]
    assert problems(sites) == [
        "inline:3 make_finding: no site=",
        "inline:9 make_finding: no site=",
        "inline:12 Finding: no site=",
        "inline:15 make_finding: site is not a string literal",
        "inline:24 make_finding: **keywords can hide the site",
        "inline:30 Finding: site is not a string literal",
        "inline:33 make_finding: no site=",
        "inline:36 make_finding: site is not a string literal",
        "inline.named-finding is used 2 times",
    ]
    # In their own modules, the forward, the lookup key and the nested helper pass, and the helper's
    # caller then needs a site of its own.
    assert [s.function for s in problems_at("findings", FINDINGS_SOURCE)].count("make_finding") == 0
    assert "_release_at" not in [s.function for s in problems_at("commands.check_repo", FINDINGS_SOURCE)]
    nested = [s.where + ": " + str(s.problem) for s in problems_at("plugins.actions.nested", FINDINGS_SOURCE)]
    # The forward inside _limit (line 36) passes; walk's call of it (line 39) names no site.
    assert [w for w in nested if " _limit:" in w] == ["plugins.actions.nested:39 _limit: no site="]
    # The real source holds none of these.
    assert [p for p in problems(scan(_source_modules())) if "finding" in p.lower()] == []


def problems_at(module: str, text: str) -> list[Site]:
    """The sites in ``text``, read as ``module``, that the scan reports."""
    return [s for s in scan({module: text}) if s.problem is not None]


def test_rule_chosen_by_a_variable_still_has_a_site() -> None:
    # The edge case: a call whose rule a variable chooses may build a violation, so it needs a site.
    chosen = "def found(ref):\n    rule = pick(ref)\n    return make_finding(rule, GHA, item=ref)\n"
    assert problems(scan({"inline": chosen})) == ["inline:3 make_finding: no site="]
    named = chosen.replace("item=ref)", "item=ref, site='inline.chosen')")
    assert [(s.function, s.site, s.problem) for s in scan({"inline": named})] == [("found", "inline.chosen", None)]
    # A rule given by an attribute that is not Rule's, or by a call, is chosen too.
    for rule in ("hit.rule", "pick(ref)"):
        text = f"def found(hit, ref):\n    return make_finding({rule}, GHA)\n"
        assert problems(scan({"inline": text})) == ["inline:2 make_finding: no site="]
    # The real source: the three rules a variable chooses each have a site, named by a test.
    live = {s.site for s in scan(_source_modules())}
    assert {"resolver.reference-not-pinned", "advisories.advisory-hit", "nested.loop"} <= live
    named_live, _ = named_sites(_test_files())
    assert {"resolver.reference-not-pinned", "advisories.advisory-hit", "nested.loop"} <= named_live


def test_finding_site_scan_is_idempotent_on_re_run() -> None:
    # Two runs give the same finding sites, and the scan writes nothing.
    watched = (BASELINE, EXEMPTIONS, *sorted(SOURCE.rglob("*.py")))
    before = {path: path.read_bytes() for path in watched}

    def finding_sites() -> list[Site]:
        return [s for s in scan(_source_modules()) if s.name in FINDING_BUILDERS or s.name == "_limit"]

    first, second = finding_sites(), finding_sites()
    assert first == second and len(first) >= 19
    assert problems(first) == []
    assert {path: path.read_bytes() for path in watched} == before


def test_refuses_literal_in_a_skipped_test_does_not_count() -> None:
    test = """
import pytest
from ssc_guardian.findings import Rule

@pytest.mark.skip(reason="not yet")
def test_skipped():
    with refuses("site.skipped"):
        run()
    assert run().rule is Rule.COOLDOWN

@pytest.mark.skipif(True, reason="never here")
def test_skipped_if():
    with refuses("site.skipped-if"):
        run()

@pytest.mark.xfail(reason="expected to fail")
def test_expected_to_fail():
    with refuses("site.xfail"):
        run()

@pytest.mark.parametrize("case", [refuses("site.parametrized")])
@pytest.mark.skip
def test_parametrized(case):
    with case:
        run()

def test_skips_itself():
    if not ready():
        pytest.skip("not ready")
    with refuses("site.skips-itself"):
        run()

@pytest.mark.skip
class TestSkipped:
    def test_inside(self):
        with refuses("site.in-a-skipped-class"):
            run()

def test_runs():
    with refuses("site.runs"):
        run()
    assert run().rule is Rule.YOUNG_REPOSITORY
"""
    named, bad = named_sites({"tests/unit/test_x.py": test})
    assert (named, bad) == ({"site.runs"}, [])
    tests = asserted({"tests/unit/test_x.py": test})
    assert "Rule.COOLDOWN" not in tests and tests["Rule.YOUNG_REPOSITORY"] == {"tests/unit/test_x.py::test_runs"}
    # A module whose pytestmark skips it counts for nothing.
    skipped = "import pytest\npytestmark = [pytest.mark.unit, pytest.mark.skip]\n" + test
    assert named_sites({"tests/unit/test_y.py": skipped}) == (set(), [])
    # requires_network is no skip: CI runs those tests and forbids skipping them.
    network = (
        "import pytest\n@pytest.mark.requires_network\ndef test_online():\n"
        "    with refuses('site.online'):\n        run()\n"
    )
    assert named_sites({"tests/unit/test_z.py": network}) == ({"site.online"}, [])


def test_coverage_check_is_idempotent_on_re_run() -> None:
    # Two runs of the whole check give the same lists, and it writes nothing.
    watched = (BASELINE, EXEMPTIONS, *sorted(SOURCE.rglob("*.py")), *sorted(TESTS.rglob("*.py")))
    before = {path: path.read_bytes() for path in watched}

    def run() -> tuple[object, ...]:
        files = _test_files()
        return (
            scan(_source_modules()),
            named_sites(files),
            swallowed(files),
            unnamed_codes(files),
            asserted(files),
        )

    first, second = run(), run()
    assert first == second
    assert first[3] == [] and first[2] == []
    assert {path: path.read_bytes() for path in watched} == before


def test_baseline_and_exemptions_only_name_live_untested_sites() -> None:
    before = (BASELINE.read_bytes(), EXEMPTIONS.read_bytes())
    for _ in range(2):  # re-running is idempotent: the check reads, and writes nothing
        live = {s.site for s in scan(_source_modules()) if s.site is not None}
        named, _ = named_sites(_test_files())
        baseline, exempt = _baseline(), _exempt_ids(_exemptions())
        for name, lines in (("baseline", baseline), ("exemptions", _exemptions())):
            assert lines == sorted(set(lines)), f"the {name} is sorted, with no repeats"
        assert sorted(set(baseline) - live) == [], "a baseline entry that no longer exists: take it out"
        assert sorted(set(exempt) - live) == [], "an exemption that no longer exists: take it out"
        assert sorted(set(baseline) & named) == [], "a baseline entry a test now names: take it out"
        assert sorted(set(exempt) & named) == [], "an exemption a test now names: take it out"
        assert sorted(set(baseline) & set(exempt)) == []
        assert len(baseline) == BASELINE_SIZE
    assert (BASELINE.read_bytes(), EXEMPTIONS.read_bytes()) == before
    # The exemption format: an ID, a colon and a reason.
    assert _exempt_ids(["net.example: the operating system fails"]) == ["net.example"]
    for line in ("net.example", "net.example: ", "not an id: reason"):
        with pytest.raises(AssertionError, match="an exemption is 'id: reason'"):
            _exempt_ids([line])


def _text_and_json(argv: list[str], **kwargs: Any) -> list[tuple[int, str, str]]:
    """``main`` on ``argv``, once as text and once with --json: (code, stdout, stderr) each."""
    runs = []
    for extra in ([], ["--json"]):
        out, err = io.StringIO(), io.StringIO()
        code = main([*argv, *extra], stdout=out, stderr=err, environ={}, **kwargs)
        runs.append((code, out.getvalue(), err.getvalue()))
    return runs


def test_site_id_never_appears_in_output(tmp_path: Path) -> None:
    ids = {s.site for s in scan(_source_modules()) if s.site is not None}
    shown: list[str] = []
    # A usage error, which main reports itself.
    with refuses("cli.scope-filters-leave-nothing-check"):
        runs = _text_and_json(["check", "--envs", "--ecosystem", "github-actions"])
    assert [code for code, _, _ in runs] == [2, 2]
    shown += [out + err for _, out, err in runs]
    # A handler's refusal, which Collector.check turns into an in-scope skip.
    (tmp_path / "home").mkdir()
    err = io.StringIO()
    handler = install.Install(home=str(tmp_path / "home"), environ={"PATH": ""}, stderr=err)
    with refuses("install.guardian-installs-into-venvs-only"):
        runs = _text_and_json(["install", "--venv", str(tmp_path), "requests"], handlers={Verb.INSTALL: handler})
    assert [code for code, _, _ in runs] == [2, 2]
    assert json.loads(runs[1][1])["skipped"][0]["reason"] == "check-error"
    shown += [out + e for _, out, e in runs] + [err.getvalue()]
    # A YAML refusal, built as a _RefusalError and passed on with its file named.
    root = make_repo(tmp_path, f"someone/leaf@{sha(5)}")
    (root / ".github" / "workflows" / "ci.yml").write_text("on: [push]\njobs: &shared\n  a: 1\n")
    github, err = GitHub(), io.StringIO()
    checker = CheckEnvs(home=str(tmp_path / "home"), environ={}, today=TODAY, client=github.client(), stderr=err)
    with refuses("yaml_subset.reserved-indicator"):
        runs = _text_and_json(["check", "--repo", str(root)], handlers={Verb.CHECK: checker})
    assert [code for code, _, _ in runs] == [2, 2]
    assert "unsupported-yaml" in runs[1][1]
    shown += [out + e for _, out, e in runs] + [err.getvalue()]
    assert all(text for text in shown)
    assert [site for site in sorted(ids) for text in shown if site in text] == []


# --- the fixture set --------------------------------------------------------------------


def load_fixtures(folder: Path = FIXTURES) -> dict[str, str]:
    """Each fixture by the ID on its first line. Two files with one ID are an error."""
    found: dict[str, str] = {}
    for path in sorted(folder.glob("*.yml")):
        text = path.read_text()
        header = re.fullmatch(r"# id: ([a-z0-9-]+)", text.split("\n", 1)[0])
        assert header is not None, f"{path.name} starts with no ID"
        assert header[1] not in found, f"duplicate fixture ID {header[1]}"
        found[header[1]] = text
    return found


def publish_fixtures(github: GitHub) -> None:
    """The whole fixture set on the GitHub fixture, each at its own commit."""
    fixtures = load_fixtures()
    node = fixtures["node-action"]
    composite_action, reusable, reference = (
        fixtures["composite-action"],
        fixtures["reusable-workflow"],
        fixtures["reference-case-2025"],
    )
    github.publisher("someone/inner", 301, tags={"v2": sha(2)}, files={(sha(2), "action.yml"): node})
    github.publisher("someone/composite", 302, tags={"v1": sha(3)}, files={(sha(3), "action.yml"): composite_action})
    github.publisher("someone/shared", 303, tags={"v1": sha(4)}, files={(sha(4), SHARED_FILE): reusable})
    github.publisher("someone/leaf", 304, tags={"v1": sha(5)}, files={(sha(5), "action.yml"): node})
    files = {(GENUINE, "action.yml"): node, (MALICIOUS, "action.yml"): node}
    github.publisher(REVIEWDOG, 305, tags={"v1": MALICIOUS}, files=files)
    github.publisher(CHANGED_FILES, 306, tags={"v45": OUTER_COMMIT}, files={(OUTER_COMMIT, "action.yml"): reference})


def _check_repo(root: Path, github: GitHub) -> tuple[int, dict[str, Any]]:
    """``check --repo ROOT --json`` through ``cli.main``, with GitHub as the fixture."""
    out, err = io.StringIO(), io.StringIO()
    handler = CheckEnvs(home=str(root.parent / "home"), environ={}, today=TODAY, client=github.client(), stderr=err)
    code = main(["check", "--repo", str(root), "--json"], handlers={Verb.CHECK: handler}, stdout=out, stderr=err)
    return code, json.loads(out.getvalue())


def _violations(doc: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["rule"], f["item"]) for f in doc["findings"] if f["level"] == "violation"]


def test_fixture_set_has_no_duplicate_ids(tmp_path: Path) -> None:
    fixtures = load_fixtures()
    for text in fixtures.values():
        assert "# Faithful: " in text and "# Modelled: " in text
    # Loading twice, into one GitHub or two, gives the same routes.
    once, twice = GitHub(), GitHub()
    publish_fixtures(once)
    publish_fixtures(twice)
    publish_fixtures(twice)
    assert once.routes == twice.routes
    # A second file with an ID already used is refused, so the check above can fail.
    for name in ("a.yml", "b.yml"):
        (tmp_path / name).write_text("# id: same\n")
    with pytest.raises(AssertionError, match="duplicate fixture ID same"):
        load_fixtures(tmp_path)


def test_composite_fixture_is_walked_to_its_inner_tag(tmp_path: Path) -> None:
    github = GitHub()
    publish_fixtures(github)
    root = make_repo(tmp_path, f"someone/composite@{sha(3)}", lock=[listed("someone/composite", sha(3), "v1")])
    code, doc = _check_repo(root, github)
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [("nested-moving-reference", "someone/inner")]


def test_reusable_workflow_fixture_is_walked_to_its_inner_tag(tmp_path: Path) -> None:
    github = GitHub()
    publish_fixtures(github)
    action = f"someone/shared/{SHARED_FILE}"
    root = make_repo(tmp_path, lock=[listed(action, sha(4), "v1")])
    (root / ".github" / "workflows" / "ci.yml").write_text(f"on: [push]\njobs:\n  call:\n    uses: {action}@{sha(4)}\n")
    code, doc = _check_repo(root, github)
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [("nested-moving-reference", "someone/inner")]


def test_node_fixture_names_no_inner_reference(tmp_path: Path) -> None:
    github = GitHub()
    publish_fixtures(github)
    root = make_repo(tmp_path, f"someone/leaf@{sha(5)}", lock=[listed("someone/leaf", sha(5), "v1")])
    code, doc = _check_repo(root, github)
    assert code == doc["exit_code"] == 0, doc
    assert _violations(doc) == []


# --- the 2025 reference case ------------------------------------------------------------
# test_pin_command's reference case pins the tag during the attack; these are what a consumer's
# check reports. The outer Action is modelled: reference-case-2025.yml's header says how.


@pytest.mark.parametrize(
    ("uses", "lock", "rule"),
    [
        (f"{REVIEWDOG}@v1", (), "moving-reference"),  # the tag
        (f"{REVIEWDOG}@{MALICIOUS}", ((REVIEWDOG, GENUINE, "v1"),), "unverified-pin"),  # the moved commit by SHA
        (f"{CHANGED_FILES}@{OUTER_COMMIT}", ((CHANGED_FILES, OUTER_COMMIT, "v45"),), "nested-moving-reference"),
    ],
    ids=["tag", "moved-commit", "composite-outer"],
)
def test_reference_case_2025_fails_with_exit_one(
    tmp_path: Path, uses: str, lock: tuple[tuple[str, str, str], ...], rule: str
) -> None:
    github = GitHub()
    publish_fixtures(github)
    root = make_repo(tmp_path, uses, lock=[listed(*entry) for entry in lock])
    code, doc = _check_repo(root, github)
    assert code == doc["exit_code"] == 1
    assert _violations(doc) == [(rule, REVIEWDOG)]


def test_reference_case_genuine_pin_passes(tmp_path: Path) -> None:
    # The control: the same GitHub and the same action, pinned to the commit the lock file lists.
    github = GitHub()
    publish_fixtures(github)
    root = make_repo(tmp_path, f"{REVIEWDOG}@{GENUINE}", lock=[listed(REVIEWDOG, GENUINE, "v1")])
    code, doc = _check_repo(root, github)
    assert code == doc["exit_code"] == 0, doc


# --- the bypass lists -------------------------------------------------------------------
# End states only: what each bypass in example-repo #366 and #367 leaves behind, as
# check --envs reads it. Blocking the command text is the hook's job, not Guardian's.

client = envs.client  # the local server for PyPI, OSV and the advisory feeds


def _young_package(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #366, "can put a package younger than 21 days into the venv": whichever
    uv path did it, the package is in the venv and inside its cooldown."""
    young = (TODAY - timedelta(days=5)).isoformat() + "T00:00:00Z"
    monkeypatch.setitem(envs.UPLOADS, "idna", {"3.7": young})
    return {}


def _pip_conf_key_unset(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #367, ``pip config --site unset install.uploaded-prior-to``: the file
    stays, without the key."""
    Path(venv, "pip.conf").write_text("[install]\n")
    return {}


def _pip_conf_key_weakened(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #367, ``pip config --site set install.uploaded-prior-to P0D``: the key
    stays, with no cooldown in it."""
    Path(venv, "pip.conf").write_text("[install]\nuploaded-prior-to = P0D\n")
    return {}


def _pip_conf_emptied(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #367, ``> .venv/pip.conf``: the file stays, empty."""
    Path(venv, "pip.conf").write_text("")
    return {}


def _pip_conf_deleted(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #367, ``rm .venv/pip.conf``: the file is gone."""
    Path(venv, "pip.conf").unlink()
    return {}


def _pip_variable(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #367, a ``PIP_*`` variable its context names, exported in the shell that
    runs ``check``: ``PIP_UPLOADED_PRIOR_TO`` beats every file. An inline assignment dies with its
    one command, so its only end state is the young package (_young_package)."""
    return {"PIP_UPLOADED_PRIOR_TO": "P0D"}


def _pip_config_file(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #367, a ``PIP_*`` variable its context names, exported in the shell that
    runs ``check``: ``PIP_CONFIG_FILE`` set to the null device stops pip reading the file. An
    inline assignment dies with its one command, so its only end state is the young package
    (_young_package)."""
    return {"PIP_CONFIG_FILE": os.devnull}


def _uv_config_without_window(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #366, a ``uv pip install`` that finds no cutoff (measured there from
    outside the repo): here the per-user uv config holds no ``exclude-newer``."""
    (tmp_path / "home" / ".config" / "uv" / "uv.toml").write_text("native-tls = true\n")
    return {}


def _uv_no_config(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #366, ``UV_NO_CONFIG`` exported in the shell that runs ``check``: uv stops
    reading its config. An inline assignment dies with its one command, so its only end state is
    the young package (_young_package)."""
    return {"UV_NO_CONFIG": "1"}


def _uv_exclude_newer(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #366, ``UV_EXCLUDE_NEWER`` exported in the shell that runs ``check``: the
    variable beats the config. An inline assignment dies with its one command, so its only end
    state is the young package (_young_package)."""
    return {"UV_EXCLUDE_NEWER": "2099-01-01"}


def _uv_config_file(tmp_path: Path, venv: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """example-repo #366, ``UV_CONFIG_FILE`` exported in the shell that runs ``check``: uv
    reads another file instead. An inline assignment dies with its one command, so its only end
    state is the young package (_young_package)."""
    return {"UV_CONFIG_FILE": os.devnull}


# Each case's rule, and the place that builds it, which its refuses block names (issue #164).
@pytest.mark.parametrize(
    ("bypass", "rule", "case"),
    [
        (_young_package, "cooldown", refuses("policy.cooldown")),
        (_pip_conf_key_unset, "unprotected", refuses("check_envs.unprotected")),
        (_pip_conf_key_weakened, "unprotected", refuses("check_envs.unprotected")),
        (_pip_conf_emptied, "unprotected", refuses("check_envs.unprotected")),
        (_pip_conf_deleted, "unprotected", refuses("check_envs.unprotected")),
        (_pip_variable, "unprotected", refuses("check_envs.unprotected")),
        (_pip_config_file, "unprotected", refuses("check_envs.unprotected")),
        (_uv_config_without_window, "unprotected", refuses("check_envs.unprotected")),
        (_uv_no_config, "unprotected", refuses("check_envs.unprotected")),
        (_uv_exclude_newer, "unprotected", refuses("check_envs.unprotected")),
        (_uv_config_file, "unprotected", refuses("check_envs.unprotected")),
    ],
    ids=lambda value: value.strip("_") if isinstance(value, str) else getattr(value, "__name__", "").strip("_") or None,
)
def test_bypass_list_cases_are_refused(
    tmp_path: Path,
    client: Client,
    monkeypatch: pytest.MonkeyPatch,
    bypass: Callable[[Path, str, pytest.MonkeyPatch], dict[str, str]],
    rule: str,
    case: Any,
) -> None:
    assert re.search(r"example-repo #36[67]", bypass.__doc__ or ""), "each case names its item"
    envs._config(tmp_path)
    venv = envs._venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    uv = tmp_path / "home" / ".local" / "bin" / "uv"
    uv.parent.mkdir(parents=True)
    uv.write_text("")
    envs._protect(tmp_path)
    assert envs._check(tmp_path, client)[0] == 0  # the control: protected and clean before the bypass
    environ = bypass(tmp_path, venv, monkeypatch)
    with case:  # the place that builds the rule reaches the result
        code, doc, _ = envs._check(tmp_path, client, **environ)
    assert code == doc["exit_code"] == 1
    assert [f["rule"] for f in doc["findings"] if f["level"] == "violation"] == [rule]


def test_a_denied_installed_package_is_a_violation(tmp_path: Path, client: Client) -> None:
    # check --envs builds deny-list at its own place, apart from install's two and pin's (#164).
    envs._config(tmp_path, '\ndeny = ["pypi:idna"]\n')
    venv = envs._venv(tmp_path, "app", ("pip", "26.2.1"), ("idna", "3.7"))
    envs._protect(tmp_path)
    with refuses("check_envs.denied-installed"):
        code, doc, _ = envs._check(tmp_path, client)
    assert code == doc["exit_code"] == 1
    denied = [f for f in doc["findings"] if f["rule"] == "deny-list"]
    assert [f["item"] for f in denied] == ["idna"]
    assert denied[0]["place"].startswith(venv + os.sep) and denied[0]["place"].endswith("site-packages")
