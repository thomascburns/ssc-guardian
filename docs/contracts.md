# ssc-guardian contracts record

> **References in this record.** Issue numbers such as #68, and "plan §" references, point to
> the development repository's issue tracker and v1.0 plan, which are not public. See
> [README.md](../README.md), "About these documents".

**This is the design record.** It holds the contracts as the owner approved and froze them, with
the decisions behind them. To use Guardian, read [docs/reference.md](reference.md): it restates
these contracts for users, and each of its sections links the section here that it summarizes.
Section numbers here do not change, because the source code cites them.

**Codes in this record.** Each code names a decision or a part of the v1.0 plan:

| Codes | Meaning |
|---|---|
| D1–D18 | The owner's decisions at the contracts checkpoint, listed in §9. |
| Q1–Q6 | The owner's answers on the settings and override formats, listed in §10.6. |
| B1, N6, N8, N-4 | The owner's rulings on the review of the first implementation of §10, listed in §10.6. |
| L1–L3 | The owner's answers on the lock-file format, listed in §11.4. |
| T1–T6 | The plan's six GitHub Actions threats: T1 moving tag, T2 malicious release (the cooldown and its start date), T3 wrong publisher, T4 impostor commit, T5 nested Action, T6 known vulnerability. |
| R1-K…, R2-K…, FC-… | Decisions from the plan's review: R1 and R2 are its two audit rounds and FC its focused check. R1-K7 is YAML and output; R1-K5 CI settings; R2-K3 the CI mechanism; R2-K4 re-checking overrides against KEV; FC-3 CI trusting the committed lock file. |
| M1–M3 | Milestones of the v1.0 plan, which runs from M0 to M3 in order. |
| fact N | Row N of the plan's table of vendor facts (plan §8), the outside facts the code relies on; source comments cite them. |

**Status: APPROVED by the owner at the contracts-frozen checkpoint (plan §6) on 2026-11-02,
with the decisions in §9. Frozen.** The settings, override and lock-file formats were added as
each was approved (D1): §10 and §11 on 2026-11-03. The finding-ID formula froze when #4
added version normalization (D18). Any change now needs owner approval (issue #2).

This record covers the parts issue #2 builds: command names and flags, the result model, the
finding ID, exit codes, the JSON shape, field grammars and the plug-in protocol, plus the npm
paper test. The code is the source of truth; this file states it for review. Plan references
are to the v1.0 plan's working copy (revision 5 plus the §10.4 amendments).

## 1. What the checkpoint covers, and what this record does not yet hold

The plan's checkpoint lists: settings, override and lock-file formats; result model; finding
ID; exit codes; JSON shape; command names; plug-in protocol.

| Contract | Where | State |
|---|---|---|
| Command names and flags | §2 below, `src/ssc_guardian/cli.py` | frozen |
| Result model, exit codes, JSON shape | §3–§5, `findings.py`, `render.py` | frozen |
| Finding ID | §5, `findings.py`, `pep440.py` | frozen (version normalization added by #4, D18) |
| Field grammars | §6, `grammars.py` | frozen |
| Plug-in protocol, npm paper test | §7–§8, `plugin.py` | frozen |
| Settings and override file formats | §10, `settings.py`, `overrides.py` (issue #3) | approved 2026-11-03 (§10.6) |
| Lock-file format | §11, `lockfile.py` (issue #28, moved from #9 by D1) | approved 2026-11-03 (§11.4) |

## 2. Commands (plan §2.1)

| Command | Flags | `--yes` | `--json` |
|---|---|---|---|
| `check` | `--path P` (repeatable) or `--repo [DIR]`, at least one: a `check` with neither is a usage error (exit 2); `--envs` or `--repo [DIR]` (exclusive); filters `--language python`, `--ecosystem pypi\|github-actions` (each repeatable; repeats of one flag add up, and the two flags together keep only what both allow) | not accepted (usage error) | yes |
| `protect [pip\|uv] --path P` | `--path P` is required (repeatable): a `protect` without it is a usage error (exit 2) | yes | yes |
| `install --venv PATH PACKAGE...` | `PACKAGE` is `NAME` or `NAME==VERSION` | yes | yes |
| `pin OWNER/REPO[/PATH]@REF` | `REF` is required (a tag, a branch or a 40-hex SHA): a bare `OWNER/REPO` is exit 2 with nothing written (owner's approval of 2026-11-10, #151) | yes | yes |
| `acknowledge OWNER/REPO` | | **refused** (exit 2) | **refused** (exit 2) |
| `override add` | | **refused** (exit 2) | **refused** (exit 2) |

- `ssc-guardian --version` prints `ssc-guardian <version>`, plus ` (<commit>)` for a Git install,
  as the text output's footer does; JSON `tool.commit` is the same commit or null (§5). The commit
  is read from the installed distribution's `direct_url.json` (PEP 610) and reported only when
  `vcs_info.vcs` is `git` and `commit_id` matches the `sha` grammar. No installed distribution, no
  file, or a non-VCS install (a wheel, an editable or a local folder) gives no commit, never an
  invented one. A file that is present but unreadable, not JSON or not PEP 610 data, or a Git
  install whose `commit_id` does not match the `sha` grammar (a short, uppercase or SHA-256
  commit is not shortened, padded, lowercased or guessed at), gives no commit and one plain
  line on stderr saying `direct_url.json` could not be read; `--version` and every command
  still run (#7).
  `--version` writes to the streams given to `cli.main`, as every command does.
- `--help`, `-h` and `--version` exit 0 only as the whole command line. With any other token
  (`check --help`, `check -h`, `--version check`) the text still prints and the run exits 2, so
  a CI gate never passes on it; `install --version` stays a usage error (exit 2). Owner's
  ruling, 2026-11-03 (#26).
- `--language` accepts only `python` in v1.0. Any other value is a usage error (exit 2) whose
  message names the supported languages and says GitHub Actions are checked with `--repo` or
  `--ecosystem github-actions` (D11).
- Filters narrow what is checked and never relax a rule. Each ecosystem that the scope or a
  filter leaves out is listed as skipped with reason `filtered` (out of scope). A scope and
  filters that leave no ecosystem at all are a usage error (exit 2), so a mistyped CI gate
  cannot pass with nothing checked.
- Where `check` and `protect` look for environments and workflows, and what they write, is decided
  only by their arguments (owner's rulings of 2026-11-13, #255; plan §10.4). A `check` with
  neither `--path` nor `--repo`, and a `protect`
  without `--path`, is a usage error (exit 2) whose message shows the `--path` form; it is decided
  from the arguments before anything is read, so it reads and writes nothing. Neither command has
  an `--all` option or a default scope, and no setting changes what a command reads (§10.2).
- Outside a Git repository, a `check` whose ecosystems include GitHub Actions (`check --path P`
  without `--envs`, or `--ecosystem github-actions`) lists that area as an in-scope skip
  `check-error` ("not inside a Git repository", exit 2) with a one-line note naming `--repo DIR`
  and `--envs`, so a run that asks for Actions never passes without them; `check --envs --path P`
  does not look for a repository, and `--repo DIR` never depends on the current folder. Owner's
  ruling of 2026-11-14 (#255), replacing the 2026-11-04 ruling (#68) for plain `check`, which no
  longer exists.
- The repository check (`--repo`, and `check --path P` without `--envs` inside a repository) lists
  the files at the
  repository's top level that v1.1 reads (plan §3.3) as skipped with reason `later-release`
  (out of scope): `pyproject.toml`, `uv.lock` and `requirements*.txt` as `pypi`, and
  `.pre-commit-config.yaml` with no ecosystem. `--path` narrows that list as it narrows the
  workflows read; a `--path` naming one of them is never reported as checked (exit 2, §3).
- `check --envs` and `protect` find Python environments only at or under each `--path` P, and
  nothing is looked for outside the named paths (#255): P itself when it is a venv or a base
  installation's `sys.prefix`; the base installations in the standard places under P, and those
  reached through interpreters in `PATH` folders under P (a `PATH` folder that is a venv's own
  `bin`, as activating the venv puts it there, names that venv: its base, the one `pyvenv.cfg`'s
  `home` names, is a candidate only when it is itself under P, #301); and the venvs and base
  installations found by walking P (every P but a venv), following symlinked folders under P,
  at most 8 levels down (a venv 8 levels below P is found), and
  never into a venv or a folder named `.git`, `node_modules`, `__pycache__` or `site-packages`. A
  venv one level past the limit, or directly inside one of those folders, is listed as an
  in-scope skip `check-error` with its place (exit 2) unless a shorter route checks it; deeper
  ones are not seen. Naming the folder with `--path` checks it (#67). An environment reached
  under P that resolves outside every named path is not read: it is an in-scope skip
  `check-error` where it was reached. A P that does not exist, cannot be read or holds nothing
  checked is an in-scope skip `check-error` at P (exit 2), never a pass. uv's user config is read
  by `check` and written by `protect` only when a `--path` names it or a folder above it, and
  only when the file it really is (through a symlink) is inside the named paths; otherwise it is
  an in-scope skip `check-error` at its place. `protect uv` with no such path is an in-scope
  skip `check-error` at each P.
- Every handler must report its area (per ecosystem, and for `check` and `protect` per `--path`
  value too, §3): for `check`, each in-scope ecosystem; for `install`,
  `protect`, `pin` and `acknowledge`, the verb's ecosystem. It reports an area with a checked
  entry or an in-scope skip; an out-of-scope skip does not count. An area it does not report
  is added as an in-scope skip `check-error` (exit 2), so a handler for one of these verbs that
  drops its report can never exit 0. `override add` has no area; its handler (#3) defines what
  it reports.
- Paths given to `--venv`, `--repo` and `--path` have `~` expanded and are made absolute
  against the current directory, dropping `.` components, repeated `/` (leading ones too) and a
  trailing `/` (each names the same place). An empty path, or one with a `..` component, is
  malformed. The absolute path is grammar-checked as typed; then its symlinks are resolved
  (`/tmp/x` is `/private/tmp/x` on macOS), so one place has one spelling (D18), and the
  resolved path is grammar-checked too. A malformed place shows the form that failed, which
  names the cause (a symlink to a folder named `odd#dir` is malformed though its own name is
  not). Letter case is kept, except where a symlink is replaced by its target. Symlinks are
  resolved only as the system follows them: parts that do not exist yet (a new venv) or sit
  under a folder that cannot be searched are kept as typed after their resolved parent, and a
  symlink the system cannot follow (dangling, in a loop, or in too long a chain) leaves the whole
  path as typed. A resolved part is used only if the system opens it and the typed part as the
  same file, so the check reads what the system would open and never a place collapsed from `..`
  as text.
- A malformed argument is a `malformed-name` violation (exit 1), and the command does not run.
- A usage error (unknown flag, missing argument) exits 2. Options are never abbreviated
  (`--h` is not `--help`).
- A writing command shows the change and writes only on confirmation (`cli.confirm`). `--yes`
  confirms in advance, except for `acknowledge` and `override add`. With no terminal there is no
  confirmation. With no terminal the change is still shown, no question is asked, and nothing is
  written (#284). The writing commands follow D15 (#3, #5, #6, #9): a declined confirmation, or
  none possible, writes nothing and exits 2, and the message says to add `--yes` where it is
  allowed; `--yes` still prints the change, to stderr, as a record (the command prints it;
  `cli.confirm` returns on `--yes` without printing); the question goes to stderr, so `--json`
  output stays valid.
- Every verb has a handler (`cli.DEFAULT_HANDLERS`); a verb without one would report its area as
  an in-scope skip `not-available` (exit 2), never exit 0.

## 3. Exit codes (plan §2.2)

| Code | Meaning |
|---|---|
| 0 | Every rule met in what was checked. Warnings and notices may appear. |
| 1 | At least one violation. For `install` and `pin`: refused because a rule failed; nothing written. |
| 2 | A check could not finish, or a usage error. For `install` and `pin`: refused; nothing written, except when the write step itself fails part way (below). |

- **1 wins over 2.** Unfinished checks are still listed.
- **A failed write step reports what it wrote.** `install` and `pin` write only after every
  check passes. If the write step then fails part way, the result is 2 and stderr names what
  was written: `pin` says "written so far: …" (the lock file first, then each workflow, each
  written atomically); `install` says "written: …; removed: …". Everything written had passed
  its checks, and nothing is rolled back; a `pin` re-run finishes the change.
- **A failed check never gives 0.** `Collector.check` turns any exception into an in-scope skip:
  with the reason an `IncompleteCheckError` names, otherwise `check-error`. The CLI does the same
  for a handler that raises or that returns something
  other than a result for its own verb; the skip appears in the normal output. Building the
  parser, rendering and writing (including the final flush) are guarded too; a failure there
  exits 2 with a fixed message on stderr (output already written may be partial). A closed or
  broken stdout or stderr cannot change the exit code either: before returning, `main` flushes
  both, and points one that cannot be flushed (a broken pipe) at the null device, so Python's
  shutdown flush cannot turn the code into 120. Every `BaseException` is caught
  (`sys.exit(0)` in a handler, `asyncio.CancelledError`), except `KeyboardInterrupt`, which
  is left to Python. So once `main` is running, Python's default exit 1 for an uncaught
  exception can never read as a violation (an import failure before `main` runs still exits 1).
- **A malformed value is a violation.** A `MalformedValueError` for a finding's field (place,
  item, version, evidence or via) raised inside a check or a handler becomes a `malformed-name`
  finding (exit 1), and the interrupted check is also listed as an in-scope skip. A mismatch
  in a field that is not part of a finding (a date, an override ID) is only an unfinished
  check (exit 2). A check started for a malformed place is recorded as a
  `malformed-name` finding and an unfinished check before it runs.
- **Every `--path` value is reported** (owner's ruling, 2026-11-03, #26; `protect` too since
  #255). For `check` and `protect`, each `--path` value P must be reported by at least one in-scope
  ecosystem, through a checked entry
  or an in-scope skip whose place is P or inside P; `cli._with_coverage` adds an unreported P as
  an in-scope skip `check-error` with place P (exit 2), as it does for an unreported ecosystem.
  A handler that ignores one of several paths, or a P that matches nothing (a folder with no
  venvs, a mistyped `.github/workflow`), is never a pass. PyPI reports P through the places
  under it that it checks. The GitHub Actions handler (`commands/check_repo.py`) reports each
  P that matched at least one workflow source as a checked entry with place P, once the
  repository's check finishes; a P that matched none stays unreported.
- **Out-of-scope skips** do not change the code. In-scope skips give 2.
- A result stores its lists as tuples and checks each element's type on construction, so a
  one-shot iterator or a stray value cannot make the summary and the exit code disagree.
- Equal findings are one fact (one Action used in two jobs of a workflow) and are kept once. A
  result holding two different findings with one ID is refused, so the run is unfinished
  (exit 2): anything that tracks by ID would merge them, and fixing one would hide the other
  (D14). A finding built with `make_finding` keeps a valid `via` when a value is malformed, so a
  malformed item reached through two outer Actions stays two findings; a `MalformedValueError`
  raised inside `Collector.check` carries no chain, so there the two collapse into one finding
  (still exit 1). Two spellings of one name share an ID (D18) but are not equal findings, so a
  handler must merge them (keep the first spelling) before building findings; one that does not
  makes the run unfinished (exit 2), never a pass. **Note for #5, #8 and #10.**
- **Warnings never fail.** Each rule has one fixed level (§4), so a warning cannot be raised as a
  violation or the reverse.
- `IncompleteCheckError` accepts only in-scope reasons, and `Collector.check` checks the reason
  again when it records the skip, so a failed check cannot be reported as out of scope.

## 4. Result model (fixed templates)

**Levels:** `violation`, `warning`, `notice`.

**Rules and their levels:**

| Level | Rules |
|---|---|
| violation | `cooldown`, `compromise`, `known-vulnerability`, `deny-list`, `unprotected`, `malformed-name`, `moving-reference` (T1), `unverified-pin` (T4), `impostor-commit` (T4), `young-repository` (T3), `nested-moving-reference` (T5), `nesting-limit` (T5), `nesting-loop` (T5), `unreleased-pin-advisory` (T6, "cannot rule out") |
| warning | `unpushed-commit` (T2), `moved-release-tag` (T1), `degraded-feed`, `kev-unavailable`, `unpinned-image` |
| notice | `cooldown-wait` (T2, "eligible on"), `first-use-publisher` (T3), `weakened-setting` (stricter wins), `hidden-pip`, `ci-overrides` |

**Skip reasons:**

| In scope (exit 2) | Out of scope (exit unchanged) |
|---|---|
| `feed-failure`, `unknown-age`, `unsupported-yaml`, `rate-limit`, `default-branch-unreadable`, `check-error`, `not-available` | `filtered`, `later-release`, `deeper-than-one-level`, `local-install` |

`default-scope` was removed with the default scope (#255), after which no command could emit it
(#282).

**Other enums:** ecosystems `pypi`, `github-actions`; labels `actively-exploited`,
`registry-quarantined`; option kinds `replace`, `protect`, `remove`, `exception`; override
categories `not-exploitable`, `no-fix-available`, `deferred-upgrade`, `accepted-risk`; limit names
(override references for a limit) `nesting-depth`, `nested-reference-count`, `nesting-loop`,
`nested-moving-reference`.

**Options.** `replace` names an item and version and, once eligible, a command; before that, an
`eligible_on` date and no command. `protect` carries `ssc-guardian protect [pip|uv] --path PATH`,
whose
`PATH` is the finding's own place (#255). `remove`
is the user's decision and has no command. `exception` goes to a person and has no command in
JSON; text output names `ssc-guardian acknowledge OWNER/REPO` or `ssc-guardian override add`.
A command can only be one of three shapes, built from grammar-checked values:
`install --venv PATH NAME==VERSION`, `pin ACTION@REF`, `protect [pip|uv] --path PATH`. A `replace`
command
installs or pins exactly the option's item and version, uses `install` for `pypi` and `pin` for
`github-actions`. A `replace` option has exactly one of a command (once eligible) and an
`eligible_on` date (before that). A `protect` option carries only the `protect` shape, naming its
finding's place, and only on a `pypi` finding. An
`exception` option names `acknowledge` with its `OWNER/REPO`, or `override add` with no target.

## 5. JSON format version 1.0

Output of `--json`: one object, keys sorted, ASCII only. Every key below is always present
(`null` or `[]` when empty). Adding a key, removing one or changing a value set is a contract
change. Additive changes (a new enum value) raise the minor version; anything else raises the
major version. The skip reason `local-install` (§4) was added by #97 within format 1.0 by the
owner's ruling of 2026-11-05, before the release, as `reference` for `nested-moving-reference`
(below) and the `registry-quarantined` label (§10.6) were.

| Object | Keys |
|---|---|
| result | `format_version` ("1.0"), `tool`, `command` (`check`, `protect`, `install`, `pin`), `exit_code`, `summary`, `findings`, `checked`, `skipped`, `overrides` |
| tool | `name` ("ssc-guardian"), `version` (PEP 440), `commit` (40-hex or null) |
| summary | `violations`, `warnings`, `notices`, `checked`, `skipped_in_scope`, `skipped_out_of_scope` (integers) |
| finding | `id`, `rule`, `level`, `ecosystem`, `place` (path), `item`, `version`, `evidence` (advisory IDs), `labels`, `options`, `malformed_field` (`place`, `item`, `version`, `evidence`, `via` or null), `via` (the outer Actions a nested finding was reached through, outermost first, each an `action-step`, `ACTION@REF`; `[]` otherwise) |
| option | `kind`, `item`, `version`, `command` (argv list or null: pass each element as exactly one argument, never join them with spaces), `eligible_on` (date or null), `requires_user_approval`, `requires_person` (booleans) |
| checked | `ecosystem`, `place` |
| skipped | `ecosystem` (or null), `place` (or null), `reason`, `in_scope` |
| overrides | `applied`, `expired` (lists of override) |
| override | `id`, `ecosystem`, `item`, `version`, `rule`, `reference` (advisory ID or limit name; for `nested-moving-reference`, the inner reference exactly as written, an `action-step`, added by #10 within format 1.0 by the owner's ruling of 2026-11-03), `category`, `expiry` (date) |

**Never in JSON:** override reasons, acknowledgment notes, the raw value of a malformed name,
an exception's details, and the `acknowledge` and `override add` commands. `render.to_json`
refuses a result whose command is `acknowledge` or `override add`.

**Finding ID.** The first 32 hex characters (128 bits, D6) of SHA-256 over the compact JSON
array `[rule, place, ecosystem, item, version, malformed_field, malformed_value, via]` (nulls
included; `via` a list). The same inputs give the same ID on every run. The outer-Action chain
gives one inner reference reached through two outer Actions two IDs (D14). The item, and the
Action in each `via` step, is hashed in its ecosystem's one spelling, while the finding still
shows it as found: the PEP 503 name for PyPI (`Requests`, `requests` and `REQUESTS` are one ID;
so are `zope.interface` and `zope-interface`), and for an Action the owner and repository
lowercased, as GitHub matches them (a path inside the repository and the Git ref are
case-sensitive and kept as given). A PyPI version is hashed in its PEP 440 normalized form with
trailing zero release parts dropped (`1.0`, `1.0.0` and `v1.0` are one ID; `pep440.canonical`), and
a Git ref as given (D18). The last two members are null except on a `malformed-name` finding, where
they keep two different malformed values at one place apart.

**Text output.** Built from the same result as JSON. It strips every Unicode control, format
(including bidirectional overrides), line-separator, surrogate (from undecodable bytes),
private-use and unassigned character from each value it prints. Commands are shell-quoted
(`shlex.join`), so a path with a space copies correctly. A stream that cannot encode a
character gets an ASCII escape for it. Colour only on a terminal, and never when `NO_COLOR`
is set to a non-empty value. Usage-error messages, which echo arguments, are stripped too.
The rejected raw value of a malformed name is the one exception to stripping: every character
outside printable ASCII is shown as a `\uXXXX` (or `\UXXXXXXXX`) escape and a backslash is
doubled, so a value that is malformed only
because of an invisible or lookalike character (a Cyrillic `е` in `requests`) does not print
as a valid-looking name.

## 6. Field grammars (plan §3.2, R1-K7)

Every match is a full match (`$` would allow a trailing newline), and ASCII only (with
case-insensitive matching, Python would otherwise let `[A-Z]` match the Kelvin sign, the long
s and the dotless i). Nothing is repaired.

| Field | Pattern (summary) | Max length |
|---|---|---|
| `pypi-name` | PEP 508 name: letters and digits at both ends, `._-` inside | 200 |
| `pep440-version` | PEP 440 (the specification's appendix pattern) | 128 |
| `owner-repo` | owner: letters, digits and hyphens, 1–39, not starting with a hyphen (doubled and trailing hyphens allowed for older accounts, D12); repo: `[A-Za-z0-9._-]`, 1–100, not `.` or `..` | 140 |
| `action` | `owner/repo` plus optional `/path` segments (no `.` or `..`) | 255 |
| `git-ref` | `[A-Za-z0-9._+-]` components separated by `/`; no `..`, no leading `.` or `-`, no `.lock` or `.` ending | 255 |
| `sha` | 40 lowercase hex | 40 |
| `advisory-id` | `CVE-YYYY-N…`, `GHSA-xxxx-xxxx-xxxx` (GitHub's lowercase alphabet), `MAL-YYYY-N…`, `PYSEC-YYYY-N…` | 64 |
| `path` | absolute: one or more `/`-prefixed components of `[A-Za-z0-9 ._+@,=~()-]`; no `.` or `..` component; no space followed by `-`; no trailing `/`; not `/` alone | 1024 |
| `date` | `YYYY-MM-DD`, a real date | 10 |
| `override-id` | 32 lowercase hex (D6) | 32 |
| `action-step` | one `via` step: an `action`, `@`, and a `git-ref`, each checked exactly (D14) | 511 |
| `docker-image` | the image a `docker://` reference names, the prefix not part of it: an optional registry host (a `.`-separated name with an optional `:port`, a name with a port, or `localhost`) and `/`; one or more `/`-separated lowercase path components (`[a-z0-9]` runs joined by `.`, `_`, `__` or hyphens); an optional `:tag` (`[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`); an optional `@sha256:` and 64 lowercase hex | 255 |

A space is allowed in a path, so a fix command's venv path may hold one (`/tmp/a b`); it is not
refused (owner's ruling, 2026-11-03, #26). The no-space-before-hyphen rule stops a command
joined with spaces gaining an option, but not a positional argument (`/tmp/a b` would become
venv `/tmp/a` plus package `b`). So a fix command is an argument list: each element is exactly
one argument, and it must never be joined into one string (text output shell-quotes it, §5).

Per ecosystem, a finding's `item` and `version` use: `pypi`: `pypi-name`, `pep440-version`;
`github-actions`: `action`, `git-ref` (a 40-hex SHA is a valid `git-ref`), except that an
`unpinned-image` finding's `item` is the image, a `docker-image`, and its `version` is null.

`docker-image` was added by the owner's ruling, 2026-11-09, #127, so the `unpinned-image`
warning names both the file and the image. Only a `@sha256:` digest pins an image; a tag can
move. An image that fails the grammar is a `malformed-name` violation (exit 1), as for the
other fields: it is never the finding's `item` and never in JSON, and text output shows the
rejected value escaped (§5).

## 7. Plug-in protocol (plan §2.3)

`src/ssc_guardian/plugin.py` defines `EcosystemPlugin`, a `typing.Protocol`. The interface is
internal in v1.0. A plug-in reports facts; rules, feeds, overrides, exit codes and output belong
to the core. Every function that cannot establish its facts raises `IncompleteCheckError` with
an in-scope reason and never returns a guess (exit 2). A value that fails its grammar raises
`MalformedValueError`, which the core reports as a `malformed-name` violation (exit 1).

| Member | Guarantee |
|---|---|
| `name` | `pip`, `uv` or `github-actions` |
| `ecosystem` | the ecosystem whose items it reports |
| `code_execution` | constant: `never` (no package code at all), `can-be-turned-off` (always turned off), `always` (core states that build code will run) |
| `discover(scope) -> Discovery` | reads files only, never runs a found program; lists every place covered and every place it could not read; names each place with its symlinks resolved, as the core does for path arguments; nothing outside `scope`, judged by the resolved place; a place that resolves outside `scope` (a symlinked workflow pointing out of the repository) is listed in `skipped` as `check-error` under the path where it was found inside `scope`, never passed over silently; changes nothing |
| `trusted_age(item) -> TrustedAge` | only the `AgeSource` sources (`registry-upload`, `activity-log`, `immutable-release`, `person-date`, `lock-first-seen`); earliest trusted date; a person's date only moves it later; `UNKNOWN_AGE` rather than a guess |
| `plan_install(target, requirements) -> InstallPlan` | runs no package code; resolves the full set `apply` would write, each downloaded file bound to its digest; writes nothing; a plug-in that does not install (uv) raises `NOT_AVAILABLE` |
| `apply(plan) -> None` | called only after every check passed and the user confirmed; writes only `plan`'s files into `plan.target` and the files `plan.also_writes` names (a pin's lock file), nothing else (D16) |
| `write_cooldown(setting) -> None` | `protect`'s writer (D16): called only after the user saw and confirmed the change; writes only that setting at `setting.place`; never runs the installer; refuses a setting with no value |
| `installer_cooldown(place) -> CooldownSetting` | reads files only, never runs the installer; a missing setting is reported as missing, never as a default |

Data shapes (`Item`, `Requirement`, `Discovery`, `TrustedAge`, `PlannedFile`, `InstallPlan`,
`CooldownSetting`) check their values on construction: names and versions by grammar; HTTPS
URLs with no spaces or control characters; lowercase hex digests of the named algorithm (`sha256`
or `sha512`); dates that are dates, not datetimes; whole-number rolling cooldowns; a cooldown
that is rolling or fixed, never both; an `InstallPlan`'s `also_writes` paths grammar-checked,
each named once and never the target. Lists are stored as tuples of the declared type.

## 8. npm paper test (2026-11-02)

The npm plug-in's signatures, written against the protocol. Nothing is built.

```python
class NpmPlugin:  # paper only; npm is outside v1.0
    name = PluginName.NPM                             # new value
    ecosystem = Ecosystem.NPM                         # new value "npm"
    code_execution = CodeExecution.CAN_BE_TURNED_OFF  # install scripts off: --ignore-scripts

    def discover(self, scope: Scope) -> Discovery:
        # Reads package-lock.json and node_modules/.package-lock.json from disk; runs nothing.
    def trusted_age(self, item: Item) -> TrustedAge:
        # Registry document's time[version] -> AgeSource.REGISTRY_UPLOAD.
    def plan_install(self, target: str, requirements: tuple[Requirement, ...]) -> InstallPlan:
        # Resolve to a lock file with scripts off; each tarball URL bound to its
        # integrity value, which npm records as SHA-512.
    def apply(self, plan: InstallPlan) -> None:
        # Install exactly the planned lock file with --ignore-scripts.
    def installer_cooldown(self, place: str) -> CooldownSetting:
        # .npmrc "before" (a fixed date), the same form as pip 26.0.
    def write_cooldown(self, setting: CooldownSetting) -> None:
        # Writes .npmrc "before"; added by D16 after the paper test, and it fits npm too.
```

**Result: the protocol fits npm with one change, made before freezing.**

1. **Changed:** `PlannedFile` carried only a SHA-256 digest. npm's `integrity` is SHA-512, so a
   planned file now names its algorithm (`DigestAlgorithm`: `sha256`, `sha512`).
2. **Additive (format 1.x, at npm time):** `Ecosystem.NPM`, `PluginName.NPM`, and two grammars,
   npm names (`@scope/name`, lowercase, up to 214) and semantic versions, mapped in `findings`,
   plus npm's rule for the finding-ID spelling (D18), without which an npm finding's ID raises an
   error rather than hash an unchecked spelling. No function signature changes.
3. **Plan, not protocol:** npm's resolver is a program Guardian would have to run. The §2.3
   execution boundary lists exactly three programs; npm support needs a fourth, decided then.
4. `code_execution`, `discover`, `trusted_age` and `installer_cooldown` fit as written.

Cargo's paper test waits for the Rust work (plan §2.3).

## 9. Owner decisions at the checkpoint (2026-11-02)

These go beyond, or settle details left open in, the plan text. The owner ruled on each on
2026-11-02; the code and this record follow the rulings. Notes for later issues are marked.

- **D1 Checkpoint split. Approved.** #2's contracts are frozen now. The settings and override
  formats (#3) and the lock-file format are added to this record at their own approval. The
  lock-file design moves from #9 (M2) into M1 as #28, because the protocol already depends on it
  (`AgeSource.LOCK_FIRST_SEEN`, and `pin` writes it through `also_writes`, D16). **Note for
  #9:** the format is §11, read and written by `src/ssc_guardian/lockfile.py` (#28), which
  replaces #9's `plugins/actions/lockfile.py`; #9 builds the resolver, `pin` and the T4 check
  on it.
- **D2 Approved.** `acknowledge` and `override add` refuse `--json` as well as `--yes` (the plan
  states only `--yes`); their output is text only, for a person.
- **D3 Path grammar. Approved.** Absolute paths of ASCII letters, digits, space and
  `._+@,=~()-` only, with no space followed by `-` (so a fix command joined with spaces cannot
  gain an option). A venv or workflow under a folder with any other character (for example
  accented letters or an apostrophe) is a `malformed-name` violation, not skipped, and cannot be
  overridden; the text output names the refused character by code point and says to rename or
  move the folder. Spaces, `~` and parentheses are allowed because macOS folders use them
  (`Mobile Documents`, `com~apple~CloudDocs`, `Dropbox (Personal)`). The set is not what the
  file system allows (macOS allows nearly any character) but what is safe to show in a command
  and to an agent. Widening it later breaks no one; narrowing it would. `/` itself is not a
  valid place, so `check --repo` run from `/` is malformed. A `place` can still carry
  instruction-like text taken from a folder or file name, and workflow file names in a cloned
  repository are chosen by its authors; that is why agents are told that JSON values are data.
- **D4 Advisory IDs. Approved.** Only CVE, GHSA, MAL and PYSEC IDs appear in output and in
  override references. **Note for #4:** the feed reader drops an alias of any other ID type
  when the advisory has at least one of the four; an advisory with none of them is a
  `malformed-name` violation (exit 1), never dropped, so a feed's new ID type cannot hide a
  vulnerability.
- **D5 Install packages. Approved.** `NAME` (loose) or `NAME==VERSION` (exact) only; any other
  specifier is malformed, and the text output names the supported forms. #6 adds the refusals
  for URLs, VCS, local paths and editables. Extras are the first widening after v1.0 (#29).
- **D6 Finding ID. Changed by the owner:** 32 hex characters (128 bits) of SHA-256, as defined
  in §5, so an ID is safe even where a tool uses it as a key. Override IDs are 32 hex too.
- **D7 Approved.** Each rule has one fixed level (§4); exceptions go through overrides only. A
  team setting that may only make a rule stricter is reserved for a later release (#30).
- **D8 Approved.** Usage errors and not-yet-built verbs exit 2; the message says which.
- **D9 Approved.** Option objects carry all seven keys, with nulls where a key does not apply.
- **D10 Approved.** An override's item is split into `ecosystem`, `item` and `version` in JSON,
  matching findings.
- **D11 Approved.** `--language` accepts only `python` in v1.0; any other value is refused
  (exit 2) with the supported languages named (§2), never skipped.
- **D12 GitHub owner names. Approved with a change:** letters, digits and hyphens, with
  doubled and trailing hyphens allowed for older accounts; a leading hyphen is still refused,
  because the name would read as an option.
- **D13 Approved.** The T5 override for "that exact outer commit and inner reference" needs a
  reference shape beyond advisory IDs and limit names. **Note for #3 and #10**, which settle
  it under three constraints: it is a new, additive kind of reference; it names the outer
  Action's exact commit SHA, never a tag, so a new outer release brings the finding back; and
  it names the inner reference exactly as written, so the override lapses if that changes.
- **D14 Finding-ID collisions. Approved.** A finding carries `via`, the outer-Action chain it
  was reached through, and the ID hashes it, so one inner reference reached through two outer
  Actions gives two IDs (T5); `make_finding` keeps a valid chain on a malformed value, and equal
  findings are kept once (§3, which also states the handlers' duty to merge spellings). **Note
  for #4:** a package version gets one `known-vulnerability` finding listing every advisory,
  never one finding per advisory. As a safety net, a result with two different findings sharing
  an ID is refused (exit 2, §3).
- **D15 Confirmation. Approved as proposed** (§2): declined or impossible gives exit 2 with
  nothing written; `--yes` still prints the change, to stderr; the question goes to stderr.
  **Note for #3, #5, #6 and #9**, whose commands write.
- **D16 Plug-in protocol gaps. Approved.** `write_cooldown(setting)` writes an installer's
  cooldown for `protect` (the setting carries its place), and `InstallPlan.also_writes` names
  every file outside the target that `apply` writes, such as `pin`'s lock file (§7).
- **D17 Approved.** `~` in a path argument is expanded to the home folder before the path is
  checked, as a shell would. A path quoted to keep a literal `~` therefore names a different
  place; write `./~/...` for a folder named `~`.
- **D18** Equivalent spellings in the finding ID. **Approved.** One package,
  repository or place under two spellings gets one ID (§5): the ID hashes the PEP 503 name for
  PyPI and the lowercased owner and repository for an Action; path arguments and plug-in places
  have their symlinks resolved (`/tmp/x` and `/private/tmp/x` are one place). Letter case in a
  path is otherwise kept, because whether it matters depends on the file system, so `/Users/a`
  and `/users/a` remain two IDs, as does a path through a symlink the system cannot follow
  (dangling, in a loop, or in too long a chain), which is kept as typed rather than guessed, and
  a part under a folder that cannot be searched, which is kept as typed after its resolved
  parent (§2). A PyPI version is hashed in its PEP 440 normalized form (`1.0` and `1.0.0` give
  one ID), added by #4; with it the ID formula is frozen.

## 10. Settings and override files (plan §2.4; issue #3)

**Status: APPROVED by the owner on 2026-11-03 (D1), with the answers in §10.6.**

### 10.1 Files, and who reads them

| File | Place | Holds | Read by |
|---|---|---|---|
| `.ssc-guardian.toml` | repository root (Git top level) | settings, deny list, acknowledgments | `check --repo`, `pin`, `acknowledge` |
| `.ssc-guardian-overrides.toml` | repository root | overrides for `github-actions` only | `check --repo`, `pin` |
| `config.toml` | `~/.config/ssc-guardian/` | settings, deny list | `check` (every form; `check --repo` in CI too), `protect`, `install`, `pin`, `acknowledge`; never `override add` |
| `overrides.toml` | `~/.config/ssc-guardian/` | overrides for `pypi` only | `check --envs`, `protect`, `install` |

- The workstation folder is always `~/.config/ssc-guardian/`; `XDG_CONFIG_HOME` is not read,
  so there is one place to protect.
- Loading is all or nothing, per file. A file that is not UTF-8, not TOML, larger than 1 MiB,
  has `format` other than `1`, an unknown key anywhere, a value of the wrong type or outside
  its range, or a value that fails its grammar (§6) is **malformed**: the command reports an
  in-scope skip `check-error` naming the file (exit 2), and nothing in that file applies. A
  malformed overrides file therefore releases nothing; findings it would have released still
  count (exit 1 wins over 2). A file never falls back to defaults.
- A missing file is not an error: that layer sets nothing.
- An unknown key is refused rather than ignored, because a mistyped key would silently leave a
  weaker built-in value in place.

### 10.2 Settings: `.ssc-guardian.toml` and `config.toml`

Both files have the same shape; a part marked for one file only makes the other malformed. Every
key except `format` is optional.

```toml
format = 1
deny = [
  "pypi:example-bad",                  # config.toml only
  "github-actions:example/bad-action",
]

[defaults]
cooldown_days = 21               # whole days, 0-3650          built-in 21
block_on = "strong"              # "never" | "strong" | "any"  built-in "strong"
fixed_date_tolerance_days = 7    # 1-3650; only lowers the computed tolerance (§3.1)
young_repository_days = 90       # T3, 90-36500; only raised   built-in 90
min_stars = 50                   # T3, 50-10000000; only raised built-in 50
nesting_depth = 10               # T5, 1-10                    built-in 10
nested_reference_limit = 500     # T5, 1-500                   built-in 500

[rules]                          # per-item settings; the key names its ecosystem
"pypi:requests" = { cooldown_days = 30 }                     # config.toml only
"github-actions:actions/checkout" = { cooldown_days = 7 }

[[acknowledgment]]               # .ssc-guardian.toml only; written by `acknowledge` (#10)
repository = "owner/repo"        # owner-repo grammar
repository_id = 123456789        # GitHub's numeric ID; a changed ID voids it
date = 2026-11-03                # TOML date
note = "free text, text output only"

[[start_date]]                   # T2: a person's start date for one commit (#9)
action = "owner/repo"            # action grammar
sha = "0123456789abcdef0123456789abcdef01234567"
date = 2026-11-01
```

- **Ecosystem prefix.** Every key in `[rules]` and every `deny` entry is `pypi:NAME` or
  `github-actions:ACTION`, with the name checked by its grammar (§6). An unprefixed or
  unknown-prefix entry makes the file malformed; it is never guessed. Names match in their one
  spelling (D18): PEP 503 for PyPI, owner and repository lowercased for an Action. No globs.
  A `github-actions:OWNER/REPO` deny entry also denies every Action under a path in that
  repository (`OWNER/REPO/sub`), whose code comes from the same repository; an entry with a
  path denies only that path (N6).
- **Within one file**, a `[rules]` entry replaces that file's default for that item, in either
  direction (Q4): it may shorten the item's cooldown. **Across files**, stricter wins (§10.3).
- A `pypi:` deny entry and a `pypi:` `[rules]` key in `.ssc-guardian.toml`, and
  `[[acknowledgment]]` in `config.toml`, make the file malformed (an in-scope skip naming the
  file, §10.1; for a `pypi:` entry the message names its line, unless the entry is spelled with
  escapes, and says to move it to `config.toml`): the commands that would use
  them never read them there, so they are refused rather than ignored. A `github-actions:` entry
  is valid in both files.
- Settings change the rules, never what a command reads (owner's rulings of 2026-11-13 and
  2026-11-14, #255). `[scope]` is removed: a file that still holds it (`venv_folders` or
  `ecosystems`, in either file) is malformed (exit 2), and the message names its line and the
  arguments that replace it (`--path`, and `--envs`, `--repo` or `--ecosystem`). It is refused,
  never ignored.
- `[[acknowledgment]]` and `[[start_date]]` entries are unique by `repository` and by
  (`action`, `sha`); a duplicate makes the file malformed.
- Free text (`note`) is at most 500 characters on one line and never reaches JSON.

### 10.3 Stricter wins

The layers are the workstation `config.toml`, the repository's `.ssc-guardian.toml` (for
commands that read it), the default branch's copy in CI (§10.5), and the command line. For each
item, a layer's value is its `[rules]` entry for that item, else its `[defaults]` value; a layer
that sets neither takes no part. The stricter of the values the layers set applies. **Built-in
defaults are only the fallback** when no layer sets a value; they take no part in stricter-wins,
so a file's `[rules]` entry can apply below a built-in default (`"pypi:requests" = {
cooldown_days = 3 }` gives 3 days when no other layer sets a cooldown for it). **In CI** the
default branch's layer has the built-in defaults beneath its own values (B1, §10.5), so a
change can only tighten, never go below a built-in value the default branch leaves unset.

| Value | Stricter is |
|---|---|
| `cooldown_days` | larger |
| `block_on` | `never` < `strong` < `any` |
| `fixed_date_tolerance_days` | smaller |
| `young_repository_days`, `min_stars` | larger |
| `nesting_depth`, `nested_reference_limit` | smaller |
| `start_date` (same action and SHA) | later |
| `deny` | union: an entry in any layer denies |
| `acknowledgment` | locally: union; in CI: the default branch's only (§10.5) |

- Each value that a higher layer would have made weaker is reported as one `weakened-setting`
  notice (exit unchanged): the finding's `place` is the weaker file (null for the command
  line), its ecosystem and item are the rule's (null for a `[defaults]` value); text output
  names the key, both values and which applied.
- A **deny entry** gives a `deny-list` violation (exit 1) whatever any other layer, override
  or acknowledgment says. It cannot be overridden.
- The command line has no setting flags in v1.0 (§2 is frozen). `settings.py` still takes a
  command-line layer, which can only tighten, so a later flag cannot weaken a rule.

### 10.4 Overrides: `.ssc-guardian-overrides.toml` and `overrides.toml`

```toml
format = 1

[[override]]
ecosystem = "pypi"
item = "example-package"           # item grammar for the ecosystem
version = "1.2.3"                  # version grammar for the ecosystem (an Action: 40-hex SHA)
rule = "known-vulnerability"
reference = "CVE-2026-12345"
category = "deferred-upgrade"
created = 2026-11-03               # the day `override add` wrote it
expiry = 2026-12-01                # last day it applies
reason = "free text, text output only"
```

**What can be overridden, and the reference each rule takes:**

| Rule | `reference` | Longest expiry from `created` |
|---|---|---|
| `known-vulnerability` | advisory ID (CVE, GHSA, PYSEC) | 90 days; 7 days if KEV-listed |
| `compromise` | advisory ID (MAL, GHSA) | 7 days (confirmed malware) |
| `unreleased-pin-advisory` | GHSA ID | 90 days; 7 days if KEV-listed |
| `nested-moving-reference` (T5) | the inner reference exactly as written, `ACTION@REF` (`action-step`, D13; accepted since #10, Q2) | 90 days |
| `nesting-limit`, `nesting-loop` | limit name (§4) | 90 days |

#10 widened `OverrideRecord` and §5 to the `action-step` reference (Q2): it is accepted for
`nested-moving-reference` only, which takes no other reference, and with any other rule it
makes the overrides file malformed. Every other rule is refused in an override (Q3): `deny-list`
(blocks whatever any layer says), `malformed-name` (D3), `young-repository` (its exception is
`acknowledge`),
`unprotected`, `moving-reference`, `unverified-pin` and `impostor-commit` (their fix is
`protect` or `pin`), and `cooldown` (its exception is a `[rules]` entry; plan §2.4 gives
overrides no reference for it).

- **Exact item.** An override names one ecosystem, item and exact version. For an Action the
  version is the 40-hex commit SHA, never a tag. For T5 and the limits, `item` and `version`
  are the outer Action and its exact commit (D13), so a new outer release brings the finding
  back; a changed inner reference no longer matches, so the override lapses.
- **One finding, several advisories** (D14 note for #4): an override releases its own
  advisory, named by any of its IDs (the advisory's ID or one of its aliases, as its feed lists
  them; §10.6). A `known-vulnerability` finding is released only when every advisory it lists
  is, so two advisories still need two overrides. An ID that two advisory records share names
  one vulnerability: one override on it releases both records (owner ruling, #70). A PYSEC
  record that lists two CVEs is one advisory, so an override on either CVE, or on the PYSEC ID,
  releases it (#42).
- **Quarantine is never released.** A `compromise` finding whose package PyPI has quarantined
  carries the `registry-quarantined` label; no override releases it, whatever its reference,
  because the quarantine is a fact about the registry, not an advisory. A quarantined package
  with no malware record has an empty `evidence` list and cannot be named by an override at
  all. An override that matches such a finding and would otherwise apply is not applied and
  is named in the stderr note below, `override <id> not applied: PyPI has quarantined this
  package`, in text and `--json` runs alike; one that has expired stays under
  `overrides.expired` (§10.6, #87).
- **Override ID** (32 hex, D6): the first 32 hex characters of SHA-256 over the compact JSON
  array `[ecosystem, item, version, rule, reference]`, with the item and the version in their
  one spelling (D18): a PyPI version in its PEP 440 normalized form, an Action's commit SHA as
  given. It is computed, never stored. An override matches a finding's version in that same
  spelling; the file keeps the version as written. Two entries with one ID make the file
  malformed, so two spellings of one version in one file do.
- **Which file.** `pypi` overrides live only in the workstation `overrides.toml`;
  `github-actions` overrides only in the repository's `.ssc-guardian-overrides.toml`. An entry
  in the wrong file makes it malformed.
- **Bounds checked at load.** `created` is not after today; `expiry` is not before `created`;
  `expiry - created` is within the rule's longest expiry above; `reason` is 1–500 characters
  on one line. Breaking any of them makes the file malformed (releases nothing).
- **Re-checked every run against current facts** (plan §2.4, R2-K4). An override applies only
  if, today:
  1. `today <= expiry`. No grace period. Otherwise it is listed under `overrides.expired`.
  2. For `known-vulnerability` and `unreleased-pin-advisory`: KEV status is known. If the
     advisory is now KEV-listed, the override ends once `today > created + 7 days` (listed as
     expired). If KEV could not be reached, the override is **not applied** and the
     vulnerability counts (exit 1), with the reason printed on stderr.
  3. For `known-vulnerability`: the check for a fixed version that passes every rule and that
     Guardian can install or pin now (installed or not) finished and found none. If such a version
     exists, the override has ended (listed as
     expired); if the check could not finish, it is **not applied**.

  An override that is not applied is named with its reason in a stderr note,
  `override <id> not applied: <why>`, control characters stripped, in text and `--json` runs
  alike: one note per override per finding per run, so a package in two environments gives
  two notes and `install` prints each note once however many requests fail (§10.6, #38, #89).
- Every applied override appears under `overrides.applied`; an override that has ended appears
  under `overrides.expired` (§5). One that matches no finding this run is not listed. One
  whose finding stays unreleased because another of its advisories has no override that
  applies is not applied and is named in the stderr note above, `override <id> not applied:
  the finding's other advisories have no override that applies: <IDs>`, one ID per uncovered
  advisory (the first, in sorted order, of its IDs that `override add` accepts for the
  finding's rule, else its first ID): an override is applied only when its finding is
  released (D14; §10.6, #89). A limit finding (T5) is released by the limit it names and gets
  no such note.
- **Locally**, `check --repo` applies the repository's overrides and adds one `ci-overrides`
  notice: "CI uses only the default branch's overrides."

**`override add`** (§2: no flags; refuses `--yes` and `--json`, D2):

1. With no terminal on stdin, it writes nothing and exits 2.
2. It asks, on stderr, for each field in turn (Q1): ecosystem, item, version, rule,
   reference, category, expiry, reason. Each answer is checked by its grammar and the bounds
   above at once; a bad answer is asked again, at most three times, then exit 2.
3. It shows the entry and the file it will write, and asks "Write this override? [y/N]" on
   stderr. For `compromise`, or a KEV-listed advisory, it shows a second, stronger warning and
   asks the person to type the reference ID. When KEV status is unknown it says the override
   ends 7 days after `created` if the advisory is KEV-listed.
4. Declined, or no answer: nothing written, exit 2 (D15).
5. Idempotent: an entry identical to one already in the file (same ID and fields) writes
   nothing and exits 0. An entry with the same ID and other fields is shown as a replacement
   (old and new) and confirmed the same way. There is never a second entry with one ID.
6. The repository file is the one at the Git top level of the current folder; outside a
   repository, a `github-actions` override is refused (exit 2).
7. Exit 0 once written. The command and its free text never appear in JSON (D2).

### 10.5 CI (plan §2.4, R1-K5, R2-K3, FC-3)

- Guardian is in CI when `GITHUB_ACTIONS` is exactly `true`. The repository is
  `GITHUB_REPOSITORY` (`owner-repo` grammar); the token is the first set of `GH_TOKEN` and
  `GITHUB_TOKEN` (`net.py`); a workflow passes `GITHUB_TOKEN` with `contents: read`.
- It reads the repository's default branch name from `GET /repos/{owner}/{repo}`, then lists
  the root of that branch (`GET /repos/{owner}/{repo}/contents/?ref={branch}`), then fetches
  `.ssc-guardian.toml` and `.ssc-guardian-overrides.toml` if the listing shows them (Q5). A
  file the listing positively does not show is absent on the default branch (that layer sets
  nothing). Every other outcome (any non-200 status, including 403 and 404 for the repository
  or the listing, a network failure, a rate limit, a malformed listing or a malformed file) is
  an in-scope skip `default-branch-unreadable` for every in-scope ecosystem (exit 2).
- Settings: stricter wins across the change's `.ssc-guardian.toml` and the default branch's
  copy (§10.3), with the built-in defaults beneath the default branch's own values (B1). A file
  absent from the default branch therefore contributes the built-in defaults: the first pull
  request that adds `.ssc-guardian.toml` passes only if it tightens. Overrides and acknowledgments:
  the default branch's only; the change's copies
  are ignored, so a pull request cannot release its own finding.
- `ci_context.py` takes the fetch function as an argument; it never imports the network client.

### 10.6 Owner answers (2026-11-03)

- **Q1 Approved.** `override add` asks for each field at the terminal (§10.4 step 2); §2 stays
  frozen, with no flags.
- **Q2 The alternative.** #10 widens `OverrideRecord` and §5 to the `action-step` reference
  (D13). Until then #3's loader refuses such a reference (the file is malformed) and
  `override add` refuses `nested-moving-reference`. #10 has since done so: the loader and
  `override add` accept it for `nested-moving-reference` (§10.4).
- **Q3 Approved.** The overridable rules are those in the §10.4 table; `cooldown` is not
  overridable.
- **Q4 Approved.** A `[rules]` entry may shorten an item's value within its own file. Built-in
  defaults are the fallback when no file sets a value and take no part in stricter-wins (§10.3).
- **Q5 Approved.** A file that a successful listing shows is absent from the default branch
  sets nothing; every other failure is exit 2.
- **Q6 Approved.** `override add` rewrites the overrides file whole and atomically, so comments
  in it are not kept and its first line says so; `.ssc-guardian.toml` is only appended to.

Rulings on the review of the first implementation (2026-11-03):

- **B1 Built-ins as the floor in CI.** In CI the default branch's layer is the built-in
  defaults overlaid by its own file (or the built-in defaults alone when it has none), so a
  pull request can only tighten a setting. The floor covers the default scope too (every
  ecosystem), and a value held only by the floor is never reported as weakened. Locally and on the
  default branch, Q4 holds as
  written.
- **N6 A repository's deny entry covers its sub-path Actions** (§10.2).
- **N8 Renewal allowed.** Re-running `override add` with the same fields on a later day
  replaces the entry with `created` set to today, shown and confirmed as a replacement
  (§10.4 step 5); it restarts the 90-day and KEV 7-day clocks.
- **N-4 T3 thresholds follow the plan.** `young_repository_days` and `min_stars` can only be
  raised from their built-in values (90 and 50); a lower value makes the file malformed. The
  T5 limits can only be lowered (their ranges end at the built-in values). Q4's shortening
  applies to a `[rules]` entry's cooldown only. When the exemption for Guardian's own repository
  (#233) keeps that repository from blocking as young or little-used, one stderr note says so
  (#284); exit codes, findings and JSON do not change.
- **#42 One override per advisory** (2026-11-03, the issue's proposed option). An override
  names one advisory by any one of its IDs and releases that advisory, aliases included; two
  advisories still need two overrides (D14; §10.4).
- **#38 A not-applied override's reason stays on stderr** (2026-11-03). An override that
  matched but was not applied keeps its reason in the one stderr note
  `override <id> not applied: <why>`, control characters stripped, in text and `--json` runs
  alike; `Result` gets no not-applied slot and JSON 1.0 is unchanged (§10.4).
- **#70 Quarantine is a label, never released** (2026-11-04). A `compromise` finding whose
  package PyPI has quarantined carries the new `registry-quarantined` label (§4), and no
  override releases a finding with that label (§10.4). Labels are not part of the finding ID.
- **#87 An override a quarantine blocks says so** (2026-11-04, on #70's report). An override
  that matches a `registry-quarantined` finding and would otherwise apply is not applied and
  is named in the one stderr note `override <id> not applied: PyPI has quarantined this
  package`, in text and `--json` runs alike; an expired one stays listed as expired, nothing
  is released, exit 1 stays and JSON 1.0 is unchanged (§10.4).
- **#89 An override a partly covered finding cannot use says so** (2026-11-05, on #87's
  report). An in-date override on an advisory finding another of whose advisories has no
  override that applies is not applied and is named in the stderr note `override <id> not
  applied: the finding's other advisories have no override that applies: <IDs>`, one ID per
  uncovered advisory, in text and `--json` runs alike; an expired one stays listed as
  expired, nothing is released, exit 1 stays and JSON 1.0 is unchanged. Notes are one per
  override per finding per run, so `install` prints each once however many requests fail
  (§10.4).
- **#97 A verified local install waives only the upload age** (2026-11-05, replacing the ruling
  of the same day that gave a full skip). In `check --envs`, a distribution whose PEP 610
  `direct_url.json` has `dir_info` (editable or not) with a `file://` URL, whose claim passes
  the four steps below, and whose version PyPI has no release for, is excused the `unknown-age`
  incomplete check and the `cooldown` rule: local code has no PyPI upload to count from.
  Everything else applies by name and version as for any distribution: its name stays in the
  feed queries, and `compromise`, `known-vulnerability`, `deny-list` and the other rules fire.
  A version PyPI has changes nothing: PyPI's date is used, and a release PyPI lists with no
  usable date stays `unknown-age`. A PyPI request that failed stays `feed-failure`.
  - **The row.** Each use of the waiver is one out-of-scope `local-install` skip, so it is never
    silent. `place` is the package folder; the text-only detail is `<name> <version>: editable
    install from <folder>; upload age not checked` (`local install from` when not editable),
    with `<folder>` the project folder, symlinks resolved. `format_version` stays "1.0".
  - **The four steps.** (1) `direct_url.json` is PEP 610 data with `dir_info` and a `url` that is
    `file://` with an empty or `localhost` host, an absolute path and no query or fragment.
    (2) The path, after `realpath`, is a folder. (3) That folder is not an environment prefix
    or package folder of the run and is not inside one; a project that holds its own `.venv`
    passes, since the venv is inside the project and not the other way round. (4) The folder
    holds a project file that names the distribution: `pyproject.toml` with `[project].name` or
    `[tool.poetry].name`, or `setup.cfg` with `[metadata] name`, whose value normalizes (PEP
    503) to the record's name. A folder with only `setup.py` is not verifiable.
  - **A refused claim changes nothing.** A failed step, or a file that cannot be read (too
    large, not JSON, not PEP 610 data), leaves the distribution judged as today, plus one stderr
    note in text and `--json` runs alike: `<package folder>/<record>: direct_url.json claims a
    local install but <step>; the upload age is required`. `<step>` is fixed text, never the
    file's content: `the file could not be read: <reason>`, `its URL is not an absolute file://
    path`, `the path it names is not a folder`, `the folder it names is inside an environment
    of this run` or `no project file in the folder names the distribution`. No in-scope skip
    reason is added. A `vcs_info` or `archive_info` install makes no claim and gets no note, and
    a distribution with no `direct_url.json` that PyPI does not know stays `unknown-age`.
    An `unknown-age` skip for a distribution's release, from `check --envs` or `install --venv`,
    names the distribution and version in its text-only detail, `<name> <version>` (normalized
    name, canonical version), like the `local-install` row's detail; §5's JSON skip object
    (`ecosystem`, `place`, `reason`, `in_scope`) is unchanged (#298).
  - **Why only the age.** `check --envs` audits files the distribution itself shipped. An index
    install can carry its own `direct_url.json` and the same editable-style `.pth` and finder
    layout a flat-layout editable install has, and once its code has run it can create the
    folder and project file a verification looks for. No rule on the record separates the two
    without also refusing genuine editable installs, so a full skip could not be made safe.
    What a local install genuinely lacks is a PyPI upload, so that is all it is excused from.
    `install --venv` is unchanged: it judges only pip's report, and refuses local requests.

## 11. Lock file: `.ssc-guardian.lock` (plan §3.2 T2 and T4; issue #28)

**Status: APPROVED by the owner on 2026-11-03 (D1), with the answers in §11.4.** Fits the
frozen `AgeSource` and `InstallPlan.also_writes` (§7, D16) without changing them.

### 11.1 File, and who reads it

| File | Place | Holds | Read by |
|---|---|---|---|
| `.ssc-guardian.lock` | repository root (Git top level), committed | each pinned Action commit: its source tag, first-seen date and trusted date | `check --repo` (T4: is the pin listed; T2: when its cooldown starts), `pin` (before it rewrites the file) |

- `pin` is the only Guardian command that writes it (#9). It names the file in
  `InstallPlan.also_writes` (D16) and rewrites it whole and atomically (`settings.atomic_write`),
  so comments are not kept and the first line says so. `lockfile.py` only turns entries into text
  and text into entries.
- **In CI** the checked-out copy is read as is (FC-3), unlike overrides, which come from the
  default branch (§10.5), so lock-file changes need review (the CODEOWNERS pattern in
  `docs/authority-patterns.md`). Verifying again the entries a pull request adds is deferred
  past v1.0 (L2, §11.4).

### 11.2 Format

```toml
# Written by ssc-guardian pin. Comments in this file are not kept.
format = 1

[[pin]]
action = "actions/checkout"                       # action grammar (§6)
sha = "11bd71901bbe5b1630ceea73d27597364c9af683"  # sha grammar: the pinned commit
tag = "v4.2.2"                                    # git-ref grammar: the source tag, giving the version
first_seen = 2026-11-03                           # TOML date: the UTC day pin first recorded this commit
trusted = 2026-10-28                              # TOML date: when the cooldown starts (T2)
trusted_source = "activity-log"                   # "activity-log" | "immutable-release" | "lock-first-seen"
```

- **Every key is required**, and no other key is allowed, in the file or in an entry. Each value
  is checked by its grammar (§6, `grammars.check`): `action`, `sha`, `git-ref`, and `date`
  for both dates (unquoted TOML dates). `trusted_source` must be one of the three `AgeSource`
  values above. `registry-upload` (PyPI only) and `person-date` (kept in
  `.ssc-guardian.toml` `[[start_date]]`, §10.2, and applied every run) are refused.
- **`lock-first-seen`** means no GitHub-recorded date was found; then `trusted` must equal
  `first_seen`. An entry gives T2 `TrustedAge(trusted, trusted_source)` directly.
- **One entry per commit:** entries are unique by the Action in its one spelling (owner and
  repository lowercased, a path kept as given; D18) and the SHA. A second entry for the same
  commit, even with another tag or dates, is a duplicate.
- **Canonical form.** The writer prints the header, `format = 1` and the entries sorted by the
  Action's one spelling, then the Action as written, then the SHA, each with its keys in the
  order above (`settings.toml_string` for strings). The same entries always give the same
  bytes, whatever order they came in. The reader accepts entries in any order (a hand-merged
  file), so only a file the writer produced reads and writes back byte for byte.

### 11.3 Reading

Loading is all or nothing, as for §10's files. The file is **malformed** if it is not UTF-8,
not TOML, larger than 1 MiB, has an unknown or a missing key, a value of the wrong type or
failing its grammar, a refused `trusted_source`, a `lock-first-seen` entry whose dates differ,
or a duplicate entry. A malformed file is an in-scope skip `check-error` naming the file
(exit 2), and nothing in it is used: it verifies no pin and dates no commit. `pin` writes
nothing over a malformed file (exit 2); a person repairs it.

- **Format version.** `format` must be a whole number. `1` is read. A larger number is refused
  (exit 2) with a message naming it: "written by a newer ssc-guardian (lock format N); this
  build reads lock format 1". Any other value, or no `format`, is malformed.
- **Empty.** A missing file, a file of zero bytes or only whitespace, and a file with
  `format = 1` and no `[[pin]]` each read as no entries: every pinned SHA is then unverified
  (T4), which is stricter, never weaker.
- Dates are not checked against today: a later date can only make a cooldown start later.

### 11.4 Owner answers (2026-11-03)

- **L1 Approved.** `trusted` and `trusted_source` are always present; `lock-first-seen` means
  no earlier date was found and requires `trusted == first_seen`; `registry-upload` and
  `person-date` are refused (a person's date stays in `.ssc-guardian.toml` and is applied on
  top every run, so it can only make the start later).
- **L2 Approved as the design, deferred past v1.0** to save v1.0 time (the plan's FC-3
  reserve, decided for the public repository in M3). In v1.0, CI trusts the committed lock file
  as is and review of lock-file changes guards it. When turned on: an entry counts as is only
  where the default branch's lock file holds the same commit with the same dates; any other
  entry is verified again as `pin` would (T4's publisher-tag, activity-log or default-branch
  check, and T2's GitHub-recorded date, else first-seen is the day of the check), so a pull
  request can only make a start later, as §10.5 lets a change only tighten. **Rollback:** an
  entry that the default branch's lock file held before keeps its recorded dates when a revert
  restores it, so a rollback never restarts the cooldown. The format is the same either way.
- **L3 Approved: several versions per Action.** One entry per (Action, SHA), so blue and green
  pipelines can run two approved commits of one Action. Re-pinning a commit already listed, by
  any tag, keeps its entry unchanged, so `first_seen` never moves and a re-run adds nothing.
  **Note for #9:** `pin` removes the entries no workflow in the repository still uses, except
  the most recent previous commit of each Action, kept as a rollback target; which commit each
  workflow uses is read from the workflows themselves, never stored in the lock file. Beside the
  rollback target, `pin` keeps for each Action one commit still inside its cooldown (the commit
  just pinned, if it is waiting, else the newest waiting one), so its first-seen clock keeps
  running and is never restarted; neither entry takes the other's place,
  and a commit that waited and was never used is dropped once its cooldown has passed and another
  rollback target exists (owner's approval of 2026-11-10, #151). A commit
  pinned by bare SHA records the SHA itself as `tag` (a 40-hex SHA is a valid `git-ref`, §6).
