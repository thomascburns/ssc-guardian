# ssc-guardian reference

This page is for people who run Guardian and for the tools that read its output. It lists the
commands and their flags, the exit codes, every rule and skip reason, the JSON format with a full
example, the field grammars, the settings and override files and the lock file, as the current
code has them (JSON format 1.0), including changes not yet in a release, such as the removed
`default-scope` skip reason.

It restates; it does not define. The definition is [docs/contracts.md](contracts.md), the frozen
design record, and each section below links the part it summarizes. The test suite checks
each table's names and values against the code (the commands, flags, exit codes, rules, skip
reasons, JSON keys and value sets, grammar lengths, settings, overridable rules and lock keys),
so a name that is not in the code, or one of the code's that is missing here, fails a test.

- [Commands](#commands)
- [Exit codes](#exit-codes)
- [Rules and levels](#rules-and-levels)
- [Skip reasons](#skip-reasons)
- [JSON output](#json-output)
- [Field grammars](#field-grammars)
- [Settings files](#settings-files)
- [Overrides](#overrides)
- [Lock file](#lock-file)

## Commands

Defined in [contracts §2](contracts.md#2-commands-plan-21).

| Command | Arguments | `--yes` | `--json` |
|---|---|---|---|
| `check` | `--path PATH` (repeatable) or `--repo [DIR]`, at least one. `--envs` (only the Python environments) or `--repo` (only one repository's workflows), not both. Filters: `--language python` and `--ecosystem pypi\|github-actions`, each repeatable; repeats of one flag add up, and the two flags together keep only what both allow. | not accepted | accepted |
| `protect` | An optional installer, `pip` or `uv`, and `--path PATH` (required, repeatable). With no installer: pip, and uv where a `--path` covers its config. | accepted | accepted |
| `install` | `--venv PATH` (required), then one or more packages, each `NAME` or `NAME==VERSION`. | accepted | accepted |
| `pin` | `OWNER/REPO[/PATH]@REF`. `REF` is required: a tag, a branch or a 40-hex commit SHA. | accepted | accepted |
| `acknowledge` | `OWNER/REPO`. | refused (exit 2) | refused (exit 2) |
| `override add` | None: it asks for each field at the terminal. | refused (exit 2) | refused (exit 2) |

`ssc-guardian --version` prints `ssc-guardian <version>`, followed by ` (<commit>)` when Guardian
was installed from Git. `-h` and `--help` print the help.

**What `check` and `protect` act on comes only from their arguments.** There is no default scope,
no option that checks everything, and no setting that changes what a command reads. A `check`
with neither `--path` nor `--repo`, and a `protect` without `--path`, is a usage error (exit 2)
decided before anything is read; the message shows the `--path` form.

- **`check --path P`** inside a Git repository checks the Python environments at or under each P
  and the workflows under P in the repository holding the current folder. Outside a Git
  repository the GitHub Actions part is an in-scope skip (`check-error`, exit 2) unless `--envs`
  is given; `--ecosystem github-actions` outside a repository gives the same skip.
  `check --repo [DIR]` checks one repository's workflows; with no folder it uses the current
  folder, which must be the repository's top folder.
- **Where environments are found.** `check --envs` and `protect` look only at or under each P: P
  itself when it is a venv or a Python installation, the Python installations in the standard
  places under P and those reached through interpreters in `PATH` folders under P, and the venvs
  and installations found by walking P at most 8 levels down. The walk never enters a venv or a
  folder named `.git`, `node_modules`, `__pycache__` or `site-packages`; a venv one level past
  the limit, or directly inside one of those folders, is an in-scope skip unless a shorter route
  checks it. An environment reached under P that resolves outside every named path is not read;
  it is an in-scope skip.
- **Every `--path` is reported.** A P that does not exist, cannot be read or holds nothing that
  was checked is an in-scope skip `check-error` at P (exit 2), never a pass.
- **Filters narrow, never relax.** Each ecosystem the scope or a filter leaves out is listed as
  skipped with reason `filtered`. A scope and filters that leave nothing to check are a usage
  error (exit 2). `--language` accepts only `python` in this version.
- **Paths.** `--path`, `--repo` and `--venv` have `~` expanded and are made absolute; `.`
  components, repeated `/` and a trailing `/` are dropped, and symlinks are resolved. An empty
  path, a `..` component, or a character outside the [path grammar](#field-grammars) makes the
  argument malformed: a `malformed-name` violation (exit 1), and the command does not run.
- **Options are never abbreviated:** each is typed in full. An unknown or abbreviated option, or
  a missing argument, is a usage error (exit 2).
- **`--help`, `-h` and `--version` exit 0 only on their own.** With anything else on the command
  line (`check --help`) the text still prints and the run exits 2, so a CI gate never passes on
  it.
- **Show before write.** `protect`, `install`, `pin`, `acknowledge` and `override add` show the
  change and write only when you confirm at a terminal. Without a terminal, `protect`, `install`
  and `pin` still show the change, ask no question and write nothing; `acknowledge` and
  `override add` need a person at a terminal and stop before showing anything. Either way
  nothing is written and the run exits 2. `--yes` confirms in
  advance for `protect`, `install` and `pin`; the change is still printed, to stderr. The
  question goes to stderr, so `--json` output stays valid.
- **`install` and `pin` write only after every check passes.** If the write step then fails part
  way, the run exits 2 and stderr names what was written.
- **There is no remove command.** Removing a package is your decision.

## Exit codes

Defined in [contracts §3](contracts.md#3-exit-codes-plan-22).

| Code | Meaning | Text output's last line ends with |
|---|---|---|
| 0 | Every rule met in what was checked. Warnings and notices may appear. | `exit 0: every rule met in what was checked.` |
| 1 | At least one violation. For `install` and `pin`: refused because a rule failed; nothing written. | `exit 1: at least one violation.` |
| 2 | A check could not finish (an in-scope skip), or a usage error. For `install` and `pin`: refused; nothing written, unless the write step itself fails part way. | `exit 2: a check could not finish. Skipped is unknown, not safe.` |

- **1 wins over 2.** Once a violation is known the result is 1, and the unfinished checks are
  still listed.
- **A failed check never gives 0.** An error inside a check, or a handler that raises, becomes an
  in-scope skip (`check-error` unless the error names another reason), so the run exits 2
  unless a violation is known; a malformed finding field is itself a violation (exit 1, see
  [Field grammars](#field-grammars)). A failure while building the parser, rendering or writing
  the output exits 2 with a fixed message on stderr, whatever was found; output already written
  may be partial.
- **Warnings and notices never fail a run.** Each rule has one fixed level.
- A usage error prints its message on stderr and no result.

## Rules and levels

Defined in [contracts §4](contracts.md#4-result-model-fixed-templates). Each rule has one
fixed level; an exception goes through an [override](#overrides), and only for the rules listed
there.

| Rule | Level | When it is reported |
|---|---|---|
| `cooldown` | violation | A PyPI version is younger than its cooldown (21 days by default), counted from its first upload; for an installed package, from the upload of the newest file that could be the one installed. |
| `compromise` | violation | A package version has malware evidence (an OSV `MAL-` record, a GitHub malware advisory, or PyPI's quarantine) of a strength that `block_on` blocks. |
| `known-vulnerability` | violation | A non-withdrawn advisory that is not a malware record names the version. One finding per version lists every advisory. |
| `deny-list` | violation | A settings file's `deny` list names the item. It cannot be overridden. |
| `unprotected` | violation | An environment's pip (a venv or a Python installation), or uv's per-user or project settings, do not hold a cooldown that meets the rule, or are given a package index other than PyPI's. `protect` fixes it where it can, never an index. |
| `malformed-name` | violation | A value fails its [grammar](#field-grammars). It cannot be overridden. |
| `moving-reference` | violation | A workflow uses an Action by tag or branch, not by a 40-hex commit SHA. `pin` fixes it. |
| `unverified-pin` | violation | A pinned commit SHA is not in the [lock file](#lock-file). |
| `impostor-commit` | violation | A pinned commit is not shown to be the publisher's: no publisher tag, branch activity or default-branch history reaches it. |
| `young-repository` | violation | An Action repository is younger than `young_repository_days` (90) or has fewer than `min_stars` (50) stars, until a person runs `acknowledge`. Guardian's own repository is exempt from this rule only. |
| `nested-moving-reference` | violation | An Action reached through another Action uses a tag or a branch. |
| `nesting-limit` | violation | Nesting goes deeper than `nesting_depth` levels, or past `nested_reference_limit` unique nested references in one run. |
| `nesting-loop` | violation | Nested Actions form a loop. |
| `unreleased-pin-advisory` | violation | Advisories exist for an Action whose pin has no release tag, so Guardian cannot rule them out. |
| `unpushed-commit` | warning | A pinned commit was never seen on one of the publisher's branches. |
| `moved-release-tag` | warning | A release tag the lock file recorded (such as `v4.2.2`) names another commit today. Major and line tags (`v4`, `v4.1`) move by design and are not compared. |
| `degraded-feed` | warning | GitHub's advisories could not be read while OSV answered. |
| `kev-unavailable` | warning | CISA's Known Exploited Vulnerabilities catalog could not be reached, so the `actively-exploited` label may be missing. |
| `unpinned-image` | warning | A `docker://` image is used without a `@sha256:` digest. |
| `cooldown-wait` | notice | An Action commit is still inside its cooldown; its option gives the date it becomes eligible. |
| `first-use-publisher` | notice | An Action publisher is used for the first time in this repository; stderr gives the repository's age, stars and forks. |
| `weakened-setting` | notice | A settings layer set a weaker value that a stricter one replaced ([stricter wins](#settings-files)). |
| `hidden-pip` | notice | An older pip sits behind the one `python -m pip` loads. |
| `ci-overrides` | notice | Outside CI, the repository's `.ssc-guardian-overrides.toml` holds at least one entry: a repository check reports it whenever it reads that file locally, because CI uses only the default branch's copy. |

## Skip reasons

Defined in [contracts §4](contracts.md#4-result-model-fixed-templates). A skip is never clean:
every report lists what it checked and what it skipped, and why. An **in-scope** skip is a check
that could not finish, and makes the run exit 2. An **out-of-scope** skip is listed for the record
and leaves the exit code as it is.

| Reason | Scope | Text output says |
|---|---|---|
| `feed-failure` | in scope | a feed could not be read |
| `unknown-age` | in scope | the age could not be established |
| `unsupported-yaml` | in scope | the file uses YAML Guardian does not read |
| `rate-limit` | in scope | the GitHub rate limit was reached |
| `default-branch-unreadable` | in scope | the default branch's settings could not be read |
| `check-error` | in scope | the check failed |
| `not-available` | in scope | this check is not available in this build |
| `filtered` | out of scope | excluded by the scope or a filter |
| `later-release` | out of scope | not covered until a later release |
| `deeper-than-one-level` | out of scope | not checked: deeper than one level |
| `local-install` | out of scope | installed from a local folder; the upload age was not checked |

`later-release` lists the files at a repository's top level that a later release reads:
`pyproject.toml`, `uv.lock` and `requirements*.txt` (ecosystem `pypi`), and
`.pre-commit-config.yaml` (no ecosystem). `local-install` is a package installed from a local
folder whose project file names it and whose version PyPI has no release for: only its upload age
is excused, and every other rule applies.

The skip reason `default-scope` was removed with the default scope; no command emits it.

## JSON output

Defined in [contracts §5](contracts.md#5-json-format-version-10). `--json` prints one object
with its keys sorted, in ASCII only. Every key is always present, as `null` or `[]` when empty.
JSON is not offered by `acknowledge` and `override add`.

**Versioning.** `format_version` is `"1.0"`. Adding a key, removing one or changing a value set is
a contract change: an additive change (a new value) raises the minor version, anything else the
major version.

| Object | Keys | Notes |
|---|---|---|
| result | `format_version`, `tool`, `command`, `exit_code`, `summary`, `findings`, `checked`, `skipped`, `overrides` | `exit_code` is 0, 1 or 2. |
| tool | `name`, `version`, `commit` | `name` is `"ssc-guardian"`; `version` is PEP 440; `commit` is a 40-hex SHA for a Git install, else `null`. |
| summary | `violations`, `warnings`, `notices`, `checked`, `skipped_in_scope`, `skipped_out_of_scope` | Integers. |
| finding | `id`, `rule`, `level`, `ecosystem`, `place`, `item`, `version`, `evidence`, `labels`, `options`, `malformed_field`, `via` | `place` is a path, or `null` when there is none or the path is outside the [path grammar](#field-grammars) (for example, a `ci-overrides` notice whose overrides file's path is outside it); `ecosystem` is `null` for a `[defaults]` setting. `evidence` lists advisory IDs. `via` lists the outer Actions a nested finding was reached through, outermost first, each `ACTION@REF`; `[]` otherwise. |
| option | `kind`, `item`, `version`, `command`, `eligible_on`, `requires_user_approval`, `requires_person` | `command` is an argument list or `null`: pass each element as exactly one argument, never joined with spaces. `eligible_on` is a date or `null`. |
| checked | `ecosystem`, `place` | |
| skipped | `ecosystem`, `place`, `reason`, `in_scope` | `ecosystem` and `place` may be `null`. |
| overrides | `applied`, `expired` | Lists of override objects. |
| override | `id`, `ecosystem`, `item`, `version`, `rule`, `reference`, `category`, `expiry` | `reference` is an advisory ID, a limit name, or for `nested-moving-reference` the inner `ACTION@REF` exactly as written. `expiry` is a date. |

| Value set | Values |
|---|---|
| `command` | `check`, `protect`, `install`, `pin` |
| `level` | `violation`, `warning`, `notice` |
| `ecosystem` | `pypi`, `github-actions` |
| `labels` | `actively-exploited`, `registry-quarantined` |
| `malformed_field` | `place`, `item`, `version`, `evidence`, `via` |
| option `kind` | `replace`, `protect`, `remove`, `exception` |
| override `category` | `not-exploitable`, `no-fix-available`, `deferred-upgrade`, `accepted-risk` |
| limit names | `nesting-depth`, `nested-reference-count`, `nesting-loop`, `nested-moving-reference` |

`rule` takes the values in [Rules and levels](#rules-and-levels), and `reason` those in
[Skip reasons](#skip-reasons).

**Options.** `replace` names an item and version and, once that version is eligible, a command
(`install --venv PATH NAME==VERSION` for `pypi`, `pin ACTION@REF` for `github-actions`); before
then it has an `eligible_on` date and no command. `protect` carries
`ssc-guardian protect [pip|uv] --path PATH` for the finding's own place. `remove` is your decision
and has no command (`requires_user_approval` is true). `exception` needs a person and has no
command in JSON (`requires_person` is true); the text output names `ssc-guardian acknowledge
OWNER/REPO` or `ssc-guardian override add`.

**Finding ID.** The first 32 hex characters of SHA-256 over the compact JSON array
`[rule, place, ecosystem, item, version, malformed_field, malformed_value, via]`. The same inputs
give the same ID on every run. Names are hashed in one spelling: the PEP 503 name for a PyPI
package (`Requests` and `requests` are one ID), the owner and repository lowercased for an Action,
and a PyPI version in its normalized PEP 440 form (`1.0` and `1.0.0` are one ID). One inner
reference reached through two outer Actions has two IDs.

**Never in JSON:** override reasons, acknowledgment notes, the raw value of a malformed name, an
exception's details, and the `acknowledge` and `override add` commands.

### Example

The output of `ssc-guardian check --path ~/projects/app --json`, run inside a repository at
`~/projects/app` that holds a venv with `requests` 2.31.0 installed, a `pyproject.toml`, and a
workflow that uses `actions/checkout@v4`, on 2026-11-17 (UTC). There is no `unprotected` finding,
so the venv either held a cooldown that meets the rule (it had been protected) or had no pip; the
output does not show which. The workstation's `overrides.toml` held one override for
`CVE-2024-35195`; it is listed as expired because a fixed `requests` passes every rule
([contracts §10.4](contracts.md#104-overrides-ssc-guardian-overridestoml-and-overridestoml)).
The output is shown whole. Guardian prints absolute paths; the folder is shown here as
`~/projects/app`, and the IDs are those of the real run. The advisories and versions you see
will differ.

```json
{
  "checked": [
    {
      "ecosystem": "pypi",
      "place": "~/projects/app/.venv"
    },
    {
      "ecosystem": "pypi",
      "place": "~/projects/app/.venv/lib/python3.11/site-packages"
    },
    {
      "ecosystem": "github-actions",
      "place": "~/projects/app"
    }
  ],
  "command": "check",
  "exit_code": 1,
  "findings": [
    {
      "ecosystem": "pypi",
      "evidence": [
        "CVE-2024-35195",
        "CVE-2024-47081",
        "CVE-2026-25645",
        "GHSA-9hjg-9r4m-mvj7",
        "GHSA-9wx4-h78v-vm56",
        "GHSA-gc5v-m9x4-r6x2",
        "PYSEC-2026-1872",
        "PYSEC-2026-1873",
        "PYSEC-2026-2275"
      ],
      "id": "90dc5705c6879e17ca13a364e6d758c9",
      "item": "requests",
      "labels": [],
      "level": "violation",
      "malformed_field": null,
      "options": [
        {
          "command": [
            "ssc-guardian",
            "install",
            "--venv",
            "~/projects/app/.venv",
            "requests==2.34.2"
          ],
          "eligible_on": null,
          "item": "requests",
          "kind": "replace",
          "requires_person": false,
          "requires_user_approval": false,
          "version": "2.34.2"
        },
        {
          "command": null,
          "eligible_on": null,
          "item": null,
          "kind": "remove",
          "requires_person": false,
          "requires_user_approval": true,
          "version": null
        },
        {
          "command": null,
          "eligible_on": null,
          "item": null,
          "kind": "exception",
          "requires_person": true,
          "requires_user_approval": false,
          "version": null
        }
      ],
      "place": "~/projects/app/.venv/lib/python3.11/site-packages",
      "rule": "known-vulnerability",
      "version": "2.31.0",
      "via": []
    },
    {
      "ecosystem": "github-actions",
      "evidence": [],
      "id": "f3bf064d5f5a24aeea046d2aba56cc4c",
      "item": "actions/checkout",
      "labels": [],
      "level": "violation",
      "malformed_field": null,
      "options": [
        {
          "command": [
            "ssc-guardian",
            "pin",
            "actions/checkout@v4"
          ],
          "eligible_on": null,
          "item": "actions/checkout",
          "kind": "replace",
          "requires_person": false,
          "requires_user_approval": false,
          "version": "v4"
        }
      ],
      "place": "~/projects/app/.github/workflows/ci.yml",
      "rule": "moving-reference",
      "version": "v4",
      "via": []
    },
    {
      "ecosystem": "github-actions",
      "evidence": [],
      "id": "d48b13ef0514b875d51bde5114136ff0",
      "item": "actions/checkout",
      "labels": [],
      "level": "notice",
      "malformed_field": null,
      "options": [],
      "place": "~/projects/app",
      "rule": "first-use-publisher",
      "version": null,
      "via": []
    }
  ],
  "format_version": "1.0",
  "overrides": {
    "applied": [],
    "expired": [
      {
        "category": "deferred-upgrade",
        "ecosystem": "pypi",
        "expiry": "2026-12-01",
        "id": "0d1eed3f2e48197d8b3791247208631c",
        "item": "requests",
        "reference": "CVE-2024-35195",
        "rule": "known-vulnerability",
        "version": "2.31.0"
      }
    ]
  },
  "skipped": [
    {
      "ecosystem": "pypi",
      "in_scope": false,
      "place": "~/projects/app/pyproject.toml",
      "reason": "later-release"
    }
  ],
  "summary": {
    "checked": 3,
    "notices": 1,
    "skipped_in_scope": 0,
    "skipped_out_of_scope": 1,
    "violations": 2,
    "warnings": 0
  },
  "tool": {
    "commit": null,
    "name": "ssc-guardian",
    "version": "1.0.0"
  }
}
```

**Text output** is built from the same result. It strips control, bidirectional-override and
other invisible characters from every value it prints, shell-quotes commands, and uses colour
only on a terminal when `NO_COLOR` is not set to a non-empty value. The raw value of a malformed
name is shown with every character outside printable ASCII escaped, so a lookalike character
cannot pass as a valid name.

## Field grammars

Defined in [contracts §6](contracts.md#6-field-grammars-plan-32-r1-k7). Every value Guardian
reads or prints is checked against its grammar: a full match, ASCII only, nothing repaired. A
malformed argument, or a finding's field (place, item, version, evidence or via) that fails, is
a `malformed-name` violation (exit 1). A failing value that is not part of a finding (a date, an
override ID) only leaves its check unfinished (exit 2), and one in a settings, override or lock
file makes that file malformed.

| Grammar | Accepts | Max length |
|---|---|---|
| `pypi-name` | A PEP 508 name: letters and digits at both ends, `.`, `_` and `-` inside. | 200 |
| `pep440-version` | A PEP 440 version. | 128 |
| `owner-repo` | Owner: letters, digits and hyphens, 1 to 39, not starting with a hyphen. Repository: letters, digits, `.`, `_` and `-`, 1 to 100, not `.` or `..`. | 140 |
| `action` | `owner/repo`, then optional `/path` segments (no `.` or `..`). | 255 |
| `git-ref` | Components of letters, digits and `._+-`, separated by `/`; no `..`, no leading `.` or `-`, no `.lock` or `.` at the end. A 40-hex SHA is a valid `git-ref`. | 255 |
| `sha` | 40 lowercase hex characters. | 40 |
| `advisory-id` | `CVE-YYYY-N…`, `GHSA-xxxx-xxxx-xxxx`, `MAL-YYYY-N…` or `PYSEC-YYYY-N…`. | 64 |
| `path` | An absolute path: `/`-prefixed components of letters, digits, space and `._+@,=~()-`; no `.` or `..` component, no space followed by `-`, no trailing `/`, not `/` alone. | 1024 |
| `date` | `YYYY-MM-DD`, a real date. | 10 |
| `override-id` | 32 lowercase hex characters. | 32 |
| `action-step` | An `action`, `@` and a `git-ref`. | 511 |
| `docker-image` | The image a `docker://` reference names: an optional registry host, lowercase path components, an optional `:tag`, an optional `@sha256:` digest. | 255 |

A finding's `item` and `version` are `pypi-name` and `pep440-version` for `pypi`, and `action` and
`git-ref` for `github-actions`; an `unpinned-image` finding's `item` is a `docker-image` and its
`version` is `null`. A folder whose name has a character outside the `path` grammar (an accented
letter, an apostrophe) gives a `malformed-name` violation; rename or move it.

## Settings files

Defined in [contracts §10](contracts.md#10-settings-and-override-files-plan-24-issue-3).

| File | Where | Holds | Read by |
|---|---|---|---|
| `.ssc-guardian.toml` | The repository's top folder | Settings, deny list, acknowledgments | `check --repo`, `pin`, `acknowledge` |
| `.ssc-guardian-overrides.toml` | The repository's top folder | Overrides for `github-actions` only | `check --repo`, `pin` |
| `config.toml` | `~/.config/ssc-guardian/` | Settings, deny list | `check` (every form; `check --repo` in CI too), `protect`, `install`, `pin`, `acknowledge`; never `override add` |
| `overrides.toml` | `~/.config/ssc-guardian/` | Overrides for `pypi` only | `check --envs`, `protect`, `install` |

`check --repo` here also stands for the repository part of `check --path` inside a repository,
and `check --envs` for its Python part. The workstation folder is always
`~/.config/ssc-guardian/`; `XDG_CONFIG_HOME` is not read.

**All or nothing.** A file that is not UTF-8, not TOML, larger than 1 MiB, has a `format` other
than `1`, an unknown key, a value of the wrong type or outside its range, or a value that fails
its grammar is malformed: the command reports an in-scope skip `check-error` naming the file
(exit 2), and nothing in that file applies. A missing file is not an error. An unknown key is
refused rather than ignored, because a mistyped key would leave a weaker value in place.

`.ssc-guardian.toml` and `config.toml` have the same shape. Every key except `format` is
optional:

```toml
format = 1
deny = ["github-actions:example/bad-action"]

[defaults]
cooldown_days = 21

[rules]
"github-actions:actions/checkout" = { cooldown_days = 7 }

[[acknowledgment]]               # .ssc-guardian.toml only; written by acknowledge
repository = "owner/repo"
repository_id = 123456789        # GitHub's numeric ID; a changed ID voids it
date = 2026-11-03
note = "free text, text output only"

[[start_date]]                   # a person's start date for one Action commit
action = "owner/repo"
sha = "0123456789abcdef0123456789abcdef01234567"
date = 2026-11-01
```

| Key | Values | Built-in | Stricter is |
|---|---|---|---|
| `cooldown_days` | whole days, 0–3650 | `21` | larger |
| `block_on` | `never`, `strong`, `any` | `strong` | `never` < `strong` < `any` |
| `fixed_date_tolerance_days` | 1–3650; it can only lower the computed tolerance (a third of the cooldown, rounded up, at least a day) | none | smaller |
| `young_repository_days` | 90–36500; it can only be raised | `90` | larger |
| `min_stars` | 50–10000000; it can only be raised | `50` | larger |
| `nesting_depth` | 1–10; it can only be lowered | `10` | smaller |
| `nested_reference_limit` | 1–500; it can only be lowered | `500` | smaller |

These keys go under `[defaults]`; a `[rules]` entry sets `cooldown_days` for one item.

- **Every rule and deny entry names its ecosystem:** `pypi:NAME` or `github-actions:ACTION`. An
  unprefixed entry makes the file malformed; it is never guessed. Names match in their one
  spelling. No globs. A `github-actions:OWNER/REPO` deny entry also denies every Action under a
  path in that repository.
- **`pypi:` entries belong in `config.toml`.** A `pypi:` deny entry or `[rules]` key in
  `.ssc-guardian.toml`, or an `[[acknowledgment]]` in `config.toml`, makes the file malformed.
- **The former `[scope]` table** (`venv_folders` or `ecosystems`) makes the file malformed; the
  message names its line and the arguments that replace it.
- **Within one file**, a `[rules]` entry replaces that file's default for that item, in either
  direction.
- **Stricter wins across files.** The layers are `config.toml`, the repository's
  `.ssc-guardian.toml`, and in CI the default branch's copy. For each item, the stricter of the
  values the layers set applies; the built-in value is used only when no layer sets one. Each
  value a stricter layer replaced is reported as a `weakened-setting` notice. A deny entry in any
  layer denies.
- **In CI** (`GITHUB_ACTIONS` is `true`) Guardian reads the default branch's `.ssc-guardian.toml`
  and `.ssc-guardian-overrides.toml` through GitHub's API, with the built-in values beneath the
  default branch's own, so a pull request can only tighten a setting. Overrides and
  acknowledgments come from the default branch only, so a pull request cannot release its own
  finding. If the default branch cannot be read, every in-scope ecosystem is skipped as
  `default-branch-unreadable` (exit 2). See
  [contracts §10.5](contracts.md#105-ci-plan-24-r1-k5-r2-k3-fc-3).

## Overrides

Defined in
[contracts §10.4](contracts.md#104-overrides-ssc-guardian-overridestoml-and-overridestoml). An
override releases one finding for a limited time. `pypi` overrides live only in
`~/.config/ssc-guardian/overrides.toml`, and `github-actions` overrides only in the repository's
`.ssc-guardian-overrides.toml`. `override add` writes them.

```toml
format = 1

[[override]]
ecosystem = "pypi"
item = "example-package"
version = "1.2.3"                  # exact; for an Action, the 40-hex commit SHA
rule = "known-vulnerability"
reference = "CVE-2026-12345"
category = "deferred-upgrade"
created = 2026-11-03               # the day override add wrote it
expiry = 2026-12-01                # the last day it applies
reason = "free text, text output only"
```

| Overridable rule | Ecosystems | `reference` | Longest expiry from `created` |
|---|---|---|---|
| `known-vulnerability` | `pypi`, `github-actions` | an advisory ID: `CVE-`, `GHSA-` or `PYSEC-` | 90 days; 7 if KEV-listed |
| `compromise` | `pypi`, `github-actions` | an advisory ID: `MAL-` or `GHSA-` | 7 days |
| `unreleased-pin-advisory` | `github-actions` | an advisory ID: `GHSA-` | 90 days; 7 if KEV-listed |
| `nested-moving-reference` | `github-actions` | the inner reference exactly as written, `ACTION@REF` | 90 days |
| `nesting-limit` | `github-actions` | a limit name: `nesting-depth` or `nested-reference-count` | 90 days |
| `nesting-loop` | `github-actions` | a limit name: `nesting-loop` | 90 days |

Every other rule is refused in an override. `cooldown` takes a `[rules]` entry instead,
`young-repository` takes `acknowledge`, and `moving-reference`, `unverified-pin`,
`impostor-commit` and `unprotected` are fixed by `pin` or `protect`.

- **Exact item.** An override names one ecosystem, item and exact version. For a nested Action,
  `item` and `version` are the outer Action and its exact commit, so a new outer release brings
  the finding back.
- **One advisory per override.** A finding that lists several advisories is released only when
  each has an override that applies.
- **Re-checked every run.** An override applies only while `today` is not after `expiry`. For
  `known-vulnerability` and `unreleased-pin-advisory`, one on an advisory that is now KEV-listed
  ends 7 days after `created`, and one whose KEV status cannot be learned is not applied. For
  `known-vulnerability`, it ends once Guardian can install or pin a fixed version that passes
  every rule, whether or not you have done so; it is not applied when that check could not
  finish. An override that has ended is listed under `overrides.expired`; one that matched but
  was not applied is named with its reason on stderr, `override <id> not applied: <why>`.
- **Quarantine is never released.** A `compromise` finding with the `registry-quarantined` label
  stays, whatever the override says.
- **Override ID:** the first 32 hex characters of SHA-256 over
  `[ecosystem, item, version, rule, reference]`. Two entries with one ID make the file
  malformed.

`override add` takes no flags. It needs a terminal, asks for each field on stderr, checks each
answer at once, shows the entry and the file, and writes only on your yes (declined: exit 2).
Writing an entry identical to one already in the file changes nothing (exit 0); the same ID
with other fields is shown as a replacement. The file is rewritten whole, so comments in it are
not kept.

## Lock file

Defined in [contracts §11](contracts.md#11-lock-file-ssc-guardianlock-plan-32-t2-and-t4-issue-28).
`.ssc-guardian.lock`, at the repository's top folder and committed, lists the allowed pins: every
pinned commit in every workflow must be in it, or the pin is an `unverified-pin`. `pin` is the
only Guardian command that writes it; it rewrites the file whole, so comments are not kept.
`check --repo` reads it, and so does `pin` before it rewrites it. In CI the checked-out copy is
read as it is, so review changes to it.

```toml
# Written by ssc-guardian pin. Comments in this file are not kept.
format = 1

[[pin]]
action = "actions/checkout"
sha = "11bd71901bbe5b1630ceea73d27597364c9af683"
tag = "v4.2.2"
first_seen = 2026-11-03
trusted = 2026-10-28
trusted_source = "activity-log"
```

| Lock key | Value |
|---|---|
| `action` | an `action` |
| `sha` | a `sha`: the pinned commit |
| `tag` | a `git-ref`: the source tag, which gives the version; a commit pinned by bare SHA, or by a branch (which gives no version), records the SHA |
| `first_seen` | a TOML date: the UTC day `pin` first recorded this commit |
| `trusted` | a TOML date: the day the commit's cooldown starts |
| `trusted_source` | `activity-log`, `immutable-release` or `lock-first-seen` |

- **Every key is required** and no other is allowed. `lock-first-seen` means no GitHub-recorded
  date was found; then `trusted` must equal `first_seen`.
- **One entry per commit:** an Action (owner and repository lowercased) and SHA appear once.
- **Malformed is all or nothing:** a malformed lock file is an in-scope skip `check-error` naming
  the file (exit 2) and verifies no pin; `pin` writes nothing over it.
- A file written by a newer Guardian (a larger `format`) is refused (exit 2) with a message
  naming its format. A missing or empty file has no entries, so every pinned SHA is unverified.
