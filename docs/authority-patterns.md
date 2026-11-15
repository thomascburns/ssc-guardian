# Authority patterns: who may weaken a rule

Plan §2.4 (R2-K3) and contracts §10. This page gives the two patterns the owner's repositories
adopt and the README builds on: a Claude Code permission pattern and a CODEOWNERS pattern. It
also says plainly what they do not do.

## What Guardian itself enforces

Guardian stops an agent from weakening a rule **through Guardian's own commands**:

- The exception commands, `ssc-guardian override add` and `ssc-guardian acknowledge`, appear
  only in text output, never in JSON.
- They refuse `--yes` and `--json`, and they ask a person at a terminal: with no terminal,
  nothing is written (exit 2).
- `override add` asks for each field, shows the entry and asks again. For confirmed malware, or
  an advisory it knows to be KEV-listed, it shows a second warning and asks the person to type
  the advisory ID. When KEV status cannot be learned, it says so, and the run-time re-check
  still ends a KEV-listed override 7 days after it was written.
- Across layers the stricter value wins, the command line cannot weaken a rule, and every
  weakened value is reported. A deny entry blocks whatever any other layer says. Within one
  file a `[rules]` entry may shorten an item's cooldown: whoever can edit that file can relax
  a rule for it, which is why the file needs review (pattern 2).
- In CI, `check --repo` is the gate for the repository's files: the default branch's settings,
  with the built-in defaults beneath them, are a floor the pull request cannot go below, and
  only the default branch's overrides and acknowledgments count, so a pull request cannot
  relax a setting or release its own finding through them. A pull request that changes
  `.ssc-guardian.toml` to relax it takes effect only once a reviewer merges it.
- `pin` and `acknowledge` read the checkout's own files (and the workstation settings) wherever
  they run, CI included: a pull request's settings, overrides and acknowledgments count for
  them. They are a person's tools for changing the repository, not the gate; what they write
  passes CI only through `check --repo`.
- The workstation files (`~/.config/ssc-guardian/`: `config.toml` is read by `check`
  (`check --repo` in CI included), `protect`, `install`, `pin` and `acknowledge`;
  `overrides.toml` by `check --envs`, `protect` and `install`) have no such rule: in CI, code
  the pull request controls (an install step, the tests) runs as the same user and can write them. Run Guardian in CI before any such code
  runs, or in a separate job.

## The honest limit

The terminal check is a speed bump, not a lock. A program that runs as the user can obtain a
terminal (`script(1)`), and it can edit any file the user can edit: the settings, override and
lock files, and Guardian's own installed code. Nothing inside Guardian can prevent that.

**The enforcement points are the agent's permission settings and CI with protected branches.**
Of those, only CI with branch protection and required review holds against a determined
program, and only for what is committed. The workstation files
(`~/.config/ssc-guardian/`) have no second line: they are protected only by the agent's
permissions.

## Pattern 1: Claude Code permissions

Add these deny rules to the repository's `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Edit(//**/.ssc-guardian.toml)",
      "Edit(//**/.ssc-guardian-overrides.toml)",
      "Edit(//**/.ssc-guardian.lock)",
      "Edit(~/.config/ssc-guardian/**)",
      "Edit(**/.github/CODEOWNERS)",
      "Bash(ssc-guardian override add)",
      "Bash(ssc-guardian override add *)",
      "Bash(ssc-guardian acknowledge *)",
      "Bash(uvx --from * ssc-guardian override add)",
      "Bash(uvx --from * ssc-guardian override add *)",
      "Bash(uvx --from * ssc-guardian acknowledge *)",
      "Bash(uv tool run --from * ssc-guardian override add)",
      "Bash(uv tool run --from * ssc-guardian override add *)",
      "Bash(uv tool run --from * ssc-guardian acknowledge *)",
      "Bash(* -m ssc_guardian override add)",
      "Bash(* -m ssc_guardian override add *)",
      "Bash(* -m ssc_guardian acknowledge *)"
    ]
  }
}
```

- **The Bash rules** are the exception-command rules of
  [claude-code-routing.md](claude-code-routing.md), repeated exactly: `override add` and
  `acknowledge` started in four spellings: as the installed command, through `uvx --from`,
  through `uv tool run --from`, or as `python -m ssc_guardian`.

- **Where the rules apply.** Claude Code reads `.claude/settings.json` only from the folder the
  session starts in; it does not look in parent folders. A session started in a subfolder gets
  none of these rules. To cover it, also put the same rules in `.claude/settings.local.json`,
  which Claude Code reads from the repository root wherever the session starts, or in your user
  settings, `~/.claude/settings.json`, which apply in every project.
- `Edit` rules cover every built-in tool that edits a file, including `Write`.
- The three Guardian file rules start `//**/`, so they match those file names in any folder,
  wherever the session starts and from any settings file, as in
  [claude-code-routing.md](claude-code-routing.md). The names are Guardian's own.
- `Edit(**/.github/CODEOWNERS)` matches only at or below the session's working folder (where it
  started, or moved to with `/cd`), so in a session started in a subfolder it does not cover the
  repository's CODEOWNERS file. Branch protection (pattern 2) is what guards that file.
- The agent instruction file says the same in words: never write or edit an override,
  acknowledgment, settings or lock file; a finding marked `requires_person` goes to a person.
- **Limit:** `Bash` deny rules match the command's text. Another spelling of the same action
  (a full path to the program, a shell wrapper, a script that edits the file) is not matched.
  The rules stop an agent that follows its instructions from doing this by accident; they do
  not stop one that is trying.

## Pattern 2: CODEOWNERS and branch protection

`.github/CODEOWNERS` in the repository:

```text
# ssc-guardian: settings, overrides, lock file and the workflows that run the check.
/.ssc-guardian.toml            @OWNER
/.ssc-guardian-overrides.toml  @OWNER
/.ssc-guardian.lock            @OWNER
/.github/workflows/            @OWNER
/.github/CODEOWNERS            @OWNER
```

Replace `@OWNER` with the people or team who may approve an exception.

**CODEOWNERS alone changes nothing.** It only names reviewers. What makes it real is branch
protection (or a ruleset) on the default branch that:

1. requires a pull request before merging, with at least one approving review;
2. requires review from Code Owners;
3. requires the status check that runs `ssc-guardian check --repo` to pass;
4. applies to administrators too, and does not allow bypassing these rules.

The workflow that runs the check needs only `contents: read`. With these settings, a change to
an override, a setting or the lock file reaches the default branch only after a code owner has
approved it, and CI judges every pull request by the default branch's settings (never below
the built-in defaults) and its overrides, never the pull request's own.

**Lock-file changes need a careful review.** CI trusts the committed lock file as it is: an
entry added there is an allowed pin, and its `trusted` date sets when that commit's cooldown
starts, which CI takes as written. Review every lock-file change in a pull request.
