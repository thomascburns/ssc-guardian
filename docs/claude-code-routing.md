# Route Claude Code package requests through ssc-guardian

This page is for a repository where Claude Code works as an agent. It has six parts: why the
routing matters, a `CLAUDE.md` snippet, permission rules, an optional hook, a pointer to the
agent instructions, and the honest limit of all of it.

## 1. Why

Claude Code agents run `pip install`, `python -m pip install`, `uv pip install`, `uv add`,
`uv sync`, `pipx install` and `uv tool install` on their own, and run tools without installing
them with `uvx`, `uv tool run` and `pipx run`. Those commands bypass Guardian's checks: no
compromise check, no known-vulnerability check, no check of the files pip chose. The cooldown
`ssc-guardian protect` wrote still applies where it wrote it: pip in an environment it protected,
and uv (`uvx` and `uv tool run` included) once uv's user config holds it. `pipx install` and
`pipx run` make new venvs with no such setting, so nothing applies to them.

`ssc-guardian install --venv <path> <packages>` runs every check first and then installs exactly
the files it checked. The rest of this page sends the agent there.

## 2. A `CLAUDE.md` snippet

Add this to the repository's `CLAUDE.md`:

```markdown
Install Python packages only with `ssc-guardian install --venv <path> <packages>`. Never run
pip, uv or pipx install commands directly. If Guardian refuses, report the refusal to the user;
do not work around it.
```

## 3. Claude Code permission rules

Add these rules to the repository's `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Bash(pip install *)",
      "Bash(pip3 install *)",
      "Bash(* -m pip install *)",
      "Bash(*/bin/pip* install *)",
      "Bash(uv pip install *)",
      "Bash(uv add *)",
      "Bash(uv tool install *)",
      "Bash(pipx install *)",
      "Bash(pipx run *)",
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
      "Bash(* -m ssc_guardian acknowledge *)",
      "Edit(//**/.ssc-guardian.toml)",
      "Edit(//**/.ssc-guardian-overrides.toml)",
      "Edit(//**/.ssc-guardian.lock)",
      "Edit(~/.config/ssc-guardian/**)"
    ],
    "allow": [
      "Bash(ssc-guardian install *)",
      "Bash(ssc-guardian check *)"
    ]
  }
}
```

What each deny rule stops:

| Rule | Command it stops |
|---|---|
| `Bash(pip install *)` | `pip install requests` |
| `Bash(pip3 install *)` | `pip3 install requests` |
| `Bash(* -m pip install *)` | `python3 -m pip install requests` |
| `Bash(*/bin/pip* install *)` | `.venv/bin/pip install requests` |
| `Bash(uv pip install *)` | `uv pip install requests` |
| `Bash(uv add *)` | `uv add requests` |
| `Bash(uv tool install *)` | `uv tool install ruff` |
| `Bash(pipx install *)` | `pipx install ruff` |
| `Bash(pipx run *)` | `pipx run ruff` |
| `Bash(ssc-guardian override add)` | `ssc-guardian override add` |
| `Bash(ssc-guardian override add *)` | `ssc-guardian override add --yes` |
| `Bash(ssc-guardian acknowledge *)` | `ssc-guardian acknowledge example/action` |
| `Bash(uvx --from * ssc-guardian override add)` | `uvx --from ./ssc_guardian-1.0.1-py3-none-any.whl ssc-guardian override add` |
| `Bash(uvx --from * ssc-guardian override add *)` | `uvx --from ./ssc_guardian-1.0.1-py3-none-any.whl ssc-guardian override add --yes` |
| `Bash(uvx --from * ssc-guardian acknowledge *)` | `uvx --from ./ssc_guardian-1.0.1-py3-none-any.whl ssc-guardian acknowledge example/action` |
| `Bash(uv tool run --from * ssc-guardian override add)` | `uv tool run --from ./ssc_guardian-1.0.1-py3-none-any.whl ssc-guardian override add` |
| `Bash(uv tool run --from * ssc-guardian override add *)` | `uv tool run --from ./ssc_guardian-1.0.1-py3-none-any.whl ssc-guardian override add --yes` |
| `Bash(uv tool run --from * ssc-guardian acknowledge *)` | `uv tool run --from ./ssc_guardian-1.0.1-py3-none-any.whl ssc-guardian acknowledge example/action` |
| `Bash(* -m ssc_guardian override add)` | `python3 -m ssc_guardian override add` |
| `Bash(* -m ssc_guardian override add *)` | `python3 -m ssc_guardian override add --yes` |
| `Bash(* -m ssc_guardian acknowledge *)` | `python -m ssc_guardian acknowledge example/action` |

- **The exception commands.** `ssc-guardian override add` and `ssc-guardian acknowledge` are for
  a person, who confirms them at a terminal. Their rules cover four spellings: the installed
  command, `uvx --from`, `uv tool run --from` and `python -m ssc_guardian`. Options placed before
  `--from`, a full path to the program and other spellings are not matched. `override add` takes
  no arguments (it asks for each field), so its rule is also listed alone, in case the form with
  a trailing `*` does not match the bare command.
  [authority-patterns.md](authority-patterns.md) repeats these Bash rules exactly.
- **`pipx run`** fetches and runs a package in a new venv, which no cooldown setting reaches, so
  it is denied with `pipx install`.
- **Optional:** `Bash(uv sync *)` and `Bash(uv run *)`. Both can install packages implicitly.
  Deny them only if the project does not rely on them. `Bash(uvx *)` and `Bash(uv tool run *)`
  are optional too: uv's user config gives them the cooldown once `protect` wrote it there, and
  denying them also blocks `uvx` calls of Guardian.
- **File edits.** The four `Edit` rules keep the agent away from your Guardian settings,
  override and lock files. An `Edit` rule covers every built-in tool that edits files; a
  `Write(...)` path
  rule never matches, so do not use one. How a path starts decides where it is anchored: `//` at
  the filesystem root, `~/` at the home folder, and a single `/` at the session's primary working
  directory (the folder the session started in, or moved to with `/cd`), not at the repository
  root; in user settings a single `/` means `~/.claude/`. So the three Guardian file rules start
  `//**/`: they match those file names in any folder, in a worktree, after `/cd`, and from any
  settings file. The names are Guardian's own, so matching them in other folders is harmless.
- **Where the rules apply.** Claude Code reads `.claude/settings.json` only from the folder the
  session starts in; it does not look in parent folders. A session started at the repository
  root gets every rule above. A session started in a subfolder gets none of them, the installer
  rules included. To cover it, also put the same rules in `.claude/settings.local.json`, which
  Claude Code reads from the repository root wherever the session starts (it belongs to one
  person and is not committed), or in your user settings, `~/.claude/settings.json`, which apply
  in every project.
- **Allow.** The two allow rules let the agent run the installed Guardian's checks and checked
  installs without asking each time. No `uvx` form of Guardian is allowed: the `*` in
  `uvx --from *` matches any package name or Git URL, and an added `--with <package>`, so such a
  rule would let the agent run code from any source without asking, as long as the command it
  runs is named `ssc-guardian`. A `uvx` call of Guardian asks each time. The deny rules keep
  their `uvx --from *` forms: a broad deny only stops more.
- **How the rules match.** `*` is a wildcard. Deny rules still match when the command starts with
  environment-variable assignments (`PIP_INDEX_URL=… pip install x`). A compound command
  (`cd app && pip install x`) is split, and each part is checked on its own.

[authority-patterns.md](authority-patterns.md) gives the matching CODEOWNERS and branch
protection pattern for the same files.

## 4. An optional PreToolUse hook

A hook catches what text rules miss: `sh -c 'pip install x'`, an absolute path such as
`/usr/local/bin/uv pip install x`, and other spellings. This example blocks the command and
suggests the matching `ssc-guardian install --venv` command.

Save it as `.claude/hooks/route-installs.py` and make it executable
(`chmod +x .claude/hooks/route-installs.py`):

```python
#!/usr/bin/env python3
"""PreToolUse hook: send Python package installs through ssc-guardian."""

import json
import re
import shlex
import sys

# An installer command anywhere in the text, also inside `sh -c '...'` or after a path.
INSTALLER = re.compile(
    r"(?:^|[\s;&|('\"/])"
    r"(?:pip3?(?:\.\d+)?\s+install|-m\s+pip\s+install|uv\s+pip\s+install"
    r"|uv\s+add|uv\s+tool\s+install|pipx\s+install)\b"
)


def packages(command):
    """Package arguments after the installer's verb, without options."""
    try:
        words = shlex.split(command)
    except ValueError:
        return []
    # Look inside a quoted command too, as in sh -c 'pip install x'.
    words = [part for word in words for part in word.split()]
    for verb in ("install", "add"):
        if verb in words:
            names = []
            for word in words[words.index(verb) + 1 :]:
                if word in ("&&", "||", ";", "|"):
                    break
                if not word.startswith("-"):
                    names.append(word)
            return names
    return []


def main():
    event = json.load(sys.stdin)
    command = event.get("tool_input", {}).get("command", "")
    if not INSTALLER.search(command):
        return 0
    suggestion = " ".join(["ssc-guardian install --venv <path-to-venv>", *packages(command)])
    print(
        "Blocked: install Python packages through ssc-guardian, which checks them first.\n"
        f"Run instead: {suggestion}\n"
        "If Guardian refuses, report the refusal to the user; do not work around it.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

Register it in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/route-installs.py"
          }
        ]
      }
    ]
  }
}
```

That file has the same limit as the rules in part 3. Claude Code's permissions page says hooks
"load from the current working directory's `.claude/` folder with no parent-directory
fallback", so a session started in a subfolder of the repository does not run this hook. To
cover it, also register the hook in `.claude/settings.local.json`, which Claude Code reads from
the repository root wherever the session starts, or in your user settings,
`~/.claude/settings.json`, which apply in every project. In either file, give the script's
absolute path in place of `$CLAUDE_PROJECT_DIR`: Claude Code's hooks page defines that variable
only as "the project root where the session started".

The hook reads the tool call from standard input and finds the command in
`tool_input.command`. Exit code 2 blocks the call, and Claude sees the message written to
standard error. Instead of exit code 2, a hook can print JSON on standard output:
`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}`.

The example matches text, so it also blocks a command that only mentions an installer, such as
a commit message containing `pip install`. Its suggestion is a starting point: it copies the
words after `install` or `add`, so an option's value (`-r requirements.txt`) can appear in it,
and Guardian refuses anything that is not a package name. Adjust the pattern to the project.

## 5. The agent instructions

[agent-instructions.md](agent-instructions.md) tells an agent how to run `ssc-guardian check`,
read its exit code and JSON, and act on each finding. An optional one-line pointer in
`CLAUDE.md`:

```markdown
When you run ssc-guardian, follow its agent instructions: docs/agent-instructions.md in the ssc-guardian repository.
```

## 6. The honest limit

A Bash rule is not a security boundary around a program. `/usr/bin/pip`, `bash -c '…'`, and a
Python or Node script that opens files itself can all bypass the Bash and Edit rules. The hook
in part 4 catches more spellings, but it still reads only the command text. A deny rule in a
project's settings file can be removed by editing that file; only managed settings cannot be
overridden. A session started in a subfolder of the repository loads neither the rules nor the
hook from the repository's `.claude/settings.json`, unless they are also in
`.claude/settings.local.json` or `~/.claude/settings.json`.

For a filesystem-level guarantee, turn on Claude Code sandboxing. Whatever gets past the rules,
the cooldown that `ssc-guardian protect` wrote still applies where it wrote it: pip in an
environment it protected, and uv (`uvx` and `uv tool run` included) once uv's user config holds
it. `pipx install` and `pipx run` make new venvs with no such setting, so nothing applies to
them. `ssc-guardian check` reports what arrived in the places you name.
