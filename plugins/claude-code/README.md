# ATAP plugin for Claude Code

The `atap` Claude Code plugin records the commits and test runs Claude Code
makes in a project as ATAP witness events, through the
[`atap-witness`](../../packages/atap-cli/) CLI. The events and blocks are
stored locally in the project's `.atap/`.

It can also enforce **operator constraints**: rules the owner signs with their
own key, checked before every tool call and put back into the context after
every compaction. See [Operator constraints](#operator-constraints).

## Requirements

- Node 20 or later. The plugin has no dependencies.
- `atap-witness init` run once in the project (see
  [`packages/atap-cli/README.md`](../../packages/atap-cli/README.md)). The CLI
  runs from a source checkout of `packages/atap-cli`; it is not on npm. The
  hook finds it via `$ATAP_WITNESS`, then `atap-witness` on `PATH`. It never runs a
  path named inside the project (a committed `.atap/config.json` could point at a script in the repo).

`init` uses the `tunnelmind:code_crew:v1` profile by default, which defines
both event types below.

In a project with no `.atap/` (at or above the session's directory) the hooks
do nothing. Everything stays in `.atap/`: no account, no server, nothing is
sent anywhere.

## What it records

One script, `scripts/atap-hook.mjs`, runs on three hooks
(`hooks/hooks.json`):

| Hook | What happens |
|---|---|
| `SessionStart` | Nothing, unless operator constraints exist: then they go into the context (startup, resume, clear and compact). |
| `PreToolUse` (every tool) | Nothing, unless operator constraints exist: then the call is checked, below. |
| `PostToolUse` (matcher `Bash`) | A commit or a test run becomes one event, below. Other commands record nothing. |
| `SessionEnd` | Closes one attestation block over the AIT's pending events. |

**`code_crew:change_committed`**, evidence `anchored`. A `git commit` (not
`--dry-run`) that exits 0. The payload is `timestamp`, `repo` (`owner/repo`
parsed from the `origin` remote URL) and `commit_sha` (`HEAD` after the
commit). A failed commit records nothing. A repo whose `origin` does not
parse as `owner/repo` (none, a local path, a `file://` remote) is named
`local/<first 12 hex of its root commit>` instead: stable for the repo's
life, with no path or name in it.

**`code_crew:verify_run`**, evidence `asserted`. A command line with a
segment (split on `&&`, `||`, `;`, `|` and newlines) that starts with a test
command. The default test commands are:

```
npm test
pnpm test
pytest
python -m unittest
cargo test
go test
```

A `test_commands` array of strings in `.atap/config.json` replaces this list.
Failing runs are recorded too. The payload is `timestamp`, `command_sha256`
(sha256 of the whole command line), `exit_code` and `output_sha256` (sha256
of stdout followed by stderr).

**Attestation block** at `SessionEnd`, over the AIT's events not yet in a
block (this session's, plus any an earlier session left). No pending events,
no block. Its period summary is all zeros (`tasks_accepted`, `tasks_rework`,
`merged_changes`, `tokens` = `0`; `overturns` = `{}`): the hook sees no QA
verdicts, merges or tokens (a passing test run is not an accepted task; a
commit is not a merge), so it reports nothing rather than a relabelled guess.
The block still covers every commit and test-run event, which carry the facts.

## What it never records

No event or summary holds commit messages, command text (only its sha256),
command output (only its sha256), file paths, file contents, prompts, model
output or token counts.

## Operator constraints

Context compaction drops instructions an agent was given, and a forged
"the owner lifted that rule" in recent context can still talk an agent out of
one ([Chen, arXiv 2606.22528](https://arxiv.org/pdf/2606.22528)). Operator
constraints move the rule out of the context: the owner signs it, the hook
enforces it before the call runs, and only a rescind the owner signs lifts it.

```sh
# once, as the owner, with the key outside any project the agent can write
atap-witness constraints keygen --out ~/.atap-operator/operator.pem

# in the project (after atap-witness init)
atap-witness constraints set --operator-key ~/.atap-operator/operator.pem <<'JSON'
{"constraint_id": "no-prod",
 "prose": "Never deploy to production or touch infra/prod.",
 "rules": [
   {"id": "deploy", "effect": "forbid", "tools": ["Bash"], "commands": ["wrangler deploy*", "terraform apply*"]},
   {"id": "prod-files", "effect": "forbid", "tools": ["Write", "Edit"], "paths": ["infra/prod/**"]},
   {"id": "fetch", "effect": "require_approval", "tools": ["WebFetch"]}]}
JSON
atap-witness constraints status
atap-witness constraints rescind --operator-key ~/.atap-operator/operator.pem --id no-prod
```

What the hook does once a store exists:

- **PreToolUse** runs `atap-witness constraints check --record`. A `forbid`
  match answers `deny`, a `require_approval` match answers `ask`, and the
  reason names the constraint and its prose. An allowed call prints nothing,
  so Claude Code's own permission rules still decide it. Denials and asks are
  recorded as `code_crew:tool_gate` events (tool name and a hash of its input,
  never the input).
- **SessionStart** prints the constraints in force as `additionalContext`. It
  fires with source `compact` too, so the constraints come back after every
  compaction instead of being summarised away.
- **Fails closed.** If the store holds a statement that fails its signature,
  one from another key, or has lost a statement a witness event recorded,
  every call is denied until the owner repairs it. If the CLI cannot answer
  (missing, killed, bad output), the call is denied. With
  `ATAP_CONSTRAINTS_REQUIRED=1` or a non-empty `ATAP_OPERATOR`, a missing
  `.atap/`, malformed hook input or a hook error also denies the call
  (PreToolUse only; `ATAP_OFF=1` still switches the plugin off).
- **Self-protection.** No tool may touch the operator key (reads included,
  when `ATAP_OPERATOR_KEY` names it). No tool but a read-only one (Read, Grep,
  Glob, LS) may touch the store, any `.atap/` directory in the project (so a
  nested one cannot re-root the guard), or the project's and the user's
  `.claude/settings*.json` (where a hook could be switched off), or the guard
  itself: the plugin's own files (`CLAUDE_PLUGIN_ROOT` and the directory the
  hook script runs from, passed to the CLI as `ATAP_PLUGIN_ROOT`), the
  `ATAP_WITNESS` binary, the CLI's own entry script, and `~/.claude.json`.
  A shell command trips on these four only by their absolute path, so
  `npm --prefix plugins/claude-code test` still runs. Paths are
  resolved through symlinks, and compared case-insensitively on macOS and
  Windows. On Windows (or with a drive-letter project root) `\` is a path
  separator, `C:\…`, `c:/…` and `\\server\…` are absolute, drive letter and
  case fold, and a relative path resolves against a drive-letter `cwd`: so
  `secrets\k` and `c:/P/Secrets/k` both match `secrets/**` under `C:\p`
  (unit-tested with Windows paths on Linux, not on a Windows host). Elsewhere
  `\` is an ordinary filename character. Any MCP tool argument that looks
  like a path is checked too. No shell command may name any of them (any
  tool whose input has a string `command` or `script`: Bash, PowerShell, an
  MCP shell such as `mcp__wsl__run`).
- **Pinned root.** The hook finds `.atap/` from `CLAUDE_PROJECT_DIR` and
  passes that root to the CLI, so the agent `cd`-ing somewhere else changes
  nothing.

Where trust comes from. The repo's `.atap/config.json` is written by whoever
wrote the repo, so for a crew set these in the **user's environment**, which
the agent cannot change:

| Variable | Effect |
|---|---|
| `ATAP_OPERATOR` | The operator did:key to trust; beats the config's `constraints_operator`. |
| `ATAP_CONSTRAINTS` | The store file; put it outside the project (default `.atap/constraints.jsonl`). |
| `ATAP_CONSTRAINTS_REQUIRED=1` | No store, or nothing in force, denies every call instead of allowing it. |
| `ATAP_OPERATOR_KEY` | The operator key's path, so the built-in rule keeps every tool off it. |
| `ATAP_AIT` | The AIT to cross-check witness events under; beats the config's `ait`. |

**The operator key must not be readable by the OS user the agent runs as.**
Anything that user can read, a Bash command can eventually read, and whoever
holds the key can sign a rescind. Keep it on another account, a hardware key
or another machine; the self-protection rule only catches the obvious tries.

Known limits, on purpose: **`commands` is a tripwire, not a boundary.** It
matches command text, not what the shell will run, so these still get past a
`commands` glob and the name tripwire:

- variables: `c=push; git $c`, `$CMD`;
- `eval` and any program that runs a string it builds (`python -c`, `node -e`, `perl -e`);
- aliases and shell functions defined earlier in the session or in a sourced file;
- encodings: `echo Z2l0IHB1c2g= | base64 -d | sh`, hex, `printf` escapes;
- `sh|bash|zsh|dash -c` strings nested more than 3 deep, and an unquoted `-c` word;
- other quoting (`g'i't push`, `"git" push`), scripts on disk (`sh push.sh`), and
  wrapper or git options this list does not name (`sudo --user me`, `git --exec-path=x`).

The guard is the second line; OS permissions (the agent's user cannot write
the store or read the key) are the first.

Rules are globs: `*` stays inside a path segment and `**` crosses them;
`commands` apply to any tool whose input has a string `command` (else
`script`), not only Bash, and match each shell segment (split on `&&`, `||`, `;`, `|`, `&`,
newlines, parentheses, backticks and `$(`, with leading `VAR=value`, shell
keywords, a command's directory, wrappers such as `sudo`, `env` and `xargs`,
and git global options (`-C dir`, `-c k=v`, `--git-dir`, `--work-tree`,
`--no-pager`, `-p`, `-P`, `--paginate`)
stripped). The quoted string of `sh|bash|zsh|dash [-flags] -c '...'` is split
the same way, up to 3 shells deep, so `bash -c 'git push'` and `git -C . push`
both meet a `git push*` glob. That makes `commands` a tripwire for the obvious
spellings, not a boundary (see Known limits); every matcher in a rule must
match. A `paths` rule also matches a shell call (any tool `commands` applies to)
whose segments hold a path-like word: quotes and a leading redirection
stripped, flags skipped, a word kept if it has a `/` (or `\` on Windows) or
starts with `.` or `~`, so `cat secrets/x` and `echo hi && cat "secrets/x"`
meet `secrets/**`. **Shell `paths` matching is a tripwire over command words,
not a boundary:** it catches the obvious forms, not variables (`cat $F`), globs
the shell expands (`cat secr*/x`), a bare word with no slash (`ls secrets`), or
paths built at runtime. `outside_project` judges only the declared path fields,
not command words. `forbid` beats `require_approval`. A `paths` rule on Grep, Glob or LS
also covers a search with no path or of any ancestor directory (searching `.`
reaches `secrets/`). A rule is only as good as its globs: a command it does
not name runs. The statement format is in the
[code_crew profile, section 5.1](../../profiles/profiles/tunnelmind-code-crew-v1/profile.md).

The compaction eval that measures whether this works on a real crew is in
[`eval/`](eval/).

## Behavior

The hook never breaks a session. It always exits 0 and writes nothing to
stderr. It writes to stdout only for operator constraints (above). Problems (CLI not found, CLI failed, no
`owner/repo`, malformed hook input) are appended as one line to
`.atap/hook.log`, which stops growing at 1 MB. Each hook has a 10 s timeout;
the `atap-witness` call is killed after 8 s.

## Install

In Claude Code:

```
/plugin marketplace add TunnelMind/atap
/plugin install atap@atap
```

From a local checkout of this repo:

```
/plugin marketplace add <path-to-this-repo>
/plugin install atap@atap
```

## Off switch

`ATAP_OFF=1` in the environment makes the hook a silent no-op.

## Uninstall

```
/plugin uninstall atap@atap
/plugin marketplace remove atap
```

The second line is optional. The recorded data is `.atap/`; remove it with
`rm -rf .atap`.

## Checking what was recorded

From the project, with the forms in
[`packages/atap-cli/README.md`](../../packages/atap-cli/README.md):

```sh
atap-witness status            # profile, ait, events, blocks, last_receipt
atap-witness receipt --out receipt
atap-witness verify receipt
/path/to/atap/verify.sh receipt   # your checkout's trusted copy, not the receipt's
```

## Tests

`npm test` (Node's built-in test runner).
