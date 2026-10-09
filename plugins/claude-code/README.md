# ATAP plugin for Claude Code

The `atap` Claude Code plugin records the commits and test runs Claude Code
makes in a project as ATAP witness events, through the
[`atap-witness`](../../packages/atap-cli/) CLI. The events and blocks are
stored locally in the project's `.atap/`.

## Requirements

- Node 20 or later. The plugin has no dependencies.
- `atap-witness init` run once in the project (see
  [`packages/atap-cli/README.md`](../../packages/atap-cli/README.md)). The CLI
  runs from a source checkout of `packages/atap-cli`; it is not on npm. The
  hook finds it via `$ATAP_WITNESS`, then `"cli"` in `.atap/config.json`, then
  `atap-witness` on `PATH`.

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
| `SessionStart` | Nothing. |
| `PostToolUse` (matcher `Bash`) | A commit or a test run becomes one event, below. Other commands record nothing. |
| `SessionEnd` | Closes one attestation block over the AIT's pending events. |

**`code_crew:change_committed`**, evidence `anchored`. A `git commit` (not
`--dry-run`) that exits 0. The payload is `timestamp`, `repo` (`owner/repo`
parsed from the `origin` remote URL) and `commit_sha` (`HEAD` after the
commit). A failed commit, or a repo whose `origin` does not parse as
`owner/repo` (a local path or `file://` remote), records nothing.

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
no block. Its period summary is integers only:

| Field | Value |
|---|---|
| `tasks_accepted` | `verify_run` events with exit code 0 |
| `tasks_rework` | `verify_run` events with a non-zero exit code |
| `merged_changes` | `change_committed` events |
| `tokens` | `0` |
| `overturns` | `{}` |

## What it never records

No event or summary holds commit messages, command text (only its sha256),
command output (only its sha256), file paths, file contents, prompts, model
output or token counts.

## Behavior

The hook never blocks or breaks a session. It always exits 0 and writes
nothing to stdout or stderr. Problems (CLI not found, CLI failed, no
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
./receipt/verify.sh receipt
```

## Tests

`npm test` (Node's built-in test runner).
