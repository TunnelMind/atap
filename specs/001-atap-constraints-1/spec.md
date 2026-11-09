# Feature: atap-constraints-1 — bring c60d4c5 in, with the guard's holes closed

**Run**: atap-constraints-1 · **Created**: 2026-11-08 · **Repo**: atap · **Base**: main (64f9ea5)

## Intent

Bring the unreviewed commit c60d4c5 ("operator-signed constraints enforced before every tool call") onto the run branch unchanged, then close every hole the coordinator's 2026-11-08 probes found in its PreToolUse guard. Each fix ships with the test that proves it, and the guard stays a silent no-op for projects with no constraints configured.

Key sentences from the owner's prompt:

> "First task: cherry-pick c60d4c5 onto the run branch, keeping its author and message. Everything else builds on it."
> "Each test goes in the same task as its fix. Never weaken an existing test."
> "The hook keeps its 'never break a session' rule for projects with no constraints configured."
> "GATE F — coordinator review (reviewer agent + verify) PASS, a probe table showing every case above with the wanted result, then Josh's merge word."

## User Scenarios

### US1 — The owner runs a crew under signed constraints (P1)
The owner sets `ATAP_OPERATOR` (and optionally `ATAP_CONSTRAINTS_REQUIRED=1`) in the agent's environment and signs constraints. Every tool call the agent makes, through any shell-like tool, on Linux, macOS or Windows paths, is checked; anything the guard cannot judge is denied.

**Acceptance scenarios**
1. Given `ATAP_CONSTRAINTS_REQUIRED=1` and no `.atap/` anywhere above the project, when PreToolUse fires, then the hook prints a `deny`.
2. Given `ATAP_OPERATOR` set, when PreToolUse fires with malformed stdin, or a handler throws, then the hook prints a `deny`.
3. Given a `forbid` rule `tools: ["mcp__*"], commands: ["git push*"]`, when `mcp__wsl__run` is called with `{command: "git push"}`, then the call is denied.
4. Given `secrets/**` forbidden and project root `C:\p`, when Write targets `C:\p\secrets\k`, then the call is denied.
5. Given a `git push*` forbid, when any of the fifteen forms listed under FR-006 is run, then it is denied (or, for a form left as a documented limit, the README names it).

### US2 — A project with no constraints keeps working untouched (P1)
Neither `ATAP_CONSTRAINTS_REQUIRED` nor `ATAP_OPERATOR` is set and there is no store.

**Acceptance scenarios**
1. Given no `.atap/`, when any hook event fires, then the hook prints nothing and exits 0 (today's behaviour).
2. Given `.atap/` with no store and malformed stdin, then the hook logs `malformed stdin` and prints nothing (the existing scaffold test stays as is).

### US3 — Ordinary work is not falsely denied (P2)
Under constraints, normal calls that merely mention a protected name in content or a commit message are allowed.

**Acceptance scenarios**
1. Write whose `content` holds `foo/.atap/config.json` → allowed.
2. Bash `jq . .vscode/settings.json` → allowed.
3. Bash `git commit -m "ignore .atap"` → allowed; `git commit -m "$(rm .atap/x)"` → still denied.

## Functional Requirements

- **FR-001** c60d4c5 is on the run branch as its own commit with its original author (`Claude <noreply@anthropic.com>`) and message; packages/atap-js, packages/atap-cli and plugins/claude-code suites pass with **zero skipped** plugin tests.
- **FR-002 (A002, fail-open)** `main()` in `plugins/claude-code/scripts/atap-hook.mjs` decides "strict" from the environment (`ATAP_CONSTRAINTS_REQUIRED=1` or a non-empty `ATAP_OPERATOR`) before `findAtap`. In strict mode, `pre-tool-use` prints `permissionDecision: "deny"` when no `.atap/` is found, when stdin is malformed, or when the handler throws. With neither variable set, behaviour is unchanged (silent no-op). The process still always exits 0 with nothing on stderr.
- **FR-003 (A003, other shells)** A tool call is a *shell call* when its `tool_input` has a string `command` or `script`. `commands` rules and the self-protection name tripwire apply to every shell call, not only `tool_name === "Bash"`. The non-shell path-string check still runs for non-shell tools.
- **FR-004 (A004, Windows)** Path handling in `packages/atap-js/src/constraints.ts` (`normalise`, `canon`, `relativeTo`, self-protection) and `decide` in `packages/atap-cli/src/constraints.ts` accept drive-letter (`C:\`, `c:/`) and backslash paths: drive letters and case fold, `\` is a separator, relative paths resolve against a Windows `cwd`. Windows mode is on when the context says so (CLI on `win32`) or the project root is a drive-letter path; on POSIX a backslash stays a literal filename character (so `secrets/a\..\..\b` is still under `secrets/`).
- **FR-005 (A005, self-edit)** The protected paths also include: the plugin root (`CLAUDE_PLUGIN_ROOT` and the hook script's own parent directory, passed by the hook to the CLI), the resolved `atap-witness` path (the `ATAP_WITNESS` file or the CLI's own entry script, realpath'd), and `~/.claude.json`. Edit/Write of any of them is denied. In the command tripwire these are matched by absolute path only, not by base name or project-relative name, so `npm --prefix plugins/claude-code test` is not denied.
- **FR-006 (A006, command forms)** `commandSegments` normalises each segment so that under `git push*` all of these match: `if true; then git push; fi`, `for i in 1; do git push; done`, `true || { git push; }`, `! git push`, `sudo -u me git push`, `env -i git push`, `nice -n 5 git push`, `time -p git push`, `/usr/bin/git push`, `\git push`, `git -C . push`, `bash -c 'git push'`, `sh -c "git push"`, `xargs git push`, `g""it push`. That is: strip shell keywords (`if then elif else fi for while until do done case esac`) and `{`, `}`, `!`; strip wrapper flags (with their arguments where the wrapper takes one); reduce `/dir/cmd` to `cmd`; drop a leading `\`; recurse into `sh|bash|zsh|dash -c <string>`; unwrap `xargs [flags]`; drop empty quotes `""`/`''`; strip git global options (`-C <dir>`, `-c <k=v>`, `--git-dir=…`, `--work-tree=…`). Variables, `eval`, aliases and encodings stay documented limits.
- **FR-007 (A006, README)** The plugin README's "Known limits" says exactly what still gets past and states that `commands` is a tripwire, not a boundary.
- **FR-008 (A007, paths on shells)** A `paths` rule whose tools match a shell call is judged against the path-like words of each command segment (quotes stripped, resolved against the call's `cwd`), so `cat secrets/x` under `{tools:["Bash"], paths:["secrets/**"]}` is denied. Documented as a tripwire.
- **FR-009 (A007, search reach)** A `paths` rule on a search tool (Grep, Glob, LS) also matches a search of a directory *below* the glob's static prefix when the remainder of the glob contains `**`. `**/.env` covers Grep with `path: src`; `src/**/x` covers Grep with `path: src/a`; `secrets/**` still does not cover `path: docs`.
- **FR-010 (A008, false denials)** (a) Self-protection counts a string as a path only if it is in a path field (`file_path`, `notebook_path`, `path`) or is a whole single-token path (no whitespace); for Write/Edit/MultiEdit/NotebookEdit only path fields count. (b) Settings files are tripwired by path (`.claude/settings`), not by bare base name (`settings.json`). (c) The tripwire skips the message text of `git commit -m/--message` when it is single-quoted, or double-quoted with no `$(`, backtick or `$` expansion.
- **FR-011** The plugin README, the atap-cli README and the plugin header comment describe the behaviour after each change; CHANGELOG has one entry for the run.
- **FR-012** A probe table test (`plugins/claude-code/test/probes.test.mjs`) holds one row per "got" case in the owner's prompt with its wanted result, run through the real hook + CLI (or through `evaluateCall` for the Windows rows), and passes.

## Success Criteria

- **SC-001** The run's verify command (plan.md) exits 0 at every task, and its TAP output contains `# skipped 0` for plugins/claude-code.
- **SC-002** `git log --format='%an <%ae>%n%s' -1 <first run commit>` prints `Claude <noreply@anthropic.com>` and `feat: operator-signed constraints enforced before every tool call`.
- **SC-003** `probes.test.mjs` has at least 30 rows (2 A002 + 3 A003 + 2 A004 + 2 A005 + 15 A006 + 2 A007 + 3 A008 + no-constraints controls) and every row passes.
- **SC-004** No test that existed at c60d4c5 is deleted or has an assertion relaxed: `git diff c60d4c5..HEAD -- '*.test.mjs'` shows only additions plus updates named in a task.
- **SC-005** With neither `ATAP_CONSTRAINTS_REQUIRED` nor `ATAP_OPERATOR` set and no `.atap/`, the hook prints nothing for every event (existing scaffold tests + a new control row).

## Edge Cases

- Strict mode with `ATAP_OFF=1`: `ATAP_OFF` stays the user's master switch and wins (it is the user's environment, like the strict flags).
- Strict mode, `session-start`, no `.atap/`: stays silent (the prompt names pre-tool-use only; a deny there is what blocks work).
- `post-tool-use` / `session-end` in strict mode with a throwing handler: logged, no output (they cannot deny).
- `git commit -m "$(rm .atap/x)"`: command substitution runs inside double quotes, so the tripwire still fires.
- `bash -c` nested twice (`bash -c "sh -c 'git push'"`): recursion has a depth cap; past it the segment is judged as text.
- Windows UNC paths (`\\server\share\…`): treated as absolute; no special share logic.
- Developing the atap repo itself under constraints: the plugin root is inside the project; FR-005's absolute-path-only tripwire keeps `cd plugins/claude-code && npm test` allowed while Edit of `scripts/atap-hook.mjs` is denied.
- A `paths` rule with tools `["*"]` matches both file tools (path fields) and shells (command words).

## Assumptions

- "Strict" means `ATAP_CONSTRAINTS_REQUIRED === '1'` or a non-empty `ATAP_OPERATOR`, both read from the hook's own environment; `.atap/config.json`'s `constraints_operator` is repo content and does not make the no-.atap case strict (there is no config then anyway).
- A004 is handled (drive letters and backslashes), not fail-closed-on-win32; the prompt prefers handling.
- A007 picks "match paths named in the command" over "refuse at sign time", because tool globs like `*` cannot be refused and the prompt's probe wants `cat secrets/x` denied.
- A008(c) picks "skip quoted commit-message text" over "document it".
- The plugin tests set `ATAP_WITNESS` themselves (a wrapper around `packages/atap-cli/dist/cli.js`); "prove none skip" is met by building the CLI first and asserting `# skipped 0`.
- `claude` is on PATH on BEAST, so the scaffold `plugin validate` test runs rather than skips.

## Out of Scope

- Pushing the branch, opening the PR, merging, publishing the CLI to npm or releasing the plugin: (owner).
- Making `commands` a security boundary (a real shell parser, variable expansion, `eval`, aliases, base64). It stays a tripwire.
- Changing the constraint statement format, signing, fold or witness events.
- Real Windows CI; Windows behaviour is proven by unit tests with Windows paths on Linux.
