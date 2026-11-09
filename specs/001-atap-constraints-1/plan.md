# Plan: atap-constraints-1

## Constitution check

No `.specify/memory/constitution.md` in this repo, so no ADR gate. House rules that apply (owner's): review-first with the why, never break behaviour (the hook's "never break a session" rule for unconfigured projects), comments for readers, never weaken an existing test, test + fix in one task. One GATE: F at the end.

## Where the change goes

All code arrives with c60d4c5 (T001); every later task edits files that commit adds or touches.

| File | What lives there | Tasks |
|---|---|---|
| `plugins/claude-code/scripts/atap-hook.mjs` | `main()`, `findAtap`, `handlers['pre-tool-use']`, `constraintsCli` | T002, T005 |
| `packages/atap-js/src/constraints.ts` | `commandSegments`, `WRAPPERS`, `normalise`, `canon`, `relativeTo`, `callPaths`, `inputStrings`, `staticDir`, `ruleMatches`, `selfProtection`, `evaluateCall`, `EvalContext` | T003, T004, T006–T010 |
| `packages/atap-js/test/constraints.test.mjs` | unit tests for the above | T003, T004, T006–T010 |
| `packages/atap-cli/src/constraints.ts` | `protectedPaths`, `secretPaths`, `decide` (cwd check, `caseInsensitive`) | T004, T005 |
| `packages/atap-cli/test/constraints.test.mjs` | CLI tests | T004, T005 |
| `plugins/claude-code/test/constraints.test.mjs` | real hook + CLI tests (`setup(t)` harness) | T002 |
| `plugins/claude-code/test/probes.test.mjs` | NEW: the GATE F probe table, one row per "got" case | T002 creates; each later task adds its rows |
| `plugins/claude-code/README.md` | "Operator constraints", self-protection list, known limits | T002–T010 |
| `packages/atap-cli/README.md`, `CHANGELOG.md` | CLI docs, run entry | T011 |

## Approach

1. **T001** cherry-picks c60d4c5 as-is (`git cherry-pick c60d4c5`; main is its ancestor, so it applies cleanly). This is the one commit the run makes before the coordinator's per-task commits; it must keep author and message, which `cherry-pick -n` would lose. If the crew's coder may not commit, the coordinator runs the cherry-pick before T002 and the coder only runs the verify.
2. **Fail-open (T002)**: compute `strict` from the environment at the top of `main()`. A small `denyCall(reason)` printer is reused for: no `.atap/`, malformed stdin, handler throw — all only for `event === 'pre-tool-use'` and only when strict. The existing "could not run" deny in the handler stays.
3. **Shell calls (T003)**: one helper `shellCommand(call): string | null` (string `command`, else string `script`) used by `ruleMatches` and `selfProtection` in place of the two `tool_name === 'Bash'` checks.
4. **Windows (T004)**: windows mode = `ctx.windows` (new optional `EvalContext` field, set by `decide` on win32) or a drive-letter project root. In that mode `normalise` turns `\` into `/`, keeps and lower-cases the drive (`c:`), treats `X:/…`/`\\…` as absolute; `canon` folds case. `decide` accepts a drive-letter `cwd`. POSIX behaviour is byte-for-byte unchanged.
5. **Self-edit (T005)**: hook passes `ATAP_PLUGIN_ROOT=<dirname(script)/..>` (plus `CLAUDE_PLUGIN_ROOT` if set) to the CLI it spawns; `protectedPaths` adds those, the realpath of `ATAP_WITNESS` / `process.argv[1]`, and `~/.claude.json`. The tripwire gets a second, absolute-path-only name list for these.
6. **Command forms (T006, T007)**: extend `commandSegments`' per-segment normaliser loop (it already iterates to a fixed point over `ASSIGNMENT`/`WRAPPERS`): keyword/brace/bang strip, wrapper-with-flags table, dirname strip, leading `\`, empty quotes; then `-c` recursion (depth cap 3), `xargs` unwrap, git global options. README limits rewritten in T007.
7. **Paths gaps (T008, T009)**: shell calls feed their segments' path-like words into `callPaths`; `staticDir` reach check extended for `**` remainders.
8. **False denials (T010)**: narrow `selfProtection`'s string filter, drop settings base names from the tripwire, skip safe-quoted `git commit -m` text.
9. **Probe table**: `probes.test.mjs` reuses the `setup(t)` pattern from `test/constraints.test.mjs` (copy the harness, or export it — whichever is smaller); rows are `{ case, env, tool_name, tool_input, want }`; Windows rows call `evaluateCall` from `packages/atap-js/dist/index.js` like `eval.test.mjs` does.

## Risks

- **Fail-closed overreach (T002)**: strict mode now denies in places that used to be silent; confined to pre-tool-use + an env the user set. Control rows prove the unconfigured path stays silent.
- **Normaliser false positives (T006/T007/T008)**: stripping more makes more commands match; a forbid over-matching is the safe direction, but every existing `commandSegments` test must still pass unchanged.
- **Backslash on POSIX (T004)**: converting `\` on Linux would let `secrets/a\..\..\b` escape; windows mode is gated, with a POSIX regression test.
- **Plugin root inside the project (T005)**: a base-name tripwire would deny ordinary `plugins/claude-code` commands in this very repo; absolute-path-only matching avoids it.
- **Commit-message skip (T010)**: `"$(…)"` executes inside double quotes; only quote forms with no expansion are skipped.
- **Cherry-pick author (T001)**: a coder that cannot commit loses the author; see Approach 1.
- **Network**: verify runs `npm ci` (ajv, typescript from the registry).

## Verify (every task)

```bash
bash -c 'set -eo pipefail; (cd packages/atap-js && npm ci --no-audit --no-fund && npm test); (cd packages/atap-cli && npm ci --no-audit --no-fund && npm test); cd plugins/claude-code && node --test --test-reporter=tap test/*.test.mjs | tee /tmp/atap-constraints-1-plugin.tap; grep -qx "# skipped 0" /tmp/atap-constraints-1-plugin.tap'
```

The plugin tests build their own `ATAP_WITNESS` wrapper around `packages/atap-cli/dist/cli.js`, which the second step builds; the final `grep` fails the run if any plugin test skipped.
