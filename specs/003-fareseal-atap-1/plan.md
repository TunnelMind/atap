# Plan: fareseal-atap-1

## Constitution check

atap has no `.specify/memory/constitution.md` (none in the repo). The crew constitution applies through `constitution-accepted.json`; this run adds no decision-issuing code, so nothing new to accept. No ADR rule applies: prose and a vendored data file only, no behaviour change. No GATE besides GATE F.

## Where the change goes

| File | Change | Task |
|---|---|---|
| `ARCHITECTURE.md:45` | "tollbooth and sdk-python carry" → "Fareseal and sdk-python carry" | T001 |
| `packages/atap-cli/test/verify-sh-canon.test.mjs:61` | comment: "receipt-verify and Fareseal" | T001 |
| `packages/atap-js/src/canonicalize.ts:7` | comment: "receipt-verify and Fareseal" | T001 |
| `viewer/dist/atap-viewer.html` | regenerated (`packages/atap-js` `npm run build`, then `node viewer/build.mjs`) | T001 |
| `packages/atap-js/test/vectors/jcs.json` | re-vendored from receipt-verify `1b6edd2` | T002 |
| `packages/atap-js/test/jcs-vectors.test.mjs:3,17-21` | comment "Fareseal carries the same copy"; pin `81a79410…` → `b294a60b…`; cite origin commit | T002 |
| `packages/atap-js/README.md:126,130` | short sha `81a79410…3dfb978cdd` → `b294a60b…82cad3a2d` | T002 |
| `CHANGELOG.md` Unreleased | `### Changed` entry | T002 |

`jcs-vectors.test.mjs` is touched by T002 only (both its comment and its pin), so T001 and T002 share no file; they still run in order because T001 rebuilds atap-js dist and both run the full verify.

## Approach

- T001: edit three comments and one prose line; rebuild, regenerate the viewer with the repo's build, `--check` passes.
- T002: red first: change the pin to `b294a60b…` and show the pin test failing on the old file; then copy the origin bytes with `git -C /home/o2k/receipt-verify show 1b6edd2:test/vectors/jcs.json > packages/atap-js/test/vectors/jcs.json`, show `cmp` = 0 and the test green. The sha is the one receipt-verify's CHANGELOG records, so the pin is the cross-repo byte-equality proof that runs in CI.
- T003: `git grep -n -i tollbooth`; expected remainder: only `specs/003-fareseal-atap-1/*` (this run's record of the rename). Justify each line in the task note.

## Risks

- **Viewer dist stale.** Forgetting to rebuild atap-js before `node viewer/build.mjs` leaves the old comment in the dist; `--check` would still pass against a stale atap-js dist locally. The verify runs `npm test` in atap-js (which builds) before `viewer` `npm test`, so the check sees the new comment.
- **Hand-edited vectors.** Only `git show 1b6edd2:…` may write `jcs.json`; the sha pin catches any other byte.
- **No CI job runs the viewer check**; it is in the verify command on purpose (same as spec 002).
- **Network:** `npm ci` fetches dev dependencies.

## Verify (every task)

```bash
bash -c 'set -eo pipefail; (cd packages/atap-js && npm ci --no-audit --no-fund && npm test); (cd packages/atap-cli && npm ci --no-audit --no-fund && npm test); (cd viewer && npm test); (cd packages/atap-py && python3 -m unittest discover -s tests); cmp verify.sh packages/atap-py/src/atap/verify.sh; cd plugins/claude-code && node --test --test-reporter=tap test/*.test.mjs | tee /tmp/fareseal-atap-1-plugin.tap; grep -qx "# skipped 0" /tmp/fareseal-atap-1-plugin.tap'
```
