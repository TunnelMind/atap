# Plan: atap-scope-1

## Constitution check

This repo has no `.specify/memory/constitution.md`, so there is no ADR gate. `constitution-accepted.json` holds one accepted finding, which this run does not touch. The owner's house rules apply:

- review first, with the why;
- never break behaviour, except the two refusals the owner asked for, which go in the CHANGELOG;
- comments for readers;
- never weaken an existing test: assertions that flip from "verifies" to "fails" are rewritten to the new rule, with the old case kept as the input;
- a test and its fix go in one task;
- never claim what the code does not do (truth-pass).

There is one stop: GATE F at the end.

## Where the change goes

| File | What lives there | Tasks |
|---|---|---|
| `packages/atap-js/src/verify.ts` | `pickKey` (~93-113, compromised branch ~103-108), `pickDidKeyKey` (~154-163), strength ceiling in `verifyReceipt` (~388-451) | T001, T002 |
| `verify.sh` (root) | `oai_keys_at`/key select (~226-236), `lookup_did_key` (~263-290), step 5 strength (~480-530) | T001, T002 |
| `packages/atap-py/src/atap/verify.sh` | byte copy of root `verify.sh` | T001, T002 |
| `viewer/dist/atap-viewer.html` | built from atap-js dist by `viewer/build.mjs`; `--check` fails if stale | T001, T002 |
| `packages/atap-js/test/didkey.test.mjs` | compromise-as-instant tests (~317-345), key strength (~367-385) | T001, T002 |
| `packages/atap-js/test/receipt-rules.test.mjs`, `witness.test.mjs` | receipt rules, ceiling | T001, T002 |
| `packages/atap-cli/test/verify-sh-hardening.test.mjs` | "a compromise notice is compared by time too" (~151), both-verifier parity | T001, T002 |
| `packages/atap-cli/test/verify-sh-v02.test.mjs` | did:key compromise table (~271-320), "key omits the field" (~676) | T001, T002 |
| `packages/atap-py/tests/test_trust.py` (or a new `test_verify_rules.py`) | atap.verify through the packaged verify.sh | T001, T002 |
| `packages/atap-js/test/jcs-vectors.test.mjs`, `packages/atap-js/README.md` | vectors pin, canonicalizer note | T003 |
| `README.md`, `ATAP-v0.1.md`, `ATAP-v0.2.md` | positioning, diagram, proposal, front-matter note | T004 |
| `CHANGELOG.md` | Unreleased entries | T001, T002 |

## Approach

- **T001 (A-1).** In `pickKey`, a `compromised` entry is skipped whatever its time: `continue` without comparing to `disclosed_at`. In `pickDidKeyKey`, any compromised entry returns `null`. In verify.sh, the jq selects at ~236, ~282 and ~510 drop the `$at < disclosed_at` alternative. The instant parsing of `disclosed_at` is then no longer on the path. Leave the `instant()` helper, which key windows still use. Each changed spot gets a comment citing ATAP-v0.1 §8.1 ("SHOULD be marked unverified … MAY treat them differently") and the review's A-1 reason: `issued_at`, `period_end` and `generated_at` are written by the key holder. Then copy verify.sh into atap-py, rebuild the viewer, and update the tests that asserted "later disclosure verifies" to assert refusal for every row.
- **T002 (A-3).** A missing key strength reads as `self-asserted` for ranking. Drop the `else if` warning branch for claims above self-asserted. A self-asserted or absent claim against a strength-less key still passes. Keep a warning there only if an existing test requires one; never add a new one. In verify.sh, `KEY_STRENGTH` defaults to `self-asserted` when empty, and the reason text matches the JS. Then copy, rebuild the viewer, and update the tests.
- **T003.** Add the sha256 pin assertion to the vectors test, plus a paragraph in the atap-js README. No import of receipt-verify (spec A1).
- **T004.** Docs only. Measure each proposal item's users with `grep -rn` in the task and put the result next to the item.

## Risks

- **Parity tests compare both verifiers.** JS and verify.sh must change in the same task, or `verify-sh-*.test.mjs` goes red. That is why T001 and T002 each own both.
- **Viewer staleness.** Forgetting `node viewer/build.mjs` turns the viewer step red. That step is in the verify command on purpose: no CI job runs it.
- **Removing the disclosure-time branch leaves dead comments** about instant comparison of `disclosed_at` in verify.ts, verify.sh and the tests. Rewrite them; don't leave them describing old behaviour.
- **atap-py tests need the built CLI** (`ATAP_WITNESS` resolves `packages/atap-cli/dist/cli.js`), plus `jq`, `openssl` and `python3` on PATH. The verify command builds the CLI first, the same order as `.github/workflows/atap-py.yml`.
- **Network:** `npm ci` fetches dev dependencies (typescript, @types/node).

## Verify (every task)

```bash
bash -c 'set -eo pipefail; (cd packages/atap-js && npm ci --no-audit --no-fund && npm test); (cd packages/atap-cli && npm ci --no-audit --no-fund && npm test); (cd viewer && npm test); (cd packages/atap-py && python3 -m unittest discover -s tests); cmp verify.sh packages/atap-py/src/atap/verify.sh; cd plugins/claude-code && node --test --test-reporter=tap test/*.test.mjs | tee /tmp/atap-scope-1-plugin.tap; grep -qx "# skipped 0" /tmp/atap-scope-1-plugin.tap'
```

Order matters: atap-js builds `dist/` for atap-cli and the viewer, and atap-cli builds `dist/cli.js` for atap-py and the plugin tests.
