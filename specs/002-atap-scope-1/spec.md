# Feature: atap-scope-1 — ATAP is the crew's conduct ledger, not a second receipt standard

Source: Josh's prompt (2026-11-10) and the review `~/.crew/coord/review-2026-11-10/01-receipt-core.md` §5 (atap verdict: REPURPOSE), findings A-1 and A-3, the §8 duplication table. Everything below was checked against `origin/main` = `759ba5a`.

## Intent

ATAP's README and spec front matter say what ATAP is now: the record of what an agent crew did (events, owner approvals, operator-signed constraints, the data_model profile), not a competing product receipt beside Receipt v1.0. Its verifiers get two parity fixes from the review: a compromised key is refused for any time the signer writes, and a key that omits `attestation_strength` no longer skips the tier ceiling.

Key sentences from the prompt:
- "ATAP records what an agent crew did … and reuses Receipt v1.0 for signatures; it does not define a competing receipt format."
- "a compromised/revoked key is refused for any signer-written time (atap-js src/verify.ts ~103) and the tier ceiling is not skipped when a bundle key omits `attestation_strength` (~427). Same rule in atap-py. Tests in both."
- "one per language in this repo; if atap-js can import receipt-verify's without a publish, do; otherwise add a byte-equality test against shared vectors and say so."
- "Docs, positioning and two verifier parity fixes; no protocol change, no publish."

## Checked against origin/main: what is already done or wrong

| Prompt claim | Finding on main | What this run does |
|---|---|---|
| Z001 "reuses Receipt v1.0 for signatures" | **Wrong today.** ATAP signs with its own shapes: AIT/manifest = Ed25519 over JCS(doc − `witness_signature`), spelled `ed25519:0x<hex>`; blocks/events = Ed25519 over the raw 32-byte `self_hash` (`packages/atap-js/src/verify.ts`, `crypto.ts`; review §8 dialects 4–6). It shares only the building blocks (Ed25519, RFC 8785 JCS, the same frozen `jcs.json` vectors). README line 4 already says this ("a dialect of their own, beside Receipt v1"). | README states the true relation; "witness events become Receipt v1.0 payloads" goes in the Proposal section, not presented as done. |
| Z001 "the data_model profile" | **Not on main.** It lives on `origin/profile/data-model-v1` and `origin/crew/data-model-v1-fix-1` (unmerged). `profiles/profiles/` has code-crew, crew-ops, agent-tools, sigil-media-buyer. | README names it as a draft on a branch; merge-or-drop is a proposal item. |
| Z002 "compromised/revoked key" | ATAP has no `revoked` status. The statuses are `active`, `rotated`, `compromised` (ATAP-v0.1 §8.1). `rotated` is normal rotation and stays valid inside its window. | The fix covers `compromised` only. |
| Z002 "Same rule in atap-py" | atap-py has no verifier of its own. `atap.verify` runs the packaged `packages/atap-py/src/atap/verify.sh`, which must be byte-identical to the root `verify.sh` (`tests/test_trust.py::test_packaged_verify_sh_is_the_repo_copy`). | Fix `verify.sh` and copy it. Add an atap-py unittest that goes through `atap.verify`. |
| Z002 tier ceiling | The rule is already in the spec. ATAP-v0.1 §8.1 says key strength "missing values are treated as `self-asserted`". Both verifiers ignore that and only warn (`verify.ts` ~427-451, `verify.sh` ~504-530). | A conformance fix, not a protocol change. |
| Z003 one JCS per language | **Already true.** JS: `packages/atap-js/src/canonicalize.ts` only (`atap-cli`, `profiles/scripts`, viewer import it; `eat-js` has none). Python: the one in `verify.sh` (its atap-py copy is the same file). Both run the frozen vectors (`packages/atap-js/test/jcs-vectors.test.mjs`, `packages/atap-cli/test/verify-sh-canon.test.mjs`). Those vectors are byte-identical to receipt-verify's (sha256 `81a79410…8cdd`), but only a comment says so. | Turn that comment into an assertion and document it. Do not import receipt-verify (see Assumptions). |

## User Scenarios

### US1 — A reader learns what ATAP is for (P1)
A visitor opens the README or ATAP-v0.1.md and comes away knowing three things: ATAP is the crew's conduct ledger, Receipt v1.0 is the estate's one product receipt, and the two share Ed25519, JCS and the vectors.
- **Given** the README, **when** read top to bottom, **then** before "What's in this repo" it says what ATAP records (events, owner approvals, operator-signed constraints, the data_model profile as an unmerged draft). It says ATAP is not a competing product receipt, and has one diagram of how an ATAP chain and a Receipt v1.0 relate.
- **Given** the README, **then** a "Proposal: remove or freeze if unused" section lists the review's candidates, each marked *proposed, not done*.
- **Given** the README, **then** operator-signed constraints are described as a guard rail against accidents and drift, not a sandbox (review A-4).

### US2 — A compromised key cannot backdate (P1, review A-1)
- **Given** a receipt whose witness key entry has `status: "compromised"`, for any `disclosed_at` (before, at, or after the signer-written `issued_at` / `period_end` / `generated_at`), **when** verified with atap-js `verifyReceipt`, `atap-witness verify`, `verify.sh`, `atap.verify` (atap-py) or the viewer, **then** all of them refuse it (non-zero / `ok: false`).
- **Given** the same receipt with the key `active`, **then** it still verifies (control).

### US3 — A key with no strength caps the claim at self-asserted (P1, review A-3)
- **Given** an OAI receipt that claims `attestation_strength: "software"` (or higher) and whose matching key entry omits `attestation_strength`, **when** verified by any of the five verifiers above, **then** it fails with "exceeds key attestation_strength=self-asserted".
- **Given** the same key and a receipt claiming `self-asserted` or no claim, **then** it verifies (control).

### US4 — The JCS vectors cannot drift silently (P2)
- **Given** someone edits `packages/atap-js/test/vectors/jcs.json`, **when** atap-js tests run, **then** a test fails on the pinned sha256 unless the pin moves too, which is visible in review.

## Functional Requirements

- **FR-001** README.md: a positioning section near the top. It says ATAP records what an agent crew did and that Receipt v1.0 is the product receipt. It states truthfully that ATAP's signatures are its own shapes and share only Ed25519, JCS and the frozen vectors with Receipt v1.0. It says ATAP defines no competing product receipt.
- **FR-002** README.md: one Mermaid diagram (GitHub renders it) of an ATAP chain (AIT → events → blocks → Receipt ZIP, witness-signed) beside a Receipt v1.0 envelope, the shared parts (Ed25519, RFC 8785 JCS, `jcs.json` vectors), and the proposed link (dashed: "proposal: event as Receipt v1.0 payload").
- **FR-003** README.md: a "Proposal: remove or freeze if unused" section, not acted on, listing: `eat/` + `packages/eat-js` (unpublished JWS draft); `profiles/profiles/sigil-media-buyer-v1` (pre-pivot); the SCITT export (`packages/atap-js/src/scitt.ts`, `atap-witness` SCITT path) unless a consumer exists; `profiles/.github/workflows/validate.yml` (dead subtree workflow); `verify.sh` inside every Receipt ZIP (A-10); `data_model:v1` branches (merge or drop); making witness events Receipt v1.0 payloads so `receipt-verify` checks the crew record. Each entry names what uses it today, measured by grep in the task, or "nothing found".
- **FR-004** ATAP-v0.1.md and ATAP-v0.2.md front matter: one non-normative "Scope" row or note pointing at the README positioning. The normative text stays unchanged.
- **FR-005** Every verifier refuses a key entry with `status: "compromised"`, whatever its `disclosed_at`: `pickKey` and `pickDidKeyKey` in `packages/atap-js/src/verify.ts`, and `verify.sh` (key lookup ~236, `lookup_did_key` ~282, the strength lookup ~510). ATAP-v0.1 §8.1 says pre-disclosure receipts "SHOULD be marked unverified" and "downstream policy MAY treat them differently", so this is a verifier policy inside the spec. Comments cite that.
- **FR-006** A matching key entry with no `attestation_strength` (undefined/null/false/"") ranks as `self-asserted` for the ceiling, per ATAP-v0.1 §8.1. A receipt claim above that fails with a reason matching `/exceeds key.attestation_strength=self-asserted/` in both verifiers.
- **FR-007** `packages/atap-py/src/atap/verify.sh` stays byte-identical to root `verify.sh`. `viewer/dist/atap-viewer.html` is rebuilt (`node viewer/build.mjs`) whenever `verify.ts` changes, so `npm test` in `viewer/` (`build.mjs --check`) passes.
- **FR-008** `packages/atap-js/test/jcs-vectors.test.mjs` asserts sha256(`test/vectors/jcs.json`) = `81a79410874c5ed24ea0468a3d684e3a03111dc0a2fd2e8317ed3e3dfb978cdd` (receipt-verify's copy). `packages/atap-js/README.md` says there is one JS and one Python canonicalizer, both checked against those vectors, and why atap-js does not import receipt-verify.
- **FR-009** CHANGELOG.md "Unreleased" gets one entry per behaviour change (FR-005, FR-006), worded as a stricter verifier and not a protocol change.

## Success Criteria

- **SC-001** The plan.md verify command exits 0 at the end of every task, with `# skipped 0` for the plugin tests.
- **SC-002** New tests for FR-005 and FR-006 exist in atap-js (`packages/atap-js/test/`), atap-cli/verify.sh (`packages/atap-cli/test/`) and atap-py (`packages/atap-py/tests/`). Each task note records that they failed on the tree before the change.
- **SC-003** `cmp verify.sh packages/atap-py/src/atap/verify.sh` exits 0, and `cd viewer && node build.mjs --check` exits 0.
- **SC-004** `grep -c "Proposal" README.md` ≥ 1, `grep -c '```mermaid' README.md` = 1, and the README no longer calls ATAP "a canonical receipt format" in its opening paragraph.
- **SC-005** No file outside the repo changes. No publish, push or deploy happens (the coordinator pushes the PR branch).

## Edge Cases

- A compromised entry with no `compromise_notice` or an unparseable `disclosed_at` is refused too. That is fail closed, as today.
- A did:key witness that has several entries, one of them compromised, is refused: a notice on any entry voids the key (ATAP-v0.2 §3.1, already the rule).
- An OAI receipt naming a different witness than its AIT (§3.4): the ceiling still binds to the receipt witness's key, as now.
- Historical fixtures `packages/atap-cli/test/fixtures/v01-real/*`: every key and manifest there is `self-asserted` and `active`, so both fixes leave them verifying. Their own `verify.sh` snapshots are historical and are not edited.
- A did:key key entry must already declare `self-asserted` (§3.2), so FR-006 does not change the did:key path.

## Assumptions

- **A1 (Z003, no import):** `@tunnelmindai/receipt-verify` 2.0.0 is on npm, so an import needs no new publish. It is still not done: it would give `@tunnelmindai/atap` its first runtime dependency, `viewer/build.mjs` only bundles relative imports and `node:crypto`, so the viewer build would break, and `verify.sh`'s Python canonicalizer cannot import JS anyway. The vectors pin (FR-008) is the "otherwise" branch of the prompt. Josh can override this at GATE F.
- **A2 (FR-005):** Refusing pre-disclosure receipts outright, instead of returning a third "unverified" verdict, keeps the verifiers' output shapes unchanged ("no protocol change"). A three-state result would be an API change.
- **A3:** Reason strings may stay "no key for …" (the compromised entry is simply not selected), as long as JS and verify.sh agree.

## Out of Scope

- Changing the signature format, adopting Receipt v1.0 envelopes, or deleting anything on the proposal list.
- A-2 (self-signed OAI exit 0), A-5 to A-10, RV-* in receipt-verify, and the publish workflow's `npm@latest` (A-9).
- Merging or dropping `data_model:v1`, removing worktrees or branches.
- Any npm or PyPI publish, deploy, tunnelmind.ai change, or GitHub setting.
