# Changelog

All notable changes to ATAP are recorded here.

## Unreleased

### Changed

- **Editorial (2026-10-08): the profile registry's repository moved.** The
  registry now lives in the `profiles/` directory of this repository; the
  separate `atap-profiles` repository was folded in with its history
  (retirement R-06, atap#1) and is being archived. §9 and §12 now send profile
  proposals and objections to `TunnelMind/atap`, and the Appendix B table
  points at `atap/tree/main/profiles`. The rendered registry URL
  (`https://tunnelmind.ai/atap/profiles`) is unchanged. No schema, hash,
  signature or Receipt layout change, so per §13 this is a re-publish in
  place, not a new version.
- **Code, schemas, and the reference verifier relicensed from MIT to
  Apache-2.0.** The Apache license adds an explicit patent grant that
  MIT does not — load-bearing for a protocol library that may face
  patent claims as it sees adoption. The CC BY 4.0 license on the spec
  text (`ATAP-v0.1.md`) is unchanged; the spec lives under
  [`LICENSE-SPEC`](./LICENSE-SPEC) and the Apache-2.0 [`LICENSE`](./LICENSE)
  covers everything else in the repository. The `@tunnelmindai/atap`
  npm package's `license` field is updated to `Apache-2.0`. The
  reference `verify.sh` header is updated to match.

### Added

- `attestation_strength` (§7.4.1) — a four-tier ordered scale (`self-asserted` <
  `software` < `tee-tpm` < `silicon-root`) declaring the trust root the witness
  service ran under for a Receipt's period. The field appears on the Receipt
  manifest (§7.4) and on each key entry at `/atap/keys` (§8.1). OPTIONAL in
  v0.1.x — receipts and keys that omit the field MUST be treated as
  `self-asserted` by verifiers, with a stderr warning. REQUIRED at v0.2 (see
  §14.8). Per-event override is reserved for v2.
- §14.8 — locked position recording that the four-tier set, its ordering, and
  receipt-and-key placement are committed for the lifetime of v0.1.x and v0.2.
- `tunnelmind:code_crew:v1` application profile
  ([`profiles/profiles/tunnelmind-code-crew-v1/`](./profiles/profiles/tunnelmind-code-crew-v1/)),
  status draft — event vocabulary, schemas, examples, and PII-rejection tests
  for a crew of role agents (supervisor, coder, QA, reviewer) changing code
  under review.
- `@tunnelmindai/atap-cli` ([`packages/atap-cli/`](./packages/atap-cli/)) —
  the `atap-witness` CLI, a file-backed witness on `@tunnelmindai/atap` with
  `ait declare`, `event`, `block`, `receipt` and `verify`, JSON on stdin and
  stdout. Runs from a source checkout; not published to npm.

### Fixed

- **Signed objects are checked against their whole schema before they are
  stored.** `atap-witness` validated a few AIT fields one by one, so an AIT
  with a witness OAI that was really an e-mail address was signed and written.
  Every signed AIT, event and block is now validated against its complete
  core schema (`ait`, `witness-event`, `attestation-block`) as it is written;
  a refusal writes nothing. `WitnessService.declareAit` refuses a malformed
  `AitInput` (wrong field types) and an unparseable `expiresAt`, which used to
  make the lifetime checks silently skip.
- **The witness signed what ATAP forbids.** `WitnessService.witness` accepted
  any `event_type`, so an un-namespaced `approval` with an email in its
  payload was signed and its Receipt verified. The library now refuses an
  `event_type` outside the §7.2 pattern before writing anything, and
  `atap-witness` validates `event` payloads and `block` period summaries
  against the AIT's registered profile schemas (the §7.6 no-PII rules) and
  refuses `ait declare` for an unregistered profile unless
  `--unregistered-profile` is given. Refused calls write nothing.
- `verify.sh`: the JSON canonicalizer serialized non-integer numbers with
  `format(o, ".17g")`, which is not RFC 8785 — it expanded values such as
  `0.7` to `0.69999999999999996`, so the recomputed hashes never matched and
  every Receipt containing a non-integer number failed verification. The
  canonicalizer now emits the RFC 8785 / ECMAScript shortest round-trip form
  (`repr`), with integer-valued floats serialized without a fractional part.
  This is a verifier bug fix, not a protocol change.
- `@tunnelmindai/atap` (npm `0.1.1`): the Witness Event and Attestation Block
  `witness_signature` was computed over `canonicalizeBytes(self_hash)` — the
  canonicalized hex *string* — instead of the 32-byte SHA-256 digest that
  `self_hash` encodes. `verify.sh` already verified the raw digest, so the
  two reference implementations disagreed and no artifact could satisfy both.
  `witness.ts` and `verify.ts` now sign and verify the raw digest, matching
  `verify.sh` and §7.7.

### Changed

- §7.7 reworded to state unambiguously that the Witness Event and Attestation
  Block `witness_signature` covers the raw 32-byte SHA-256 digest encoded by
  `self_hash`, while the AIT and Receipt signatures cover the object's
  canonical JSON bytes directly (neither carries a `self_hash`). Editorial
  clarification of intent — no behavioural change for a conformant
  implementation.

## v0.1 — 2026-05-14

Initial public draft. Public comment window through **2026-08-12**.

### Scope

Protocol spec, JSON Schemas, JSON-LD context, reference verifier, and
reference TypeScript wrapper for **agent behavioral attestation**:

- AIT (Agent Identity Token) — capability declaration, witness-signed.
- Witness Event — per-action record, hash-chained.
- Attestation Block — periodic roll-up, hash-chained.
- Receipt — portable ZIP-format compliance export with embedded verifier.

### Decisions locked at ship

- Object IDs use uuidv7 with type prefixes.
- Witness service signs every artifact (AIT included); operator does not sign.
- Witness services identified by canonical OAI under the `witness.operator`
  category (added to OAI v1.0 §3 alongside this publication).
- SHA-256 over RFC 8785 (JCS) canonical bytes; Ed25519 signatures.
- Block interval bounds 60s ≤ x ≤ 3600s.
- Key rotation SHOULD ≥ 6 months under normal operation; MUST ≤ 1 hour
  post-compromise detection.
- Receipts are immutable. No protocol-level revocation.
- Profile-domain collisions resolve as separate namespaces, not editor
  arbitration.
- Governance automated via the `atap-profiles` repository (forthcoming).
  Profile-review SLO 7 days; objection-response SLO 14 days.

### Deferred to v1.x

- Transparency log (`/atap/log` URL reserved; implementation post-v1
  pending external adoption).

### Deferred to v2

- Post-quantum signatures (parallel chain, not replacement).
- Witness federation (multi-witness co-signed events).
- Privacy-preserving zero-knowledge aggregations.

## v0.0 — 2026-05-13

Scope locked in `Claude Memory/project_p38_atap.md`:
solo-viable scope = protocol + receipt + reference verifier.
NOT a kernel observer.
