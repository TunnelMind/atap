# Changelog

All notable changes to ATAP are recorded here.

## Unreleased

### Fixed

- `verify.sh`: the JSON canonicalizer serialized non-integer numbers with
  `format(o, ".17g")`, which is not RFC 8785 — it expanded values such as
  `0.7` to `0.69999999999999996`, so the recomputed hashes never matched and
  every Receipt containing a non-integer number failed verification. The
  canonicalizer now emits the RFC 8785 / ECMAScript shortest round-trip form
  (`repr`), with integer-valued floats serialized without a fractional part.
  This is a verifier bug fix, not a protocol change.

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
