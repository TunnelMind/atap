# TunnelMind EAT Profile

> **Part of TunnelMind — the intelligence layer agents call before they trust the internet.**
> Three lenses on one signed corpus: **Scry** (*who is attacking?*) · **Sigil** (*who can you trust?*) · **Tracker Data API** (*who is watching?*).
> This repo serves: **the open protocol layer.** EAT Profile is CC-BY-4.0 (spec) + Apache-2.0 (reference code). See [tunnelmind.ai](https://tunnelmind.ai).

This repo holds the **TunnelMind EAT Profile v0.1** — an IETF RATS-aligned ([RFC 9711]) Entity Attestation Token serialization for TunnelMind [ATAP receipts](https://tunnelmind.ai/atap/standard) and their cross-lens enrichments.

The profile is a **serialization over ATAP, not a replacement**: ATAP v0.1.2 remains the canonical receipt format on `data.tunnelmind.ai`. This profile exists so that any relying party already speaking EAT — every confidential-computing platform, TEE vendor, and enterprise security stack that adopts the RATS architecture — can consume a TunnelMind attestation natively without learning ATAP first.

## Status

**DRAFT** — published 2026-05-31. Public-comment window closes **2026-08-29**.

Canonical spec: <https://tunnelmind.ai/eat/profile/v0.1>
Raw markdown:  [EAT-PROFILE-v0.1.md](./EAT-PROFILE-v0.1.md)
Reference verifier: planned at `packages/eat-js` inside [`TunnelMind/atap`](https://github.com/TunnelMind/atap) (npm `@tunnelmindai/eat`).

## What's in scope

- **6 TunnelMind-specific EAT claims** (§9 of the spec):
  - `tunnelmind-attestation-strength-tier` — declared trust root (self-asserted / software / tee-tpm / silicon-root)
  - `tunnelmind-oai-entity-ref` — the OAI of the attested entity (resolves at `tunnelmind.ai/id/{OAI}`)
  - `tunnelmind-behavioral-consistency-score` — Scry's cross-lens consistency signal
  - `tunnelmind-observation-depth` — observation history backing the attestation
  - `tunnelmind-deviation-flags` — named behavioral anomalies
  - `tunnelmind-graph-context` — entity's position in the reputation graph
- **Two serializations**: CBOR/CWT (primary) + JSON/JWT (secondary). Verifier MUST emit both; relying parties MAY accept either.
- **Two submodules**: `atap-receipt` (witness-signed) + `sensor-evidence` (Familiar hardware, reserved for v0.2+).
- **Signing**: EdDSA over Ed25519 for both serializations, using the existing ATAP key material at `tunnelmind.ai/atap/keys` — zero new key infrastructure.

## License

| Component | License |
|---|---|
| Specification (`EAT-PROFILE-v0.1.md`) | CC BY 4.0 |
| Reference code (when published in `packages/eat-js` inside the atap monorepo) | Apache-2.0 |

Open protocol layer per [TunnelMind open-protocol policy](https://tunnelmind.ai/standards) — the format is open, the scoring weights stay closed.

## How to engage

- File an issue on this repo for spec discussion.
- File a PR for typo fixes / clarifications.
- For protocol-level changes, open an issue with `[v0.2]` in the title — substantive changes are deferred to v0.2 per the spec's §1 stability statement.
- Implementation discussion lives on [`TunnelMind/atap` Discussions](https://github.com/TunnelMind/atap/discussions); cross-link from issues here as needed.

## Related

- [ATAP v0.1.2](https://tunnelmind.ai/atap/standard) — the receipt format this profile serializes.
- [TunnelMind Receipt Format v1.0](https://tunnelmind.ai/standards/receipt-format/v1) — the JSON serialization of the same claim set.
- [OAI v1.0](https://tunnelmind.ai/oai/standard) — the identifier standard for the entities EAT tokens describe.
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) — IETF RATS EAT.
- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) — IETF RATS architecture.
