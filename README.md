# ATAP application profiles

> **Part of TunnelMind — the intelligence layer agents call before they trust the internet.**
> Three lenses on one signed corpus: **Scry** (*who is attacking?*) · **Sigil** (*who can you trust?*) · **Tracker Data API** (*who is watching?*).
> This repo serves: **the open protocol layer.** Profile registry for ATAP; consumed by lens-specific witnesses across all three. See [tunnelmind.ai](https://tunnelmind.ai).

Source-of-truth registry for [ATAP v0.1](https://tunnelmind.ai/atap/standard)
application profiles. Published at <https://tunnelmind.ai/atap/profiles>.

ATAP — the Agent Trust Attestation Protocol — is a structural envelope: it
defines Agent Identity Tokens, Witness Events, Attestation Blocks, Receipts,
and a hash-chain + Ed25519 signature scheme over them. It deliberately says
nothing about *what* an agent does. That domain-specific vocabulary — the
event types, the payload shapes, the aggregation rules — lives in an
**application profile** (ATAP v0.1 §9).

## Profiles in this registry

| Profile | Domain | Maintainer | Status |
|---|---|---|---|
| [`sigil:media_buyer:v1`](profiles/sigil-media-buyer-v1/profile.md) | Programmatic ad-buying agents | TunnelMind (via Sigil) | Reference |

`sigil:ecommerce_buyer:v1` and `sigil:data_broker:v1` are reserved.

## What a profile defines

Per ATAP v0.1 §9.3, a profile defines, for one agent domain:

1. the vocabulary of `event_type` strings the witness emits;
2. the JSON Schema for each event type's `payload`;
3. the JSON Schema for the Attestation Block `period_summary`;
4. the JSON Schema for the AIT `constraints` object;
5. the contents of `profile_artifacts/` in the Receipt ZIP.

A profile directory holds those schemas, a human-readable `profile.md`, the
capability vocabulary, signed example artifacts, and PII-rejection test cases.

## Proposing a profile

Profiles are added by pull request. Per ATAP v0.1 §9.4, CI runs four acceptance
checks and **auto-merges** a passing PR within 7 days absent an editorial
objection:

1. every schema is valid JSON Schema 2020-12;
2. the schemas encode the §7.6 no-PII prohibition — proven by `tests/pii-rejection.json`
   cases that MUST fail validation;
3. the `{namespace}` token is not already claimed (first-comer wins);
4. the profile ships a signed example AIT, Witness Event, Attestation Block,
   and Receipt that round-trip through the reference verifier.

Checks (1), (2) and (4) run in CI:

```bash
npm install
npm test          # validate + verify
```

`npm run validate` covers checks 1-2; `npm run verify` covers check 4.

## Repository layout

```
atap-v0.1-schemas/              pinned copy of the frozen ATAP v0.1 base schemas
profiles/<profile>/
  profile.md                    human-readable profile definition
  capabilities.json             capability vocabulary
  schemas/                      constraints / witness-events / period-summary
  examples/                     signed AIT, event chain, block, receipt, keys
  tests/pii-rejection.json      §7.6 negative test cases
  scripts/generate-examples.mjs regenerates the signed examples
scripts/                        validate.mjs, verify-examples.mjs (registry CI)
registry.json                   machine-readable index
```

## Licence

CC BY 4.0. See [`LICENSE`](LICENSE).
