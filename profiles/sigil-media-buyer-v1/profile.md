# `sigil:media_buyer:v1` — ATAP application profile

| | |
|---|---|
| **Profile identifier** | `sigil:media_buyer:v1` |
| **ATAP version** | 0.1 |
| **Domain** | Programmatic advertising — autonomous media-buying agents |
| **Maintainer** | TunnelMind (via Sigil) |
| **Status** | Reference profile — ships alongside ATAP v0.1 |
| **Standard** | <https://tunnelmind.ai/atap/standard> |

## 1. Purpose

An AI agent that buys programmatic advertising makes thousands of autonomous
spending decisions. Today its principal — the brand, the CISO, the DPO — gets a
self-reported campaign log: no signature, no chain, nothing to verify. This
profile defines the ATAP vocabulary that turns those decisions into a
**witness-signed, hash-chained attestation record** the principal can verify
independently with `verify.sh`.

It is the application profile referenced by ATAP v0.1 §9.3 and is consumed by
[Sigil](https://tunnelmind.ai), which acts as the witness (§3).

## 2. Identifier and versioning

The profile string is `sigil:media_buyer:v1` — `{namespace}:{domain}:v{N}`.
TunnelMind owns the `sigil` namespace in this registry. A breaking change to
any schema in this profile is published as `sigil:media_buyer:v2`; this
version's schemas are frozen.

## 3. Witness model

Per ATAP v0.1 §9.1, the witness is not the agent — it is a service that
observes the agent's actions, signs them, and chains them. **For this profile
the witness is Sigil.** The agent calls Sigil supply-path verification before a
bid; Sigil sees the decision, signs it, and chains it. Bid-lifecycle and budget
events that Sigil does not perform itself are reported to the Sigil witness
endpoint by the agent and signed on receipt — weaker than direct observation,
but, per ATAP §9.1, strictly better than an unsigned log, and bypassing the
witness shows up as a chain discontinuity.

This profile introduces no kernel or eBPF observer. A future `:v2` MAY bind a
stronger observation tier without changing the receipt format.

`attestation_policy.witness_granularity` for this profile SHOULD be `per_bid`
(a profile-defined value permitted by ATAP §6.2, which reserves `per_action`
and `per_decision` and lets profiles add their own).

## 4. Capabilities

An AIT's `capabilities` array MUST draw only from the vocabulary in
[`capabilities.json`](capabilities.json):

| Capability | Meaning |
|---|---|
| `bid:submit` | Submit a bid into an exchange auction. |
| `bid:read_response` | Read the auction response (won / lost / clearing price). |
| `supply:verify_via_sigil` | Call Sigil supply-path verification before bidding. |
| `budget:read` | Read remaining campaign budget. |
| `budget:decrement` | Decrement campaign budget on a won impression. |
| `creative:select` | Select which creative to attach to a bid. |
| `report:generate` | Generate an internal performance report. |
| `report:export_receipt` | Request an ATAP compliance receipt for a period. |

## 5. Constraints

The AIT `constraints` object is validated by
[`schemas/constraints.schema.json`](schemas/constraints.schema.json). Its
canonical-byte serialization MUST NOT exceed 4096 bytes (ATAP v0.1 §6.2).

| Field | Req. | Meaning |
|---|---|---|
| `currency` | yes | ISO 4217 code for every monetary amount in this AIT's events. |
| `max_bid_cpm` | yes | Maximum cost-per-mille the agent may bid. |
| `supply_trust_minimum` | yes | Minimum Sigil trust score (0–1) required before bidding. |
| `budget_total_cap` | yes | Total spend ceiling over the AIT lifetime. |
| `allowed_channels` | yes | Subset of `display`, `video`, `ctv`, `audio`, `native`. |
| `budget_daily_cap` | no | Optional per-day spend ceiling. |
| `blocked_domains` | no | Publisher domains not to bid on (≤ 100, to respect the 4 KB ceiling). |
| `blocked_categories` | no | IAB content categories not to bid on (≤ 50). |
| `geo_targeting` | no | `allowed_countries` / `blocked_countries`, ISO 3166-1 alpha-2. |

Constraints are declarative. The witness records a `constraint:violated` event
(§6) when an observed action exceeds a declared value — it does not block.

## 6. Witness event types

A conformant Witness Event MUST validate against **both** the ATAP v0.1 base
`witness-event` schema (the envelope) **and**
[`schemas/witness-events.schema.json`](schemas/witness-events.schema.json)
(the `event_type` → `payload` binding). Every payload sets
`additionalProperties: false` — see §8.

| `event_type` | Payload (required fields) | Optional |
|---|---|---|
| `bid:submitted` | `timestamp`, `exchange`, `publisher_domain`, `seller_id`, `bid_amount`, `currency`, `creative_id`, `channel` | `sigil_token`, `supply_trust_score` |
| `bid:won` | `timestamp`, `exchange`, `clearing_price`, `currency`, `impression_id` | — |
| `bid:lost` | `timestamp`, `exchange` | `reason` |
| `budget:decremented` | `timestamp`, `amount`, `currency`, `remaining_total` | `remaining_daily` |
| `supply:verified` | `timestamp`, `supply_path`, `sigil_result`, `trust_score` | `sigil_token` |
| `supply:rejected` | `timestamp`, `supply_path`, `sigil_result`, `rejection_reason` | `trust_score` |
| `constraint:violated` | `timestamp`, `constraint_name`, `declared_value`, `actual_value` | — |

`supply_path` carries `publisher_domain`, `exchange_domain`, `seller_id` only.
The device/user IP that Sigil's supply-path verification accepts as input is
deliberately **excluded** from the witnessed payload — it is a person-resolvable
field forbidden by ATAP §7.6.

`constraint:violated` is the load-bearing event: it is how the witness records
that the agent acted outside its declared `constraints` — bid above
`max_bid_cpm`, bid on supply below `supply_trust_minimum`, bid on a blocked
domain or category. A principal scanning a receipt looks here first.

## 7. Attestation Block `period_summary`

The Attestation Block `period_summary` is validated by
[`schemas/period-summary.schema.json`](schemas/period-summary.schema.json). It
aggregates the block's events: `bids_submitted`, `bids_won`, `total_spend`
(+`currency`), `unique_publishers`, `unique_exchanges`, `supply_verifications`,
`supply_rejections`, `average_trust_score`, `constraint_violations`,
`channels_used`, `geos_reached`. Every field is a count, a sum, or a mean — no
field resolves to a natural person.

## 8. PII prohibition (ATAP §7.6)

ATAP v0.1 §7.6 forbids any person-resolvable field in a Witness Event payload,
an Attestation Block summary, or a profile artifact. This profile encodes that
prohibition structurally: **every payload object, and the `supply_path`
sub-object, set `additionalProperties: false`.** A payload carrying an end-user
IP, email, cookie, session, device fingerprint, or named individual has no
permitted key and fails schema validation.

[`tests/pii-rejection.json`](tests/pii-rejection.json) is the §9.4(2) evidence:
six events that smuggle a forbidden field, each of which CI confirms is
rejected.

In scope, and permitted: domains, exchanges, seller IDs, creative and
impression IDs, prices, volumes, trust scores, channels, ISO country codes.

## 9. Receipt `profile_artifacts/`

Per ATAP v0.1 §7.5.1, the Receipt ZIP's `profile_artifacts/` directory carries
the application-specific evidence. For `sigil:media_buyer:v1` it contains:

| Path | Contents |
|---|---|
| `profile_artifacts/sigil_tokens.json` | Every `sigil_token` issued during the period, each tied to the `ATAP-WE-…` event that cited it. |

`verify.sh` verifies the chain without reading `profile_artifacts/`; a
profile-aware auditor uses it to confirm each bid was justified by a real Sigil
verification.

## 10. Conformance

An implementation conforms to `sigil:media_buyer:v1` if:

1. its AITs carry `profile: "sigil:media_buyer:v1"`, capabilities from §4, and
   `constraints` valid against the constraints schema;
2. its Witness Events validate against both the ATAP base `witness-event`
   schema and this profile's `witness-events` schema;
3. its Attestation Block `period_summary` validates against the period-summary
   schema;
4. no payload, summary, or artifact contains PII (§8);
5. its Receipts follow ATAP §7.5 with the `profile_artifacts/` of §9.

## 11. Examples

[`examples/`](examples/) holds a signed, hash-chained set — `ait.json`, a
seven-event `witness-events.json` chain (one of each event type), an
`attestation-block.json`, a `receipt.json`, and the `public_keys.json` they
verify against. They are generated by
[`scripts/generate-examples.mjs`](scripts/generate-examples.mjs) using the
`@tunnelmindai/atap` reference witness with an ephemeral fixture keypair, and
are re-verified in CI (`npm run verify`).

## 12. Changelog

- **v1 (2026-05-16)** — initial reference profile, published with ATAP v0.1.
