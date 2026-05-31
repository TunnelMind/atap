# TunnelMind EAT Profile v0.1 (draft)

**Status:** DRAFT — published 2026-05-31 · 90-day public-comment window closes 2026-08-29.
**Editor:** TunnelMind
**Canonical URL:** https://tunnelmind.ai/eat/profile/v0.1
**License:** spec CC BY 4.0 · reference code Apache-2.0.
**Companion:** [TunnelMind Receipt Format v1.0](https://tunnelmind.ai/standards/receipt-format/v1) is the JSON serialization of the same claim set; this document is the RATS-aligned (CWT/JWT) view.
**Reference verifier:** `@tunnelmindai/eat` (planned, see `packages/eat-js` in `github.com/TunnelMind/atap`).

This profile defines how a TunnelMind ATAP receipt and its cross-lens
enrichments are conveyed as an IETF RATS Entity Attestation Token (EAT,
[RFC 9711]). It is a **serialization profile**, not a replacement: ATAP
v0.1.2 remains the canonical receipt format on `data.tunnelmind.ai`. This
profile exists so that any relying party that already speaks EAT — every
confidential-computing platform, TEE vendor, and enterprise security stack
that adopts the RATS architecture — can consume a TunnelMind attestation
natively, without learning ATAP first.

## 1. Status of this document

This is a draft. The bytes-on-the-wire formats, the claim names, and the
CBOR claim keys are all subject to change. Two things will not change
before v1:

1. The set of TunnelMind-specific claims and their semantic meaning
   (§9). The claim *keys* may move during IANA registration; the *fields*
   are settled.
2. The mapping from ATAP receipt fields to EAT claims (§10). ATAP v0.1.x
   is the source of truth; this profile is a view over it.

If you implement against this draft, pin the spec URL with a version
suffix (`/eat/profile/v0.1`) and re-verify against the latest CHANGELOG
when v1 publishes.

## 2. Notational conventions

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[BCP 14] ([RFC 2119], [RFC 8174]) when, and only when, they appear in
all capitals.

CBOR examples are written in the Extended Diagnostic Notation
([RFC 8610] Appendix G). JSON examples are pretty-printed for readability;
on-the-wire JSON is RFC-8785 canonicalized when signed.

Claim identifiers are written as `cbor_key / "json_name"`. Private-use
CBOR keys assigned by this profile are negative integers in the
[-65536, -1] private-use range defined by [RFC 9711] §7.1.

## 3. RATS roles and TunnelMind components

[RFC 9334] defines the RATS architecture in terms of roles. This profile
maps each role to an existing TunnelMind component so the architecture is
operational, not abstract.

| RATS role | TunnelMind component | Notes |
|---|---|---|
| Attester | Sigil witness service in `tunnelmind-data-api` | Signs ATAP witness events and blocks; emits the inner attestation. |
| Verifier | Sigil + Scry verification stack on `data.tunnelmind.ai` | Aggregates raw evidence into an EAT token signed by a verifier key. |
| Relying Party | Any agent or principal querying the verification API | Sends an EAT token, with or without a nonce; consumes claims to make a trust decision. |
| Endorser | Operator OAI registry at `tunnelmind.ai/id/{OAI}` | Endorses witness identity; the OAI resolver is the canonical endorsement path. |
| Reference-Value Provider | `atap-profiles` repo + Scry actor-class catalog | Names the values an evidence claim is expected to take. |

In the EAT-over-ATAP composition, the **inner attestation** is the ATAP
receipt (witness-signed) and the **outer attestation** is the EAT token
(verifier-signed). Both signatures are reproducible end-to-end against
the keys published at `tunnelmind.ai/atap/keys`.

## 4. Profile metadata

| Field | Value |
|---|---|
| Profile name | `urn:tunnelmind:eat-profile:v0.1` |
| Profile URL  | `https://tunnelmind.ai/eat/profile/v0.1` |
| Schemas      | `https://tunnelmind.ai/eat/profile/v0.1/schemas/` (TBD) |
| Examples     | `https://github.com/TunnelMind/eat-profile` (TBD) |
| Reference verifier | `verify.sh` + `@tunnelmindai/eat` (planned; not yet built) |

The profile URL is the value that MUST appear in the `profile` EAT claim
([RFC 9711] §4.2.7) of every token claiming conformance to this profile.

## 5. Serializations

This profile defines two serializations of the same claim set:

1. **CBOR / CWT** — the primary format. CWT ([RFC 8392]) wraps a CBOR
   map of claims, signs it with COSE_Sign1 ([RFC 9052]), and produces a
   compact binary token. CBOR is the recommended format for
   high-throughput API responses and for any path where bandwidth or
   parse cost matters.
2. **JSON / JWT** — the secondary format. JWT ([RFC 7519]) wraps a JSON
   map of claims, signs it with JWS ([RFC 7515]), and produces a base64
   URL-safe string. JSON is the recommended format for web integrations,
   MCP tool responses, and developer-facing debug surfaces.

A verifier MUST be able to issue both. A relying party MAY accept either.
Both serializations carry identical semantic claims; the wire format is
the only difference.

Signing algorithms (frozen for v0.1.x):
- CWT: COSE alg `EdDSA` over Ed25519. Identical to the curve already
  used by ATAP witness signatures.
- JWT: JWS alg `EdDSA` over Ed25519.

These match the existing ATAP key material at `tunnelmind.ai/atap/keys`;
no new key infrastructure is required.

## 6. Media types

Per [RFC 9782]:

- `application/eat+cwt` — CBOR/CWT serialization
- `application/eat+jwt` — JSON/JWT serialization

When conveyed in an HTTP response, the `Content-Type` MUST be one of
these. When conveyed inside a larger payload (a Sigil verify response,
an OAI resolver response), it appears under a named field with the
serialization implied by the field name (`eat_cwt_b64`, `eat_jwt`).

## 7. Endpoint conveyance

Existing TunnelMind endpoints add EAT representations via HTTP content
negotiation. The legacy JSON response remains the default; an EAT token
is returned only when the client explicitly asks for one.

| Endpoint | Default representation | EAT representation |
|---|---|---|
| `GET /id/{OAI}` | JSON (OAI resolver) | `Accept: application/eat+cwt` → CWT body; `Accept: application/eat+jwt` → JWT body |
| `POST /atap/witness` | ATAP receipt JSON | `Accept: application/eat+cwt` → CWT wrapping the receipt as a submodule |
| `GET /atap/keys` | JSON key list | `Accept: application/eat+cwt` → CWT carrying the key bundle (each key as a UEID-anchored sub-claim) |
| `GET /verify/{class}/{value}` (Sigil) | Sigil verdict JSON | `Accept: application/eat+cwt` → CWT carrying verdict + behavioral claims + the underlying ATAP receipt |

A relying party MAY also include a `nonce` query parameter or
`X-Eat-Nonce` header on any endpoint; the issued EAT token MUST carry
that nonce in the standard `nonce` claim ([RFC 9711] §4.2.1) to anchor
freshness.

## 8. Standard EAT claims used

This profile uses the following claims from the EAT claims registry
([RFC 9711] §4):

| CBOR key | JSON name | Source | Use |
|---|---|---|---|
| 1 | `iss` | RFC 7519 | Verifier's OAI, URL-form (`https://tunnelmind.ai/id/OAI-2026-0000201`). |
| 2 | `sub` | RFC 7519 | The entity being attested. URL-form OAI for an entity; URL of a Sigil-verified object (e.g. `https://example.com/sellers.json`) for a check. |
| 3 | `aud` | RFC 7519 | Relying party identifier when supplied by the request; otherwise omitted. |
| 4 | `exp` | RFC 7519 | Token expiry. Default 300 seconds from issuance; tokens carrying receipts MAY extend to the receipt's `period_end` + 300 s. |
| 6 | `iat` | RFC 7519 | Issuance time. MUST be present. |
| 7 | `cti` / `jti` | RFC 7519 / RFC 8392 | Token ID. Uuidv7 to inherit ATAP's time-ordering convention. |
| 10 | `nonce` | RFC 9711 §4.2.1 | Relying-party freshness anchor. Echoed verbatim when supplied. |
| 256 | `ueid` | RFC 9711 §4.2.2 | Universal Entity ID. When the subject is an OAI-registered entity, this carries the raw OAI bytes per the OAI binary form (see §9 entity-ref). |
| 265 | `profile` | RFC 9711 §4.2.7 | MUST be `urn:tunnelmind:eat-profile:v0.1`. |
| -65540 (TBD) | `submods` | RFC 9711 §4.2.20 | Submodule map carrying the ATAP receipt and Familiar sensor evidence (§11). |

The CBOR key `-65540` is a placeholder; submods claim uses an existing
registered key. Final keys will be aligned at implementation time.

## 9. TunnelMind-specific claims

This profile introduces six new claims. CBOR keys are placeholders in
the [RFC 9711] §7.1 private-use range pending IANA assignment.

### 9.1 `tunnelmind-attestation-strength-tier`

| CBOR key | -65531 (TBD) |
|---|---|
| JSON name | `tunnelmind-attestation-strength-tier` |
| Type | text string |
| Values | `"self-asserted"`, `"software"`, `"tee-tpm"`, `"silicon-root"` |
| Source | [ATAP v0.1.2 §7.4.1] `receipt.attestation_strength`. |

Declares the trust root the witness service ran under for the period
covered by this attestation. Ordered weakest-to-strongest. Missing means
`self-asserted` (the verifier MAY emit a `warnings` claim noting the
omission). A relying party MUST refuse a token whose declared strength
exceeds the matching key's declared strength at
`tunnelmind.ai/atap/keys`. This is the single load-bearing field for the
hardware upgrade path; see [ATAP v0.1.2 §14.8].

### 9.2 `tunnelmind-oai-entity-ref`

| CBOR key | -65532 (TBD) |
|---|---|
| JSON name | `tunnelmind-oai-entity-ref` |
| Type | text string |
| Pattern | `^OAI-[0-9]{4}-[0-9]{7}$` |
| Source | [ATAP v0.1.2 §6] `receipt.witness` (witness OAI) or `ait.operator` (operator OAI), depending on what the EAT is attesting. |

The canonical OAI of the entity this attestation concerns. Relying
parties resolve the OAI via `https://tunnelmind.ai/id/{OAI}` for
identity + endorsement detail. Distinct from `sub`: `sub` carries the
URL form; `entity-ref` carries the bare OAI for code paths that key
on it directly.

### 9.3 `tunnelmind-behavioral-consistency-score`

| CBOR key | -65533 (TBD) |
|---|---|
| JSON name | `tunnelmind-behavioral-consistency-score` |
| Type | float, range [0.0, 1.0] |
| Source | Computed by Scry at verification time. NOT carried in the ATAP receipt today. |

How consistent the entity's behavior in the observation window is with
its historical baseline. `1.0` = perfectly consistent. `0.0` = total
deviation. The computation algorithm is private (it lives behind the
Sigil scoring weights, which are the paid edge). The output is open and
auditable: every score reported in an EAT MUST be reproducible by replay
against the same observation set.

This claim is NEW signal not present in ATAP v0.1.2 today; it represents
the cross-lens enrichment described in [[project_a2_cross_lens_join]].

### 9.4 `tunnelmind-observation-depth`

| CBOR key | -65534 (TBD) |
|---|---|
| JSON name | `tunnelmind-observation-depth` |
| Type | map / JSON object |
| Source | Scry observation graph. |

Tells the relying party how much history backs the attestation.

Fields:
- `first-observed` — RFC 3339 timestamp, first time this entity (by
  OAI or by canonical identifier) appeared in any Scry observation.
- `total-sessions` — non-negative integer, count of distinct
  observation sessions credited to this entity.
- `observation-window-days` — positive integer, the rolling window
  the consistency score and deviation flags are computed over. Default
  90.

### 9.5 `tunnelmind-deviation-flags`

| CBOR key | -65535 (TBD) |
|---|---|
| JSON name | `tunnelmind-deviation-flags` |
| Type | array of text strings |
| Source | Scry deviation detector. |

Named behavioral anomalies. Empty array = clean. Enum (extensible, but
v0.1 SHOULD use only these names):

- `infrastructure-change` — IP/ASN/domain churn beyond the entity's
  baseline.
- `cadence-shift` — request timing pattern shifted from baseline.
- `coordination-pattern` — proximity to other entities in a cluster
  exhibiting joint behavior.
- `known-malicious-association` — direct edge to a Scry-flagged
  malicious entity.
- `credential-rotation-anomaly` — signing key rotated outside the
  declared policy window from [ATAP v0.1.2 §8].

A relying party SHOULD treat any non-empty `deviation-flags` array as
cause to lower trust, regardless of the consistency score.

### 9.6 `tunnelmind-graph-context`

| CBOR key | -65536 (TBD) |
|---|---|
| JSON name | `tunnelmind-graph-context` |
| Type | map / JSON object |
| Source | Cross-lens join over Scry × Sigil × Tracker. |

Position in the reputation graph. Fields:

- `known-associations` — non-negative integer, count of distinct
  entities linked to this one (any edge type).
- `malicious-adjacency-score` — float [0.0, 1.0], proximity to
  Scry-flagged malicious entities. `0.0` = no path within 2 hops.
  `1.0` = direct edge to a malicious cluster.
- `cluster-id` — OPTIONAL string. Present only when the entity is a
  member of a recognized coordinated-behavior cluster; absent
  otherwise. Cluster IDs are NOT stable across verifier restarts in
  v0.1 (the clusterer is stateful; this will tighten in v0.2).

## 10. ATAP receipt mapping

When a Sigil endpoint returns an EAT for a verifiable artifact, the
ATAP receipt fields map to EAT claims as follows:

| ATAP receipt field | EAT claim | Notes |
|---|---|---|
| `id` | `cti` / `jti` | Receipt UUID reused as token ID. |
| `ait` | `tunnelmind-ait-ref` (TBD) | Subordinate AIT identifier. |
| `profile` | `tunnelmind-profile` (TBD) | ATAP profile, e.g. `sigil:media_buyer:v1`. Distinct from the EAT `profile` claim, which is `urn:tunnelmind:eat-profile:v0.1`. |
| `period_start` | `iat` | Token issuance ≈ receipt start. |
| `period_end` | `exp` (+300 s) | Token expires shortly after the receipt window. |
| `witness` | `tunnelmind-oai-entity-ref` + `iss` | Witness OAI is both the verifier identifier and the entity-ref. |
| `attestation_strength` | `tunnelmind-attestation-strength-tier` | Verbatim. |
| `chain_head_hash` | `tunnelmind-chain-head-hash` (TBD) | Verifiable replay anchor. |
| `witness_signature` | (carried inside the submodule) | The original ATAP signature is preserved in the receipt submodule (§11), not flattened into the outer COSE_Sign1. |
| `verifier_url` | `tunnelmind-verifier-url` (TBD) | Where to re-run `verify.sh`. |
| `keys_url` | `tunnelmind-keys-url` (TBD) | Source of truth for the witness key. |

Fields not listed (e.g., `block_count`, `event_count`, `files`) are
carried verbatim inside the `submods["atap-receipt"]` submodule and are
not lifted into outer EAT claims. This keeps the outer claim set
focused on what a relying party needs at decide-time.

## 11. Submodule structure

EAT submodules ([RFC 9711] §4.2.20) carry nested attestations signed by
distinct authorities. This profile defines two:

```
Outer EAT (signed by Scry/Sigil verifier):
  iss, sub, iat, exp, jti, nonce?, profile,
  tunnelmind-attestation-strength-tier,
  tunnelmind-oai-entity-ref,
  tunnelmind-behavioral-consistency-score,
  tunnelmind-observation-depth,
  tunnelmind-deviation-flags,
  tunnelmind-graph-context,
  submods: {
    "atap-receipt": {
      // The full ATAP receipt manifest (§10 source-of-truth fields),
      // unmodified. Carries its own witness_signature, separately
      // verifiable against tunnelmind.ai/atap/keys.
    },
    "sensor-evidence": {  // OPTIONAL, present only with hardware-attested sensors (H2/H3)
      "hardware-identity": <DevID per RFC 9711 Appendix C / IEEE 802.1AR>,
      "measured-components": <per draft-ietf-rats-eat-measured-component>,
      "observation-timestamp": <RFC 3339>,
      "raw-observation-hash": <0x{64}>
      // Signed by the Familiar sensor key, NOT the outer verifier key.
    }
  }
```

A relying party MUST verify each submodule's signature against the
appropriate key bundle before trusting its claims. The outer signature
attests to the *composition*; the inner signatures attest to the
*contents*.

The `sensor-evidence` submodule is reserved for v0.2+ (Familiar fleet
+ hardware-anchored evidence). In v0.1, only `atap-receipt` is defined.

## 12. Verification procedure

A relying party verifying a TunnelMind EAT token MUST:

1. Decode the outer envelope (COSE_Sign1 for CWT; JWS for JWT).
2. Resolve the verifier key via the `iss` claim — fetch
   `{iss}/atap/keys` and find the active key matching the envelope's
   key ID.
3. Verify the outer signature against that key.
4. Reject if `exp` is in the past or `iat` is more than 60 seconds in
   the future.
5. If a `nonce` was supplied to the request, reject if the token's
   `nonce` does not match verbatim.
6. Compare the token's `tunnelmind-attestation-strength-tier` against
   the matching key's declared `attestation_strength` from the keys
   bundle. Reject if the token's strength exceeds the key's.
7. For each present submodule, recurse: extract the nested signature,
   resolve the signing authority, verify. For `atap-receipt`,
   `verify.sh` MAY be used directly against the submodule payload.
8. Surface the merged claim set to the application, including any
   `warnings` accumulated during verification.

A reference verifier (`@tunnelmindai/eat`, planned) will encapsulate
these steps and produce a single boolean + warnings array per call.

## 13. IANA considerations

This profile requests registration of:

- Profile URI `urn:tunnelmind:eat-profile:v0.1` in the EAT profiles
  registry ([RFC 9711] §10.X — placeholder).
- Six private-use claims (§9). CBOR keys requested in the [-65531,
  -65536] range; final values will be assigned by IANA at registration
  time.

Until IANA assigns final values, implementations MUST use the
placeholder CBOR keys listed in §8 and §9 and pin the spec by URL.

## 14. Security considerations

### 14.1 Signature scope and submodule trust

The outer EAT signature attests only to the composition of claims and
submodules. Each submodule's contents are attested by its own inner
signature. A relying party that consumes a submodule's claims without
verifying its inner signature is trusting only the verifier's good
faith. This is explicit in the protocol.

### 14.2 Token freshness

Tokens are short-lived (default 300 s `exp`) and SHOULD carry a
relying-party-supplied `nonce` when replay is a concern. Without a
nonce, a token within its `exp` window is replayable to any relying
party that does not maintain per-token state.

### 14.3 Attestation strength ceiling

The `tunnelmind-attestation-strength-tier` claim asserts the trust root
the witness ran under; a relying party MUST cross-check it against the
key's declared strength at `/atap/keys`. The key's strength is a
ceiling — a witness running on commodity hardware cannot truthfully
claim `tee-tpm` regardless of what the verifier writes in the outer EAT.

### 14.4 Behavioral score gameability

The `behavioral-consistency-score` is computed against historical
baselines. An entity that has only just begun being observed will have
a thin baseline and a score that is easily moved by a single anomalous
session. Relying parties SHOULD weight scores against
`observation-depth.total-sessions` and treat low-depth scores as low
confidence.

### 14.5 Cluster ID instability

`cluster-id` (§9.6) is NOT stable across verifier restarts in v0.1.
Relying parties MUST NOT use a cluster ID as a long-term identifier or
join key. Cluster identity stabilizes in v0.2.

### 14.6 No PII in claims

This profile inherits ATAP v0.1.2 §7.6: no end-user IPs, user agents,
cookies, emails, phones, account identifiers, wallet addresses tied to
natural persons, biometrics, browser/device fingerprints, or content
of communications. The claim set in this profile is constrained to
*entity-level* signal; nothing in §9 names an individual.

## 15. References

### Normative

- [RFC 2119] — Key words for use in RFCs to Indicate Requirement Levels
- [RFC 7515] — JSON Web Signature (JWS)
- [RFC 7519] — JSON Web Token (JWT)
- [RFC 8174] — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- [RFC 8392] — CBOR Web Token (CWT)
- [RFC 8610] — Concise Data Definition Language (CDDL)
- [RFC 8785] — JSON Canonicalization Scheme (JCS)
- [RFC 9052] — CBOR Object Signing and Encryption (COSE)
- [RFC 9334] — Remote ATtestation procedureS (RATS) Architecture
- [RFC 9711] — The Entity Attestation Token (EAT)
- [RFC 9782] — EAT Media Types
- [ATAP v0.1.2] — Agent Trust Attestation Protocol, `https://tunnelmind.ai/atap/standard`
- [OAI v1] — Observed Actor Identifier, `https://tunnelmind.ai/oai/standard`

### Informative

- [draft-ietf-rats-eat-measured-component] — Measured component claims
  for EAT.
- [IEEE 802.1AR] — Secure Device Identity (DevID).

### Companion documents

This profile ships with three companion documents. They live alongside
this spec at `tunnelmind.ai/docs/` and are versioned together with it.

- [EAT IANA registration draft](./EAT-IANA-REGISTRATION-v0.1.md) —
  the claim-allocation ledger and profile-registration template that
  goes to IANA when the profile is submitted.
- [EAT OAI resolver update](./EAT-OAI-RESOLVER-v0.1.md) — how the
  `tunnelmind.ai/id/{OAI}` resolver issues EAT-formatted responses on
  Accept-header negotiation, while preserving its legacy JSON path.
- [EAT migration plan for existing consumers](./EAT-MIGRATION-PLAN-v0.1.md) —
  the rollout sequence across Scry / Sigil / OAI endpoints, the
  backward-compatibility guarantees, and the client-side migration
  guidance.

## Appendix A: example CWT (informative)

CDDL sketch of an outer-EAT CWT body for a Sigil supply-path
verification:

```cddl
sigil-eat-cwt = {
  1   => "https://tunnelmind.ai/id/OAI-2026-0000201", ; iss
  2   => "https://example.com/sellers.json",          ; sub
  6   => 1748400000,                                  ; iat
  4   => 1748400300,                                  ; exp
  7   => h'018fc7a9...',                              ; cti / jti (uuidv7 bytes)
  10  => h'<nonce>',                                  ; nonce, if supplied
  265 => "urn:tunnelmind:eat-profile:v0.1",           ; profile
  -65531 => "software",                               ; attestation_strength_tier
  -65532 => "OAI-2026-0000201",                       ; oai_entity_ref
  -65533 => 0.94,                                     ; behavioral_consistency_score
  -65534 => {                                         ; observation_depth
              "first-observed": "2024-12-04T...",
              "total-sessions": 438,
              "observation-window-days": 90
            },
  -65535 => [],                                       ; deviation_flags
  -65536 => {                                         ; graph_context
              "known-associations": 17,
              "malicious-adjacency-score": 0.0
            },
  -65540 => {                                         ; submods
              "atap-receipt": { ... },
              ; "sensor-evidence" absent at v0.1
            }
}
```

## Appendix B: example JWT (informative)

```json
{
  "iss": "https://tunnelmind.ai/id/OAI-2026-0000201",
  "sub": "https://example.com/sellers.json",
  "iat": 1748400000,
  "exp": 1748400300,
  "jti": "018fc7a9-...",
  "nonce": "<nonce>",
  "profile": "urn:tunnelmind:eat-profile:v0.1",
  "tunnelmind-attestation-strength-tier": "software",
  "tunnelmind-oai-entity-ref": "OAI-2026-0000201",
  "tunnelmind-behavioral-consistency-score": 0.94,
  "tunnelmind-observation-depth": {
    "first-observed": "2024-12-04T11:08:33Z",
    "total-sessions": 438,
    "observation-window-days": 90
  },
  "tunnelmind-deviation-flags": [],
  "tunnelmind-graph-context": {
    "known-associations": 17,
    "malicious-adjacency-score": 0.0
  },
  "submods": {
    "atap-receipt": { "...": "ATAP v0.1.2 receipt object" }
  }
}
```

## Appendix C: migration plan (informative)

This profile is purely additive. Existing consumers of
`data.tunnelmind.ai` see no change unless they explicitly request EAT
representations via `Accept`. The implementation work, when authorized,
will land in three phases:

1. **EAT library** (`@tunnelmindai/eat`): pure encoder/decoder against
   this spec. Imports `@tunnelmindai/atap` for the submodule payload.
   No service dependency. Apache-2.0.
2. **Verifier wiring**: the Sigil verifier service in
   `tunnelmind-data-api` adds an EAT serializer. The serializer is
   conditional on an Accept-header content-negotiation step at the top
   of each endpoint. The default JSON path is untouched.
3. **Reference relying-party**: `verify-eat.sh` (bash + openssl + jq +
   a tiny CBOR helper) plus a worked example in `eat-profile` repo
   that fetches a token, decodes both submodules, and reports the
   final trust decision.
