# `tunnelmind:data_model:v1` — ATAP application profile

| | |
|---|---|
| **Profile identifier** | `tunnelmind:data_model:v1` |
| **ATAP version** | 0.1 |
| **Domain** | Semantic data models as code — built by an agent crew, gated, published, and assessed by agents and people |
| **Maintainer** | TunnelMind |
| **Status** | Draft profile |
| **Standard** | <https://tunnelmind.ai/atap/standard> |

## 1. Purpose

An agent asking a question of a database gets a plausible wrong answer when it
guesses at joins and metric meaning. A semantic model written as code — the
metrics, dimensions, joins and access rules defined once — turns that guess
into a compiled query that is right or refuses. This profile defines the ATAP
vocabulary that makes such a model **checkable**: how it was drafted and from
what, which correctness gates it passed and on which pinned data, when it was
published, and every later accuracy assessment, re-run and resolution.

One AIT covers one model lineage (`constraints.model_id`). Its receipt is that
model's full life story, verifiable offline with a trusted `verify.sh` or
`atap-witness verify` (ATAP v0.1.1 §3: never the copy inside the receipt).

## 2. Identifier and versioning

The profile string is `tunnelmind:data_model:v1`. TunnelMind claims the
`tunnelmind` namespace in this registry. A breaking change to any schema is
published as `tunnelmind:data_model:v2`. While the status is draft the
identifier may still be renamed; once the status is reference, this version's
schemas are frozen. An additive change, one that every existing event still
validates against unchanged, stays `v1`.

Model versions are separate from profile versions: each model version carries
a semver `version` and a `model_sha256`, the SHA-256 of the RFC 8785
canonical bytes of the model document parsed to JSON. Whitespace or key order
in the YAML therefore never changes a model's identity.

## 3. Witness model

Per ATAP v0.1 §9.1 the witness is not the agent. The **build crew** is the
agent: it holds the AIT and only drafts. The **registry** is the witness: the
crew submits each draft to it, and the registry pins the schema, runs the
gates, publishes, takes and resolves assessments, changes coverage and retires
versions itself. Those are **witness-derived events** (ATAP v0.1.1 §2(3)):
chained under the crew's AIT like any other event, emitted on the registry's
own account, and not suppressible, omittable or reorderable by the crew. The
crew cannot publish, mark its own work clean, or hide an assessment.

| Tier | Meaning |
|---|---|
| `asserted` | The reporter says so. Signed and chained, nothing more. |
| `anchored` | Bound to something a verifier can look up: a published model artifact by `model_sha256`, a pinned fixture by hash. |
| `witnessed` | The witness observed it itself — it read the schema, or it ran the gate. |

Tier rules for this profile:

- `data_model:gate_run` and `data_model:schema_pinned` are `witnessed` only if
  the registry ran or read them itself; otherwise `asserted`.
- `data_model:approved` is always `witnessed` — the schema pins it. The
  registry records the owner's decision itself; nobody reports it.
- `data_model:assessment_received` is always `asserted` — the schema pins it.
  An assessment is a claim until a resolution re-runs it.
- `data_model:drafted`, `published` and `retired` are `anchored` once the
  model artifact is retrievable by its hash; otherwise `asserted`.

`attestation_policy.witness_granularity` SHOULD be `per_action`.

## 4. Capabilities

An AIT's `capabilities` MUST draw only from [`capabilities.json`](capabilities.json):

| Capability | Meaning |
|---|---|
| `data_model:draft` | Write or revise a semantic model as code (Apache Ossie YAML) from declared, hashed inputs and submit it to the registry. |

That is the whole vocabulary. Every other event type in §7 is witness-derived
(§3) and needs no agent capability.

| Event | Emitted by |
|---|---|
| `drafted` | crew (submitted to the registry) |
| `schema_pinned`, `gate_run`, `approved`, `published`, `coverage_changed`, `assessment_received`, `assessment_resolved`, `retired` | registry, on its own account |

## 5. Constraints

The AIT `constraints` object is validated by
[`schemas/constraints.schema.json`](schemas/constraints.schema.json) and MUST
NOT exceed 4096 canonical bytes.

| Field | Req. | Meaning |
|---|---|---|
| `model_id` | yes | The one model lineage this AIT witnesses. |
| `allowed_sources` | yes | Source identifiers the model may be built from or compiled against (1–50). |
| `required_gates` | yes | Exactly `compile`, `structural`, `golden`, `reconcile`. |
| `fixture_policy` | yes | `fixture_only`, or `fixture_then_live` (fixture runs required; live runs permitted in addition, after publish). Every `pre_publish` run is on a pinned fixture under either value; live runs are `post_publish` only. |
| `max_live_reruns_per_day` | yes | Ceiling on live gate runs per UTC day, across all triggers (0–1000). |
| `min_assessor_tier_for_rerun` | yes | Lowest assessor tier whose reproducible assessment triggers a free re-run. |
| `models` | yes | Model identifier for one or more of the agent roles `drafter`, `reviewer`, `coordinator`. |

A principal checks the events against the constraints — for example a
`published` event with no preceding passing `pre_publish` `gate_run` for each
required gate on the same `model_sha256`, a `drafted` input whose `source_id`
is not in `allowed_sources`, or more `target: live` runs in a day than
`max_live_reruns_per_day`.

## 6. The four gates

| Gate | What it proves | What it cannot catch |
|---|---|---|
| `compile` | Every metric, dimension and join compiles to valid SQL against the pinned schema of every source it uses (`schema_fingerprints`). | Joins that compile and are semantically wrong. |
| `structural` | Join fan-out (row counts before and after each join), declared-key uniqueness, null-rate bounds per field. | Wrong business definitions on correct joins. |
| `golden` | The model's answers match expected answers from an **independent** source, within each metric's declared tolerance. | Questions nobody asked. |
| `reconcile` | The same fact computed through two sources agrees within tolerance (e.g. a client count from the API and from syslog). | Errors both sources share. |

Independence is structural: `golden_source` is one of `human_sql`,
`vendor_ui`, `second_source` or `confirmed_assessment`. The drafting crew is
not a permitted source; [`tests/gate-shapes.json`](tests/gate-shapes.json)
proves a crew-sourced golden run is rejected.

Tolerance is declared per metric in the model document, not in the event, so
it is covered by `model_sha256` and cannot be loosened after the fact without
a new version.

## 7. Witness event types

A conformant Witness Event MUST validate against **both** the ATAP v0.1 base
`witness-event` schema and
[`schemas/witness-events.schema.json`](schemas/witness-events.schema.json).
Every payload requires `timestamp` and `evidence` and sets
`additionalProperties: false`.

| `event_type` | Payload (besides `timestamp`, `evidence`) |
|---|---|
| `data_model:drafted` | `model_id`, `version` (semver), `model_sha256`, `format` (`apache-ossie`), `format_version`, `drafter_model`, `prompt_sha256`, `inputs[]` {`source_id`, `kind`, `sha256`} |
| `data_model:schema_pinned` | `model_sha256` (the draft this pin was taken for), `source_id`, `source_version`, `schema_fingerprint_sha256`. One event per source the draft used. |
| `data_model:gate_run` | `model_sha256`, `gate`, `phase` (`pre_publish` \| `post_publish`), `trigger` (`build` \| `scheduled` \| `assessment`), `target` (`fixture` \| `live`), `schema_fingerprints[]` {`source_id`, `sha256`} (one per source, `source_id` unique), `fixture_sha256` (fixture runs only), `golden_source` (golden runs only), `result`, `checks` {`total`, `passed`, `failed`, `refused`}, `output_sha256` |
| `data_model:approved` | `role` (always `owner`), `decision` (`approve` \| `reject`), `model_sha256`, `approval_text_sha256`. The approval text is recorded only as its sha256, never the text; the person appears only as the role. |
| `data_model:published` | `model_id`, `version`, `model_sha256`, `supersedes_sha256` (or null), `diff_sha256` (when superseding), `coverage` {counts per state}, `coverage_sha256`, `golden_count` |
| `data_model:coverage_changed` | `model_sha256`, `field_ref`, `from`, `to`, `cause_event` |
| `data_model:assessment_received` | `model_sha256`, `field_ref`, `verdict`, `assessor_kind` (`agent` \| `human`), `assessor_tier`, `assessor_nullifier_sha256`, `evidence_kind` (`bare` \| `reproducible`); when reproducible also `query_sha256`, `expected`, `observed` |
| `data_model:assessment_resolved` | `assessment_event`, `rerun_event` (unless `out_of_scope`), `outcome` (`confirmed` \| `not_reproduced` \| `out_of_scope`), `golden_added` |
| `data_model:retired` | `model_sha256`, `reason` (`superseded` \| `failed_rerun` \| `source_retired`), `superseded_by_sha256` (when superseded), `cause_event` (required when `failed_rerun`) |

### 7.1 Receipts are immutable; status is derived

ATAP v0.1 §14.1 locks receipts as immutable. Nothing in this profile edits a
published version or an earlier event. A version's **current status** — its
coverage per field, its open and confirmed assessments, whether it is retired
— is the fold of every later event in the chain over its `published` event.
Coverage changes are `coverage_changed` events; retirement is a `retired`
event. A consumer that wants freshness reads status from the registry's
attribute endpoint, which carries the PIP freshness contract (`valid_until`,
`stale_if_error`); the chain is the evidence behind that answer.

### 7.2 Assessments

An assessment is one agent's or person's signed claim that a field of one
published version is accurate or inaccurate.

- **No identity in the chain.** The assessor is recorded by `assessor_kind`,
  `assessor_tier` and `assessor_nullifier_sha256` — SHA-256 of the
  assessor's Ed25519 signature over `model_sha256`. Ed25519 signatures are
  deterministic, so one key yields exactly one nullifier per version and the
  registry enforces one assessment per key per version by refusing a repeated
  nullifier. Only the key holder can produce the signature, so nobody holding
  the assessor's public key can recompute nullifiers to link that assessor
  across versions. The registry verifies the signature at intake and records
  only its digest; no key id, name or account appears in any payload.
- **Bare vs reproducible.** A `bare` assessment is a recorded signal only. A
  `reproducible` one carries `query_sha256` (the structured query artifact,
  §9), `expected` and `observed`, and can trigger a re-run.
- **Re-runs are rate-limited and ordered.** A reproducible assessment at or
  above `min_assessor_tier_for_rerun` triggers a `post_publish`, `trigger:
  assessment` gate run, on the fixture first. Below that tier the re-run is
  paid per call. Live re-runs count against `max_live_reruns_per_day`. A
  failed re-run on a gate the version previously passed retires it
  (`failed_rerun`, with its `cause_event`) unless the failure is confined to
  fields already `degraded` before the re-run (marked by an earlier
  `coverage_changed` event, not by the re-run itself).
- **Confirmed assessments harden the suite.** `outcome: confirmed` with
  `golden_added: true` means the assessor's query, with the independently
  re-computed expected value, is now a permanent golden question for every
  later version of the lineage (`golden_source: confirmed_assessment`).
  Only a confirmed assessment may add a golden; the schema enforces it.
- **Votes never decide correctness.** A model with any confirmed inaccurate
  assessment on a field has that field `degraded` regardless of how many
  `accurate` assessments it holds. Tallies are reported beside gate results,
  never merged into them.

## 8. Attestation Block `period_summary`

Validated by [`schemas/period-summary.schema.json`](schemas/period-summary.schema.json).
Every field is a non-negative integer: `drafted`, `published`, `retired`,
`gate_runs` {`pass`, `fail`}, `coverage_degraded`, `assessments`
{`received`, `confirmed`, `not_reproduced`, `out_of_scope`}, `golden_added`.
No field resolves to a natural person.

## 9. Receipt `profile_artifacts/`

| Path | Content |
|---|---|
| `profile_artifacts/witness_events.json` | Every Witness Event the receipt's blocks cover, in chain order, as in `tunnelmind:code_crew:v1` §9. |
| `profile_artifacts/models/{model_sha256}.yaml` | Each model version's Apache Ossie document. Its parsed RFC 8785 canonical bytes MUST hash to the file name. |
| `profile_artifacts/golden_questions.json` | The golden suite: per question, `query_sha256`, the structured query, `golden_source`, expected value and tolerance. No natural-language text. Validated by [`schemas/golden-questions.schema.json`](schemas/golden-questions.schema.json). |
| `profile_artifacts/queries/{query_sha256}.json` | Structured queries referenced by assessments: metric, dimensions, filters, time range. Validated by [`schemas/query.schema.json`](schemas/query.schema.json); no free text. `query_sha256` is the SHA-256 of the query's RFC 8785 canonical bytes. |
| `profile_artifacts/coverage/{model_sha256}.json` | Per-field coverage map at publication; MUST hash to the event's `coverage_sha256`. |
| `profile_artifacts/diffs/{diff_sha256}.json` | Fields added, changed, removed and regressed between a version and the one it supersedes. |

Fixtures are not shipped in the receipt; they are referenced by
`fixture_sha256`. Fixtures MUST be synthetic or taken from a vendor sandbox,
never from an operator's production estate, so a fixture can be published
without exposing anyone's network.

A profile-aware verifier checks, beyond `verify.sh`: the event-chain checks
of `tunnelmind:code_crew:v1` §9; that each `published` version has a passing
`pre_publish` run of every required gate on the same `model_sha256`; that
every source the draft used (`drafted.inputs[].source_id`) is pinned by a
`schema_pinned` event for that `model_sha256`, and each of those
`pre_publish` gate runs' `schema_fingerprints` equals those pins exactly —
the same set of `source_id`s, each with the pinned
`schema_fingerprint_sha256` (spec AC-2.1). A gate run whose fingerprint for a
source differs from its pin, that omits a pinned source, or that names a
source with no pin fails the check; `source_id` MUST be unique within
`schema_fingerprints` (the schema cannot express per-key uniqueness, so the
verifier rejects a repeated `source_id`); that each of the first three versions of a
lineage (same `model_id`, counted in `published` order) has a
`data_model:approved` event with `decision: approve` for the same
`model_sha256` earlier in the chain than its `published` event — version four
onward needs no approval, the gates decide (spec AC-3.2 as settled in §9.4);
that every `cause_event`, `assessment_event` and
`rerun_event` names an earlier event in the chain; and that each artifact's
bytes match the hash its event names.

## 10. PII prohibition (ATAP §7.6)

- every payload object and sub-object sets `additionalProperties: false`;
- assessors appear only as kind, tier and a per-version nullifier digest;
- the approving human appears only as the role `owner`, and the approval
  text only as `approval_text_sha256`;
- questions, prompts, queries and outputs appear only as sha256 digests in
  events; the structured query artifacts admit no free text:
  [`schemas/query.schema.json`](schemas/query.schema.json) takes metric and
  dimensions as `field_ref`s and a filter value only as a number, a boolean
  or an opaque token, and
  [`schemas/golden-questions.schema.json`](schemas/golden-questions.schema.json)
  holds only machine fields per golden question;
- identifier fields (`model_id`, `source_id`) are opaque tokens with no `@`
  or whitespace, and MUST NOT carry an IP address or a key id (a `did:key`,
  a fingerprint); `source_version` and `format_version` are version tokens
  (letters, digits, `.`, `+`, `_`, `-`; no `:`, `/`, `@` or whitespace), so
  an `ip:port` or a `did:key` cannot pass as a version; and `field_ref` is
  lower-case dotted identifiers only.

[`tests/pii-rejection.json`](tests/pii-rejection.json) is the §9.4(2)
evidence: fifteen cases — ten events smuggling a name, an email, a key id,
free-text question, a client IP, or an `ip:port` or `did:key` as a source
version, four structured queries carrying an email
filter value, an email filter object, a free-text filter string or an extra
question key, and one golden entry with question text; CI confirms each is
rejected.

## 11. Conformance

An implementation conforms to `tunnelmind:data_model:v1` if:

1. AITs carry `profile: "tunnelmind:data_model:v1"`, capabilities from §4,
   and `constraints` valid against the constraints schema;
   events other than `drafted` are emitted by the witness on its own
   account (§3);
2. Witness Events validate against the ATAP base and this profile's schemas;
3. the `period_summary` validates against the period-summary schema;
4. no payload, summary or artifact contains PII (§10);
5. every event's `evidence` follows §3;
6. no version is published without passing every gate in `required_gates`
   (§6), none of a lineage's first three versions is published without an
   earlier owner `approved` event with `decision: approve` for the same
   `model_sha256` (§9; version four onward needs none), and no published
   version or event is edited (§7.1).

## 12. Examples

[`examples/`](examples/) holds a signed, hash-chained set: `ait.json`, a
thirteen-event chain covering every event type — draft, schema pin, four
passing gates, the owner's approval, publication, a reproducible assessment, its re-run against an
independently recomputed answer (`human_sql`), its confirmation, the field
degraded, and the version retired as `failed_rerun` — plus
`attestation-block.json`, `receipt.json`, `public_keys.json`, the
assessment's structured query `query.json` (its hash is the event's
`query_sha256`) and the golden suite it joined, `golden-questions.json`. Regenerate
with `node scripts/generate-examples.mjs`. All values are illustrative.
