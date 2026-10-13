# `tunnelmind:code_crew:v1` — ATAP application profile

| | |
|---|---|
| **Profile identifier** | `tunnelmind:code_crew:v1` |
| **ATAP version** | 0.1 |
| **Domain** | Software work — a crew of role agents changing code under review |
| **Maintainer** | TunnelMind |
| **Status** | Draft profile |
| **Standard** | <https://tunnelmind.ai/atap/standard> |

## 1. Purpose

A crew of AI agents (supervisor, coder, QA, reviewer) claims tasks, commits
changes, runs tests, passes verdicts on each other's work, and asks a human
owner to approve merges and deploys. Today the record of that work is the
crew's own log: no signature, no chain, nothing to verify. This profile defines
the ATAP vocabulary that turns each claim into a **witness-signed, hash-chained
attestation record**, with an evidence tier on every event saying how strong
the claim is. A principal verifies the record independently with `verify.sh`.

## 2. Identifier and versioning

The profile string is `tunnelmind:code_crew:v1` — `{namespace}:{domain}:v{N}`.
TunnelMind claims the `tunnelmind` namespace in this registry. A breaking
change to any schema in this profile is published as `tunnelmind:code_crew:v2`.
While the status is draft the identifier may still be renamed; once the status
is reference, this version's schemas are frozen. An additive change, one that
every existing event still validates against unchanged, stays `v1` (see §12).

## 3. Witness model

Per ATAP v0.1 §9.1, the witness is not the agent — it is a service that
receives the crew's claims, signs them, and chains them. Most events are
reported to the witness by the crew; each event's `evidence` field says what a
verifier can rely on:

| Tier | Meaning |
|---|---|
| `asserted` | The crew says so. Signed and chained, nothing more. |
| `anchored` | Bound to something a verifier can look up: a git commit sha, a merge commit, a publicly checkable version id. |
| `witnessed` | The witness observed it itself — for example the witness ran the verify command, or the event came from a CI runner rather than an agent. |

Tier rules for this profile:

- `code_crew:change_committed` is always `anchored` — the sha is checkable in
  the repo. The schema pins `evidence` to `anchored`.
- `code_crew:merged` is `anchored` for a PR merge — the PR and its merge
  commit are public and checkable in the repo — and `asserted` for a local
  merge, because no third party can check a private local repo. The schema
  pins `evidence` per `merge_kind`.
- `code_crew:verify_run` is `witnessed` only if the witness ran the command
  itself; otherwise `asserted`.
- `code_crew:deployed` is `anchored` when `version_id` is publicly checkable
  at `target`; otherwise `asserted`.
- The other events are `asserted` unless the witness itself observed them.

`attestation_policy.witness_granularity` for this profile SHOULD be
`per_action` (ATAP §7.1.1).

## 4. Capabilities

An AIT's `capabilities` array MUST draw only from the vocabulary in
[`capabilities.json`](capabilities.json). ATAP §7.1 requires capability tokens
to be colon-delimited, so each carries the `code_crew:` prefix:

| Capability | Meaning |
|---|---|
| `code_crew:plan` | Pick the next task and write the brief and acceptance checks for it. |
| `code_crew:code` | Change files in a working tree and commit the change. |
| `code_crew:verify` | Run the task's verify command (tests, build, lint) and report its exit code. |
| `code_crew:qa_verdict` | Independently check a change and accept it or send it back for rework. |
| `code_crew:review_verdict` | Review a branch head and pass or fail it with finding counts by severity. |
| `code_crew:approve` | Record the owner's approve or reject decision on a gated step. |
| `code_crew:merge` | Merge a reviewed change into the target branch. |
| `code_crew:deploy` | Release a merged change to a deployment target. |
| `code_crew:revert` | Undo a committed, merged or deployed change. |

## 5. Constraints

The AIT `constraints` object is validated by
[`schemas/constraints.schema.json`](schemas/constraints.schema.json). Its
canonical-byte serialization MUST NOT exceed 4096 bytes (ATAP v0.1 §6.2).

| Field | Req. | Meaning |
|---|---|---|
| `autonomy_class` | yes | `supervised` (the owner approves every change before merge), `gated` (unattended, stops at declared gates such as merge and deploy for an owner approval), or `autonomous` (may merge and deploy without an approval event). |
| `allowed_repos` | yes | Repositories the crew may commit to, as `owner/repo` (1–50). |
| `max_iterations` | yes | Maximum coder/QA attempts per task (1–100). |
| `models` | yes | Model identifier per agent role: `supervisor`, `coder`, `qa`, `reviewer`, `coordinator`. |

Constraints are declarative. A principal compares them against the events —
for example a `code_crew:merged` with no preceding owner `code_crew:approval`
under `autonomy_class: gated`, or a `code_crew:qa_verdict` whose `attempt`
exceeds `max_iterations`.

## 6. Witness event types

A conformant Witness Event MUST validate against **both** the ATAP v0.1 base
`witness-event` schema (the envelope) **and**
[`schemas/witness-events.schema.json`](schemas/witness-events.schema.json)
(the `event_type` → `payload` binding). ATAP §7.2 requires colon-delimited
event types, so each carries the `code_crew:` prefix. Every payload requires
`timestamp` and `evidence` (§3) and sets `additionalProperties: false` — see §8.

| `event_type` | Payload (besides `timestamp`, `evidence`) |
|---|---|
| `code_crew:task_claimed` | `task_id`, `role` (agent role), `model` |
| `code_crew:change_committed` | `repo` (`owner/repo`), `commit_sha` (40-hex git sha); `evidence` = `anchored` |
| `code_crew:verify_run` | `command_sha256`, `exit_code`, `output_sha256` (64-hex sha256) |
| `code_crew:qa_verdict` | `task_id`, `verdict` (`accepted` \| `rework`), `attempt` (≥ 1) |
| `code_crew:review_verdict` | `head_sha`, `verdict` (`pass` \| `fail`), `findings` {`critical`, `high`, `medium`, `low`} counts |
| `code_crew:approval` | `role` (always `owner`), `decision` (`approve` \| `reject`), `channel`, `approval_text_sha256` |
| `code_crew:merged` (PR merge) | `merge_kind` (`pr`, or absent), `repo` (`owner/repo`), `pr_number` (≥ 1), `merge_commit_sha`; `evidence` = `anchored` |
| `code_crew:merged` (local merge) | `merge_kind` = `local`, `repo` (repo basename, no owner), `merge_commit_sha`; no `pr_number`; `evidence` = `asserted` |
| `code_crew:deployed` | `target`, `version_id` |

Commands, outputs and approval texts are recorded as sha256 digests only: the
text may carry user communications (ATAP §7.6), while the digest still lets a
holder of the text prove it matches.

## 7. Attestation Block `period_summary`

The Attestation Block `period_summary` is validated by
[`schemas/period-summary.schema.json`](schemas/period-summary.schema.json).
Every field is a non-negative integer: `tasks_accepted`, `tasks_rework`,
`merged_changes`, `tokens`, and `overturns` — per agent role, how many of that
role's verdicts a later step overturned. No field resolves to a natural person.

## 8. PII prohibition (ATAP §7.6)

ATAP v0.1 §7.6 forbids any person-resolvable field in a Witness Event payload,
an Attestation Block summary, or a profile artifact. This profile encodes that
prohibition structurally:

- **every payload object, and the `findings` sub-object, set
  `additionalProperties: false`**, so a name, email, IP address or free-text
  note has no permitted key;
- a human approval records the **role** `owner`, never the person
  (`role` is `const: "owner"`);
- identifier fields (`task_id`, `model`, `target`, `version_id`, `channel`,
  `repo`) are opaque tokens whose patterns admit no `@` or whitespace.

[`tests/pii-rejection.json`](tests/pii-rejection.json) is the §9.4(2) evidence:
six events, each smuggling a forbidden value (a person's name or email in an
approval, a name in place of `owner`, an email in a free-text note or in the
`model` field, a client IP address); CI confirms each is rejected.

In scope, and permitted: repository names, git shas, sha256 digests, task and
PR numbers, agent roles, model identifiers, verdicts, counts, deploy targets.

## 9. Receipt `profile_artifacts/`

ATAP §7.5 lets a profile define the structure of `profile_artifacts/`. This
profile defines one file:

- **`profile_artifacts/witness_events.json`** — a JSON array of every Witness
  Event the receipt's Attestation Blocks cover, in chain order: from the AIT's
  first event up to and including the last block's `last_event`. Events
  witnessed after the last block (still pending) are not included. Each entry
  is the full signed event (ATAP §7.2), so a reader of the track record sees each
  event, not only the block counts.

The file is listed in `manifest.files[]` with its sha256, so the signed
Receipt pins its bytes and `verify.sh` checks that hash. `verify.sh` does not
read the events (ATAP §7.5.1); a profile-aware verifier (`atap-witness verify`)
also checks:

1. each event's `self_hash` recomputes per ATAP §7.7 (SHA-256 of the RFC 8785
   canonical bytes minus `self_hash` and `witness_signature`) and its `ait` is
   the receipt's AIT;
2. the first event's `prev_event_hash` is `0x` + 64 zeros and each later one is
   the previous event's `self_hash`;
3. walking the blocks in order, each block's `event_count` events begin with
   its `first_event`, end with its `last_event`, and the last one's `self_hash`
   equals the block's `chain_head_hash` — the only binding between a block and
   its events in ATAP §7.3 — and the blocks cover every event in the file.

A removed, altered, or reordered event fails one of these checks even when
the manifest hash and Receipt signature are refreshed. Every anchor a verifier
needs (commit and merge shas, version ids) is in the event payloads.

## 10. Conformance

An implementation conforms to `tunnelmind:code_crew:v1` if:

1. AITs carry `profile: "tunnelmind:code_crew:v1"`, capabilities from §4, and
   `constraints` valid against the constraints schema;
2. Witness Events validate against the ATAP base `witness-event` schema and
   this profile's `witness-events` schema;
3. the Attestation Block `period_summary` validates against the period-summary
   schema;
4. no payload, summary, or artifact contains PII (§8);
5. every event's `evidence` follows the tier rules in §3.

## 11. Examples

[`examples/`](examples/) holds a signed, hash-chained set — `ait.json`, an
eight-event `witness-events.json` chain (one of each event type), an
`attestation-block.json`, a `receipt.json`, and the `public_keys.json` they
verify against. They are generated by
[`scripts/generate-examples.mjs`](scripts/generate-examples.mjs) using the
`@tunnelmindai/atap` reference witness with an ephemeral fixture keypair, and
are re-verified in CI (`npm run verify`). Repos, shas and OAIs are illustrative.

## 12. Changelog

- **v1 (2026-10-08)** — initial draft profile.
- **v1 (2026-10-08)** — §9 defines `profile_artifacts/witness_events.json`.
- **v1 (2026-10-12)** — `code_crew:merged` also accepts a local merge
  (`merge_kind: "local"`) for a repo with no PR; §3 and §6 updated. Additive:
  every existing event validates unchanged, so the identifier stays `v1`.
