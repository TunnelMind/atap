# ATAP v0.1.1 — Agent Trust Attestation Protocol (patch to v0.1)

> **DRAFT for Josh.** Not published. Normative once approved; until then, ATAP v0.1 is the
> standard in force.

| | |
|---|---|
| **Standard** | ATAP v0.1.1 |
| **Status** | DRAFT for Josh — not yet published |
| **Amends** | [ATAP v0.1](ATAP-v0.1.md) |
| **Editor** | TunnelMind |
| **License** | CC BY 4.0 (spec) · Apache-2.0 (reference implementations) |

---

## 1. Scope of this document

ATAP v0.1.1 is ATAP v0.1 plus the witness-side and verifier-side requirements below, written after the 2026-10-17 audit (findings A001–A008). No AIT, Witness Event, Attestation Block, Receipt, hash or signature changes: every v0.1 artifact remains valid and verifies exactly as under v0.1. Every section of v0.1 not amended here applies unchanged. Section numbers refer to the v0.1 section amended.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

---

## 2. AIT acceptance (amends v0.1 §6.1)

Replace "A signed AIT is the agent's credential. Subsequent `witness(event)` calls reference it by `id`." with:

**The signed AIT is a public identity document, not a credential.** Anyone holding a receipt holds the AIT; knowing it MUST NOT let anyone write to its chain.

1. **Holder credential.** On accepting an AIT the witness MUST issue a holder credential that:
   - carries at least **128 bits** of entropy from a cryptographically secure source;
   - is bound to the AIT `id` and valid for that AIT only;
   - is returned to the submitter exactly once, in the acceptance response;
   - is stored by the witness only as a **one-way hash**, never in recoverable form;
   - is never written into any artifact (AIT, Witness Event, Attestation Block, Receipt, or any file in a Receipt ZIP).
2. **Authentication.** The witness MUST authenticate the holder credential on every `witness(event)`, flush (`POST /v1/atap/flush`, §6.2) and `receipt(period)` call, comparing in **constant time**. It MUST refuse writes for any AIT that has no holder credential (including AITs accepted before this amendment).
3. **Witness-derived events.** Events the witness emits on its own account (e.g. `ait.retired`, §6; roll-up on shutdown or key rotation, §6.2) MUST be chained like any other event and MUST NOT be suppressible, omittable or reorderable by the holder.
4. **Receipts cover the chain from genesis.** A Receipt MUST cover the event and block chains from genesis (§10.2: `prev_*_hash` of 32 zero bytes) to its chain head, never a suffix. A `receipt(period)` request narrows what is summarized, not where the chain starts.
5. **Operator identity is asserted unless verified.** The AIT `operator` field (§7.1) is a reference field the operator does not sign, and §6.1 leaves the onboarding check out of scope. Verifiers and relying parties MUST treat `operator` as **asserted** by the submitter unless the witness's onboarding policy verified it and says so out of band.

---

## 3. Verification (amends v0.1 §11.1)

Add after the step list:

The `verify.sh` inside a Receipt ZIP is chosen by whoever produced the Receipt. Verifiers **MUST NOT run** the bundled `verify.sh` on a Receipt they do not already trust; they MUST run their own trusted copy — the `atap-witness verify` CLI or a `verify.sh` obtained from `https://tunnelmind.ai/atap/verify.sh`. Verifiers SHOULD use their own installed verifier, not the one in the Receipt, in every case.

Receipts sealed before the A001–A008 fixes carry the old script. Re-verifying them with their bundled copy is unsafe; verify them with a current trusted verifier.

---

## 4. Versioning (amends v0.1 §13)

Add a row to the change-class table:

| Change class | Version impact |
|---|---|
| New witness-side requirement, no artifact change | Patch — v0.1.x. |

This document is such a change, hence v0.1.1.

---

## 5. Spec gaps found

Recorded for a later revision; this draft does not resolve them.

- **(a) §7.3 period equality for single-event blocks.** §7.3 requires `period_end > period_start`, but a block's period is its first and last event's `witnessed_at` (reference witness), so a one-event block has `period_start == period_end`. The v0.1 schema does not enforce the strict inequality; v0.1 does not say whether equality is allowed.
- **(b) §6 `ait.retired` is specified but unimplemented.** §6 records retirement as a final `ait.retired` event after which the witness MUST refuse events; no reference implementation emits or enforces it (only the `expires_at` cutoff is enforced).
- **(c) §10.3 vs §7.7.** §10.3 says "the signed quantity for each Witness Event, Attestation Block, and Receipt is the raw 32-byte hash"; §7.7 and §7.4 say the Receipt (which has no `self_hash`) is signed over its canonical bytes minus `witness_signature`, not over a hash. They disagree on what a Receipt signature covers; implementations follow §7.7.
- **(d) §11.1 step 2 AIT schema validation is not done.** §11.1 step 2 says the verifier validates the AIT's structure against the v0.1 schema; neither `verify.sh` nor the reference TypeScript verifier validates against `schemas/v0.1/ait.schema.json`; they spot-check a few fields (`id`, `profile`, `witness`, `ait_version` for did:key) and the signature.
