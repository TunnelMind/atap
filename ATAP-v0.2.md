# ATAP v0.2 — Agent Trust Attestation Protocol (delta to v0.1)

> **DRAFT for Josh.** Not published. Normative once approved; until then, ATAP v0.1 is the
> standard in force.

| | |
|---|---|
| **Standard** | ATAP v0.2 |
| **Status** | DRAFT for Josh — not yet published |
| **Amends** | [ATAP v0.1](ATAP-v0.1.md) |
| **Schemas** | `profiles/atap-v0.2-schemas/` (`https://tunnelmind.ai/atap/schemas/v0.2/…`) |
| **Editor** | TunnelMind |
| **License** | CC BY 4.0 (spec) · MIT (reference implementations) |

---

## 1. Scope of this document

ATAP v0.2 is ATAP v0.1 plus **one change**: the `witness` and `operator` identifiers MAY be an Ed25519 `did:key` as well as an issued OAI.

Every section of v0.1 not amended below applies to v0.2 unchanged and is incorporated by reference. Section numbers below refer to the v0.1 section they amend. Every v0.1 record, receipt and key set remains valid and MUST continue to verify exactly as under v0.1 (v0.1 §13: "A v2 verifier MUST verify v0.1 and v1 receipts").

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

---

## 2. Object identifiers (amends v0.1 §2)

### 2.4 Witness service identifier (replaces v0.1 §2.4)

A witness service, and an AIT's operator, is identified by **either**:

1. a canonical OAI under the **`witness.operator`** category, exactly as in v0.1 §2.4 and §9.2 (an *issued OAI*); **or**
2. an Ed25519 **`did:key`** per the W3C did:key method.

The AIT `witness` and `operator` fields, the Receipt `witness` field, and the `witness` field of each entry in the key endpoint response (v0.1 §8.1) all accept either form.

#### 2.4.1 did:key encoding

A did:key identifier is formed from the witness's 32-byte Ed25519 public key (RFC 8032):

1. prefix the key with the multicodec `ed25519-pub` varint `0xed 0x01`, giving 34 bytes;
2. encode those 34 bytes in base58btc (Bitcoin alphabet);
3. prefix the multibase code `z`, then `did:key:`.

The result is always `did:key:z6Mk` followed by 44 base58btc characters (56 characters in total).

```abnf
did-key-ed25519 = "did:key:z6Mk" 44base58btc
base58btc       = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
                  ; 1-9 A-H J-N P-Z a-k m-z (no 0, I, O, l)
```

Regular expression used by the v0.2 schemas: `^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$`.

A did:key with any other multicodec (for example secp256k1, `did:key:zQ3s…`) is not an ATAP v0.2 identifier and MUST be rejected. ATAP's signature algorithm remains Ed25519 only (v0.1 §14.3).

#### 2.4.2 Rationale

A self-hosted witness that has no issued OAI previously had to invent one, conventionally in the `OAI-0000-{7 digits}` local space. That space holds 10^7 values, so by the birthday bound two independent witnesses have a 50% chance of colliding at roughly 3,700 witnesses — and nothing in the identifier ties it to the signing key, so a colliding or copied ID is indistinguishable from the real one. A did:key *is* the public key: it is globally unique without a registry, works offline, and any verifier can check that a signature came from the identifier it claims. Issued OAIs remain the identifier for registered witnesses.

---

## 3. Normative rules for did:key identifiers

**3.1 Key binding.** A verifier MUST reject any record whose `witness` is a did:key unless every `witness_signature` on the AIT, its Witness Events, its Attestation Blocks and its Receipt verifies under exactly the Ed25519 public key that the did:key encodes. A key-endpoint entry (v0.1 §8.1) whose `witness` is a did:key MUST carry that same key in `public_key`; a verifier MUST reject an entry that does not. A verifier MUST find a valid key-endpoint entry for the witness under v0.1 §8.2; the did:key alone does not replace it. A did:key's key has no validity window: the entry's `valid_from` and `valid_until` do not apply, but a compromise notice (`status: "compromised"`, from its `disclosed_at`) still does, on any entry for the witness. Key selection (v0.1 §8.2) is otherwise unchanged. A verifier MUST reject a Receipt whose `witness` differs from the AIT `witness` when either is a did:key; for OAI witnesses v0.1 behavior is unchanged.

**3.2 Self-asserted only.** A did:key witness is by definition self-asserted (v0.1 §7.4.1): nothing beyond the key holder vouches for it. A Receipt or key-endpoint entry whose `witness` is a did:key MUST carry `attestation_strength: "self-asserted"`, and a verifier MUST reject any other value, including an absent field.

**3.3 Version declaration.** Any AIT whose `witness` or `operator` is a did:key MUST declare `ait_version: "0.2"`, and every Attestation Block under such an AIT MUST declare `ab_version: "0.2"`. Receipts, Witness Events and key entries carry no version field; a did:key `witness` in them fails the v0.1 OAI pattern, so a v0.1-only verifier rejects them rather than misreading them. A v0.2 verifier MUST reject a did:key-identified AIT or Attestation Block that declares version `0.1`.

**3.4 Issued OAIs unchanged.** Issued OAIs remain valid `witness` and `operator` identifiers for registered witnesses, in v0.1 and v0.2 records alike. For an OAI-identified witness, rules 3.1 and 3.2 do not apply and v0.1 §7.4.1 and §8 govern.

**3.5 Operator.** The operator does not sign (v0.1 §7.1). A did:key `operator` is an identifier only; rule 3.1 binds the witness, not the operator.

---

## 6. Lifecycle (amends v0.1 §6.1)

In AIT acceptance, "the `witness` field matches its own canonical OAI" reads, for a did:key witness, "the `witness` field is the did:key of the witness service's own signing key".

---

## 7. Schemas (amends v0.1 §7)

The v0.2 JSON Schemas are the v0.1 schemas with these changes only:

| Schema | Change |
|---|---|
| all five | `$id` `…/schemas/v0.2/…`; title "ATAP v0.2". `@context` unchanged. |
| AIT | `ait_version` const `"0.2"`; `witness`, `operator` accept issued OAI or did:key. |
| Attestation Block | `ab_version` const `"0.2"`. |
| Receipt | `witness` accepts issued OAI or did:key; a did:key `witness` requires `attestation_strength` = `"self-asserted"`. |
| Key endpoint | each entry's `witness` accepts issued OAI or did:key; a did:key entry requires `attestation_strength` = `"self-asserted"`. |
| Witness Event | `$id` and title only. |

The key binding (rule 3.1) cannot be expressed in JSON Schema; verifiers enforce it.

---

## 13. Versioning (amends v0.1 §13)

v0.2 widens a required field's grammar, so it is a major pre-v1 change under v0.1 §13. A v0.2 verifier MUST verify v0.1 records under the v0.1 rules.

---

## Open questions for Josh

1. v0.1 §7.4 and §14.8 say `attestation_strength` becomes REQUIRED in v0.2. This draft requires it only for did:key witnesses, keeping the delta to one change. Make it required for every v0.2 Receipt and key entry?

---

## Appendix A. References (additions)

- W3C — The did:key Method, https://w3c-ccg.github.io/did-method-key/
- W3C — Decentralized Identifiers (DIDs) v1.0, https://www.w3.org/TR/did-core/
- Multiformats — multicodec table (`ed25519-pub` = `0xed`), multibase (`z` = base58btc)
