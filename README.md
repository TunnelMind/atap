# ATAP — Agent Trust Attestation Protocol

**ATAP v0.1** is an open protocol for **agent behavioral attestation**: a
canonical receipt format that lets the principal of an agentic system —
the advertiser, the compliance officer, the regulator, the auditor —
cryptographically verify what an agent actually did, in chronological
order, without trusting the agent's self-report.

- **Standard:** [tunnelmind.ai/atap/standard](https://tunnelmind.ai/atap/standard) · raw markdown: [`ATAP-v0.1.md`](./ATAP-v0.1.md)
- **Status:** v0.1 — Public comment through **2026-08-12**
- **License:** CC BY 4.0 (spec) · MIT (code in `packages/`)
- **Editor:** TunnelMind

## What's in this repo

| Path | Purpose |
|---|---|
| [`ATAP-v0.1.md`](./ATAP-v0.1.md) | The canonical specification. |
| [`schemas/v0.1/`](./schemas/v0.1/) | JSON Schemas for AIT, Witness Event, Attestation Block, Receipt, and the public-key endpoint. |
| [`context.jsonld`](./context.jsonld) | JSON-LD context for ATAP artifacts. |
| [`verify.sh`](./verify.sh) | Reference verifier (bash + openssl + jq + python3). Anyone can audit it in one sitting. |
| [`packages/atap-js/`](./packages/atap-js/) | Reference TypeScript wrapper — `@tunnelmind/atap` on npm. |

## What ATAP solves

Today, agentic systems hand their principals an unsigned, self-reported
log of what the agent did. There is no cryptographic chain, no
independent verification path, and no way for the principal to detect
silent rewrites. ATAP gives the principal a portable Receipt ZIP that:

1. Names the agent and its declared capabilities (the **AIT**).
2. Lists every action the agent took, signed by a trusted witness service
   (**Witness Events**, hash-chained).
3. Aggregates those actions into time-bounded summaries (**Attestation
   Blocks**, also hash-chained).
4. Bundles the chain, the witness's public keys, and a verifier into a
   single ZIP that runs anywhere bash + openssl + jq + python3 are
   present (`verify.sh`).

The trust unit is the **witness service** — a service the principal
already trusts, sitting between the agent and the world it acts on.
For the v0.1 reference deployment in programmatic advertising,
[Sigil](https://tunnelmind.ai) is the witness: agents call Sigil
before each bid, Sigil sees the decision, Sigil signs and chains it.
Other domains follow the same pattern: choose a trusted interface,
make it the witness.

ATAP v0.1 does **not** specify kernel-level observation. Stronger
observation tiers (sidecar daemons, TEEs, kernel attestation) can be
added in later versions without invalidating earlier receipts or
breaking the verifier.

## Verifying a receipt

```bash
unzip ATAP-RCPT-018f3c4d-...zip -d receipt/
cd receipt/
./verify.sh
# ==> Verifying file integrity (manifest.files[])
#   OK   ait.json
#   OK   attestation_chain.json
#   ...
# ==> Verifying AIT witness signature
#   OK   AIT-018f3c4d-...
# ==> Walking block chain
#   OK   ATAP-AB-018f3c4d-...
# ==> Receipt verifies (blocks=N)
```

Requirements: bash 4+, openssl 3.0+ (or 1.1.1 with `-rawin`), jq 1.6+, python3.

## Building witness services

Install the reference TypeScript wrapper:

```bash
npm install @tunnelmind/atap
```

See [`packages/atap-js/README.md`](./packages/atap-js/README.md) for the API.
Implementations in other languages are welcomed; conform to §7 (schemas),
§10 (hash chain), and §11 (verification) of the standard.

## Application profiles

ATAP v0.1 specifies the protocol envelope. The **vocabulary** of event
types and aggregation rules lives in **application profiles**:

| Profile | Maintainer | Status |
|---|---|---|
| `sigil:media_buyer:v1` | TunnelMind | Reference profile, ships with v0.1. |
| `sigil:ecommerce_buyer:v1` | TBD | Reserved. |
| `sigil:data_broker:v1` | TBD | Reserved. |

Profile proposals are PRs to [`github.com/TunnelMind/atap-profiles`](https://github.com/TunnelMind/atap-profiles) (forthcoming).
CI validates schema conformance, the PII prohibition (§7.6), and example
round-trip through `verify.sh`. Conformant PRs auto-merge within 7 days
absent an editorial objection. See §9 and §12.3 of the spec.

## Comment, object, or contribute

- **Discussions** ([GitHub](https://github.com/TunnelMind/atap/discussions)) — open-ended feedback, questions, proposals.
- **Issues** ([GitHub](https://github.com/TunnelMind/atap/issues)) — concrete defects, contradictions, broken examples.
- **Pull requests** — editorial fixes, clarifications, new examples. Substantive changes go through Discussions first.

## Locked positions

§14 of the spec records decisions v0.1 commits to (vs items genuinely
deferred). The big ones:

- **Receipts are immutable.** No protocol-level revocation; the only
  remediation is witness-key compromise marking (§8.4).
- **Profile-domain collisions resolve as separate namespaces**, not as
  editor arbitration.
- **SHA-256 + Ed25519 are frozen at v0.1.** Post-quantum signatures
  land in v2 in parallel, not as a replacement.
- **The transparency log is a v1.x priority**, not v2.

## License

- Spec ([`ATAP-v0.1.md`](./ATAP-v0.1.md)) is licensed [CC BY 4.0](./LICENSE).
- Code in [`packages/`](./packages/) is licensed MIT (see each package's own LICENSE).
- The reference verifier ([`verify.sh`](./verify.sh)) is licensed MIT.

You may cite, redistribute, fork, and build on ATAP without asking. The
only ask is attribution — link to [tunnelmind.ai/atap/standard](https://tunnelmind.ai/atap/standard)
when you reference the standard.
