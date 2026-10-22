# ATAP repo architecture

What each part is for, how a record flows from an agent to a verdict, and
where untrusted input is checked. The spec is `ATAP-v0.1.md` (v0.2 draft:
`ATAP-v0.2.md`); the README's table lists every path.

## Module map

| Path | Role |
|---|---|
| `packages/atap-js/` | `@tunnelmindai/atap`: JCS (`canonicalize.ts`), Ed25519 + SHA-256 (`crypto.ts`), did:key (`didkey.ts`), the signer (`witness.ts`), the verifier (`verify.ts`), SCITT statements (`scitt.ts`). |
| `packages/atap-cli/` | `atap-witness`: a file-backed witness over atap-js (`storage.ts` JSONL store, `profile.ts` schema guards, `gitstore.ts` records branch). |
| `verify.sh` | The reference verifier in bash + jq + openssl + python3. Copied verbatim into every receipt and into `packages/atap-py/src/atap/`. |
| `viewer/` | One HTML file that bundles atap-js over a WebCrypto shim and verifies a Receipt ZIP in the browser. |
| `packages/atap-py/` | Python client: one `atap-witness` subprocess per call; no crypto of its own. |
| `packages/eat-js/` | Draft verifier for the EAT profile (compact JWS, EdDSA). Not published. |
| `plugins/claude-code/`, `actions/witness/` | Callers of `atap-witness`: a Claude Code hook and a GitHub Action. |
| `profiles/`, `schemas/` | Application profiles (schemas, examples) and the core JSON Schemas. |

## Data flow

1. A caller (plugin hook, Action, atap-py, a script) pipes JSON to
   `atap-witness`. The CLI shape- and schema-checks it, then, under the store
   lock, `WitnessService` signs an AIT, a Witness Event or an Attestation Block
   and `DirStorage` appends it to `.atap/*.jsonl`.
2. `atap-witness receipt` signs a manifest over the chain and writes a Receipt
   directory (+ ZIP): manifest, AIT, chain, keys, events, `verify.sh`.
3. Anyone verifies it with `verify.sh`, `atap-witness verify`, or the viewer.
   The three apply the same rules in the same order; atap-cli's `verify-sh-*`
   tests run both verifiers on the same receipts and compare verdicts.

## Trust boundaries

- **Every receipt file is hostile.** Paths are normalised and kept inside the
  receipt (no `..`, no symlinks); every file must be listed in
  `manifest.files`, the AIT, chain, keys and `verify.sh` with a sha256 (the
  manifest is covered by its own signature); every record's signature is
  checked; reasons are stripped of control characters before printing.
- **Keys.** An OAI witness is trusted only through `--keys` (a bundle the
  verifier picked). Without it, the receipt's own `public_keys.json` is used
  and the verdict carries a warning: that proves self-consistency, not who
  signed. A did:key witness is its own key.
- **Canonical bytes.** Signers and verifiers share `canonicalize.ts`'s bytes,
  pinned by `packages/atap-js/test/vectors/jcs.json` (vendored verbatim by
  receipt-verify and tollbooth). A lone UTF-16 surrogate is refused everywhere,
  so two texts can never verify as one byte string.
- **Strength ceiling.** `attestation_strength` must be one of the four tiers and
  at most what the receipt witness's key declares at the AIT's issue time.
- **Config.** A committed `.atap/config.json` can only name a key inside the
  store; nothing in a repo names a binary to run.

Failure is closed everywhere: a verifier's answer to anything it cannot check
is a failed verdict with a reason. Callers that record (hook, Action, atap-py)
fail open by design: they never break the session or build they observe.

## Tests

```
cd packages/atap-js  && npm test   # library, JCS vectors
cd packages/atap-cli && npm test   # CLI + verify.sh parity (needs jq, openssl, python3, zip)
cd viewer            && npm test   # dist is current + browser verifier
cd packages/eat-js   && npm test   # needs typescript installed in eat-js
cd packages/atap-py  && python -m unittest discover -s tests
cd profiles          && npm run validate && npm run verify
```
