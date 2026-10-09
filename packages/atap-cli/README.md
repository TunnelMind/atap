# @tunnelmindai/atap-cli

`atap-witness`: a file-backed ATAP v0.1 witness built on
[`@tunnelmindai/atap`](../atap-js/). Every command reads JSON on stdin and
writes JSON on stdout, so any language can drive it.

## Install

From a source checkout of this repo (Node 20+). The package is not on npm.

```bash
cd packages/atap-js && npm i && npm run build
cd ../atap-cli && npm i && npm run build
```

The bin is `dist/cli.js` (`atap-witness`). `receipt` copies the reference
`verify.sh` from the repo root into each receipt, so the CLI only works from a
source checkout.

`receipt` also needs the `zip` binary. The receipt's `verify.sh` needs bash,
openssl, jq and python3 (see the [root README](../../README.md)).

## Quickstart

In an empty directory, with `atap-witness` on your PATH. `init` writes a key
and an AIT to `.atap/`, so no command after it needs flags.

```sh
atap-witness init
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:01.500Z","evidence":"asserted","task_id":"A101","role":"coder","model":"claude-opus-5-5"}}' | atap-witness event
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:02.500Z","evidence":"asserted","task_id":"A102","role":"coder","model":"claude-opus-5-5"}}' | atap-witness event
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:03.500Z","evidence":"asserted","task_id":"A103","role":"coder","model":"claude-opus-5-5"}}' | atap-witness event
echo '{"tasks_accepted":3,"tasks_rework":0,"merged_changes":0,"tokens":0,"overturns":{}}' | atap-witness block
atap-witness receipt --out receipt
atap-witness verify receipt
```

The last command prints `"ok": true` and `"blocks": 1` and exits 0. The bundled verifier
checks the same receipt: `./receipt/verify.sh receipt`.
[`test/quickstart.test.mjs`](./test/quickstart.test.mjs) runs this block as
written and times it.

## Commands

```
atap-witness status
atap-witness ait declare            --key K --witness-oai OAI   < AitInput  [--unregistered-profile]
atap-witness event   --ait ID       --key K --witness-oai OAI   < {"event_type","payload"}
atap-witness block   --ait ID       --key K --witness-oai OAI   < period_summary (optional)
atap-witness receipt --ait ID --out DIR --key K --witness-oai OAI
atap-witness verify DIR
atap-witness scitt export DIR --key K --issuer ISS
atap-witness scitt verify DIR
atap-witness scitt register DIR --service URL
```

| Command | Stdin | Stdout |
|---|---|---|
| `status` | none | `{profile, ait, witness_oai, dir, events, blocks, last_receipt}` for the nearest `.atap/` at or above cwd; `last_receipt` is `{out, at, id}` from the last `receipt` run there, or `null`. Exit 1 outside any `.atap/` |
| `ait declare` | An `AitInput` object (`agentType`, `profile`, `operator`, `capabilities`, `attestationPolicy`, `expiresAt`; lifetime at most 365 days) | The signed AIT |
| `event` | `{"event_type": string, "payload": object}` | The signed, chained Witness Event |
| `block` | A `period_summary` object; empty stdin means `{}` (which the profile's schema may refuse) | The signed Attestation Block over the events since the last block |
| `receipt` | none | The signed Receipt (`manifest.json`). Writes the §7.5 files to `--out DIR` and `DIR.zip` |
| `verify DIR` | none | `{"ok", "blocks", ...}`. Checks `manifest.files[]` hashes, then signatures and chains. Exit 0 only if `ok` is true |
| `scitt export\|verify\|register DIR` | none | See [SCITT export](#scitt-export) |

Flags:

| Flag | Used by | Meaning |
|---|---|---|
| `--key PATH` | `ait declare`, `event`, `block`, `receipt`, `scitt export` | Ed25519 private key, PEM. Required. |
| `--witness-oai OAI` | `ait declare`, `event`, `block`, `receipt` | The witness's OAI. Falls back to `$ATAP_WITNESS_OAI`. Required. |
| `--ait ID` | `event`, `block`, `receipt` | The AIT id returned by `ait declare`. |
| `--out DIR` | `receipt` | Output directory; `DIR.zip` is written next to it. |
| `--dir DIR` | `ait declare`, `event`, `block`, `receipt` | Witness store (JSONL files). Default `./.atap-witness`. |
| `--strength TIER` | `ait declare`, `event`, `block`, `receipt` | `attestation_strength` to declare. Default `self-asserted`. See [Evidence tiers](#evidence-tiers). |
| `--issuer ISS` | `scitt export` | CWT `iss` of every statement (1–8192 chars), e.g. the witness's OAI. Required. |
| `--service URL` | `scitt register` | Transparency service base URL, `http(s)`, no credentials. Required. |
| `--profiles-dir DIR` | `ait declare`, `event`, `block` | Profile registry and schemas. Default the repo's `profiles/`. See [What the witness enforces](#what-the-witness-enforces). |
| `--unregistered-profile` | `ait declare` | Declare an AIT whose `profile` is not in the registry. |

Errors go to stderr as one line of `{"error": "..."}` with a non-zero exit.

## What the witness enforces

A refused call exits non-zero with `{"error": "..."}` on stderr and writes
nothing to the store.

- **`event_type` pattern (ATAP §7.2).** `WitnessService.witness` in
  `@tunnelmindai/atap` refuses any `event_type` not matching
  `^[a-z][a-z0-9_]*(:[a-z][a-z0-9_]*)+$`, before any storage write. The CLI
  also checks it against the ATAP v0.1 base schema (`event_type`, 3–128 chars).
- **Profile schemas.** The CLI looks the AIT's `profile` up in
  `<profiles-dir>/registry.json` and validates with the schemas under the
  entry's `path`: `event` validates `{event_type, payload}` against
  `schemas/witness-events.schema.json` (an `event_type` the profile does not
  define is refused by name), and `block` validates the `period_summary`
  against `schemas/period-summary.schema.json`. These schemas carry the
  profile's §7.6 no-PII rules.
- **Registered profiles.** `ait declare` refuses a `profile` that is not in
  the registry unless `--unregistered-profile` is given. Events on such an AIT
  get the §7.2 and base-schema checks only; no profile schema applies.
- **Whole-schema write checks.** Every signed object is validated against its
  complete ATAP v0.1 core schema at the moment it is written, after the
  library has signed it and before anything is appended: the AIT against
  `ait.schema.json`, each event against `witness-event.schema.json`, each
  block against `attestation-block.schema.json` (`additionalProperties:
  false`, every required field, every pattern — so a witness or operator that
  is an e-mail address, a missing field or a stray key is refused and nothing
  is written). No field list in the CLI can drift from the schemas. A given
  `constraints` object is also checked against the profile's
  `schemas/constraints.schema.json` when the profile is registered, and the
  library refuses a malformed `AitInput` (wrong types, unparseable
  `expiresAt`) before signing.
- **Monotonic `witnessed_at`.** `witnessed_at` never goes backwards within an
  AIT's chain: if the clock steps back, the witness reuses the previous
  event's `witnessed_at` (read from the store, so it holds across processes).

`--profiles-dir DIR` points at another registry; it must contain
`registry.json` and `atap-v0.1-schemas/`. Error messages name the schema and
the failing path, never the refused payload values.

## SCITT export

`scitt` turns an unpacked receipt's artifacts into SCITT signed statements
(RFC 9943). The ATAP artifacts are unchanged; the statements are an extra view
of them. Export and verify read only `DIR` and need no network.

**What a statement holds** (`toSignedStatement` in
[`@tunnelmindai/atap`](../atap-js/src/scitt.ts)): a tagged COSE_Sign1
(tag 18, RFC 9943 §6) with an empty unprotected header and this protected
header:

| Label | Value |
|---|---|
| `1` alg | `-8` (EdDSA) |
| `4` kid | the witness key's `key_id` |
| `15` CWT claims | `{1: iss, 2: sub}`: `iss` from `--issuer`, `sub` the AIT id |
| `258` payload hash alg | `-16` (SHA-256), COSE Hash Envelope (RFC 9995) |
| `259` preimage content type | `application/vnd.atap.ait+json`, `application/vnd.atap.attestation-block+json` or `application/vnd.atap.receipt+json` |

The payload is `sha256` of the artifact's canonical JSON (RFC 8785), 32 raw
bytes. Label `3` (content type) is absent: RFC 9995 §4 says it MUST NOT be
present in a hash envelope. `verifySignedStatement(bytes, publicKey, artifact)`
checks alg, hash alg, payload and signature.

**Export.** `scitt export DIR --key K --issuer ISS` writes `DIR/scitt/`:

| File | Statement over |
|---|---|
| `ait.cose` | `ait.json` |
| `<block-id>.cose` | each block in `attestation_chain.json` |
| `manifest.cose` | `manifest.json` |
| `index.json` | `[{file, artifact_id, sha256}]`, one entry per statement |

`--key` must be a key listed in the receipt's `public_keys.json`. An existing
`scitt/` is replaced. `manifest.files[]` does not list `scitt/`, so the receipt
and its `verify.sh` are unchanged by an export.

**Verify.** `scitt verify DIR` prints `{"ok": true, "statements": N}` and exits
0, or `{"ok": false, "statements": 0, "reason": "..."}` and exits 1. It fails
on a missing statement file, a statement whose bytes do not match its
`index.json` `sha256`, an `artifact_id` that is not in the receipt, a `kid`
not in `public_keys.json`, a statement that does not verify against its
artifact (an altered artifact), and an artifact with no statement.

**Register.** `scitt register DIR --service URL` is the only `scitt` command
that touches the network, and only to `--service`. `URL` must be `http:` or
`https:` without credentials. It runs `scitt verify` first and posts nothing
if that fails. Each statement is sent as `POST <URL>/entries` with
`content-type: application/cose` (draft-ietf-scitt-scrapi-11 §2.3). A `201`
body is saved as `scitt/<name>.receipt`; any other status, `202` included,
fails the command with no polling or retry.

Register is built but off by default: no transparency service has been chosen,
so nothing is registered anywhere and the whole feature works offline.

**Interop.** [`test/scitt-interop.test.mjs`](./test/scitt-interop.test.mjs)
verifies every exported statement with pycose, an independent COSE
implementation, and checks it rejects a flipped byte (skipped with a printed
reason if pycose cannot be installed). It also pins the exact statement bytes
for a fixed key and record.

```bash
atap-witness scitt export receipt --key witness.pem --issuer OAI-2026-0010002
atap-witness scitt verify receipt
```

## Worked example

From the repo root, after Install. Needs `openssl` and `jq`.

```bash
REPO=$PWD
atap-witness() { node "$REPO/packages/atap-cli/dist/cli.js" "$@"; }
cd "$(mktemp -d)"
openssl genpkey -algorithm ed25519 -out witness.pem
W="--key witness.pem --witness-oai OAI-2026-0010002"
EXPIRES=$(node -p 'new Date(Date.now() + 30 * 864e5).toISOString()')

AIT=$(atap-witness ait declare $W <<JSON | jq -r .id
{
  "agentType": "code-crew",
  "profile": "tunnelmind:code_crew:v1",
  "operator": "OAI-2026-0010001",
  "capabilities": ["code_crew:code"],
  "attestationPolicy": {
    "witness_granularity": "per_action",
    "block_interval_seconds": 3600,
    "receipt_generation": "on_demand"
  },
  "expiresAt": "$EXPIRES"
}
JSON
)

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"'"$NOW"'","evidence":"asserted","task_id":"A105","role":"coder","model":"claude-opus-5-5"}}' \
  | atap-witness event --ait "$AIT" $W
echo '{"tasks_accepted":1,"tasks_rework":0,"merged_changes":0,"tokens":0,"overturns":{}}' \
  | atap-witness block --ait "$AIT" $W
atap-witness receipt --ait "$AIT" --out receipt $W
atap-witness verify receipt
```

The last command prints and exits 0:

```json
{
  "ok": true,
  "blocks": 1,
  "attestation_strength": "self-asserted"
}
```

`receipt/` and `receipt.zip` now hold `manifest.json`, `ait.json`,
`attestation_chain.json`, `summary.json`, `public_keys.json`, `verify.sh` and
`profile_artifacts/witness_events.json` (every event the blocks cover; `verify`
checks each event's hash chain against the blocks' `chain_head_hash`, see the
profile's §9).
The bundled verifier checks the same receipt: `./receipt/verify.sh receipt`.

`tunnelmind:code_crew:v1` is the profile in
[`profiles/profiles/tunnelmind-code-crew-v1/`](../../profiles/profiles/tunnelmind-code-crew-v1/).

## Evidence tiers

`--strength` sets `attestation_strength` (ATAP §7.4.1) on the Receipt and on
the key entry in `public_keys.json`. It declares the trust root the witness
ran under for the receipt's period. Four values, weakest to strongest:

1. `self-asserted`: the witness publishes its own key and signs its own
   events. Whoever controls the signing host can forge any history.
2. `software`: the witness runs under OS-enforced isolation on a host the
   operator controls. A root compromise of the host can forge any history.
3. `tee-tpm`: the witness runs in a hardware-isolated environment (SGX/TDX,
   SEV-SNP, TrustZone, Secure Enclave, or TPM-backed measured boot) with the
   signing key sealed to it and a remote attestation report. A host-level
   compromise outside the enclave cannot forge new history; an enclave break
   can.
4. `silicon-root`: the signing key is generated and used only inside
   non-reprogrammable silicon, attested by a chain rooted in the silicon
   manufacturer. A host-level root compromise cannot forge new history.

A receipt that omits the field is treated as `self-asserted`. A verifier must
not promote a receipt above its declared tier.

The CLI writes whatever `--strength` says. It does not prove the tier: it
signs with a PEM key file on disk, which is `self-asserted` unless the
operator's environment says otherwise.

This tier is about the witness. It is separate from the per-event `evidence`
grade in the `tunnelmind:code_crew:v1` profile.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
