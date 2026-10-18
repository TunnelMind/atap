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
and an AIT to `.atap/`, so no command after it needs flags. The witness is the
key's own `did:key` (ATAP-v0.2 §3): it is the AIT's witness and operator, and
`config.json` records it as `witness_oai` with `oai_origin: "did:key"`. No
registry is involved; a did:key witness is always `self-asserted`.

```sh
atap-witness init
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:01.500Z","evidence":"asserted","task_id":"A101","role":"coder","model":"claude-opus-5-5"}}' | atap-witness event
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:02.500Z","evidence":"asserted","task_id":"A102","role":"coder","model":"claude-opus-5-5"}}' | atap-witness event
echo '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:03.500Z","evidence":"asserted","task_id":"A103","role":"coder","model":"claude-opus-5-5"}}' | atap-witness event
echo '{"tasks_accepted":3,"tasks_rework":0,"merged_changes":0,"tokens":0,"overturns":{}}' | atap-witness block
atap-witness receipt --out receipt
atap-witness verify receipt
```

The last command prints `"ok": true` and `"blocks": 1` and exits 0. The trusted
`verify.sh` from your checkout's root checks the same receipt:
`/path/to/atap/verify.sh receipt`. The receipt's bundled `verify.sh` is for
reference only; never run it on a receipt you did not make
([`ATAP-v0.1.1.md`](../../ATAP-v0.1.1.md) §3).
[`test/quickstart.test.mjs`](./test/quickstart.test.mjs) runs this block as
written and times it.
`atap-witness ait rotate` declares a fresh 365-day AIT in the same store; old receipts keep verifying.

Stores made before v0.2 hold a self-asserted `OAI-0000-*` witness instead.
`init` no longer creates those, but every command still reads, receipts and
verifies them. `atap-witness ait rotate --did-key` moves such a store onto its
key's did:key: a new AIT with the did:key as witness and operator, and
`config.json` updated; the old AIT and its chain are untouched. To witness
under an OAI a registry issued you, pass `--witness-oai OAI` as before.

### Off and uninstall

`ATAP_OFF=1` makes `event` and `block` exit 0 with one stderr line and write
nothing, so a hook that calls them cannot break a workflow. Other commands are
unaffected. Uninstall is `rm -rf .atap`: nothing is created outside it.

## Commands

```
atap-witness init [--profile ID] [--dir .atap] [--force] [--git]
atap-witness status
atap-witness git sync
atap-witness git restore [--into DIR]
atap-witness ait rotate [--did-key]
atap-witness ait declare            --key K --witness-oai OAI   < AitInput  [--unregistered-profile]
atap-witness event   --ait ID       --key K --witness-oai OAI   < {"event_type","payload"}
atap-witness block   --ait ID       --key K --witness-oai OAI   < period_summary (optional)
atap-witness receipt --ait ID --out DIR --key K --witness-oai OAI
atap-witness verify DIR
atap-witness verify --store [DIR] [--ait ID] [--keys public_keys.json]
atap-witness scitt export DIR --key K [--issuer ISS]
atap-witness scitt verify DIR
atap-witness scitt register DIR --service URL
```

| Command | Stdin | Stdout |
|---|---|---|
| `init` | none | Sets up `./.atap/` (store, key `witness.pem` 0600, its own `.gitignore`, `config.json`) and declares one AIT (365 days) whose witness and operator are the key's did:key. Writes nothing outside `.atap/`; refuses if it exists (`--force` only re-inits an empty store) |
| `init --git` | none | As `init`, and also writes `git_sync: true` into `config.json`, so every `block` then runs `git sync`. See [Records in git](#records-in-git) |
| `git sync` | none | `{synced, commit, events, blocks}`. Commits the store's records to the branch `atap/records`. See [Records in git](#records-in-git) |
| `git restore` | none | `{restored, dir, commit}`. Rebuilds a store's records from `atap/records` into `--into DIR` (default `./.atap`) |
| `ait rotate` | none | Declares a new AIT in the same store, with the same key and profile, and points `config.json` at it. The old chain stays intact and receiptable. With `--did-key`, the new AIT's witness and operator are the key's did:key and `config.json` gets `witness_oai` = that did:key, `oai_origin: "did:key"` (for `OAI-0000-*` stores) |
| `status` | none | `{profile, ait, witness_oai, dir, events, blocks, last_receipt}` for the nearest `.atap/` at or above cwd; `last_receipt` is `{out, at, id}` from the last `receipt` run there, or `null`. Exit 1 outside any `.atap/` |
| `ait declare` | An `AitInput` object (`agentType`, `profile`, `operator`, `capabilities`, `attestationPolicy`, `expiresAt`; lifetime at most 365 days) | The signed AIT |
| `event` | `{"event_type": string, "payload": object}` | The signed, chained Witness Event |
| `block` | A `period_summary` object; empty stdin means `{}` (which the profile's schema may refuse) | The signed Attestation Block over the events since the last block |
| `receipt` | none | The signed Receipt (`manifest.json`). Writes the §7.5 files to `--out DIR` and `DIR.zip` |
| `verify DIR` | none | `{"ok", "blocks", ...}`. Checks `manifest.files[]` hashes, then signatures and chains. Exit 0 only if `ok` is true |
| `verify --store [DIR]` | none | `{"ok", "events", "blocks", "witness", "attestation_strength"}`, plus `reason` on failure. Checks a store (`--dir`, DIR, the nearest `.atap/`, or `./.atap`) with no receipt and no key. See [Records in git](#records-in-git). Exit 0 only if `ok` is true |
| `scitt export\|verify\|register DIR` | none | See [SCITT export](#scitt-export) |

Flags:

| Flag | Used by | Meaning |
|---|---|---|
| `--key PATH` | `ait declare`, `event`, `block`, `receipt`, `scitt export` | Ed25519 private key, PEM. Required. |
| `--witness-oai OAI` | `ait declare`, `event`, `block`, `receipt` | The witness's OAI (or did:key). Falls back to `$ATAP_WITNESS_OAI`, then `config.json`. Required outside an init'd project. Without it, `receipt` signs as its AIT's own witness. |
| `--did-key` | `ait rotate` | Rotate onto the key's did:key as witness and operator; no `--witness-oai` needed. |
| `--ait ID` | `event`, `block`, `receipt`, `verify --store` | The AIT id returned by `ait declare`. `verify --store` needs it only when the store holds more than one AIT. |
| `--keys PATH` | `verify --store` | `public_keys.json` (e.g. from a receipt) for an OAI witness. Not needed for a did:key witness. |
| `--out DIR` | `receipt` | Output directory; `DIR.zip` is written next to it. |
| `--dir DIR` | `ait declare`, `event`, `block`, `receipt` | Witness store (JSONL files). Default `./.atap-witness`. |
| `--strength TIER` | `ait declare`, `event`, `block`, `receipt` | `attestation_strength` to declare. Default `self-asserted`. See [Evidence tiers](#evidence-tiers). |
| `--issuer ISS` | `scitt export` | CWT `iss` of every statement (1–8192 chars), e.g. the witness's OAI. Optional when the nearest `.atap/config.json` has a did:key witness (that did:key is the default); otherwise required. |
| `--service URL` | `scitt register` | Transparency service base URL, `http(s)`, no credentials. Required. |
| `--profiles-dir DIR` | `ait declare`, `event`, `block` | Profile registry and schemas. Default the repo's `profiles/`. See [What the witness enforces](#what-the-witness-enforces). |
| `--unregistered-profile` | `ait declare` | Declare an AIT whose `profile` is not in the registry. |

Errors go to stderr as one line of `{"error": "..."}` with a non-zero exit.

## Records in git

The store's records can live in the project's own git repo, on an orphan
branch `atap/records` (`refs/heads/atap/records`), so they travel with a
clone.

**Sync.** `atap-witness git sync` commits the records of the nearest
`.atap/` (or `--dir DIR`) to `atap/records`. It must run inside the git repo
that holds the store; outside one it fails with `run git init first`. It
uses plumbing only (`hash-object`, `mktree`, `commit-tree`, `update-ref`), so
it never touches `HEAD`, the index or the worktree. Each commit has the
message `atap: N events, M blocks` and the fixed author `atap-witness`, so no
`user.name` is needed. A sync with nothing new is a no-op (`"synced": false`).
The branch is append-only: if a file on it is not a whole-line prefix of the
store's, sync refuses rather than drop history.

**Push.** The CLI never pushes. After a commit it prints
`to publish: git push origin atap/records` on stderr; running it is your step.

**What is on the branch.** Only the four record files: `aits.jsonl`,
`blocks.jsonl`, `cleared.jsonl` and `events.jsonl`. Never `witness.pem`,
`config.json`, `last-receipt.json` or `.gitignore`. The key never leaves the
machine.

**Sync on every block.** `init --git` writes `git_sync: true` into
`config.json`. After that, `block` runs a sync once the block is written. It
is best-effort: a failure prints `git sync failed: ...` on stderr and the
block still succeeds, with the same stdout and exit code. A plain `init` is
unchanged.

**Restore.** `atap-witness git restore [--into DIR]` (default `./.atap`)
rebuilds the records from `atap/records`, or from `origin/atap/records` when
only a clone's remote copy exists. If neither exists it says to run
`git fetch origin atap/records:atap/records`. It reads with `rev-parse`,
`ls-tree` and `cat-file` only, and writes only the four JSONL files plus a
`.gitignore` containing `witness.pem`. It writes no key and no
`config.json`, so `receipt` then needs `--key`, `--dir`, `--ait` and
`--witness-oai`. It refuses to overwrite a file that differs, checking every
target before the first write; restoring twice is a no-op.

**Verify a store.** A reviewer needs no key:

```sh
git fetch origin atap/records:atap/records && atap-witness git restore && atap-witness verify --store
```

`verify --store` reads only the JSONL files and writes nothing. It checks the
AIT signature, every block's signature and the block chain (the same
`verifyReceipt` that `verify` uses), then every event the blocks cover: each
`self_hash`, the `prev_event_hash` chain, each block's `first_event`,
`last_event` and `chain_head_hash`, and for a did:key witness each event's
signature. Events after the last block are pending: not checked, not counted
in `events`. A did:key witness is its own public key. An OAI witness needs
`--keys public_keys.json`, since the store holds no public keys. If the store
holds several AITs (after `ait rotate`), pick one with `--ait`.

A receipt still needs the key holder. From a fresh clone, copy the witness key in by hand to `.atap/witness.pem`,
which the restored `.gitignore` covers; never put it anywhere git would commit it.

```sh
git fetch origin atap/records:atap/records
atap-witness git restore
atap-witness receipt --dir .atap --key .atap/witness.pem --ait ID --witness-oai OAI --out receipt
atap-witness verify receipt
```

`ID` is the AIT's `id` in `.atap/aits.jsonl` and `OAI` is its `witness`
(the did:key for an `init` store).

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
  complete ATAP core schema (v0.2 for an AIT or block declaring `0.2`, as
  every did:key AIT does; v0.1 otherwise) at the moment it is written, after the
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
`registry.json` and `atap-v0.1-schemas/` (and `atap-v0.2-schemas/` for did:key AITs). Error messages name the schema and
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

**Export.** `scitt export DIR --key K [--issuer ISS]` writes `DIR/scitt/`.
`--issuer` defaults to the did:key witness of the nearest `.atap/config.json`;
with no such config (or an OAI witness) it is required.

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
EXPIRES=$(node -p 'new Date(Date.now() + 365 * 864e5).toISOString()')

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
The trusted `verify.sh` from your checkout's root checks the same receipt:
`/path/to/atap/verify.sh receipt`. The bundled copy is for reference only; never
run it on a receipt you did not make.

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
