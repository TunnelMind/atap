# @tunnelmind/atap

Reference TypeScript wrapper for **ATAP v0.1** — the Agent Trust Attestation Protocol.

- **Standard:** https://tunnelmind.ai/atap/standard
- **Verifier (bash):** https://tunnelmind.ai/atap/verify.sh
- **JSON Schemas:** https://tunnelmind.ai/atap/schemas/v0.1/
- **License:** MIT

This package gives a witness service the helpers it needs to sign and chain
ATAP artifacts (AITs, Witness Events, Attestation Blocks, Receipts), plus an
in-process verifier that mirrors `verify.sh`.

The package is **non-normative**: the standard is the source of truth.
Implementations in other languages are welcomed and need only conform to
§7 (schemas), §10 (hash chain), and §11 (verification) of the spec.

## Install

```bash
npm install @tunnelmind/atap
```

Node 20+ is required (uses the built-in `node:crypto` Ed25519 + SHA-256
APIs and the standard-library only — zero runtime dependencies).

## Quick start

```ts
import {
  WitnessService,
  InMemoryStorage,
  privateKeyFromRaw,
  publicKeyFromRaw,
  verifyReceipt,
} from '@tunnelmind/atap'
import { generateKeyPairSync } from 'node:crypto'

// 1. Generate (or load) an Ed25519 keypair for the witness service.
const { publicKey, privateKey } = generateKeyPairSync('ed25519')

const witness = new WitnessService({
  witnessOAI: 'OAI-2026-0000017',
  privateKey,
  storage: new InMemoryStorage(),
})

// 2. Declare an AIT.
const ait = await witness.declareAit({
  agentType: 'media-buyer',
  profile: 'sigil:media_buyer:v1',
  operator: 'OAI-2026-0000234',
  capabilities: ['bid:submit', 'budget:read', 'budget:decrement'],
  attestationPolicy: {
    witness_granularity: 'per_action',
    block_interval_seconds: 300,
    receipt_generation: 'on_demand',
  },
  expiresAt: '2026-08-12T00:00:00Z',
})

// 3. Witness events.
await witness.witness(ait.id, 'bid:submitted', {
  exchange: 'openx.com',
  publisher_domain: 'example-publisher.com',
  seller_id: '12345',
  bid_amount: 1.45,
})

// 4. Roll up a block.
await witness.rollUp(ait.id, { bids_submitted: 1, total_spend: 1.45 })

// 5. Generate a receipt.
const receipt = await witness.generateReceipt(
  ait.id,
  '2026-05-01T00:00:00Z',
  '2026-05-31T23:59:59Z',
)
```

## Verifying

```ts
import { verifyReceipt } from '@tunnelmind/atap'

const result = verifyReceipt({
  receipt,           // Parsed manifest.json
  ait,               // Parsed ait.json
  chain,             // Parsed attestation_chain.json
  keys,              // Parsed public_keys.json
})
if (!result.ok) throw new Error(result.reason)
console.log(`receipt verifies: ${result.blocks} blocks`)
```

## Storage

`InMemoryStorage` is provided for tests. Production witnesses implement the
`WitnessStorage` interface against a durable backend (Postgres, S3 + a lock
service, etc.). The interface is intentionally narrow: a witness only needs
last-event-hash, last-block-hash, append-event, append-block, and a few
list queries.

## Constraints

The package enforces v0.1 limits at signing time:

- AIT lifetime ≤ 365 days
- Capability list 1–64 items
- `block_interval_seconds` 60–3600
- Event `payload` ≤ 16 KB canonical-bytes
- AIT id collision detection via `WitnessStorage.hasAitId`

These match §6.3, §7.1, §7.1.1, and §7.2 of the standard.

## License

MIT.
