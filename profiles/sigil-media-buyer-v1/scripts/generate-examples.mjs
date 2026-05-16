/**
 * Regenerates the signed example artifacts for the sigil:media_buyer:v1
 * profile. Run: `node scripts/generate-examples.mjs` from the profile dir.
 *
 * Uses the @tunnelmindai/atap reference WitnessService with a FRESH ephemeral
 * keypair each run — the matching public key is written to examples/public_keys.json,
 * so the committed examples and their key always verify together. There is no
 * private key in this repo: these are illustrative fixtures, not production keys.
 */
import { WitnessService, InMemoryStorage } from '@tunnelmindai/atap';
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const examplesDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'examples');

// Ephemeral fixture keypair.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = '0x' + Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');

const WITNESS_OAI  = 'OAI-2026-0009002'; // illustrative — Sigil's witness operator OAI
const OPERATOR_OAI = 'OAI-2026-0009001'; // illustrative — the media-buyer's operator OAI

// A mutable clock so timestamps (and the time-ordered uuidv7 IDs) advance.
let clock = new Date('2026-05-16T12:00:00Z').getTime();
const tick = (ms = 1500) => { clock += ms; return new Date(clock).toISOString(); };

const w = new WitnessService({
  witnessOAI: WITNESS_OAI,
  privateKey,
  storage: new InMemoryStorage(),
  now: () => new Date(clock),
});

const SIGIL_TOKEN = 'eyJhbGciOiJFZERTQSJ9.example-payload.example-signature';

const ait = await w.declareAit({
  agentType: 'media-buyer',
  profile: 'sigil:media_buyer:v1',
  operator: OPERATOR_OAI,
  capabilities: [
    'bid:submit', 'bid:read_response', 'supply:verify_via_sigil',
    'budget:read', 'budget:decrement', 'creative:select',
    'report:generate', 'report:export_receipt',
  ],
  constraints: {
    currency: 'USD',
    max_bid_cpm: 50,
    supply_trust_minimum: 0.7,
    budget_total_cap: 150000,
    budget_daily_cap: 10000,
    allowed_channels: ['display', 'video', 'ctv', 'audio'],
    blocked_categories: ['IAB25-3', 'IAB26'],
    geo_targeting: { allowed_countries: ['US', 'CA'] },
  },
  attestationPolicy: {
    witness_granularity: 'per_bid',
    block_interval_seconds: 300,
    receipt_generation: 'on_demand',
  },
  expiresAt: new Date(clock + 60 * 86400_000).toISOString(),
});

const supplyPath = {
  publisher_domain: 'news.example',
  exchange_domain: 'exchange-a.example',
  seller_id: 'pub-12345',
};

const events = [];
events.push(await w.witness(ait.id, 'supply:verified', {
  timestamp: tick(), supply_path: supplyPath,
  sigil_result: 'pass', trust_score: 0.86, sigil_token: SIGIL_TOKEN,
}));
events.push(await w.witness(ait.id, 'bid:submitted', {
  timestamp: tick(), exchange: 'exchange-a.example', publisher_domain: 'news.example',
  seller_id: 'pub-12345', bid_amount: 3.2, currency: 'USD', creative_id: 'cr-0001',
  channel: 'display', sigil_token: SIGIL_TOKEN, supply_trust_score: 0.86,
}));
events.push(await w.witness(ait.id, 'bid:won', {
  timestamp: tick(), exchange: 'exchange-a.example',
  clearing_price: 2.8, currency: 'USD', impression_id: 'imp-77001',
}));
events.push(await w.witness(ait.id, 'budget:decremented', {
  timestamp: tick(), amount: 2.8, currency: 'USD',
  remaining_daily: 9997.2, remaining_total: 149997.2,
}));
events.push(await w.witness(ait.id, 'supply:rejected', {
  timestamp: tick(),
  supply_path: {
    publisher_domain: 'spoofed.example',
    exchange_domain: 'exchange-b.example',
    seller_id: 'reseller-998',
  },
  sigil_result: 'fail', rejection_reason: 'datacenter IP and ads.txt mismatch',
  trust_score: 0.31,
}));
events.push(await w.witness(ait.id, 'bid:lost', {
  timestamp: tick(), exchange: 'exchange-a.example', reason: 'outbid',
}));
events.push(await w.witness(ait.id, 'constraint:violated', {
  timestamp: tick(), constraint_name: 'max_bid_cpm',
  declared_value: 50, actual_value: 62,
}));

const block = await w.rollUp(ait.id, {
  bids_submitted: 1,
  bids_won: 1,
  total_spend: 2.8,
  currency: 'USD',
  unique_publishers: 1,
  unique_exchanges: 2,
  supply_verifications: 1,
  supply_rejections: 1,
  average_trust_score: 0.585,
  constraint_violations: 1,
  channels_used: ['display'],
  geos_reached: ['US'],
});

// The ATAP v0.1 §7.5 Receipt ZIP manifest (sha256 left null in this fixture —
// the production witness fills them when it assembles the actual ZIP).
const receipt = await w.generateReceipt(ait.id, block.period_start, block.period_end, 'full', [
  { path: 'manifest.json', sha256: null },
  { path: 'ait.json', sha256: null },
  { path: 'attestation_chain.json', sha256: null },
  { path: 'summary.json', sha256: null },
  { path: 'public_keys.json', sha256: null },
  { path: 'verify.sh', sha256: null },
  { path: 'profile_artifacts/sigil_tokens.json', sha256: null },
]);

const publicKeys = {
  keys: [{
    witness: WITNESS_OAI,
    key_id: 'example-key-1',
    algorithm: 'ed25519',
    public_key: pubHex,
    valid_from: '2026-05-16T00:00:00Z',
    valid_until: '2027-05-16T00:00:00Z',
    status: 'active',
  }],
  updated_at: '2026-05-16T12:00:00Z',
};

const write = (name, obj) =>
  writeFileSync(join(examplesDir, name), JSON.stringify(obj, null, 2) + '\n');

write('ait.json', ait);
write('witness-events.json', events);
write('attestation-block.json', block);
write('receipt.json', receipt);
write('public_keys.json', publicKeys);

console.log(`Generated ${events.length} events, 1 block, 1 receipt. Witness key ${pubHex}`);
