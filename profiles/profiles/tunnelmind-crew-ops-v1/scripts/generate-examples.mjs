/**
 * Regenerates the signed example artifacts for the crew-ops profile (PROFILE
 * below). Run: `node scripts/generate-examples.mjs` from the profile dir.
 *
 * Uses the @tunnelmindai/atap reference WitnessService with a FRESH ephemeral
 * keypair each run — the matching public key is written to examples/public_keys.json,
 * so the committed examples and their key always verify together. There is no
 * private key in this repo: these are illustrative fixtures, not production keys.
 */
import { WitnessService, InMemoryStorage } from '@tunnelmindai/atap';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// The one place the profile name lives (it may be renamed before release).
const PROFILE = 'tunnelmind:crew_ops:v1';

const examplesDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'examples');

// Ephemeral fixture keypair.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = '0x' + Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');

const WITNESS_OAI  = 'OAI-2026-0010002'; // illustrative — the crew witness operator OAI
const OPERATOR_OAI = 'OAI-2026-0010001'; // illustrative — the crew's operator OAI

// A mutable clock so timestamps (and the time-ordered uuidv7 IDs) advance.
let clock = new Date('2026-10-09T12:00:00Z').getTime();
const tick = (ms = 1500) => { clock += ms; return new Date(clock).toISOString(); };

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const w = new WitnessService({
  witnessOAI: WITNESS_OAI,
  privateKey,
  storage: new InMemoryStorage(),
  // ATAP §7.4.1 attestation strength = 'software', as in the Sigil profile's
  // examples, so verifiers exercise the full forward path.
  attestationStrength: 'software',
  now: () => new Date(clock),
});

const ait = await w.declareAit({
  agentType: 'crew-ops',
  profile: PROFILE,
  operator: OPERATOR_OAI,
  capabilities: ['crew_ops:autonomy_decide', 'crew_ops:ratify', 'crew_ops:intake_decide'],
  constraints: {
    allowed_agents: ['crew-toolsmith', 'crew-curator', 'crew-merchant', 'coordinator'],
    max_class: 2,
  },
  attestationPolicy: {
    witness_granularity: 'per_action',
    block_interval_seconds: 3600,
    receipt_generation: 'on_demand',
  },
  expiresAt: new Date(clock + 30 * 86400_000).toISOString(),
});

// One of each event type: the rails ask for a grant, the owner ratifies it by
// DKIM-verified mail (anchored), the rails allow the action, and the toolsmith
// routes a thinker idea to a workstream.
const INBOX_PATH = 'specs/toolsmith-inbox/example-idea.md';
const events = [];
events.push(await w.witness(ait.id, 'crew_ops:autonomy_decision', {
  timestamp: tick(), evidence: 'asserted', agent: 'crew-toolsmith', class: 2,
  action: 'propose', decision: 'request', target_sha256: sha256(INBOX_PATH),
}));
events.push(await w.witness(ait.id, 'crew_ops:ratification', {
  timestamp: tick(), evidence: 'anchored', role: 'owner', decision: 'approved', channel: 'mail',
  text_sha256: sha256('approve the toolsmith grant'),
  dkim_message_id_sha256: sha256('<example-message-id@example.invalid>'),
}));
events.push(await w.witness(ait.id, 'crew_ops:autonomy_decision', {
  timestamp: tick(), evidence: 'asserted', agent: 'crew-toolsmith', class: 2,
  action: 'propose', decision: 'allow', target_sha256: sha256(INBOX_PATH),
  reason_sha256: sha256('within grant'),
}));
events.push(await w.witness(ait.id, 'crew_ops:intake_decision', {
  timestamp: tick(), evidence: 'asserted', by: 'toolsmith', source: 'thinker',
  decision: 'act', title_sha256: sha256('example idea'), route: 'workstream',
}));

const block = await w.rollUp(ait.id, {
  autonomy_decisions: { allow: 1, refuse: 0, grant: 0, expired: 0, request: 1, approved: 0, rejected: 0 },
  intake_decisions: { act: 1, park: 0, drop: 0 },
  ratifications: 1,
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
]);

const publicKeys = {
  keys: [{
    witness: WITNESS_OAI,
    key_id: 'example-key-1',
    algorithm: 'ed25519',
    public_key: pubHex,
    valid_from: '2026-10-09T00:00:00Z',
    valid_until: '2027-10-09T00:00:00Z',
    status: 'active',
    // ATAP §8.1 — matches the witness service's deployment strength.
    // Verifiers cross-check receipt.attestation_strength against this.
    attestation_strength: 'software',
  }],
  updated_at: '2026-10-09T12:00:00Z',
};

const write = (name, obj) =>
  writeFileSync(join(examplesDir, name), JSON.stringify(obj, null, 2) + '\n');

write('ait.json', ait);
write('witness-events.json', events);
write('attestation-block.json', block);
write('receipt.json', receipt);
write('public_keys.json', publicKeys);

console.log(`Generated ${events.length} events, 1 block, 1 receipt. Witness key ${pubHex}`);
