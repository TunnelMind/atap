/**
 * Regenerates the signed example artifacts for the code-crew profile (PROFILE
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
const PROFILE = 'tunnelmind:code_crew:v1';

const examplesDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'examples');

// Ephemeral fixture keypair.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = '0x' + Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');

const WITNESS_OAI  = 'OAI-2026-0010002'; // illustrative — the crew witness operator OAI
const OPERATOR_OAI = 'OAI-2026-0010001'; // illustrative — the code crew's operator OAI

// A mutable clock so timestamps (and the time-ordered uuidv7 IDs) advance.
let clock = new Date('2026-10-08T12:00:00Z').getTime();
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
  agentType: 'code-crew',
  profile: PROFILE,
  operator: OPERATOR_OAI,
  capabilities: [
    'code_crew:plan', 'code_crew:code', 'code_crew:verify',
    'code_crew:qa_verdict', 'code_crew:review_verdict', 'code_crew:approve',
    'code_crew:merge', 'code_crew:deploy', 'code_crew:revert',
  ],
  constraints: {
    autonomy_class: 'gated',
    allowed_repos: ['example-org/example-repo'],
    max_iterations: 3,
    models: {
      supervisor: 'claude-opus-5-5',
      coder: 'claude-opus-5-5',
      qa: 'claude-sonnet-5-5',
      reviewer: 'claude-opus-5-5',
    },
  },
  attestationPolicy: {
    witness_granularity: 'per_action',
    block_interval_seconds: 3600,
    receipt_generation: 'on_demand',
  },
  expiresAt: new Date(clock + 30 * 86400_000).toISOString(),
});

// Fake but well-formed git shas.
const COMMIT_SHA = '3f1c2a9e8b7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f';
const MERGE_SHA  = 'a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0';

const events = [];
events.push(await w.witness(ait.id, 'code_crew:task_claimed', {
  timestamp: tick(), evidence: 'asserted', task_id: 'A101', role: 'coder', model: 'claude-opus-5-5',
}));
events.push(await w.witness(ait.id, 'code_crew:change_committed', {
  timestamp: tick(), evidence: 'anchored', repo: 'example-org/example-repo', commit_sha: COMMIT_SHA,
}));
events.push(await w.witness(ait.id, 'code_crew:verify_run', {
  timestamp: tick(), evidence: 'witnessed',
  command_sha256: sha256('npm test'), exit_code: 0, output_sha256: sha256('example test output'),
}));
events.push(await w.witness(ait.id, 'code_crew:qa_verdict', {
  timestamp: tick(), evidence: 'asserted', task_id: 'A101', verdict: 'accepted', attempt: 1,
}));
events.push(await w.witness(ait.id, 'code_crew:review_verdict', {
  timestamp: tick(), evidence: 'asserted', head_sha: COMMIT_SHA, verdict: 'pass',
  findings: { critical: 0, high: 0, medium: 1, low: 2 },
}));
events.push(await w.witness(ait.id, 'code_crew:approval', {
  timestamp: tick(), evidence: 'asserted', role: 'owner', decision: 'approve',
  channel: 'cli', approval_text_sha256: sha256('approve merge'),
}));
events.push(await w.witness(ait.id, 'code_crew:merged', {
  timestamp: tick(), evidence: 'anchored', repo: 'example-org/example-repo',
  pr_number: 42, merge_commit_sha: MERGE_SHA,
}));
events.push(await w.witness(ait.id, 'code_crew:deployed', {
  timestamp: tick(), evidence: 'asserted', target: 'staging', version_id: 'v-0001',
}));

const block = await w.rollUp(ait.id, {
  tasks_accepted: 1,
  tasks_rework: 0,
  merged_changes: 1,
  tokens: 182000,
  overturns: { supervisor: 0, coder: 0, qa: 0, reviewer: 0 },
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
    valid_from: '2026-10-08T00:00:00Z',
    valid_until: '2027-10-08T00:00:00Z',
    status: 'active',
    // ATAP §8.1 — matches the witness service's deployment strength.
    // Verifiers cross-check receipt.attestation_strength against this.
    attestation_strength: 'software',
  }],
  updated_at: '2026-10-08T12:00:00Z',
};

const write = (name, obj) =>
  writeFileSync(join(examplesDir, name), JSON.stringify(obj, null, 2) + '\n');

write('ait.json', ait);
write('witness-events.json', events);
write('attestation-block.json', block);
write('receipt.json', receipt);
write('public_keys.json', publicKeys);

console.log(`Generated ${events.length} events, 1 block, 1 receipt. Witness key ${pubHex}`);
