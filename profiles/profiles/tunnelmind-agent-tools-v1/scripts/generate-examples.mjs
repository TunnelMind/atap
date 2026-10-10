/**
 * Regenerates the signed example artifacts for the agent-tools profile (PROFILE
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
const PROFILE = 'tunnelmind:agent_tools:v1';

const examplesDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'examples');

// Ephemeral fixture keypair.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubHex = '0x' + Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');

const WITNESS_OAI  = 'OAI-2026-0010002'; // illustrative witness OAI
const OPERATOR_OAI = 'OAI-2026-0010001'; // illustrative operator OAI

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
  agentType: 'agent-tools',
  profile: PROFILE,
  operator: OPERATOR_OAI,
  capabilities: ['agent_tools:call_tools', 'agent_tools:call_models', 'agent_tools:handoff', 'agent_tools:ask_human'],
  constraints: {
    allowed_tools: ['web_search', 'mcp:files/read'],
    max_tool_calls_per_session: 100,
  },
  attestationPolicy: {
    witness_granularity: 'per_action',
    block_interval_seconds: 3600,
    receipt_generation: 'on_demand',
  },
  expiresAt: new Date(clock + 30 * 86400_000).toISOString(),
});

// One of each event type, all `asserted`: the agent's own code reports them.
// A session starts, the agent calls a tool and a model, hands off to a
// reviewer agent, and the operator approves the result.
const events = [];
events.push(await w.witness(ait.id, 'agent_tools:session_started', {
  timestamp: tick(), evidence: 'asserted', agent: 'research-agent', framework: 'langgraph',
  model: 'claude-sonnet-5-5',
}));
events.push(await w.witness(ait.id, 'agent_tools:tool_called', {
  timestamp: tick(), evidence: 'asserted', tool: 'web_search',
  input_sha256: sha256('{"query":"example"}'), output_sha256: sha256('example result'),
  outcome: 'ok', duration_ms: 420,
}));
events.push(await w.witness(ait.id, 'agent_tools:model_called', {
  timestamp: tick(), evidence: 'asserted', model: 'claude-sonnet-5-5',
  input_tokens: 1200, output_tokens: 300, duration_ms: 2100, output_sha256: sha256('example answer'),
}));
events.push(await w.witness(ait.id, 'agent_tools:handoff', {
  timestamp: tick(), evidence: 'asserted', from_agent: 'research-agent', to_agent: 'review-agent',
}));
events.push(await w.witness(ait.id, 'agent_tools:human_decision', {
  timestamp: tick(), evidence: 'asserted', role: 'operator', decision: 'approve',
  subject_sha256: sha256('example answer'), channel: 'cli',
}));

const block = await w.rollUp(ait.id, {
  events: { session_started: 1, tool_called: 1, model_called: 1, handoff: 1, human_decision: 1 },
  tool_outcomes: { ok: 1, error: 0, denied: 0 },
  total_tokens: 1500,
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
