/**
 * The one example generator behind every profile's scripts/generate-examples.mjs
 * (was four copies of this scaffolding, 2026-10-20). A profile script passes its
 * data — OAIs, start time, AIT input, events, period summary — and this signs
 * and writes examples/*.json next to it.
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

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// The ATAP v0.1 §7.5 Receipt ZIP manifest (sha256 left null in these fixtures —
// the production witness fills them when it assembles the actual ZIP).
const RECEIPT_FILES = ['manifest.json', 'ait.json', 'attestation_chain.json', 'summary.json', 'public_keys.json', 'verify.sh'];

/**
 * @param {string} scriptUrl the calling script's import.meta.url; examples/ sits beside its scripts/
 * @param {object} spec
 * @param {string} spec.witnessOAI
 * @param {string} spec.operatorOAI
 * @param {string} spec.start RFC 3339 instant the fixture clock starts at; the key is valid from that day for a year
 * @param {number} spec.lifetimeDays AIT lifetime from `start`
 * @param {{agentType: string, profile: string, capabilities: string[], constraints: object, attestationPolicy: object}} spec.ait
 * @param {(h: {witness: (type: string, payload: object) => Promise<object>, tick: (ms?: number) => string, sha256: (s: string) => string}) => Promise<object[]>} spec.events
 *   the events in order; `tick` advances the clock and returns the timestamp
 * @param {object} spec.summary the block's period_summary
 * @param {string[]} [spec.extraFiles] profile_artifacts the receipt lists after the standard files
 */
export async function generateExamples(scriptUrl, spec) {
  const examplesDir = join(dirname(fileURLToPath(scriptUrl)), '..', 'examples');

  // Ephemeral fixture keypair.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubHex = '0x' + Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');

  // A mutable clock so timestamps (and the time-ordered uuidv7 IDs) advance.
  let clock = new Date(spec.start).getTime();
  const tick = (ms = 1500) => { clock += ms; return new Date(clock).toISOString(); };

  const w = new WitnessService({
    witnessOAI: spec.witnessOAI,
    privateKey,
    storage: new InMemoryStorage(),
    // ATAP §7.4.1 attestation strength = 'software' (Sigil's reference
    // deployment runs in a CF Worker under OS-enforced isolation; the other
    // profiles follow it), so verifiers exercise the full forward path.
    attestationStrength: 'software',
    now: () => new Date(clock),
  });

  const ait = await w.declareAit({
    agentType: spec.ait.agentType,
    profile: spec.ait.profile,
    operator: spec.operatorOAI,
    capabilities: spec.ait.capabilities,
    constraints: spec.ait.constraints,
    attestationPolicy: spec.ait.attestationPolicy,
    expiresAt: new Date(clock + spec.lifetimeDays * 86400_000).toISOString(),
  });

  const events = await spec.events({ witness: (type, payload) => w.witness(ait.id, type, payload), tick, sha256 });

  const block = await w.rollUp(ait.id, spec.summary);

  const receipt = await w.generateReceipt(ait.id, block.period_start, block.period_end, 'full',
    [...RECEIPT_FILES, ...(spec.extraFiles ?? [])].map(path => ({ path, sha256: null })));

  const day = spec.start.slice(0, 10);
  const publicKeys = {
    keys: [{
      witness: spec.witnessOAI,
      key_id: 'example-key-1',
      algorithm: 'ed25519',
      public_key: pubHex,
      valid_from: `${day}T00:00:00Z`,
      valid_until: `${Number(day.slice(0, 4)) + 1}${day.slice(4)}T00:00:00Z`,
      status: 'active',
      // ATAP §8.1 — matches the witness service's deployment strength.
      // Verifiers cross-check receipt.attestation_strength against this.
      attestation_strength: 'software',
    }],
    updated_at: spec.start,
  };

  const write = (name, obj) =>
    writeFileSync(join(examplesDir, name), JSON.stringify(obj, null, 2) + '\n');

  write('ait.json', ait);
  write('witness-events.json', events);
  write('attestation-block.json', block);
  write('receipt.json', receipt);
  write('public_keys.json', publicKeys);

  console.log(`Generated ${events.length} events, 1 block, 1 receipt. Witness key ${pubHex}`);
}
