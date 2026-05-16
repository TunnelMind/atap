/**
 * Chain-integrity verification — ATAP v0.1 §9.4 acceptance check (4).
 *
 * Each profile ships a signed example AIT, Witness Event chain, Attestation
 * Block, and Receipt. This re-derives every hash and checks every Ed25519
 * signature against the bundled public key, exactly as the reference verifier
 * (verify.sh) does — proving the examples round-trip.
 */
import {
  canonicalizeBytes, sha256, ed25519Verify, publicKeyFromHex, GENESIS_HASH,
} from '@tunnelmindai/atap';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

let failures = 0;
const check = (cond, msg) => {
  if (cond) console.log(`  ✓ ${msg}`);
  else { console.error(`  ✗ ${msg}`); failures++; }
};
const drop = (obj, ...keys) => {
  const c = { ...obj };
  for (const k of keys) delete c[k];
  return c;
};

for (const profile of readdirSync(join(root, 'profiles'))) {
  const ex = join(root, 'profiles', profile, 'examples');
  if (!existsSync(join(ex, 'ait.json'))) continue;
  console.log(`\n${profile}`);

  const ait = readJson(join(ex, 'ait.json'));
  const events = readJson(join(ex, 'witness-events.json'));
  const block = readJson(join(ex, 'attestation-block.json'));
  const receipt = readJson(join(ex, 'receipt.json'));
  const keys = readJson(join(ex, 'public_keys.json'));
  const pub = publicKeyFromHex(keys.keys[0].public_key);

  // AIT — signature over canonical bytes minus witness_signature
  check(
    ed25519Verify(canonicalizeBytes(drop(ait, 'witness_signature')), ait.witness_signature, pub),
    'AIT witness signature verifies',
  );

  // Witness Event chain — recompute self_hash, check linkage + signature
  let prev = GENESIS_HASH;
  events.forEach((evt, i) => {
    const recomputed = sha256(canonicalizeBytes(drop(evt, 'self_hash', 'witness_signature')));
    check(recomputed === evt.self_hash, `event[${i}] (${evt.event_type}) self_hash recomputes`);
    check(evt.prev_event_hash === prev, `event[${i}] (${evt.event_type}) links to previous event`);
    check(
      ed25519Verify(canonicalizeBytes(evt.self_hash), evt.witness_signature, pub),
      `event[${i}] (${evt.event_type}) signature verifies`,
    );
    prev = evt.self_hash;
  });

  // Attestation Block
  const blockRecomputed = sha256(canonicalizeBytes(drop(block, 'self_hash', 'witness_signature')));
  check(blockRecomputed === block.self_hash, 'block self_hash recomputes');
  check(block.prev_block_hash === GENESIS_HASH, 'block links to genesis (first block)');
  check(block.chain_head_hash === events.at(-1).self_hash, 'block chain_head_hash matches last event');
  check(block.event_count === events.length, 'block event_count matches chain length');
  check(
    ed25519Verify(canonicalizeBytes(block.self_hash), block.witness_signature, pub),
    'block signature verifies',
  );

  // Receipt
  check(
    ed25519Verify(canonicalizeBytes(drop(receipt, 'witness_signature')), receipt.witness_signature, pub),
    'receipt signature verifies',
  );
  check(receipt.chain_head_hash === block.self_hash, 'receipt chain_head_hash matches block');
}

console.log(failures === 0 ? '\nAll examples round-trip cleanly.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
