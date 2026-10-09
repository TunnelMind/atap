// verify.sh on ATAP v0.2 receipts with a did:key witness (ATAP-v0.2 §3): the
// key binding, the self-asserted rule and the version rule. Throwaway keys
// and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  WitnessService,
  InMemoryStorage,
  didKeyFromPublicKey,
  publicKeyFromDidKey,
  toHex,
  ed25519Sign,
  canonicalizeBytes,
  fromHex,
  sha256,
} from '@tunnelmindai/atap'

const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const POLICY = { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' }

function rawPub(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  return new Uint8Array(der.subarray(der.length - 32))
}

// A did:key-witnessed receipt dir as `atap-witness receipt` lays it out, or an
// OAI-witnessed one when `oai` is given.
async function didReceiptDir(oai) {
  const { privateKey } = generateKeyPairSync('ed25519')
  const witness = oai ?? didKeyFromPublicKey(rawPub(privateKey))
  const svc = new WitnessService({ witnessOAI: witness, privateKey, storage: new InMemoryStorage() })
  const ait = await svc.declareAit({
    agentType: 'crew-ops',
    profile: 'tunnelmind:crew_ops:v1',
    operator: witness,
    capabilities: ['crew_ops:ratify'],
    attestationPolicy: POLICY,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  })
  await svc.witness(ait.id, 'crew_ops:ratify', { n: 1 })
  const block = await svc.rollUp(ait.id, { ratifications: 1 })
  const receipt = await svc.generateReceipt(ait.id, '2000-01-01T00:00:00.000Z', '2100-01-01T00:00:00.000Z')
  const keys = {
    keys: [{
      witness,
      key_id: 'k1',
      algorithm: 'ed25519',
      public_key: '0x' + toHex(rawPub(privateKey)),
      valid_from: '2000-01-01T00:00:00Z',
      valid_until: '2100-01-01T00:00:00Z',
      status: 'active',
      attestation_strength: 'self-asserted',
      rotated_to: null,
      compromise_notice: null,
    }],
    updated_at: new Date().toISOString(),
  }
  const dir = mkdtempSync(join(tmpdir(), 'atap-v02-'))
  const files = { 'manifest.json': receipt, 'ait.json': ait, 'attestation_chain.json': [block], 'public_keys.json': keys }
  for (const [f, v] of Object.entries(files)) writeFileSync(join(dir, f), JSON.stringify(v))
  return { dir, privateKey, witness, ait, block }
}

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
function edit(dir, f, fn) { writeFileSync(join(dir, f), JSON.stringify(fn(readJson(dir, f)))) }
const verifySh = dir => spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8' })

function assertFails(r, re) {
  assert.notEqual(r.status, 0, r.stdout)
  assert.match(r.stderr, /FAIL: /)
  assert.match(r.stderr, re)
}

test('a valid v0.2 did:key receipt verifies', async () => {
  const { dir } = await didReceiptDir()
  assert.equal(readJson(dir, 'ait.json').ait_version, '0.2')
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /Receipt verifies \(blocks=1, attestation_strength=self-asserted\)/)
})

// The did:key alone does not replace the key entry (as verifyReceipt).
for (const [what, fn] of [
  ['no key entry', k => ({ ...k, keys: [] })],
  ['only a compromised key entry', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at: '2001-01-01T00:00:00Z' } }] })],
  ['only an expired key entry', k => ({ ...k, keys: [{ ...k.keys[0], valid_until: '2001-01-01T00:00:00Z' }] })],
]) {
  test(`a did:key receipt with ${what} fails`, async () => {
    const { dir } = await didReceiptDir()
    edit(dir, 'public_keys.json', fn)
    assertFails(verifySh(dir), /no key for/)
  })
}

test('a tampered did:key witness fails', async () => {
  const { dir, witness } = await didReceiptDir()
  // Still a well-formed Ed25519 did:key, but of another key.
  const last = witness.at(-1)
  const forged = witness.slice(0, -1) + (last === 'a' ? 'b' : 'a')
  edit(dir, 'ait.json', a => ({ ...a, witness: forged }))
  edit(dir, 'manifest.json', m => ({ ...m, witness: forged }))
  // An honest key entry for the forged did:key, so the signature check is what fails.
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], witness: forged, public_key: '0x' + toHex(publicKeyFromDidKey(forged)) }] }))
  assertFails(verifySh(dir), /AIT signature invalid/)
})

test('a did:key receipt claiming tee-tpm fails', async () => {
  const { dir } = await didReceiptDir()
  edit(dir, 'manifest.json', m => ({ ...m, attestation_strength: 'tee-tpm' }))
  assertFails(verifySh(dir), /§3\.2/)
})

test('a did:key receipt with no attestation_strength fails', async () => {
  const { dir } = await didReceiptDir()
  edit(dir, 'manifest.json', ({ attestation_strength, ...m }) => m)
  assertFails(verifySh(dir), /'self-asserted', got 'MISSING'.*§3\.2/)
})

test('a key entry whose public_key is not the did:key fails', async () => {
  const { dir } = await didReceiptDir()
  const other = toHex(rawPub(generateKeyPairSync('ed25519').privateKey))
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], public_key: '0x' + other }] }))
  assertFails(verifySh(dir), /§3\.1/)
})

test('a did:key AIT declaring ait_version 0.1 fails, even when re-signed', async () => {
  const { dir, privateKey } = await didReceiptDir()
  edit(dir, 'ait.json', ({ witness_signature, ...a }) => {
    const u = { ...a, ait_version: '0.1' }
    return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
  })
  assertFails(verifySh(dir), /ait_version '0\.1'.*§3\.3/)
})

test('a block declaring ab_version 0.1 under a did:key AIT fails, even when re-signed', async () => {
  const { dir, privateKey } = await didReceiptDir()
  let head
  edit(dir, 'attestation_chain.json', ([{ self_hash, witness_signature, ...b }]) => {
    const u = { ...b, ab_version: '0.1' }
    head = sha256(canonicalizeBytes(u))
    return [{ ...u, self_hash: head, witness_signature: ed25519Sign(fromHex(head), privateKey) }]
  })
  edit(dir, 'manifest.json', m => ({ ...m, chain_head_hash: head }))
  assertFails(verifySh(dir), /ab_version '0\.1'.*§3\.3/)
})

test('an OAI-witnessed AIT paired with a did:key manifest and blocks fails', async () => {
  const did = await didReceiptDir()
  const oai = await didReceiptDir('OAI-2026-0010002')
  // The AIT verifies under its OAI key entry; the blocks under the did:key.
  writeFileSync(join(did.dir, 'ait.json'), readFileSync(join(oai.dir, 'ait.json')))
  writeFileSync(join(did.dir, 'public_keys.json'), readFileSync(join(oai.dir, 'public_keys.json')))
  assertFails(verifySh(did.dir), /manifest witness did:key:\S+ != AIT witness OAI-2026-0010002/)
})

// The manifest/AIT witness equality rule is did:key-only (ATAP-v0.2 §3.4), as
// in verifyReceipt: an OAI manifest naming another OAI witness with a key verifies.
test('an OAI manifest naming a different OAI witness than its AIT verifies', async () => {
  const { dir } = await didReceiptDir('OAI-2026-0010002')
  edit(dir, 'manifest.json', m => ({ ...m, witness: 'OAI-2026-0010003' }))
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [...k.keys, { ...k.keys[0], witness: 'OAI-2026-0010003', key_id: 'k2' }] }))
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
})

test('a did:key AIT whose operator is a non-Ed25519 did:key fails, even when re-signed', async () => {
  const { dir, privateKey } = await didReceiptDir()
  edit(dir, 'ait.json', ({ witness_signature, ...a }) => {
    // W3C secp256k1 did:key (multicodec 0xe701).
    const u = { ...a, operator: 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme' }
    return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
  })
  assertFails(verifySh(dir), /AIT identifier did:key:zQ3s\S+ is not an Ed25519 did:key/)
})

test('a did:key key entry valid at a block but not self-asserted fails', async () => {
  const { dir, block } = await didReceiptDir()
  // The AIT-period entry stays self-asserted; a second entry for the same key
  // covers the block's period_end and claims tee-tpm.
  edit(dir, 'public_keys.json', k => ({
    ...k,
    keys: [
      { ...k.keys[0], valid_until: block.period_end },
      { ...k.keys[0], key_id: 'k2', valid_from: block.period_end, attestation_strength: 'tee-tpm' },
    ],
  }))
  assertFails(verifySh(dir), /key entry for did:key:\S+ must declare attestation_strength 'self-asserted', got 'tee-tpm'/)
})
