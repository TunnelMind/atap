// did:key (ATAP-v0.2 §3): encode/decode, the witness's key binding, the
// self-asserted rule and the version rule, end to end through verifyReceipt.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import {
  WitnessService,
  InMemoryStorage,
  verifyReceipt,
  didKeyFromPublicKey,
  publicKeyFromDidKey,
  isDidKey,
  toHex,
  fromHex,
  ed25519Sign,
  canonicalizeBytes,
  sha256,
} from '../dist/index.js'

// W3C did:key test vector (Ed25519).
const W3C = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp'
const W3C_HEX = '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29'

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function b58(bytes) {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  return s
}

function rawPub(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  return new Uint8Array(der.subarray(der.length - 32))
}

test('W3C vector decodes and round-trips', () => {
  const raw = publicKeyFromDidKey(W3C)
  assert.equal(toHex(raw), W3C_HEX)
  assert.equal(didKeyFromPublicKey(raw), W3C)
  assert.ok(isDidKey(W3C))
  for (let i = 0; i < 20; i++) {
    const k = rawPub(generateKeyPairSync('ed25519').privateKey)
    const d = didKeyFromPublicKey(k)
    assert.ok(isDidKey(d), d)
    assert.deepEqual(publicKeyFromDidKey(d), k)
  }
  // A key with leading zero bytes still round-trips.
  const z = new Uint8Array(32); z[31] = 1
  assert.deepEqual(publicKeyFromDidKey(didKeyFromPublicKey(z)), z)
})

test('decode rejects other multicodecs, bad prefix, bad base58 and wrong length', () => {
  // W3C secp256k1 (0xe701) and x25519 (0xec01) vectors.
  assert.throws(() => publicKeyFromDidKey('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'), /0xed01/)
  assert.throws(() => publicKeyFromDidKey('did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F'), /0xed01/)
  assert.throws(() => publicKeyFromDidKey(W3C.replace('did:key:z', 'did:web:z')), /must start/)
  assert.throws(() => publicKeyFromDidKey(W3C.replace('did:key:z', 'did:key:m')), /must start/)
  assert.throws(() => publicKeyFromDidKey(W3C.slice(0, -1) + '0'), /bad base58/)
  assert.throws(() => publicKeyFromDidKey(W3C.slice(0, -1) + 'l'), /bad base58/)
  const short = new Uint8Array(33); short[0] = 0xed; short[1] = 0x01; short[2] = 0x80
  assert.throws(() => publicKeyFromDidKey('did:key:z' + b58(short)), /33 bytes/)
  const long = new Uint8Array(35); long[0] = 0xed; long[1] = 0x01
  assert.throws(() => publicKeyFromDidKey('did:key:z' + b58(long)), /35 bytes/)
  assert.throws(() => didKeyFromPublicKey(new Uint8Array(31)), /32 bytes/)
  assert.ok(!isDidKey('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'))
  assert.ok(!isDidKey('OAI-2026-0010002'))
})

const POLICY = { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' }

async function chain({ witness, privateKey, operator = 'OAI-2026-0010001' }) {
  const storage = new InMemoryStorage()
  const svc = new WitnessService({ witnessOAI: witness, privateKey, storage })
  const ait = await svc.declareAit({
    agentType: 'crew-ops',
    profile: 'tunnelmind:crew_ops:v1',
    operator,
    capabilities: ['crew_ops:ratify'],
    attestationPolicy: POLICY,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  })
  await svc.witness(ait.id, 'crew_ops:ratify', { n: 1 })
  await svc.witness(ait.id, 'crew_ops:ratify', { n: 2 })
  const block = await svc.rollUp(ait.id, { ratifications: 2 })
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
  return { ait, chain: [block], receipt, keys }
}

async function didChain() {
  const { privateKey } = generateKeyPairSync('ed25519')
  const witness = didKeyFromPublicKey(rawPub(privateKey))
  return { privateKey, witness, ...(await chain({ witness, privateKey, operator: witness })) }
}

// Re-sign a record after editing it, as a forger holding `privateKey` would.
const resignAit = (ait, k) => { const { witness_signature, ...u } = ait; return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), k) } }
const resignReceipt = resignAit
function resignBlock(b, k) {
  const { self_hash, witness_signature, ...u } = b
  const h = sha256(canonicalizeBytes(u))
  return { ...u, self_hash: h, witness_signature: ed25519Sign(fromHex(h), k) }
}

test('did:key witness: declare → witness → rollUp → receipt verifies as v0.2 self-asserted', async () => {
  const c = await didChain()
  assert.equal(c.ait.ait_version, '0.2')
  assert.equal(c.chain[0].ab_version, '0.2')
  assert.equal(c.receipt.attestation_strength, 'self-asserted')
  assert.equal(c.receipt.witness, c.witness)
  const r = verifyReceipt(c)
  assert.equal(r.ok, true, r.reason)
  assert.equal(r.attestation_strength, 'self-asserted')
})

test('did:key operator alone also makes the AIT v0.2; a non-Ed25519 did operator is refused', async () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  const c = await chain({ witness: 'OAI-2026-0010002', privateKey, operator: W3C })
  assert.equal(c.ait.ait_version, '0.2')
  assert.equal(verifyReceipt(c).ok, true)
  const svc = new WitnessService({ witnessOAI: 'OAI-2026-0010002', privateKey, storage: new InMemoryStorage() })
  await assert.rejects(svc.declareAit({
    agentType: 'x', profile: 'tunnelmind:crew_ops:v1', operator: 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme',
    capabilities: ['a:b'], attestationPolicy: POLICY, expiresAt: new Date(Date.now() + 86400_000).toISOString(),
  }), /Ed25519 did:key/)
})

test('WitnessService refuses a did:key that is not its signing key, or a stronger tier', () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  const other = didKeyFromPublicKey(rawPub(generateKeyPairSync('ed25519').privateKey))
  assert.throws(() => new WitnessService({ witnessOAI: other, privateKey, storage: new InMemoryStorage() }), /not the did:key of the signing key/)
  const own = didKeyFromPublicKey(rawPub(privateKey))
  assert.throws(() => new WitnessService({ witnessOAI: own, privateKey, storage: new InMemoryStorage(), attestationStrength: 'tee-tpm' }), /self-asserted/)
})

test('§3.1: records signed by another key under a did:key witness are rejected', async () => {
  const c = await didChain()
  const { privateKey: forger } = generateKeyPairSync('ed25519')
  // The key entry advertises the forger's key; every record is re-signed with it.
  const keys = { ...c.keys, keys: [{ ...c.keys.keys[0], public_key: '0x' + toHex(rawPub(forger)) }] }
  const r = verifyReceipt({
    ait: resignAit(c.ait, forger),
    chain: [resignBlock(c.chain[0], forger)],
    receipt: resignReceipt(c.receipt, forger),
    keys,
  })
  assert.equal(r.ok, false)
  assert.match(r.reason, /§3\.1/)
  // Only the receipt signed by another key (the key entry still honest).
  const r2 = verifyReceipt({ ...c, receipt: resignReceipt(c.receipt, forger) })
  assert.equal(r2.ok, false)
  assert.match(r2.reason, /receipt signature invalid/)
})

test('§3.2: a did:key receipt with tee-tpm or no strength, or a key entry without self-asserted, is rejected', async () => {
  const c = await didChain()
  const tee = resignReceipt({ ...c.receipt, attestation_strength: 'tee-tpm' }, c.privateKey)
  const keysTee = { ...c.keys, keys: [{ ...c.keys.keys[0], attestation_strength: 'tee-tpm' }] }
  for (const keys of [c.keys, keysTee]) {
    const r = verifyReceipt({ ...c, keys, receipt: tee })
    assert.equal(r.ok, false)
    assert.match(r.reason, /§3\.2/)
  }
  const { attestation_strength, ...noStrength } = c.receipt
  const r = verifyReceipt({ ...c, receipt: resignReceipt(noStrength, c.privateKey) })
  assert.equal(r.ok, false)
  assert.match(r.reason, /§3\.2/)
  const { attestation_strength: _, ...bareKey } = c.keys.keys[0]
  const r2 = verifyReceipt({ ...c, keys: { ...c.keys, keys: [bareKey] } })
  assert.equal(r2.ok, false)
  assert.match(r2.reason, /§3\.2/)
})

test('§3.3: a did:key AIT or block declaring 0.1 is rejected', async () => {
  const c = await didChain()
  const r = verifyReceipt({ ...c, ait: resignAit({ ...c.ait, ait_version: '0.1' }, c.privateKey) })
  assert.equal(r.ok, false)
  assert.match(r.reason, /§3\.3/)
  const b = resignBlock({ ...c.chain[0], ab_version: '0.1' }, c.privateKey)
  const r2 = verifyReceipt({ ...c, chain: [b], receipt: resignReceipt({ ...c.receipt, chain_head_hash: b.self_hash }, c.privateKey) })
  assert.equal(r2.ok, false)
  assert.match(r2.reason, /§3\.3/)
})

test('receipt witness must equal the AIT witness', async () => {
  const c = await didChain()
  const r = verifyReceipt({ ...c, receipt: { ...c.receipt, witness: 'OAI-2026-0010002' } })
  assert.equal(r.ok, false)
  assert.match(r.reason, /receipt witness/)
})

test('an OAI v0.1 chain still verifies, unchanged', async () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  const c = await chain({ witness: 'OAI-2026-0010002', privateKey })
  assert.equal(c.ait.ait_version, '0.1')
  assert.equal(c.chain[0].ab_version, '0.1')
  assert.equal(c.receipt.attestation_strength, undefined)
  const r = verifyReceipt(c)
  assert.equal(r.ok, true, r.reason)
  assert.equal(r.attestation_strength, 'self-asserted')
})

// The v0.2 examples are schema fixtures: their AIT and receipt signatures and
// the block's self_hash do not verify (edited after signing), so they cannot
// be a verifyReceipt fixture. Check only that their did:key binds their key.
test('the profiles/atap-v0.2-examples did:key encodes its key entry', () => {
  const ex = name => JSON.parse(readFileSync(new URL(`../../../profiles/atap-v0.2-examples/${name}.json`, import.meta.url)))
  const key = ex('public_keys').keys[0]
  for (const id of [ex('ait').witness, ex('ait').operator, ex('receipt').witness, key.witness]) assert.ok(isDidKey(id), id)
  assert.equal('0x' + toHex(publicKeyFromDidKey(key.witness)), key.public_key)
})
