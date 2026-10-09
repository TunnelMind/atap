// SCITT signed statements: round trip for each ATAP artifact kind, tamper and
// wrong-key rejection, determinism, and a known answer that pins the protected
// header byte for byte so a header-label change cannot pass silently.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  toSignedStatement,
  verifySignedStatement,
  canonicalizeBytes,
  privateKeyFromRaw,
  publicKeyFromRaw,
  fromHex,
  toHex,
} from '../dist/index.js'

const ISS = 'OAI-2026-0010002'
const KID = 'witness-key-1'

const ait = {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld',
  '@type': 'AgentIdentityToken',
  id: 'AIT-0190a1b2-c3d4-7e5f-8a6b-1c2d3e4f5a6b',
  operator: 'OAI-2026-0010001',
  witness: ISS,
  capabilities: ['code_crew:code'],
  witness_signature: 'ed25519:0x00',
}
const block = {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld',
  '@type': 'AttestationBlock',
  id: 'ATAP-AB-1',
  ait: ait.id,
  event_count: 3,
  chain_head_hash: '0x' + 'ab'.repeat(32),
  witness_signature: 'ed25519:0x00',
}
const receipt = {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld',
  '@type': 'Receipt',
  id: 'ATAP-RCPT-1',
  ait: ait.id,
  block_count: 1,
  files: [{ path: 'blocks/ATAP-AB-1.json', sha256: null }],
  witness_signature: 'ed25519:0x00',
}

const keys = () => generateKeyPairSync('ed25519')

test('round trip: AIT, Attestation Block and Receipt manifest verify', () => {
  const { privateKey, publicKey } = keys()
  for (const rec of [ait, block, receipt]) {
    const s = toSignedStatement(rec, privateKey, ISS, KID)
    assert.ok(s instanceof Uint8Array)
    assert.equal(verifySignedStatement(s, publicKey, rec), true, rec['@type'])
    // Key order in the artifact does not matter: the hash is over JCS bytes.
    const reordered = Object.fromEntries(Object.entries(rec).reverse())
    assert.equal(verifySignedStatement(s, publicKey, reordered), true)
  }
})

test('altered artifact is rejected', () => {
  const { privateKey, publicKey } = keys()
  const s = toSignedStatement(block, privateKey, ISS, KID)
  assert.equal(verifySignedStatement(s, publicKey, { ...block, event_count: 4 }), false)
  assert.equal(verifySignedStatement(s, publicKey, receipt), false)
})

test('altered statement bytes and wrong key are rejected', () => {
  const { privateKey, publicKey } = keys()
  const s = toSignedStatement(ait, privateKey, ISS, KID)
  for (let i = 0; i < s.length; i++) {
    const t = Uint8Array.from(s)
    t[i] ^= 0x01
    assert.equal(verifySignedStatement(t, publicKey, ait), false, `byte ${i}`)
  }
  assert.equal(verifySignedStatement(s.subarray(0, s.length - 1), publicKey, ait), false)
  assert.equal(verifySignedStatement(new Uint8Array([...s, 0]), publicKey, ait), false)
  assert.equal(verifySignedStatement(s, keys().publicKey, ait), false)
})

test('unsupported artifacts and bad issuer are refused', () => {
  const { privateKey } = keys()
  assert.throws(() => toSignedStatement({ '@type': 'WitnessEvent', ait: ait.id }, privateKey, ISS, KID), /unsupported/)
  assert.throws(() => toSignedStatement({ '@type': 'Receipt' }, privateKey, ISS, KID), /AIT id/)
  assert.throws(() => toSignedStatement(ait, privateKey, '', KID), /issuer/)
})

// Known answer: RFC 8032 §7.1 TEST 1 key, a fixed AIT-shaped record.
const KAT_PRIV = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const KAT_PUB = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
const KAT_RECORD = { '@type': 'AgentIdentityToken', id: 'AIT-1' }
// a5                      map(5)
//   01 27                 1 (alg) : -8 (EdDSA)
//   04 42 6b31            4 (kid) : h'6b31' ("k1")
//   0f a2                 15 (CWT Claims) : map(2)
//     01 70 4f41..32      1 (iss) : "OAI-2026-0010002"
//     02 65 4149542d31    2 (sub) : "AIT-1"
//   19 0102 2f            258 (payload_hash_alg) : -16 (SHA-256)
//   19 0103 78 1d 61..6e  259 (preimage content type) : "application/vnd.atap.ait+json"
const KAT_PROTECTED =
  'a5012704426b310fa201704f41492d323032362d3030313030303202654149542d31' +
  '1901022f190103781d6170706c69636174696f6e2f766e642e617461702e6169742b6a736f6e'
const KAT_SIG =
  '8710ea310dea5fbe5809041a8a33672372c7f52644b7b8e1b857a7175e40bc77' +
  '73953a915e7d78e98e9ec6257c37bcff0120d845445bd62a07dd3b8e9d4b8e03'

test('known answer: exact COSE_Sign1 bytes', () => {
  const s = toSignedStatement(KAT_RECORD, privateKeyFromRaw(fromHex(KAT_PRIV)), ISS, 'k1')
  const digest = createHash('sha256').update(canonicalizeBytes(KAT_RECORD)).digest('hex')
  const expected =
    'd2' + '84' + // tag 18 (COSE_Sign1), array(4)
    '5848' + KAT_PROTECTED + // protected: bstr(72)
    'a0' + // unprotected: {}
    '5820' + digest + // payload: bstr(32) sha256 of the JCS bytes
    '5840' + KAT_SIG // signature: bstr(64)
  assert.equal(toHex(s), expected)
  assert.equal(verifySignedStatement(s, publicKeyFromRaw(fromHex(KAT_PUB)), KAT_RECORD), true)
})

test('deterministic: same input gives identical bytes', () => {
  const { privateKey } = keys()
  for (const rec of [ait, block, receipt]) {
    assert.equal(
      toHex(toSignedStatement(rec, privateKey, ISS, KID)),
      toHex(toSignedStatement(structuredClone(rec), privateKey, ISS, KID)),
    )
  }
})
