// Ed25519 sign/verify: round trip with a fresh key, plus the RFC 8032 §7.1
// TEST 1 known answer so the raw-key DER wrapping is checked against the spec.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import {
  ed25519Sign,
  ed25519Verify,
  privateKeyFromRaw,
  publicKeyFromRaw,
  publicKeyFromHex,
  fromHex,
} from '../dist/index.js'

const enc = s => new TextEncoder().encode(s)

test('sign/verify round trip with raw 32-byte keys', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  // The last 32 bytes of the PKCS#8 / SPKI DER are the raw key.
  const rawPriv = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32)
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
  const priv = privateKeyFromRaw(new Uint8Array(rawPriv))
  const pub = publicKeyFromRaw(new Uint8Array(rawPub))

  const msg = enc('atap round trip')
  const sig = ed25519Sign(msg, priv)
  assert.match(sig, /^ed25519:0x[0-9a-f]{128}$/)
  assert.equal(ed25519Verify(msg, sig, pub), true)
  assert.equal(ed25519Verify(enc('atap round trip!'), sig, pub), false)
})

test('raw key helpers reject wrong lengths', () => {
  assert.throws(() => privateKeyFromRaw(new Uint8Array(31)), /32 bytes/)
  assert.throws(() => publicKeyFromRaw(new Uint8Array(33)), /32 bytes/)
})

test('RFC 8032 §7.1 TEST 1 known answer', () => {
  const priv = privateKeyFromRaw(
    fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
  )
  const pub = publicKeyFromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
  const expected =
    'ed25519:0x' +
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
  const msg = new Uint8Array(0)
  assert.equal(ed25519Sign(msg, priv), expected)
  assert.equal(ed25519Verify(msg, expected, pub), true)
})
