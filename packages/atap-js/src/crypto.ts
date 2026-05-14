// SHA-256 and Ed25519 helpers (Node 20+ crypto module).

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  KeyObject,
} from 'node:crypto'
import type { Ed25519Sig, HexHash } from './types.js'

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map(x => x.toString(16).padStart(2, '0'))
    .join('')
}

function fromHex(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex
  if (s.length % 2 !== 0) throw new Error('fromHex: odd-length hex')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.substr(i * 2, 2), 16)
    if (Number.isNaN(byte)) throw new Error('fromHex: bad hex character')
    out[i] = byte
  }
  return out
}

export function sha256(data: Uint8Array): HexHash {
  const h = createHash('sha256').update(data).digest()
  return ('0x' + toHex(new Uint8Array(h))) as HexHash
}

// Ed25519 PKCS#8 DER prefix for a raw 32-byte private key: 302e020100300506032b657004220420
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
])

// Ed25519 SubjectPublicKeyInfo DER prefix for a raw 32-byte public key: 302a300506032b6570032100
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
  0x70, 0x03, 0x21, 0x00,
])

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function privateKeyFromRaw(raw32: Uint8Array): KeyObject {
  if (raw32.length !== 32) throw new Error('Ed25519 private key must be 32 bytes')
  const der = concat(ED25519_PKCS8_PREFIX, raw32)
  return createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' })
}

export function publicKeyFromRaw(raw32: Uint8Array): KeyObject {
  if (raw32.length !== 32) throw new Error('Ed25519 public key must be 32 bytes')
  const der = concat(ED25519_SPKI_PREFIX, raw32)
  return createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' })
}

export function publicKeyFromHex(hex: string): KeyObject {
  return publicKeyFromRaw(fromHex(hex))
}

export function ed25519Sign(message: Uint8Array, privateKey: KeyObject): Ed25519Sig {
  const sig = nodeSign(null, Buffer.from(message), privateKey)
  return ('ed25519:0x' + toHex(new Uint8Array(sig))) as Ed25519Sig
}

export function ed25519Verify(
  message: Uint8Array,
  signature: Ed25519Sig,
  publicKey: KeyObject,
): boolean {
  const sigHex = signature.replace(/^ed25519:0x/, '')
  return nodeVerify(null, Buffer.from(message), publicKey, fromHex(sigHex))
}

export { toHex, fromHex }
