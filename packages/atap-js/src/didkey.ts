// did:key for Ed25519 public keys (ATAP-v0.2 §3; W3C did:key method).
// did:key:z<base58btc(0xed 0x01 || raw32)> — 'z' is the multibase prefix for
// base58btc and 0xed01 is the varint of multicodec ed25519-pub.

import type { DidKey } from './types.js'

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const PREFIX = 'did:key:z'
// Mirrors the did:key pattern in profiles/atap-v0.2-schemas/ait.schema.json;
// keep the two in step. 34 bytes with the 0xed01 prefix always encode to
// 'z6Mk' + 44 base58 characters.
const DID_KEY_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/

function base58Encode(bytes: Uint8Array): string {
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  let out = ''
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out
    n /= 58n
  }
  // Each leading zero byte is a leading '1'.
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out
  return out
}

function base58Decode(s: string): Uint8Array {
  let n = 0n
  for (const c of s) {
    const v = B58.indexOf(c)
    if (v < 0) throw new Error(`did:key: bad base58 character '${c}'`)
    n = n * 58n + BigInt(v)
  }
  const body: number[] = []
  while (n > 0n) {
    body.unshift(Number(n & 0xffn))
    n >>= 8n
  }
  let zeros = 0
  while (zeros < s.length && s[zeros] === '1') zeros++
  return new Uint8Array([...new Array(zeros).fill(0), ...body])
}

export function isDidKey(s: unknown): s is DidKey {
  return typeof s === 'string' && DID_KEY_RE.test(s)
}

export function didKeyFromPublicKey(raw32: Uint8Array): DidKey {
  if (raw32.length !== 32) throw new Error('did:key: Ed25519 public key must be 32 bytes')
  const bytes = new Uint8Array(34)
  bytes[0] = 0xed
  bytes[1] = 0x01
  bytes.set(raw32, 2)
  return `${PREFIX}${base58Encode(bytes)}` as DidKey
}

export function publicKeyFromDidKey(did: string): Uint8Array {
  if (typeof did !== 'string' || !did.startsWith(PREFIX)) {
    throw new Error(`did:key: must start with '${PREFIX}'`)
  }
  const bytes = base58Decode(did.slice(PREFIX.length))
  // Only Ed25519 (ATAP-v0.2 §3): secp256k1 (0xe701), x25519 (0xec01) etc. are refused.
  if (bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error('did:key: multicodec is not ed25519-pub (0xed01)')
  }
  if (bytes.length !== 34) {
    throw new Error(`did:key: decodes to ${bytes.length} bytes, want 34`)
  }
  return bytes.slice(2)
}
