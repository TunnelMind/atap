// SCITT export: one ATAP artifact (AIT, Attestation Block or Receipt manifest) as a
// COSE_Sign1 signed statement (RFC 9943 §6) over the hash of its canonical JSON
// (COSE Hash Envelope, RFC 9995). The ATAP record itself is unchanged; this is an
// additional view of it that IETF transparency services can register.
//
// Statement = 18([protected bstr, {} , payload bstr, signature bstr])
//   protected = {1: -8, 4: kid, 15: {1: iss, 2: sub}, 258: -16, 259: preimage type}
//   payload   = sha256(canonicalizeBytes(artifact)), 32 raw bytes
//
// Label 3 (content type) is deliberately absent: RFC 9995 §4 says it MUST NOT be
// present in a hash envelope, because it would describe the digest, not the
// artifact. The ATAP artifact type travels in 259 instead.

import { createHash, sign as nodeSign, verify as nodeVerify, KeyObject } from 'node:crypto'
import { canonicalizeBytes } from './canonicalize.js'

// --- Minimal deterministic CBOR (RFC 8949) -----------------------------------
// ponytail: only what COSE_Sign1 needs (ints, bstr, tstr, array, map, tag), no
// floats/indefinite lengths/bigints. Swap for a library if statements grow richer.

export type Cbor = number | string | Uint8Array | Cbor[] | Map<number | string, Cbor> | CborTag
export class CborTag {
  constructor(public tag: number, public value: Cbor) {}
}

function head(major: number, n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`CBOR: bad argument ${n}`)
  const m = major << 5
  if (n < 24) return Uint8Array.of(m | n)
  if (n < 0x100) return Uint8Array.of(m | 24, n)
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 0xff)
  if (n < 0x100000000) return Uint8Array.of(m | 26, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
  const b = new Uint8Array(9)
  b[0] = m | 27
  new DataView(b.buffer).setBigUint64(1, BigInt(n))
  return b
}

function cat(parts: Uint8Array[]): Uint8Array {
  return Uint8Array.from(Buffer.concat(parts))
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  return Buffer.compare(a, b)
}

export function cborEncode(v: Cbor): Uint8Array {
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error(`CBOR: only integers are supported, got ${v}`)
    return v >= 0 ? head(0, v) : head(1, -1 - v)
  }
  if (typeof v === 'string') {
    const b = new TextEncoder().encode(v)
    return cat([head(3, b.length), b])
  }
  if (v instanceof Uint8Array) return cat([head(2, v.length), v])
  if (Array.isArray(v)) return cat([head(4, v.length), ...v.map(cborEncode)])
  if (v instanceof Map) {
    // RFC 8949 §4.2.1: core deterministic encoding sorts map keys by the
    // bytewise lexicographic order of their deterministic encodings.
    const entries = [...v].map(([k, val]) => [cborEncode(k), cborEncode(val)] as const)
    entries.sort((x, y) => compareBytes(x[0], y[0]))
    return cat([head(5, entries.length), ...entries.flat()])
  }
  if (v instanceof CborTag) return cat([head(6, v.tag), cborEncode(v.value)])
  throw new Error('CBOR: unsupported value')
}

export function cborDecode(bytes: Uint8Array): Cbor {
  let pos = 0
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const need = (n: number) => {
    if (pos + n > bytes.length) throw new Error('CBOR: truncated input')
  }
  const arg = (info: number): number => {
    if (info < 24) return info
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0
    if (!size) throw new Error(`CBOR: unsupported additional info ${info}`)
    need(size)
    const n =
      size === 1 ? view.getUint8(pos)
      : size === 2 ? view.getUint16(pos)
      : size === 4 ? view.getUint32(pos)
      : Number(view.getBigUint64(pos))
    if (!Number.isSafeInteger(n)) throw new Error('CBOR: integer out of range')
    pos += size
    return n
  }
  const item = (): Cbor => {
    need(1)
    const ib = bytes[pos++]!
    const major = ib >> 5
    const n = arg(ib & 0x1f)
    switch (major) {
      case 0: return n
      case 1: return -1 - n
      case 2: need(n); return bytes.slice(pos, (pos += n))
      case 3: need(n); return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(pos, (pos += n)))
      case 4: return Array.from({ length: n }, item)
      case 5: {
        const m = new Map<number | string, Cbor>()
        for (let i = 0; i < n; i++) {
          const k = item()
          if (typeof k !== 'number' && typeof k !== 'string') throw new Error('CBOR: unsupported map key')
          if (m.has(k)) throw new Error('CBOR: duplicate map key')
          m.set(k, item())
        }
        return m
      }
      case 6: return new CborTag(n, item())
      default: throw new Error(`CBOR: unsupported major type ${major}`)
    }
  }
  const out = item()
  if (pos !== bytes.length) throw new Error('CBOR: trailing bytes')
  return out
}

// --- COSE / CWT / hash-envelope labels ----------------------------------------

const COSE_SIGN1_TAG = 18 // RFC 9052 §4.2 and §2 Table 1: COSE_Sign1 is tag 18
const HDR_ALG = 1 // RFC 9052 §3.1 Table 3: alg
const HDR_KID = 4 // RFC 9052 §3.1 Table 3: kid (bstr)
const HDR_CWT_CLAIMS = 15 // RFC 9597 §2: CWT Claims; RFC 9943 §6: MUST be in the protected header
const CWT_ISS = 1 // RFC 8392 §3.1.1: iss; RFC 9943 §6: required in a signed statement
const CWT_SUB = 2 // RFC 8392 §3.1.2: sub; RFC 9943 §6: required in a signed statement
const HDR_PAYLOAD_HASH_ALG = 258 // RFC 9995 §3: payload_hash_alg; §4: MUST be protected
const HDR_PREIMAGE_CONTENT_TYPE = 259 // RFC 9995 §3: payload_preimage_content_type
const ALG_EDDSA = -8 // RFC 9053 §2.2 Table 2: EdDSA
const ALG_SHA256 = -16 // RFC 9054 §3.2 Table 2: SHA-256

// Preimage content types, one per ATAP artifact. Scheme:
// application/vnd.atap.<artifact>+json; the bytes hashed are the RFC 8785 (JCS)
// canonical JSON that ATAP itself signs.
const PREIMAGE_TYPES: Record<string, string> = {
  AgentIdentityToken: 'application/vnd.atap.ait+json',
  AttestationBlock: 'application/vnd.atap.attestation-block+json',
  Receipt: 'application/vnd.atap.receipt+json',
}

type Artifact = { '@type'?: unknown; id?: unknown; ait?: unknown }

// The AIT id the artifact is about: an AIT's own id, else the block's/receipt's `ait`.
function subjectOf(a: Artifact): string {
  const sub = a['@type'] === 'AgentIdentityToken' ? a.id : a.ait
  if (typeof sub !== 'string' || !sub.startsWith('AIT-')) throw new Error('SCITT: artifact has no AIT id')
  return sub
}

function sigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  // RFC 9052 §4.4: Sig_structure for COSE_Sign1, empty external_aad.
  return cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload])
}

function digest(artifact: unknown): Uint8Array {
  return new Uint8Array(createHash('sha256').update(canonicalizeBytes(artifact)).digest())
}

/**
 * Turn one ATAP artifact into a SCITT signed statement (tagged COSE_Sign1 bytes).
 * `key` is the witness Ed25519 private key, `issuer` the witness OAI, `kid` the
 * key's `key_id` from keys.json.
 */
export function toSignedStatement(
  record: unknown,
  key: KeyObject,
  issuer: string,
  kid: string,
): Uint8Array {
  const a = (record ?? {}) as Artifact
  const preimageType = PREIMAGE_TYPES[String(a['@type'])]
  if (!preimageType) throw new Error(`SCITT: unsupported artifact type ${String(a['@type'])}`)
  // RFC 9943 §6: iss length MUST be 1..8192 characters.
  if (issuer.length < 1 || issuer.length > 8192) throw new Error('SCITT: issuer must be 1..8192 characters')
  if (!kid) throw new Error('SCITT: kid is required')

  const protectedBytes = cborEncode(
    new Map<number, Cbor>([
      [HDR_ALG, ALG_EDDSA],
      [HDR_KID, new TextEncoder().encode(kid)],
      [HDR_CWT_CLAIMS, new Map<number, Cbor>([[CWT_ISS, issuer], [CWT_SUB, subjectOf(a)]])],
      [HDR_PAYLOAD_HASH_ALG, ALG_SHA256],
      [HDR_PREIMAGE_CONTENT_TYPE, preimageType],
    ]),
  )
  const payload = digest(record)
  const signature = new Uint8Array(nodeSign(null, sigStructure(protectedBytes, payload), key))
  // RFC 9943 §6.3: the unprotected header is an empty map.
  return cborEncode(new CborTag(COSE_SIGN1_TAG, [protectedBytes, new Map(), payload, signature]))
}

/**
 * True only if `bytes` is a COSE_Sign1 with alg EdDSA and payload hash SHA-256,
 * its signature verifies under `publicKey`, and its payload equals
 * sha256(canonicalizeBytes(artifact)). Malformed input returns false.
 */
export function verifySignedStatement(
  bytes: Uint8Array,
  publicKey: KeyObject,
  artifact: unknown,
): boolean {
  try {
    const msg = cborDecode(bytes)
    if (!(msg instanceof CborTag) || msg.tag !== COSE_SIGN1_TAG) return false
    const parts = msg.value
    if (!Array.isArray(parts) || parts.length !== 4) return false
    const [protectedBytes, unprotected, payload, signature] = parts
    if (!(protectedBytes instanceof Uint8Array) || !(unprotected instanceof Map)) return false
    if (!(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) return false
    const hdr = cborDecode(protectedBytes)
    if (!(hdr instanceof Map)) return false
    if (hdr.get(HDR_ALG) !== ALG_EDDSA || hdr.get(HDR_PAYLOAD_HASH_ALG) !== ALG_SHA256) return false
    if (Buffer.compare(payload, digest(artifact)) !== 0) return false
    return nodeVerify(null, sigStructure(protectedBytes, payload), publicKey, signature)
  } catch {
    return false
  }
}
