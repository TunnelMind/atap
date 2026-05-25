// In-process verifier. Parallel to /atap/verify.sh — same logic, JS-native.

import {
  AIT,
  AttestationBlock,
  AttestationStrength,
  ATTESTATION_STRENGTH_RANK,
  GENESIS_HASH,
  HexHash,
  KeysDocument,
  PublicKey,
  Receipt,
  ATAP_CONTEXT,
} from './types.js'
import { canonicalizeBytes } from './canonicalize.js'
import { ed25519Verify, fromHex, publicKeyFromHex, sha256 } from './crypto.js'

export interface VerifyOptions {
  receipt: Receipt
  ait: AIT
  chain: AttestationBlock[]
  keys: KeysDocument
}

export interface VerifyResult {
  ok: boolean
  blocks: number
  /** Effective attestation strength of this receipt (defaults to 'self-asserted' if the receipt omits the field). */
  attestation_strength?: AttestationStrength
  /** Non-fatal advisories. v0.1.x omissions become entries here. */
  warnings?: string[]
  reason?: string
}

function pickKey(doc: KeysDocument, witness: string, at: string): PublicKey | null {
  for (const k of doc.keys) {
    if (k.witness !== witness) continue
    if (k.valid_from > at || k.valid_until <= at) continue
    if (k.status === 'compromised') {
      if (!k.compromise_notice || at >= k.compromise_notice.disclosed_at) continue
    }
    return k
  }
  return null
}

export function verifyReceipt(opts: VerifyOptions): VerifyResult {
  const { receipt, ait, chain, keys } = opts

  if (ait['@context'] !== ATAP_CONTEXT) {
    return { ok: false, blocks: 0, reason: `bad @context on AIT` }
  }

  // 1. AIT signature
  const aitKey = pickKey(keys, ait.witness, ait.issued_at)
  if (!aitKey) {
    return {
      ok: false,
      blocks: 0,
      reason: `no key for AIT witness ${ait.witness} at ${ait.issued_at}`,
    }
  }
  const { witness_signature: aitSig, ...aitMinusSig } = ait
  const aitOk = ed25519Verify(
    canonicalizeBytes(aitMinusSig),
    aitSig,
    publicKeyFromHex(aitKey.public_key),
  )
  if (!aitOk) return { ok: false, blocks: 0, reason: 'AIT signature invalid' }

  // 2. Block chain
  let prev: HexHash = GENESIS_HASH
  for (const block of chain) {
    if (block.prev_block_hash !== prev) {
      return {
        ok: false,
        blocks: 0,
        reason: `block chain break at ${block.id} (want prev=${prev}, got ${block.prev_block_hash})`,
      }
    }
    const { self_hash, witness_signature, ...rest } = block
    const expectedHash = sha256(canonicalizeBytes(rest))
    if (expectedHash !== self_hash) {
      return { ok: false, blocks: 0, reason: `self_hash mismatch on ${block.id}` }
    }
    const blockKey = pickKey(keys, receipt.witness, block.period_end)
    if (!blockKey) {
      return {
        ok: false,
        blocks: 0,
        reason: `no key for ${receipt.witness} at ${block.period_end}`,
      }
    }
    const blockOk = ed25519Verify(
      fromHex(self_hash), // ATAP §7.7: signature is over the raw 32-byte digest
      witness_signature,
      publicKeyFromHex(blockKey.public_key),
    )
    if (!blockOk) {
      return { ok: false, blocks: 0, reason: `block signature invalid on ${block.id}` }
    }
    prev = self_hash
  }

  if (receipt.chain_head_hash !== prev) {
    return {
      ok: false,
      blocks: chain.length,
      reason: `receipt chain_head_hash ${receipt.chain_head_hash} != last block self_hash ${prev}`,
    }
  }

  // 3. Attestation strength (ATAP §7.4.1 — optional in v0.1.x, required at v0.2)
  const warnings: string[] = []
  let effectiveStrength: AttestationStrength = 'self-asserted'
  if (receipt.attestation_strength) {
    if (!(receipt.attestation_strength in ATTESTATION_STRENGTH_RANK)) {
      return {
        ok: false,
        blocks: chain.length,
        reason: `unrecognized attestation_strength '${receipt.attestation_strength}'`,
      }
    }
    effectiveStrength = receipt.attestation_strength
  } else {
    warnings.push(
      "manifest.attestation_strength missing — treated as 'self-asserted' (ATAP §7.4.1). Required at v0.2.",
    )
  }
  // Cross-check against the AIT-period key, if that key declares a strength.
  const aitPeriodKey = pickKey(keys, ait.witness, ait.issued_at)
  if (aitPeriodKey?.attestation_strength) {
    const keyRank = ATTESTATION_STRENGTH_RANK[aitPeriodKey.attestation_strength]
    const rcptRank = ATTESTATION_STRENGTH_RANK[effectiveStrength]
    if (rcptRank > keyRank) {
      return {
        ok: false,
        blocks: chain.length,
        reason: `attestation_strength=${effectiveStrength} exceeds key attestation_strength=${aitPeriodKey.attestation_strength}`,
      }
    }
  } else if (receipt.attestation_strength) {
    warnings.push(
      "matching key entry omits attestation_strength — receipt's claim is not key-attested (ATAP §8.1). Required at v0.2.",
    )
  }

  return {
    ok: true,
    blocks: chain.length,
    attestation_strength: effectiveStrength,
    ...(warnings.length ? { warnings } : {}),
  }
}
