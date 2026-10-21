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
  WitnessEvent,
  ATAP_CONTEXT,
} from './types.js'
import { canonicalizeBytes } from './canonicalize.js'
import { ed25519Verify, fromHex, publicKeyFromHex, sha256, toHex } from './crypto.js'
import { isDidKey, publicKeyFromDidKey } from './didkey.js'

export interface VerifyOptions {
  receipt: Receipt
  ait: AIT
  chain: AttestationBlock[]
  keys: KeysDocument
  /**
   * Skip the receipt signature check (verify.sh step 6) and run everything
   * else. For `atap-witness verify --store`, which has a chain but no signed
   * receipt (since 2026-10-20, replacing its own key lookup). Never for a
   * receipt someone handed you.
   */
  skipReceiptSignature?: boolean
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

// An RFC 3339 time as epoch ms, NaN if it does not parse. Key validity is
// compared as instants, not strings, so "+00:00" vs "Z" or fractional
// seconds cannot flip the verdict (as verify.sh's oai_keys_at). The shape is
// checked first, case-sensitively as verify.sh's jq does: bare Date.parse
// would also take a date-only or zoneless value, the latter in host local time.
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/
const instant = (s: unknown): number => (typeof s === 'string' && RFC3339.test(s) ? Date.parse(s) : NaN)

// ATAP §8.2 key lookup for an OAI witness: the one entry with valid_from <= at
// < valid_until that is not compromised before `at`. Returns the entry, null
// for none, or the reason it is refused: a time that does not parse, or more
// than one entry in force (taking the first would let file order pick the key).
function pickKey(doc: KeysDocument, witness: string, at: string): PublicKey | string | null {
  const t = instant(at)
  if (Number.isNaN(t)) return `${at} is not an RFC 3339 time`
  const hits: PublicKey[] = []
  for (const k of doc.keys) {
    if (k.witness !== witness) continue
    const from = instant(k.valid_from)
    const until = instant(k.valid_until)
    if (Number.isNaN(from) || Number.isNaN(until)) return `key ${k.key_id} validity is not an RFC 3339 time`
    if (from > t || until <= t) continue
    if (k.status === 'compromised') {
      if (!k.compromise_notice) continue
      const disclosed = instant(k.compromise_notice.disclosed_at)
      if (Number.isNaN(disclosed)) return `key ${k.key_id} disclosed_at is not an RFC 3339 time`
      if (t >= disclosed) continue
    }
    hits.push(k)
  }
  if (hits.length > 1) return `ambiguous: ${hits.length} keys for ${witness} valid at ${at} (ATAP §8.2)`
  return hits[0] ?? null
}

// ATAP-v0.2 §3.1/§3.2: a key entry for a did:key witness must carry the key
// the did:key encodes and declare 'self-asserted'. Returns why not, or null.
function didKeyEntryProblem(k: PublicKey, didRaw: Uint8Array): string | null {
  if (toHex(fromHex(k.public_key)) !== toHex(didRaw)) {
    return `key ${k.key_id} public_key is not the key ${k.witness} encodes (ATAP-v0.2 §3.1)`
  }
  if (k.attestation_strength !== 'self-asserted') {
    return `key ${k.key_id} for did:key witness must declare attestation_strength 'self-asserted', got '${k.attestation_strength ?? 'absent'}' (ATAP-v0.2 §3.2)`
  }
  return null
}

// Key lookup for a did:key witness (ATAP-v0.2 §3.1). The key is the one the
// did:key encodes, so it has no validity window: valid_from/valid_until are
// ignored. An entry is still required, every entry for the witness must pass
// didKeyEntryProblem (they all describe the one key), and a compromise notice
// on any of them in force at `at` voids the key. Returns the entry, null for
// no usable entry, or the reason an entry is refused.
export function pickDidKeyKey(doc: KeysDocument, witness: string, didRaw: Uint8Array, at: string): PublicKey | string | null {
  const entries = doc.keys.filter(k => k.witness === witness)
  for (const k of entries) {
    const problem = didKeyEntryProblem(k, didRaw)
    if (problem) return problem
    if (k.status === 'compromised' && (!k.compromise_notice || at >= k.compromise_notice.disclosed_at)) return null
  }
  return entries[0] ?? null
}

// Reasons echo ids and paths from the receipt, which is attacker-controlled:
// control characters (C0 incl. ESC, DEL, C1) are stripped so a reason printed
// to a terminal cannot drive it or forge extra lines (as verify.sh's clean).
// Exported for atap-cli, which had its own copy until 2026-10-20.
export function clean(reason: string): string
export function clean(reason: string | null): string | null
export function clean(reason: string | null): string | null {
  return reason === null ? null : reason.replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
}

export function verifyReceipt(opts: VerifyOptions): VerifyResult {
  const r = verifyReceiptRaw(opts)
  return r.reason === undefined ? r : { ...r, reason: clean(r.reason) }
}

function verifyReceiptRaw(opts: VerifyOptions): VerifyResult {
  const { receipt, ait, chain, keys, skipReceiptSignature } = opts

  if (ait['@context'] !== ATAP_CONTEXT) {
    return { ok: false, blocks: 0, reason: `bad @context on AIT` }
  }
  // ATAP-v0.2 §3. `didRaw` is the witness's own public key when the witness is
  // a did:key; null for an OAI witness, which verifies exactly as in v0.1 (§3.4).
  let didRaw: Uint8Array | null = null
  let didIdentified = false
  for (const [field, id] of [['witness', ait.witness], ['operator', ait.operator]] as const) {
    // Malformed input is a verdict, not a TypeError.
    if (typeof id !== 'string') return { ok: false, blocks: 0, reason: `AIT ${field} is not a string` }
    if (!id.startsWith('did:')) continue
    didIdentified = true
    if (!isDidKey(id)) {
      return { ok: false, blocks: 0, reason: `AIT ${field} ${id} is not an Ed25519 did:key (ATAP-v0.2 §3)` }
    }
    // §3.3: a did:key-identified AIT must declare 0.2.
    if (ait.ait_version !== '0.2') {
      return { ok: false, blocks: 0, reason: `AIT with did:key ${field} declares ait_version '${ait.ait_version}', want '0.2' (ATAP-v0.2 §3.3)` }
    }
    if (field === 'witness') didRaw = publicKeyFromDidKey(id) // §3.5: only the witness binds a key
  }

  // ATAP-v0.2 §3.1: for a did:key witness the receipt and AIT name the same
  // witness. OAI-witnessed records are not held to it, as in v0.1 (§3.4).
  // Prefix match, as verify.sh: a malformed did:key is still held to it.
  // After the loop above, so ait.witness is known to be a string.
  if (typeof receipt.witness !== 'string') return { ok: false, blocks: 0, reason: 'receipt witness is not a string' }
  if ((receipt.witness.startsWith('did:key:') || ait.witness.startsWith('did:key:')) && receipt.witness !== ait.witness) {
    return { ok: false, blocks: 0, reason: `receipt witness ${receipt.witness} != AIT witness ${ait.witness}` }
  }

  // The receipt and every block (below) belong to this AIT: a record validly
  // signed by the witness for another AIT or profile attests nothing here (as
  // verify.sh). Strings only, so a missing field can't match a missing one.
  if (typeof ait.id !== 'string' || typeof ait.profile !== 'string') {
    return { ok: false, blocks: 0, reason: 'AIT id or profile is not a string' }
  }
  if (receipt.ait !== ait.id) {
    return { ok: false, blocks: 0, reason: `receipt ait ${receipt.ait} != AIT id ${ait.id}` }
  }

  // 1. AIT signature
  const aitKey = didRaw ? pickDidKeyKey(keys, ait.witness, didRaw, ait.issued_at) : pickKey(keys, ait.witness, ait.issued_at)
  if (!aitKey) {
    return {
      ok: false,
      blocks: 0,
      reason: `no key for AIT witness ${ait.witness} at ${ait.issued_at}`,
    }
  }
  if (typeof aitKey === 'string') return { ok: false, blocks: 0, reason: aitKey }
  const { witness_signature: aitSig, ...aitMinusSig } = ait
  const aitOk = ed25519Verify(
    canonicalizeBytes(aitMinusSig),
    aitSig,
    publicKeyFromHex(aitKey.public_key),
  )
  if (!aitOk) return { ok: false, blocks: 0, reason: 'AIT signature invalid' }

  // 2. Block chain. An empty chain would leave prev at genesis and pass against
  // a receipt whose chain_head_hash is genesis; a receipt with no blocks attests
  // nothing (as verify.sh).
  if (!Array.isArray(chain) || chain.length === 0) {
    return { ok: false, blocks: 0, reason: 'attestation chain is not a non-empty array' }
  }
  let prev: HexHash = GENESIS_HASH
  for (const block of chain) {
    // ATAP-v0.2 §3.3: every block under a did:key-identified AIT declares 0.2.
    if (didIdentified && block.ab_version !== '0.2') {
      return { ok: false, blocks: 0, reason: `block ${block.id} declares ab_version '${block.ab_version}' under a v0.2 AIT (ATAP-v0.2 §3.3)` }
    }
    if (block.prev_block_hash !== prev) {
      return {
        ok: false,
        blocks: 0,
        reason: `block chain break at ${block.id} (want prev=${prev}, got ${block.prev_block_hash})`,
      }
    }
    if (block.ait !== ait.id) {
      return { ok: false, blocks: 0, reason: `block ${block.id} ait ${block.ait} != AIT id ${ait.id}` }
    }
    if (block.profile !== ait.profile) {
      return { ok: false, blocks: 0, reason: `block ${block.id} profile ${block.profile} != AIT profile ${ait.profile}` }
    }
    const { self_hash, witness_signature, ...rest } = block
    const expectedHash = sha256(canonicalizeBytes(rest))
    if (expectedHash !== self_hash) {
      return { ok: false, blocks: 0, reason: `self_hash mismatch on ${block.id}` }
    }
    const blockKey = didRaw
      ? pickDidKeyKey(keys, receipt.witness, didRaw, block.period_end)
      : pickKey(keys, receipt.witness, block.period_end)
    if (!blockKey) {
      return {
        ok: false,
        blocks: 0,
        reason: `no key for ${receipt.witness} at ${block.period_end}`,
      }
    }
    if (typeof blockKey === 'string') return { ok: false, blocks: 0, reason: blockKey }
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

  // Receipt signature, over the canonical receipt minus its signature, as
  // verify.sh step 6. A did:key witness's key has no validity window (ATAP-v0.2
  // §3.1), so generated_at serves. An OAI key's valid_until is often the AIT's
  // expires_at, and a receipt of an expired AIT is generated after it, so the
  // key is the one in force at the last block's period_end (step 2 refused an
  // empty chain).
  if (!skipReceiptSignature) {
    const at = didRaw ? receipt.generated_at : chain[chain.length - 1]!.period_end
    const rcptKey = didRaw ? pickDidKeyKey(keys, receipt.witness, didRaw, at) : pickKey(keys, receipt.witness, at)
    if (!rcptKey) {
      return { ok: false, blocks: chain.length, reason: `no key for ${receipt.witness} at ${at}` }
    }
    if (typeof rcptKey === 'string') return { ok: false, blocks: chain.length, reason: rcptKey }
    const { witness_signature: rcptSig, ...rcptMinusSig } = receipt
    if (!ed25519Verify(canonicalizeBytes(rcptMinusSig), rcptSig, publicKeyFromHex(rcptKey.public_key))) {
      return { ok: false, blocks: chain.length, reason: 'receipt signature invalid' }
    }
  }

  // The signed receipt's period and counts must describe this chain (ATAP §7.5,
  // as verify.sh step 4), or a validly re-signed receipt could claim a period
  // or size the blocks do not have. After the signature check, which verify
  // --store relies on reaching with its unsigned stand-in receipt.
  {
    const last = chain[chain.length - 1]!
    const want: [keyof Receipt, unknown][] = [
      ['period_start', chain[0]!.period_start],
      ['period_end', last.period_end],
      ['block_count', chain.length],
      ['event_count', chain.reduce((n, b) => n + b.event_count, 0)],
      ['first_block', chain[0]!.id],
      ['last_block', last.id],
    ]
    for (const [field, w] of want) {
      if (receipt[field] !== w) {
        return { ok: false, blocks: chain.length, reason: `receipt ${field} mismatch (want ${JSON.stringify(w)}, got ${JSON.stringify(receipt[field])})` }
      }
    }
  }

  // ATAP-v0.2 §3.2: a did:key receipt says exactly 'self-asserted'; absent is not enough.
  if (didRaw && receipt.attestation_strength !== 'self-asserted') {
    return {
      ok: false,
      blocks: chain.length,
      reason: `did:key witness receipt must carry attestation_strength 'self-asserted', got '${receipt.attestation_strength ?? 'absent'}' (ATAP-v0.2 §3.2)`,
    }
  }

  // 3. Attestation strength (ATAP §7.4.1 — optional in v0.1.x, required at v0.2)
  const warnings: string[] = []
  let effectiveStrength: AttestationStrength = 'self-asserted'
  if (receipt.attestation_strength) {
    // Object.hasOwn, not `in`: a prototype name ("constructor", "__proto__") is not a strength.
    if (!Object.hasOwn(ATTESTATION_STRENGTH_RANK, receipt.attestation_strength)) {
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
  // Cross-check against the key the receipt's witness held at the AIT's issue
  // time, as verify.sh step 5 (oai_keys_at "$WITNESS" "$AIT_TS"). For a did:key
  // witness that is step 1's AIT key (receipt and AIT name the same witness).
  // An OAI receipt may name another witness than its AIT (ATAP-v0.2 §3.4), and
  // the ceiling binds to the key that signed the receipt's claim, not the
  // AIT's: until 2026-10-21 this read the AIT witness's key, so a receipt
  // signed by a self-asserted witness over a silicon-root AIT passed here and
  // failed verify.sh.
  const aitPeriodKey = didRaw || receipt.witness === ait.witness ? aitKey : pickKey(keys, receipt.witness, ait.issued_at)
  if (typeof aitPeriodKey === 'string') return { ok: false, blocks: chain.length, reason: aitPeriodKey }
  // No entry at all is a failure, not the "omits the field" warning below: a
  // witness with no key at the AIT's issue time attests nothing about it.
  if (!aitPeriodKey) return { ok: false, blocks: chain.length, reason: `no key for receipt witness ${receipt.witness} at ${ait.issued_at}` }
  if (aitPeriodKey.attestation_strength) {
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

// tunnelmind:code_crew:v1 profile.md §9: every event the receipt's blocks cover.
export const WITNESS_EVENTS = 'profile_artifacts/witness_events.json'

// Exported for atap-cli, which had its own copy until 2026-10-20.
export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

// The block chain binds to the event chain only through chain_head_hash
// (ATAP §7.3, §10): each block's chain_head_hash is the self_hash of the last
// event it covers. Recompute every self_hash (§7.7), walk prev_event_hash from
// genesis, then slice the events by event_count and match each block's head.
// For an OAI witness no signature check is needed: the signed blocks' heads pin
// every earlier event through the prev_event_hash chain. For a did:key witness
// every witness_signature must verify under the key it encodes (ATAP-v0.2
// §3.1), as verify.sh checks too, over the raw 32-byte self_hash (§7.7).
export function checkWitnessEvents(events: WitnessEvent[], chain: AttestationBlock[], ait: AIT, keys: KeysDocument): string | null {
  return clean(witnessEventsProblem(events, chain, ait, keys))
}

function witnessEventsProblem(events: WitnessEvent[], chain: AttestationBlock[], ait: AIT, keys: KeysDocument): string | null {
  if (!Array.isArray(events)) return `${WITNESS_EVENTS} is not an array`
  let prev: string = GENESIS_HASH
  for (const [i, e] of events.entries()) {
    if (!isObject(e)) return `event ${i} is not an object`
    const { self_hash, witness_signature: _, ...unsigned } = e
    if (e.ait !== ait.id) return `event ${i} (${e.id}) is not under ${ait.id}`
    if (sha256(canonicalizeBytes(unsigned)) !== self_hash) return `event ${i} (${e.id}) self_hash mismatch`
    if (e.prev_event_hash !== prev) return `event ${i} (${e.id}) prev_event_hash breaks the chain`
    if (isDidKey(ait.witness)) {
      const key = pickDidKeyKey(keys, ait.witness, publicKeyFromDidKey(ait.witness), e.witnessed_at)
      if (!key) return `no key for ${ait.witness} at ${e.witnessed_at}`
      if (typeof key === 'string') return key
      // Malformed input is a verdict, not a TypeError.
      if (typeof e.witness_signature !== 'string' || !ed25519Verify(fromHex(self_hash), e.witness_signature, publicKeyFromHex(key.public_key))) {
        return `event ${i} (${e.id}) signature invalid`
      }
    }
    prev = self_hash
  }
  let at = 0
  for (const b of chain) {
    if (!Number.isInteger(b.event_count) || b.event_count < 1) return `block ${b.id} event_count is not a positive integer`
    const first = events[at]
    const last = events[at + b.event_count - 1]
    if (!first || !last) return `block ${b.id} covers events ${at}..${at + b.event_count - 1}; only ${events.length} present`
    if (first.id !== b.first_event) return `event ${at} (${first.id}) is not block ${b.id}'s first_event`
    if (last.id !== b.last_event) return `event ${at + b.event_count - 1} (${last.id}) is not block ${b.id}'s last_event`
    if (last.self_hash !== b.chain_head_hash) return `event ${at + b.event_count - 1} (${last.id}) does not match block ${b.id}'s chain_head_hash`
    at += b.event_count
  }
  if (at !== events.length) return `${events.length} events but the blocks cover ${at}`
  return null
}

// A manifest path resolved against a virtual receipt root: the normalised
// path, or null if `rel` is absolute or lands outside the root (or on it).
// Pure string work, no node:path, so the browser viewer can bundle it.
// Backslashes and drive letters are refused outright: on a Windows host the
// CLI's join() would treat them as separators or roots.
export function normaliseReceiptPath(rel: string): string | null {
  if (rel.startsWith('/') || rel.includes('\\') || /^[A-Za-z]:/.test(rel)) return null
  const out: string[] = []
  for (const s of rel.split('/')) {
    if (s === '' || s === '.') continue
    if (s !== '..') out.push(s)
    else if (!out.pop()) return null
  }
  return out.length ? out.join('/') : null
}

// A manifest path that has a .. segment anywhere is refused even if it
// normalises back inside the receipt, as verify.sh refuses it.
const hasDotDot = (rel: string): boolean => rel.split('/').includes('..')

// ATAP §7.5: files every receipt carries. All but manifest.json (which cannot
// hash itself) are listed with a sha256, so none can be swapped unnoticed.
const MANDATORY_RECEIPT_FILES = ['manifest.json', 'ait.json', 'attestation_chain.json', 'public_keys.json', 'verify.sh']

// manifest.files[] integrity, as verify.sh checks it first. `read` returns a
// file's bytes or undefined if it is missing; it is synchronous so the viewer
// can run this inside its record/replay crypto shim. The manifest is untrusted
// input: a path like ../x is refused before it is read, so a receipt cannot
// make us hash files outside its own directory. `present`, when given, is every
// file in the receipt (relative paths, scitt/ left out): each must be listed,
// or a file could ride along in the receipt with no hash covering it.
export function checkManifestFiles(receipt: Receipt, read: (rel: string) => Uint8Array | undefined, present?: Iterable<string>): string | null {
  return clean(manifestFilesProblem(receipt, read, present))
}

function manifestFilesProblem(receipt: Receipt, read: (rel: string) => Uint8Array | undefined, present?: Iterable<string>): string | null {
  const listed = new Map<string, string | null>()
  for (const f of receipt.files ?? []) {
    const rel = normaliseReceiptPath(f.path)
    if (rel === null || hasDotDot(f.path)) return `${f.path} escapes the receipt directory`
    listed.set(rel, f.sha256)
    if (f.sha256 === null) continue
    const bytes = read(rel)
    if (!bytes) return `${f.path} missing`
    if (sha256(bytes) !== f.sha256) return `${f.path} sha256 mismatch`
  }
  for (const m of MANDATORY_RECEIPT_FILES) {
    if (!listed.has(m)) return `${m} is not listed in manifest.files[] (ATAP §7.5)`
    if (m !== 'manifest.json' && typeof listed.get(m) !== 'string') return `${m} is listed with no sha256 (ATAP §7.5)`
  }
  for (const p of present ?? []) {
    if (!listed.has(p)) return `${p} is in the receipt but not listed in manifest.files[]`
  }
  return null
}
