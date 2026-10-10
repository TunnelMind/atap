// The page's verifier and its wiring to the DOM.
//
// verifyFiles is a port of `atap-witness verify DIR` (packages/atap-cli/src/
// cli.ts: verify, checkWitnessEvents, escapes): same steps, same order, same
// reason strings, so the page and the CLI agree. Keep the two in step. The
// chain and signature checks are atap-js's own verifyReceipt, bundled.

import { canonicalizeBytes, ed25519Verify, fromHex, GENESIS_HASH, isDidKey, pickDidKeyKey, publicKeyFromDidKey, publicKeyFromHex, sha256, verifyReceipt } from '@atap'
import { pendingCount, resolvePending } from './shim.js'
import { MAX_ZIP_BYTES, readZip } from './zip.js'
import { render } from './render.js'

const WITNESS_EVENTS = 'profile_artifacts/witness_events.json'

// RFC 8032 §7.1 test 1: the empty message signed by this key.
const TEST_PK = fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
const TEST_SIG = fromHex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')

export async function ed25519Supported() {
  try {
    const k = await crypto.subtle.importKey('raw', TEST_PK, { name: 'Ed25519' }, false, ['verify'])
    return await crypto.subtle.verify({ name: 'Ed25519' }, k, TEST_SIG, new Uint8Array(0))
  } catch {
    return false
  }
}

function isObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

// cli.ts escapes() against a virtual root: the normalised path, or null if
// `rel` lands outside the root (or on it).
function normalise(rel) {
  if (rel.startsWith('/')) return null
  const out = []
  for (const s of rel.split('/')) {
    if (s === '' || s === '.') continue
    if (s !== '..') out.push(s)
    else if (!out.pop()) return null
  }
  return out.length ? out.join('/') : null
}

function readJson(files, name) {
  try {
    return JSON.parse(new TextDecoder().decode(files.get(name)))
  } catch {
    throw new Error(`cannot read ${name} in the receipt`)
  }
}

async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return '0x' + Array.from(d, x => x.toString(16).padStart(2, '0')).join('')
}

// Copied from cli.ts checkWitnessEvents; see the comment there.
function checkWitnessEvents(events, chain, ait, keys) {
  if (!Array.isArray(events)) return `${WITNESS_EVENTS} is not an array`
  let prev = GENESIS_HASH
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
      if (typeof e.witness_signature !== 'string' || !ed25519Verify(fromHex(self_hash), e.witness_signature, publicKeyFromHex(key.public_key))) {
        return `event ${i} (${e.id}) signature invalid`
      }
    }
    prev = self_hash
  }
  let at = 0
  for (const b of chain) {
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

// files: Map<path, bytes> from readZip. Returns { result, receipt, ait, events }.
// Where the CLI would crash with an error, the result carries it as the reason.
async function verifyFiles(files) {
  const fail = reason => ({ result: { ok: false, blocks: 0, reason } })
  const receipt = readJson(files, 'manifest.json')
  for (const f of receipt.files ?? []) {
    const rel = normalise(f.path)
    if (rel === null) return fail(`${f.path} escapes the receipt directory`)
    if (f.sha256 === null) continue
    const bytes = files.get(rel)
    if (!bytes) return fail(`${f.path} missing`)
    if ((await sha256Hex(bytes)) !== f.sha256) return fail(`${f.path} sha256 mismatch`)
  }
  const ait = readJson(files, 'ait.json')
  const chain = readJson(files, 'attestation_chain.json')
  const keys = readJson(files, 'public_keys.json')
  const listed = receipt.files?.some(f => f.path === WITNESS_EVENTS)
  let events = []
  const run = () => {
    try {
      const result = verifyReceipt({ receipt, ait, chain, keys })
      if (!result.ok || !listed) return result
      events = readJson(files, WITNESS_EVENTS)
      const reason = checkWitnessEvents(events, chain, ait, keys)
      return reason ? { ok: false, blocks: 0, reason } : result
    } catch (e) {
      return { ok: false, blocks: 0, reason: String(e?.message ?? e) }
    }
  }
  // See shim.js. Each pass gets at least one hash or signature further, so
  // this bound only stops a loop that would never settle.
  // ponytail: every pass reruns from the top, O(n²) in blocks+events; fine
  // under the 10 MiB entry cap, batch-precompute if receipts grow past that.
  const n = (Array.isArray(chain) ? chain.length : 0) + (listed ? (readJsonOr(files, WITNESS_EVENTS)?.length ?? 0) : 0)
  for (let pass = 0; pass <= 4 * n + 8; pass++) {
    const result = run()
    if (pendingCount() === 0) return { result, receipt, ait, events }
    await resolvePending()
  }
  return fail('verification did not settle')
}

function readJsonOr(files, name) {
  try {
    return readJson(files, name)
  } catch {
    return null
  }
}

// One receipt ZIP (ArrayBuffer or Uint8Array) to the view render() draws.
// No Ed25519 in WebCrypto means no verdict at all, never an unverified view.
export async function verifyZip(buf) {
  if (!(await ed25519Supported())) return { status: 'no-ed25519' }
  let files
  try {
    files = await readZip(buf)
  } catch (e) {
    return { status: 'error', reason: e.message }
  }
  try {
    return { status: 'done', ...(await verifyFiles(files)) }
  } catch (e) {
    return { status: 'done', result: { ok: false, blocks: 0, reason: e.message } }
  }
}

globalThis.atapViewer = { verifyZip, render, readZip }

if (typeof document !== 'undefined') {
  const input = document.getElementById('file')
  const out = document.getElementById('out')
  let seq = 0
  const show = async file => {
    const mine = ++seq
    out.replaceChildren(document.createTextNode('Checking…'))
    const view =
      file.size > MAX_ZIP_BYTES
        ? { status: 'error', reason: `the ZIP is over the ${MAX_ZIP_BYTES}-byte cap` }
        : await verifyZip(await file.arrayBuffer())
    // A later file replaces an earlier one still being checked.
    if (mine === seq) out.replaceChildren(render(document, view))
  }
  input.addEventListener('change', () => input.files[0] && show(input.files[0]))
  // The whole window is the drop target, so a near miss never makes the
  // browser navigate to the file.
  window.addEventListener('dragover', e => e.preventDefault())
  window.addEventListener('drop', e => {
    e.preventDefault()
    const f = e.dataTransfer?.files[0]
    if (f) show(f)
  })
}
