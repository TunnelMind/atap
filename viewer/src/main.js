// The page's verifier and its wiring to the DOM.
//
// verifyFiles runs the same steps as `atap-witness verify DIR` (packages/
// atap-cli/src/cli.ts: verify) in the same order. The rules themselves
// (checkManifestFiles, verifyReceipt, checkWitnessEvents) live in atap-js and
// are bundled, so the page and the CLI share one implementation: the same
// dialect (ATAP v0.1/v0.2 ed25519 over JCS bytes), the same lone-surrogate
// refusal and the same attestation_strength ceiling (see atap-js verify.ts).
// Trust: the ZIP is hostile (zip.js bounds it, render.js never parses its
// strings as HTML). The page has no --keys, so an OAI witness is checked
// against the receipt's own public_keys.json and the verdict carries the
// CLI's warning that this proves self-consistency only; a did:key is its own
// key. Fails closed: anything that throws becomes {ok:false, reason}, and no
// Ed25519 in WebCrypto means no verdict at all. No network (CSP connect-src 'none').

import { checkManifestFiles, checkWitnessEvents, fromHex, isDidKey, isObject, verifyReceipt, WITNESS_EVENTS } from '@atap'
import { pendingCount, resolvePending } from './shim.js'
import { MAX_ZIP_BYTES, readZip } from './zip.js'
import { render } from './render.js'

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

const CODE_CREW_PROFILE = 'tunnelmind:code_crew:v1'

// A page has no --keys: an OAI witness is checked against the receipt's own
// public_keys.json, which whoever made the receipt chose, so a pass proves
// self-consistency, not who signed (or what strength they hold). The CLI's
// warning, word for word; a did:key is its own key and needs none.
const OWN_KEYS_WARNING = "OAI witness checked against the receipt's own public_keys.json: proves self-consistency, not who signed; pass --keys"

// Strict UTF-8, as the CLI's readJsonFile: a lossy decode would let raw
// invalid bytes stand in for the U+FFFD text that was signed. A leading BOM
// is still dropped, as the page always did (the CLI refuses one).
function readJson(files, name) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(files.get(name)))
  } catch {
    throw new Error(`cannot read ${name} in the receipt`)
  }
}

// files: Map<path, bytes> from readZip. Returns { result, receipt, ait, events }.
// Where the CLI would crash with an error, the result carries it as the reason.
async function verifyFiles(files) {
  const fail = reason => ({ result: { ok: false, blocks: 0, reason } })
  const receipt = readJson(files, 'manifest.json')
  // Any JSON value: a wrong shape gets the CLI's verdict, not a TypeError
  // message as the reason. A malformed files[] is checkManifestFiles's verdict.
  if (!isObject(receipt)) return fail('manifest.json is not an object')
  const listed = Array.isArray(receipt.files) ? receipt.files : []
  // Every entry must be listed in files[], as in the CLI's receiptEntries (scitt/
  // is the CLI's own sidecar, never listed).
  const present = [...files.keys()].filter(k => !k.startsWith('scitt/'))
  // The events are checked whenever the receipt carries or lists them, or its
  // profile requires them, as the CLI's verify(): dropping them from files[]
  // must not skip the check. Absent but required, readJson throws and the
  // reason says so (the CLI crashes there).
  const hasEvents = files.has(WITNESS_EVENTS) || listed.some(f => isObject(f) && f.path === WITNESS_EVENTS)
  let ait
  let events = []
  // Everything that hashes or verifies runs inside a pass, manifest files
  // first, so the shim can record and replay it. A read error here was a
  // crash in the CLI; it lands in the reason, as verifyZip would put it.
  const run = () => {
    try {
      const bad = checkManifestFiles(receipt, rel => files.get(rel), present)
      if (bad) return { ok: false, blocks: 0, reason: bad }
      ait = readJson(files, 'ait.json')
      const chain = readJson(files, 'attestation_chain.json')
      const keys = readJson(files, 'public_keys.json')
      const result = verifyReceipt({ receipt, ait, chain, keys })
      if (!isDidKey(ait?.witness) || !isDidKey(receipt?.witness)) result.warnings = [...(result.warnings ?? []), OWN_KEYS_WARNING]
      if (!result.ok) return result
      if (!hasEvents && ait.profile !== CODE_CREW_PROFILE) return result
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
  const chain = readJsonOr(files, 'attestation_chain.json')
  const n = listed.length +(Array.isArray(chain) ? chain.length : 0) + (readJsonOr(files, WITNESS_EVENTS)?.length ?? 0)
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
