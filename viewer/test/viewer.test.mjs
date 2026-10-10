// The built page, driven headlessly: dist/atap-viewer.html's own script runs
// in a node:vm context with no document or window, and its verifyZip must
// agree with `atap-witness verify DIR` on real and tampered receipts and
// refuse hostile ZIPs. Temp files only under os.tmpdir().

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
import { crc32, deflateRawSync } from 'node:zlib'
import { MAX_ENTRIES, MAX_ENTRY_BYTES } from '../src/zip.js'

const here = p => fileURLToPath(new URL(p, import.meta.url))
const HTML = readFileSync(here('../dist/atap-viewer.html'), 'utf8')
const CLI = here('../../packages/atap-cli/dist/cli.js')
const ATAP_JS = here('../../packages/atap-js/dist/index.js')
const FIXTURES = here('../../packages/atap-cli/test/fixtures/v01-real/')
const EXAMPLES = here('../../profiles/profiles/tunnelmind-code-crew-v1/examples/witness-events.json')
const ARTIFACT = 'profile_artifacts/witness_events.json'
const HOSTILE = '<img src=x onerror=alert(1)>'

const hasZip = spawnSync('zip', ['-v']).status === 0
const hasCli = existsSync(CLI)

// The one inline <script> body, run with only the web globals the page uses.
const viewer = (() => {
  const scripts = [...HTML.matchAll(/<script>([\s\S]*?)<\/script>/g)]
  assert.equal(scripts.length, 1, 'expected exactly one inline script')
  const ctx = vm.createContext({ crypto, TextDecoder, TextEncoder, DecompressionStream, Blob })
  vm.runInContext(scripts[0][1], ctx)
  return ctx.atapViewer
})()

const tmp = () => mkdtempSync(join(tmpdir(), 'atap-viewer-'))

// As cli.ts zipDir does: entries relative to the receipt dir.
function zipDir(dir) {
  const out = join(tmp(), 'r.zip')
  execFileSync('zip', ['-q', '-X', '-r', out, '.'], { cwd: dir })
  return readFileSync(out)
}

// The CLI's verdict on a dir: its JSON stdout, whatever the exit code.
function cliVerify(dir) {
  const r = spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  return JSON.parse(r.stdout)
}

// A minimal ZIP writer: entries are [name, bytes, {method, data, usize}?].
// Stored unless method 8 is given with pre-deflated data.
function makeZip(entries) {
  const locals = []
  const central = []
  let off = 0
  for (const [name, bytes, o = {}] of entries) {
    const n = Buffer.from(name)
    const data = o.data ?? bytes
    const method = o.method ?? 0
    const usize = o.usize ?? bytes.length
    const lfh = Buffer.alloc(30)
    lfh.writeUInt32LE(0x04034b50, 0)
    lfh.writeUInt16LE(20, 4)
    lfh.writeUInt16LE(method, 8)
    lfh.writeUInt32LE(crc32(bytes), 14)
    lfh.writeUInt32LE(data.length, 18)
    lfh.writeUInt32LE(usize, 22)
    lfh.writeUInt16LE(n.length, 26)
    const cdh = Buffer.alloc(46)
    cdh.writeUInt32LE(0x02014b50, 0)
    cdh.writeUInt16LE(20, 4)
    cdh.writeUInt16LE(20, 6)
    cdh.writeUInt16LE(method, 10)
    cdh.writeUInt32LE(crc32(bytes), 16)
    cdh.writeUInt32LE(data.length, 20)
    cdh.writeUInt32LE(usize, 24)
    cdh.writeUInt16LE(n.length, 28)
    cdh.writeUInt32LE(off, 42)
    locals.push(lfh, n, data)
    central.push(cdh, n)
    off += 30 + n.length + data.length
  }
  const cd = Buffer.concat(central)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(cd.length, 12)
  eocd.writeUInt32LE(off, 16)
  return Buffer.concat([...locals, cd, eocd])
}

// A fresh v0.2 receipt from the built CLI: two events in one block, with
// profile_artifacts/witness_events.json. Throwaway key.
function freshReceipt() {
  const dir = tmp()
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyPath = join(dir, 'witness.pem')
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  const common = ['--dir', join(dir, 'store'), '--key', keyPath, '--witness-oai', 'OAI-2026-0010002']
  const cli = (args, input) =>
    JSON.parse(execFileSync(process.execPath, [CLI, ...args, ...common], { input, encoding: 'utf8', env: { PATH: process.env.PATH } }))
  const ait = cli(['ait', 'declare'], JSON.stringify({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  const examples = JSON.parse(readFileSync(EXAMPLES, 'utf8'))
  for (const { event_type, payload } of examples.slice(0, 2)) cli(['event', '--ait', ait.id], JSON.stringify({ event_type, payload }))
  cli(['block', '--ait', ait.id], JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }))
  const out = join(dir, 'receipt')
  cli(['receipt', '--ait', ait.id, '--out', out], '')
  return { dir, out, privateKey }
}

const skipFresh = !hasZip || !hasCli ? 'needs the zip binary and packages/atap-cli/dist' : false
const fresh = skipFresh ? null : freshReceipt()

test('the built page keeps its no-network CSP', () => {
  assert.match(HTML, /<meta http-equiv="Content-Security-Policy" content="[^"]*connect-src 'none'/)
})

for (const name of readdirSync(FIXTURES)) {
  test(`real receipt ${name} verifies`, { skip: !hasZip && 'needs the zip binary' }, async () => {
    const v = await viewer.verifyZip(zipDir(join(FIXTURES, name)))
    assert.equal(v.status, 'done')
    assert.equal(v.result.ok, true, v.result.reason)
    assert.ok(v.events.length > 0)
  })
}

test('fresh v0.2 receipt verifies, as a zipped dir and as the CLI\'s own receipt.zip', { skip: skipFresh }, async () => {
  assert.equal(cliVerify(fresh.out).ok, true)
  for (const buf of [zipDir(fresh.out), readFileSync(`${fresh.out}.zip`)]) {
    const v = await viewer.verifyZip(buf)
    assert.equal(v.status, 'done')
    assert.equal(v.result.ok, true, v.result.reason)
    assert.equal(v.events.length, 2)
  }
})

// The viewer's verdict on a tampered dir must carry the CLI's exact reason.
async function sameReasonAsCli(dir, expect) {
  const cli = cliVerify(dir)
  assert.equal(cli.ok, false)
  assert.match(cli.reason, expect)
  const v = await viewer.verifyZip(zipDir(dir))
  assert.equal(v.status, 'done')
  assert.equal(v.result.ok, false)
  assert.equal(v.result.reason, cli.reason)
}

test('tamper: an event byte changed without fixing the manifest fails like the CLI', { skip: !hasZip || !hasCli }, async () => {
  const dir = join(tmp(), 'r')
  cpSync(join(FIXTURES, 'a3-overturn-atap'), dir, { recursive: true })
  const bytes = readFileSync(join(dir, ARTIFACT))
  bytes[bytes.indexOf('"witnessed_at"') + 20] ^= 1
  writeFileSync(join(dir, ARTIFACT), bytes)
  await sameReasonAsCli(dir, /witness_events\.json sha256 mismatch/)
})

test('tamper: an altered event under a refreshed, re-signed manifest fails like the CLI', { skip: skipFresh }, async () => {
  const { canonicalizeBytes } = await import(ATAP_JS)
  const dir = join(fresh.dir, 'altered')
  cpSync(fresh.out, dir, { recursive: true })
  // As witness-events.test.mjs tamper(): only the event check can object.
  const events = JSON.parse(readFileSync(join(dir, ARTIFACT), 'utf8'))
  events[1].witnessed_at = '2020-01-01T00:00:00Z'
  const bytes = Buffer.from(JSON.stringify(events, null, 2) + '\n')
  writeFileSync(join(dir, ARTIFACT), bytes)
  const { witness_signature: _, ...rcpt } = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))
  rcpt.files = rcpt.files.map(f => (f.path === ARTIFACT ? { ...f, sha256: `0x${createHash('sha256').update(bytes).digest('hex')}` } : f))
  const sig = sign(null, canonicalizeBytes(rcpt), fresh.privateKey).toString('hex')
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ ...rcpt, witness_signature: `ed25519:0x${sig}` }, null, 2) + '\n')
  await sameReasonAsCli(dir, /event 1 .*self_hash mismatch/)
})

test('hostile ZIP: a ../ entry is refused', async () => {
  const v = await viewer.verifyZip(makeZip([['manifest.json', Buffer.from('{}')], ['../evil.json', Buffer.from('{}')]]))
  assert.equal(v.status, 'error')
  assert.match(v.reason, /refused path/)
})

test('hostile ZIP: an entry over the size cap is refused, declared or not', async () => {
  const big = Buffer.alloc(MAX_ENTRY_BYTES + 1024 * 1024)
  const data = deflateRawSync(big)
  assert.ok(data.length < 64 * 1024, 'the bomb itself is small')
  // Honest about its size: refused before inflating.
  let v = await viewer.verifyZip(makeZip([['manifest.json', big, { method: 8, data }]]))
  assert.equal(v.status, 'error')
  assert.match(v.reason, /cap/)
  // Lying about its size: refused while inflating.
  v = await viewer.verifyZip(makeZip([['manifest.json', big, { method: 8, data, usize: 100 }]]))
  assert.equal(v.status, 'error')
  assert.match(v.reason, /inflates past/)
})

test('hostile ZIP: more than the entry cap is refused', async () => {
  const entries = Array.from({ length: MAX_ENTRIES + 1 }, (_, i) => [`f${i}.json`, Buffer.from('{}')])
  const v = await viewer.verifyZip(makeZip(entries))
  assert.equal(v.status, 'error')
  assert.match(v.reason, /entries/)
})

test('viewer/src never parses strings as HTML or code', () => {
  const banned = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/
  const files = readdirSync(here('../src')).filter(f => f.endsWith('.js'))
  assert.ok(files.length >= 4)
  for (const f of files) {
    for (const [i, line] of readFileSync(here(`../src/${f}`), 'utf8').split('\n').entries()) {
      assert.doesNotMatch(line, banned, `${f}:${i + 1}`)
    }
  }
})

// A fake document that records every property set and method call on its
// elements, so the test sees exactly where each string lands.
function fakeDoc() {
  const sets = []
  const mk = tag => {
    const target = { tag, children: [] }
    const methods = {
      appendChild: k => (target.children.push(k), k),
      append: (...ks) => target.children.push(...ks),
      setAttribute: (k, v) => sets.push([`attr:${k}`, String(v)]),
    }
    return new Proxy(target, {
      get: (t, k) => methods[k] ?? t[k],
      set: (t, k, v) => (sets.push([k, String(v)]), (t[k] = v), true),
    })
  }
  return {
    sets,
    createElement: mk,
    createTextNode: t => (sets.push(['textNode', String(t)]), { text: t }),
  }
}

test('render puts hostile receipt strings only into text', () => {
  const receipt = {
    witness: HOSTILE, profile: HOSTILE, ait: HOSTILE, id: HOSTILE, period_start: HOSTILE, period_end: HOSTILE,
    chain_head_hash: HOSTILE, files: [{ path: HOSTILE, sha256: HOSTILE }],
  }
  const views = [
    { status: 'done', result: { ok: true, blocks: 1, attestation_strength: HOSTILE, warnings: [HOSTILE] }, receipt, ait: { operator: HOSTILE },
      events: [{ event_type: HOSTILE, payload: { evidence: HOSTILE }, witnessed_at: HOSTILE }] },
    { status: 'done', result: { ok: false, blocks: 0, reason: HOSTILE } },
    { status: 'error', reason: HOSTILE },
    { status: 'no-ed25519' },
  ]
  for (const view of views) {
    const doc = fakeDoc()
    viewer.render(doc, view)
    assert.ok(doc.sets.length > 0)
    const landed = doc.sets.filter(([, v]) => v.includes(HOSTILE))
    if (view.status !== 'no-ed25519') assert.ok(landed.length > 0, `${view.status}: hostile string never rendered`)
    for (const [where] of landed) assert.ok(where === 'textContent' || where === 'textNode', `landed in ${where}`)
  }
})
