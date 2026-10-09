// scitt register against a local node:http mock on 127.0.0.1 only. No real
// SCITT service is contacted. Same receipt-building pattern as scitt.test.mjs.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const PROFILE = 'tunnelmind:code_crew:v1'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))

function run(args, stdin = '') {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH } })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
}

async function ok(args, stdin) {
  const r = await run(args, stdin)
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout)
}

// One block of crew events, a receipt, and its scitt export.
async function buildExport() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-scitt-reg-'))
  const keyPath = join(tmp, 'witness.pem')
  writeFileSync(keyPath, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }))
  const common = ['--dir', join(tmp, 'store'), '--key', keyPath, '--witness-oai', WITNESS]
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'code-crew',
    profile: PROFILE,
    operator: 'OAI-2026-0010001',
    capabilities: Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities),
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  for (const { event_type, payload } of readJson(PROFILE_DIR, 'examples/witness-events.json')) {
    await ok(['event', '--ait', ait.id, ...common], JSON.stringify({ event_type, payload }))
  }
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 1, tokens: 0, overturns: {} }))
  const out = join(tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  await ok(['scitt', 'export', out, '--key', keyPath, '--issuer', WITNESS])
  return { tmp, out }
}

// A SCRAPI mock that answers every POST with `status`. The 201 body is a
// fake receipt that names the request number, so each file can be checked.
async function mock(status) {
  const seen = []
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, type: req.headers['content-type'], body: Buffer.concat(chunks) })
      res.writeHead(status, status === 201 ? { 'content-type': 'application/cose' } : {})
      res.end(status === 201 ? `receipt-${seen.length}` : '')
    })
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  return { seen, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(r => server.close(r)) }
}

const receiptsIn = dir => readdirSync(join(dir, 'scitt')).filter(f => /\.receipt/.test(f))

test('scitt register: 201 stores receipts; 202/500, tamper and bad --service fail', async () => {
  const { tmp, out } = await buildExport()
  const index = readJson(out, 'scitt/index.json')
  const copy = name => {
    const d = join(tmp, name)
    cpSync(out, d, { recursive: true })
    return d
  }

  // 201 on every post: one .receipt per statement holding the mock's body.
  const good = await mock(201)
  const okDir = copy('ok')
  const r = await ok(['scitt', 'register', okDir, '--service', good.url])
  await good.close()
  assert.equal(r.registered, index.length)
  assert.equal(r.service, `${good.url}/`)
  assert.equal(good.seen.length, index.length)
  for (const [i, e] of index.entries()) {
    const s = good.seen[i]
    assert.equal(s.method, 'POST')
    assert.equal(s.url, '/entries')
    assert.equal(s.type, 'application/cose')
    assert.deepEqual(s.body, readFileSync(join(okDir, 'scitt', e.file)))
    const name = e.file.replace(/\.cose$/, '.receipt')
    assert.equal(readFileSync(join(okDir, 'scitt', name), 'utf8'), `receipt-${i + 1}`)
  }
  assert.deepEqual(r.receipts, index.map(e => e.file.replace(/\.cose$/, '.receipt')))
  // .receipt files are outside index.json, so scitt verify still passes.
  await ok(['scitt', 'verify', okDir])

  // 202 (async) and 500: non-zero exit, no receipt written.
  for (const status of [202, 500]) {
    const m = await mock(status)
    const d = copy(`status-${status}`)
    const res = await run(['scitt', 'register', d, '--service', m.url])
    await m.close()
    assert.equal(res.code, 1, `accepted ${status}`)
    assert.match(res.stderr, new RegExp(`answered ${status}`))
    assert.equal(m.seen.length, 1)
    assert.deepEqual(receiptsIn(d), [])
  }

  // A tampered .cose is refused before any request reaches the mock.
  const t = await mock(201)
  const td = copy('tampered')
  const file = join(td, 'scitt', index[0].file)
  const bytes = readFileSync(file)
  bytes[bytes.length - 1] ^= 1
  writeFileSync(file, bytes)
  const tampered = await run(['scitt', 'register', td, '--service', t.url])
  await t.close()
  assert.equal(tampered.code, 1)
  assert.match(tampered.stderr, /scitt verify failed/)
  assert.equal(t.seen.length, 0)
  assert.deepEqual(receiptsIn(td), [])

  // Missing, malformed, non-http or credentialed --service is refused.
  for (const [args, why] of [
    [[], /--service <URL> is required/],
    [['--service', 'not a url'], /--service <URL> is required/],
    [['--service', 'file:///etc/passwd'], /http: or https:/],
    [['--service', 'ftp://127.0.0.1/'], /http: or https:/],
    [['--service', 'http://user:secret@127.0.0.1/'], /credentials/],
  ]) {
    const res = await run(['scitt', 'register', out, ...args])
    assert.equal(res.code, 1)
    assert.match(res.stderr, why)
    assert.doesNotMatch(res.stderr, /secret/)
  }
  assert.ok(!existsSync(join(out, 'scitt', 'ait.receipt')))
})
