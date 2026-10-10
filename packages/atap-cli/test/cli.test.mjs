// Drives the built atap-witness bin as a subprocess, the way any other
// language would. Throwaway keys and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { appendFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const WITNESS = 'OAI-2026-0010002'
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))

// Valid tunnelmind:code_crew:v1 content: the witness refuses anything else.
const EXAMPLES = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
  .map(({ event_type, payload }) => ({ event_type, payload }))
const SUMMARY = { tasks_accepted: 2, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }

function setup() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-cli-'))
  const { privateKey } = generateKeyPairSync('ed25519')
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' })
  const keyPath = join(tmp, 'witness.pem')
  writeFileSync(keyPath, pem)
  return { tmp, pem, keyPath, store: join(tmp, 'store') }
}

// Resolves with {code, stdout, stderr}; never rejects on a non-zero exit.
function run(args, stdin = '', env = {}) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { PATH: process.env.PATH, ...env },
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
}

const aitInput = () => ({
  agentType: 'code-crew',
  profile: 'tunnelmind:code_crew:v1',
  operator: 'OAI-2026-0010001',
  capabilities: ['code_crew:code'],
  attestationPolicy: {
    witness_granularity: 'per_action',
    block_interval_seconds: 3600,
    receipt_generation: 'on_demand',
  },
  expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
})

async function ok(args, stdin, outputs) {
  const r = await run(args, stdin)
  outputs?.push(r.stdout, r.stderr)
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout)
}

async function declare(ctx, outputs) {
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify(aitInput()), outputs)
  return { ait, common }
}

test('declare -> event x2 -> block -> receipt -> verify', async () => {
  const ctx = setup()
  const outputs = []
  const { ait, common } = await declare(ctx, outputs)
  assert.equal(ait.witness, WITNESS)

  const e1 = await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[0]), outputs)
  const e2 = await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[1]), outputs)
  assert.equal(e1.prev_event_hash, '0x' + '0'.repeat(64))
  assert.equal(e2.prev_event_hash, e1.self_hash)

  const block = await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY), outputs)
  assert.equal(block.event_count, 2)
  assert.equal(block.chain_head_hash, e2.self_hash)
  // Nothing pending now: null, exit 0.
  assert.equal(await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY), outputs), null)

  const out = join(ctx.tmp, 'receipt')
  const rcpt = await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '', outputs)
  assert.equal(rcpt.attestation_strength, 'self-asserted')
  assert.equal(rcpt.chain_head_hash, block.self_hash)
  assert.deepEqual(JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')), rcpt)
  assert.deepEqual(JSON.parse(readFileSync(join(out, 'summary.json'), 'utf8')), SUMMARY)

  // verify.sh is the repo's reference verifier, byte for byte.
  assert.ok(readFileSync(join(out, 'verify.sh')).equals(readFileSync(REPO_VERIFY_SH)))

  // The .zip sits next to the dir and holds every §7.5 file.
  assert.ok(existsSync(`${out}.zip`))
  const listing = execFileSync('unzip', ['-Z1', `${out}.zip`], { encoding: 'utf8' }).split('\n')
  for (const f of ['manifest.json', 'ait.json', 'attestation_chain.json', 'summary.json', 'public_keys.json', 'verify.sh']) {
    assert.ok(listing.includes(f), `${f} missing from zip`)
  }

  const v = await run(['verify', out])
  outputs.push(v.stdout, v.stderr)
  assert.equal(v.code, 0, v.stdout)
  assert.equal(JSON.parse(v.stdout).ok, true)
  assert.equal(JSON.parse(v.stdout).blocks, 1)

  // Tamper one byte of attestation_chain.json: verify fails with exit 1.
  const chainPath = join(out, 'attestation_chain.json')
  const chain = readFileSync(chainPath, 'utf8')
  const i = chain.indexOf('"event_count": 2')
  writeFileSync(chainPath, chain.slice(0, i) + '"event_count": 3' + chain.slice(i + 16))
  const bad = await run(['verify', out])
  outputs.push(bad.stdout, bad.stderr)
  assert.equal(bad.code, 1)
  assert.equal(JSON.parse(bad.stdout).ok, false)

  // The PEM body never appears in anything the CLI printed.
  const body = ctx.pem.split('\n').filter(l => l && !l.startsWith('-----')).join('')
  for (const o of outputs) {
    assert.ok(!o.includes(body) && !o.includes('PRIVATE KEY'), 'key material leaked')
  }
})

test('verify refuses a manifest path that escapes the receipt directory', async () => {
  const ctx = setup()
  const { ait, common } = await declare(ctx)
  await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[0]))
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  const out = join(ctx.tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  assert.equal(JSON.parse((await run(['verify', out])).stdout).ok, true)

  // ../x exists and its hash matches, so only the containment guard stops it.
  writeFileSync(join(ctx.tmp, 'x'), 'outside')
  const manifestPath = join(out, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const hash = '0x' + createHash('sha256').update('outside').digest('hex')
  manifest.files.push({ path: '../x', sha256: hash })
  writeFileSync(manifestPath, JSON.stringify(manifest))
  const bad = await run(['verify', out])
  assert.equal(bad.code, 1, bad.stderr)
  const r = JSON.parse(bad.stdout)
  assert.equal(r.ok, false)
  assert.match(r.reason, /\.\.\/x escapes the receipt directory/)
})

test('concurrent event commands never fork the chain', async () => {
  const ctx = setup()
  const { ait, common } = await declare(ctx)
  const N = 12
  const results = await Promise.all(
    Array.from({ length: N }, (_, n) =>
      run(['event', '--ait', ait.id, ...common], JSON.stringify({ ...EXAMPLES[0], payload: { ...EXAMPLES[0].payload, task_id: `T${n}` } })),
    ),
  )
  for (const r of results) assert.equal(r.code, 0, r.stderr)

  const events = readFileSync(join(ctx.store, 'events.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l))
  assert.equal(events.length, N)
  let prev = '0x' + '0'.repeat(64)
  for (const e of events) {
    assert.equal(e.prev_event_hash, prev)
    prev = e.self_hash
  }
  assert.equal(new Set(events.map(e => e.prev_event_hash)).size, N, 'two events share a parent')
  assert.ok(!existsSync(join(ctx.store, 'lock')), 'lock left behind')

  const block = await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  assert.equal(block.event_count, N)
})

test('rejects non-ed25519 keys, unknown strengths and a missing witness OAI', async () => {
  const ctx = setup()
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const ecPem = privateKey.export({ type: 'pkcs8', format: 'pem' })
  const ecPath = join(ctx.tmp, 'ec.pem')
  writeFileSync(ecPath, ecPem)
  const input = JSON.stringify(aitInput())

  const ec = await run(['ait', 'declare', '--dir', ctx.store, '--key', ecPath, '--witness-oai', WITNESS], input)
  assert.notEqual(ec.code, 0)
  assert.match(JSON.parse(ec.stderr).error, /Ed25519/)
  assert.ok(!ec.stderr.includes('PRIVATE KEY') && !ec.stdout.includes('PRIVATE KEY'))

  const garbage = join(ctx.tmp, 'garbage.pem')
  writeFileSync(garbage, 'not a key')
  const g = await run(['ait', 'declare', '--dir', ctx.store, '--key', garbage, '--witness-oai', WITNESS], input)
  assert.notEqual(g.code, 0)
  assert.ok(!g.stderr.includes('not a key'))

  const s = await run(['ait', 'declare', '--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS, '--strength', 'platinum'], input)
  assert.notEqual(s.code, 0)
  assert.match(JSON.parse(s.stderr).error, /--strength/)

  const w = await run(['ait', 'declare', '--dir', ctx.store, '--key', ctx.keyPath], input)
  assert.notEqual(w.code, 0)
  assert.match(JSON.parse(w.stderr).error, /witness-oai/)

  // The env var is the fallback for --witness-oai.
  const env = await run(['ait', 'declare', '--dir', ctx.store, '--key', ctx.keyPath], input, { ATAP_WITNESS_OAI: WITNESS })
  assert.equal(env.code, 0, env.stderr)
})

test('a non-default --strength is declared by the key entry and verifies', async () => {
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS, '--strength', 'software']
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify(aitInput()))
  await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[0]))
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  const out = join(ctx.tmp, 'r')
  const rcpt = await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  assert.equal(rcpt.attestation_strength, 'software')
  const keys = JSON.parse(readFileSync(join(out, 'public_keys.json'), 'utf8'))
  assert.equal(keys.keys[0].attestation_strength, 'software')
  const v = await run(['verify', out])
  assert.equal(v.code, 0, v.stdout)
})

test('verify --store on an OAI-witnessed store needs --keys, and passes with them', async () => {
  const ctx = setup()
  const { ait, common } = await declare(ctx)
  await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[0]))
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  // The key holder publishes public_keys.json with a receipt.
  const out = join(ctx.tmp, 'r')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  const bare = await run(['verify', '--store', '--dir', ctx.store])
  assert.notEqual(bare.code, 0)
  assert.match(JSON.parse(bare.stderr).error, new RegExp(`OAI witness ${WITNESS}: pass --keys public_keys.json`))
  const v = await ok(['verify', '--store', ctx.store, '--keys', join(out, 'public_keys.json')])
  assert.deepEqual(v, { ok: true, events: 1, blocks: 1, witness: WITNESS, attestation_strength: 'self-asserted' })
})

test('a torn final line is an error naming the file and line, and the file is left untouched', async () => {
  const ctx = setup()
  const { ait, common } = await declare(ctx)
  await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[0]))
  // A normal run leaves no temp file behind.
  assert.deepEqual(readdirSync(ctx.store).filter(f => f.endsWith('.tmp')), [])

  const events = join(ctx.store, 'events.jsonl')
  appendFileSync(events, '{"id":"x')
  const before = readFileSync(events)
  const r = await run(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[1]))
  assert.notEqual(r.code, 0)
  assert.match(r.stderr, /events\.jsonl: line 2 /)
  assert.deepEqual(readFileSync(events), before)
})

test('receipt refuses a non-empty --out and leaves it untouched', async () => {
  const ctx = setup()
  const { ait, common } = await declare(ctx)
  await ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[0]))
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))

  const out = join(ctx.tmp, 'busy')
  mkdirSync(out)
  writeFileSync(join(out, 'unrelated.txt'), 'keep me')
  const r = await run(['receipt', '--ait', ait.id, '--out', out, ...common])
  assert.notEqual(r.code, 0)
  assert.match(r.stderr, /not empty/)
  assert.deepEqual(readdirSync(out), ['unrelated.txt'])
  assert.equal(readFileSync(join(out, 'unrelated.txt'), 'utf8'), 'keep me')
  assert.equal(existsSync(`${out}.zip`), false)

  // An existing empty dir is still fine.
  const empty = join(ctx.tmp, 'empty')
  mkdirSync(empty)
  await ok(['receipt', '--ait', ait.id, '--out', empty, ...common], '')
  assert.ok(existsSync(`${empty}.zip`))
})

test('--help prints the usage table without a key or witness', async () => {
  for (const flag of ['--help', '-h']) {
    const r = await run([flag])
    assert.equal(r.code, 0, r.stderr)
    for (const cmd of ['ait declare', 'event', 'block', 'receipt', 'verify']) assert.ok(r.stdout.includes(cmd), cmd)
  }
})
