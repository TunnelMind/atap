// did:key witnesses through the bin (ATAP-v0.2 §3): init makes one, `ait
// rotate --did-key` moves a pre-v0.2 OAI-0000 store onto one, and scitt
// export defaults its issuer to it. Throwaway keys and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { CborTag, cborDecode, didKeyFromPublicKey } from '@tunnelmindai/atap'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const [EV] = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
const EVENT = JSON.stringify({ event_type: EV.event_type, payload: EV.payload })
const SUMMARY = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })
const LEGACY = 'OAI-0000-1234567'

// Resolves with {code, stdout, stderr}; never rejects on a non-zero exit.
function run(cwd, args, stdin = '') {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env: { PATH: process.env.PATH } })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
}

async function ok(cwd, args, stdin) {
  const r = await run(cwd, args, stdin)
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout)
}

const lines = (dir, f) => readFileSync(join(dir, f), 'utf8').trim().split('\n').map(l => JSON.parse(l))
const readConfig = store => JSON.parse(readFileSync(join(store, 'config.json'), 'utf8'))

function didOf(pem) {
  const der = createPublicKey(pem).export({ format: 'der', type: 'spki' })
  return didKeyFromPublicKey(new Uint8Array(der.subarray(der.length - 32)))
}

// receipt + both verifiers (the JS one and the shipped verify.sh) on one AIT.
async function receiptVerifies(cwd, out, ait) {
  await ok(cwd, ['receipt', '--out', out, ...(ait ? ['--ait', ait] : [])])
  assert.equal((await ok(cwd, ['verify', out])).ok, true)
  const sh = spawnSync('bash', ['verify.sh'], { cwd: join(cwd, out), encoding: 'utf8' })
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
  return JSON.parse(readFileSync(join(cwd, out, 'manifest.json'), 'utf8'))
}

// A store as init made it before v0.2: a self-asserted OAI-0000 witness and
// operator, one event and one block under its AIT.
async function legacyStore() {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-didkey-'))
  const store = join(cwd, '.atap')
  mkdirSync(store)
  const { privateKey } = generateKeyPairSync('ed25519')
  writeFileSync(join(store, 'witness.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
  const ait = await ok(cwd, ['ait', 'declare', '--dir', store, '--key', join(store, 'witness.pem'), '--witness-oai', LEGACY], JSON.stringify({
    agentType: 'code_crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: LEGACY,
    capabilities: Object.keys(JSON.parse(readFileSync(join(PROFILE_DIR, 'capabilities.json'), 'utf8')).capabilities),
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  writeFileSync(join(store, 'config.json'), JSON.stringify({ profile: 'tunnelmind:code_crew:v1', key: 'witness.pem', witness_oai: LEGACY, oai_origin: 'self-asserted', ait: ait.id }))
  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  return { cwd, store, ait }
}

// The iss claim (protected header 15, CWT claim 1) of a COSE_Sign1 statement.
function issOf(bytes) {
  const msg = cborDecode(bytes)
  assert.ok(msg instanceof CborTag)
  return cborDecode(msg.value[0]).get(15).get(1)
}

test('init makes a did:key witness and operator; its receipt verifies', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-didkey-'))
  const store = join(cwd, '.atap')
  const config = await ok(cwd, ['init'])
  assert.equal(config.witness_oai, didOf(readFileSync(join(store, 'witness.pem'))))
  assert.equal(config.oai_origin, 'did:key')
  const [ait] = lines(store, 'aits.jsonl')
  assert.equal(ait.witness, config.witness_oai)
  assert.equal(ait.operator, config.witness_oai)
  assert.equal(ait.ait_version, '0.2')
  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  const rcpt = await receiptVerifies(cwd, 'r')
  assert.equal(rcpt.witness, config.witness_oai)
  assert.equal(rcpt.attestation_strength, 'self-asserted')
})

test('ait rotate --did-key moves an OAI-0000 store onto its did:key; the old AIT still verifies', async () => {
  const { cwd, store, ait: old } = await legacyStore()
  const oldEvents = readFileSync(join(store, 'events.jsonl'), 'utf8')
  const oldBlocks = readFileSync(join(store, 'blocks.jsonl'), 'utf8')
  const did = didOf(readFileSync(join(store, 'witness.pem')))

  // No --witness-oai needed (the config's OAI-0000 is not the new witness).
  const config = await ok(cwd, ['ait', 'rotate', '--did-key'])
  assert.deepEqual(readConfig(store), config)
  assert.equal(config.witness_oai, did)
  assert.equal(config.oai_origin, 'did:key')
  assert.notEqual(config.ait, old.id)
  const [oldAit, newAit] = lines(store, 'aits.jsonl')
  assert.deepEqual(oldAit, old)
  assert.equal(newAit.id, config.ait)
  assert.equal(newAit.witness, did)
  assert.equal(newAit.operator, did)
  assert.equal(newAit.ait_version, '0.2')
  for (const k of ['profile', 'capabilities', 'attestation_policy']) assert.deepEqual(newAit[k], oldAit[k])
  assert.equal(readFileSync(join(store, 'events.jsonl'), 'utf8'), oldEvents)
  assert.equal(readFileSync(join(store, 'blocks.jsonl'), 'utf8'), oldBlocks)

  // The pre-rotation AIT receipts under its own OAI witness, with no flags.
  assert.equal((await receiptVerifies(cwd, 'old', old.id)).witness, LEGACY)
  // An explicit --witness-oai still wins.
  await ok(cwd, ['receipt', '--ait', old.id, '--witness-oai', LEGACY, '--out', 'old2'])
  assert.equal((await ok(cwd, ['verify', 'old2'])).ok, true)

  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  assert.equal((await receiptVerifies(cwd, 'new')).witness, did)
})

test('plain ait rotate on an OAI-0000 store keeps its OAI', async () => {
  const { cwd, store, ait: old } = await legacyStore()
  const config = await ok(cwd, ['ait', 'rotate'])
  assert.equal(config.witness_oai, LEGACY)
  assert.equal(config.oai_origin, 'self-asserted')
  const newAit = lines(store, 'aits.jsonl')[1]
  assert.equal(newAit.witness, LEGACY)
  assert.equal(newAit.operator, LEGACY)
  assert.equal(newAit.ait_version, old.ait_version)
})

test('scitt export defaults --issuer to a did:key witness; an explicit one wins; OAI stores still need it', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-didkey-'))
  const config = await ok(cwd, ['init'])
  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  await ok(cwd, ['receipt', '--out', 'r'])
  const exported = await ok(cwd, ['scitt', 'export', 'r'])
  assert.equal(exported.issuer, config.witness_oai)
  for (const f of readdirSync(join(cwd, 'r', 'scitt')).filter(f => f.endsWith('.cose'))) {
    assert.equal(issOf(readFileSync(join(cwd, 'r', 'scitt', f))), config.witness_oai)
  }
  assert.equal((await ok(cwd, ['scitt', 'verify', 'r'])).ok, true)
  const named = await ok(cwd, ['scitt', 'export', 'r', '--issuer', 'OAI-2026-0010002'])
  assert.equal(named.issuer, 'OAI-2026-0010002')
  assert.equal(issOf(readFileSync(join(cwd, 'r', 'scitt', 'ait.cose'))), 'OAI-2026-0010002')

  const legacy = await legacyStore()
  await ok(legacy.cwd, ['receipt', '--out', 'r'])
  const refused = await run(legacy.cwd, ['scitt', 'export', 'r'])
  assert.equal(refused.code, 1)
  assert.match(refused.stderr, /--issuer/)
})
