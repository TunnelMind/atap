// What the witness refuses to sign: ATAP §7.2 event_types, the profile's
// event and period_summary schemas, and unregistered profiles. Every refusal
// must exit non-zero with {"error"} on stderr and leave the store unchanged.
// Throwaway keys and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILES = fileURLToPath(new URL('../../../profiles/', import.meta.url))
const PROFILE_DIR = join(PROFILES, 'profiles/tunnelmind-code-crew-v1')
const WITNESS = 'OAI-2026-0010002'
const SUMMARY = { tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }

const readJson = p => JSON.parse(readFileSync(p, 'utf8'))
const EXAMPLES = readJson(join(PROFILE_DIR, 'examples/witness-events.json'))
const PII = readJson(join(PROFILE_DIR, 'tests/pii-rejection.json')).must_reject

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

// Refused: non-zero exit, one {"error"} line, and the store byte-identical.
async function refused(store, args, stdin) {
  const before = snapshot(store)
  const r = await run(args, stdin)
  assert.notEqual(r.code, 0, `accepted: ${stdin}`)
  assert.equal(r.stdout, '')
  const { error } = JSON.parse(r.stderr)
  assert.equal(typeof error, 'string')
  assert.deepEqual(snapshot(store), before, 'a refused call wrote to the store')
  return error
}

function snapshot(dir) {
  if (!existsSync(dir)) return {}
  return Object.fromEntries(readdirSync(dir).map(f => [f, readFileSync(join(dir, f), 'utf8')]))
}

const aitInput = profile => JSON.stringify({
  agentType: 'code-crew',
  profile,
  operator: 'OAI-2026-0010001',
  capabilities: ['code_crew:code'],
  attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
  expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
})

function setup() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-enforce-'))
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyPath = join(tmp, 'witness.pem')
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  const store = join(tmp, 'store')
  return { tmp, store, common: ['--dir', store, '--key', keyPath, '--witness-oai', WITNESS] }
}

async function codeCrewAit() {
  const ctx = setup()
  const ait = await ok(['ait', 'declare', ...ctx.common], aitInput('tunnelmind:code_crew:v1'))
  // One accepted event first, so "unchanged" is checked against a non-empty chain.
  const { event_type, payload } = EXAMPLES[0]
  await ok(['event', '--ait', ait.id, ...ctx.common], JSON.stringify({ event_type, payload }))
  return { ...ctx, ait }
}

test('every pii-rejection.json must_reject case is refused and nothing is written', async () => {
  const { store, common, ait } = await codeCrewAit()
  assert.ok(PII.length > 0)
  for (const c of PII) {
    const error = await refused(store, ['event', '--ait', ait.id, ...common], JSON.stringify(c.event))
    assert.match(error, /witness-events\.schema\.json/, c.name)
  }
})

test('the measured finding: un-namespaced approval with an email payload is refused', async () => {
  const { store, common, ait } = await codeCrewAit()
  const error = await refused(store, ['event', '--ait', ait.id, ...common],
    JSON.stringify({ event_type: 'approval', payload: { role: 'someone@example.com' } }))
  assert.match(error, /pattern/)
  assert.ok(!error.includes('@'), 'payload value echoed in the error')
})

test('unknown event_type is refused by name; a valid example is accepted', async () => {
  const { store, common, ait } = await codeCrewAit()
  const error = await refused(store, ['event', '--ait', ait.id, ...common],
    JSON.stringify({ event_type: 'code_crew:bogus', payload: {} }))
  assert.match(error, /code_crew:bogus/)

  const { event_type, payload } = EXAMPLES.find(e => e.event_type === 'code_crew:approval')
  const e = await ok(['event', '--ait', ait.id, ...common], JSON.stringify({ event_type, payload }))
  assert.equal(e.event_type, 'code_crew:approval')
})

test('block with an invalid period_summary is refused; a valid one is accepted', async () => {
  const { store, common, ait } = await codeCrewAit()
  for (const bad of [{}, { ...SUMMARY, approver: 'Jane Doe' }, { ...SUMMARY, tokens: -1 }]) {
    const error = await refused(store, ['block', '--ait', ait.id, ...common], JSON.stringify(bad))
    assert.match(error, /period-summary\.schema\.json/)
  }
  const block = await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  assert.equal(block.event_count, 1)
})

test('the complete signed AIT is checked against the whole ait schema: a witness OAI that is an e-mail is refused', async () => {
  const { store, common } = setup()
  const args = common.map(a => (a === WITNESS ? 'person@example.com' : a))
  const error = await refused(store, ['ait', 'declare', ...args], aitInput('tunnelmind:code_crew:v1'))
  assert.match(error, /ATAP v0\.1 ait schema/)
  assert.match(error, /witness/)
  assert.ok(!error.includes('person@example.com'), 'the refused value was echoed')
})

test('one probe per required AitInput field: each missing or malformed field is refused by the whole schema', async () => {
  const { store, common } = setup()
  const base = JSON.parse(aitInput('tunnelmind:code_crew:v1'))
  const probes = {
    agentType: [undefined, ''],
    profile: [undefined],
    operator: [undefined, 'person@example.com'],
    capabilities: [undefined, 'not-an-array'],
    attestationPolicy: [undefined, { witness_granularity: 'sometimes' }],
  }
  // --unregistered-profile on every probe, so the registry check (which fires
  // first for a missing profile) is not what refuses: the whole schema is.
  const args = [...common, '--unregistered-profile']
  for (const [field, values] of Object.entries(probes)) {
    for (const value of values) {
      const input = { ...base }
      if (value === undefined) delete input[field]
      else input[field] = value
      const error = await refused(store, ['ait', 'declare', ...args], JSON.stringify(input))
      assert.match(error, /ATAP v0\.1 ait schema|must be an? (array|object|string)/, `${field}=${JSON.stringify(value)}: ${error}`)
      assert.ok(!error.includes('person@example.com'), 'the refused value was echoed')
    }
  }
  // and the untouched input still declares
  await ok(['ait', 'declare', ...common], JSON.stringify(base))
})

test('ait declare refuses an unregistered profile unless --unregistered-profile', async () => {
  const { store, common } = setup()
  const error = await refused(store, ['ait', 'declare', ...common], aitInput('acme:widget:v1'))
  assert.match(error, /--unregistered-profile/)

  const args = [...common, '--unregistered-profile']
  const ait = await ok(['ait', 'declare', ...args], aitInput('acme:widget:v1'))
  // No profile schema applies, but the core §7.2 event_type rule still does.
  await refused(store, ['event', '--ait', ait.id, ...args], JSON.stringify({ event_type: 'approval', payload: {} }))
  await ok(['event', '--ait', ait.id, ...args], JSON.stringify({ event_type: 'widget:made', payload: { n: 1 } }))
  await ok(['block', '--ait', ait.id, ...args], '')
})

test('--profiles-dir overrides the package-resolved profiles dir', async () => {
  const { tmp, store, common } = setup()
  // A copy of the registry without code_crew: the default dir accepts the
  // profile, the override refuses it.
  const dir = join(tmp, 'profiles')
  cpSync(PROFILES, dir, { recursive: true, filter: src => !src.includes('node_modules') })
  const registry = readJson(join(dir, 'registry.json'))
  registry.profiles = registry.profiles.filter(p => p.id !== 'tunnelmind:code_crew:v1')
  writeFileSync(join(dir, 'registry.json'), JSON.stringify(registry))

  await refused(store, ['ait', 'declare', ...common, '--profiles-dir', dir], aitInput('tunnelmind:code_crew:v1'))
  await ok(['ait', 'declare', ...common], aitInput('tunnelmind:code_crew:v1'))

  const missing = await refused(store, ['ait', 'declare', ...common, '--profiles-dir', join(tmp, 'nope')], aitInput('tunnelmind:code_crew:v1'))
  assert.match(missing, /registry\.json/)
})

test('ait declare refuses an AIT the core ait schema or the profile constraints reject', async () => {
  const { store, common } = setup()
  const aits = join(store, 'aits.jsonl')
  const base = JSON.parse(aitInput('tunnelmind:code_crew:v1'))
  const pii = { ...base, profile: 'Jane Example', operator: 'someone@example.com', capabilities: ['person@example.com'] }
  // Each probe with and without --unregistered-profile; the registered profile
  // with a PII operator and capabilities must not slip past either.
  for (const input of [pii, { ...pii, profile: 'tunnelmind:code_crew:v1' }]) {
    for (const extra of [[], ['--unregistered-profile']]) {
      const error = await refused(store, ['ait', 'declare', ...common, ...extra], JSON.stringify(input))
      assert.doesNotMatch(error, /example\.com|jane/i)
      assert.equal(existsSync(aits), false)
    }
  }
  const { constraints } = readJson(join(PROFILE_DIR, 'examples/ait.json'))
  const bad = { ...base, constraints: { ...constraints, models: { coder: 'person@example.com' } } }
  for (const extra of [[], ['--unregistered-profile']]) {
    const error = await refused(store, ['ait', 'declare', ...common, ...extra], JSON.stringify(bad))
    assert.match(error, /constraints\.schema\.json/)
    assert.doesNotMatch(error, /example\.com|jane/i)
    assert.equal(existsSync(aits), false)
  }
  // A missing required field, and an attestation_policy the core schema
  // rejects (extra key, bad enum), must be refused rather than signed.
  const { agentType, profile, operator, ...bare } = base
  const missing = await refused(store, ['ait', 'declare', ...common, '--unregistered-profile'], JSON.stringify(bare))
  assert.match(missing, /required property|must be a string/)
  assert.equal(existsSync(aits), false)
  const policy = { witness_granularity: 'person@example.com', receipt_generation: 'whenever', note: 'person@example.com' }
  const badPolicy = await refused(store, ['ait', 'declare', ...common], JSON.stringify({ ...base, attestationPolicy: policy }))
  assert.match(badPolicy, /attestation_policy/)
  for (const error of [missing, badPolicy]) assert.doesNotMatch(error, /example\.com|jane/i)
  assert.equal(existsSync(aits), false)
  // Positive control: the profile example's constraints declare.
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({ ...base, constraints }))
  assert.deepEqual(ait.constraints, constraints)
})
