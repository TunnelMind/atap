// tunnelmind:crew_ops:v1 through the atap-witness bin with no CLI change:
// declare, the profile's example events, block, receipt, then verify.sh,
// verifyReceipt and `atap-witness verify` on it. Throwaway keys and temp
// dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyReceipt } from '@tunnelmindai/atap'

const PROFILE = 'tunnelmind:crew_ops:v1'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-crew-ops-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))

function setup() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-crew-ops-'))
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyPath = join(tmp, 'witness.pem')
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  return { tmp, keyPath, store: join(tmp, 'store') }
}

// Resolves with {code, stdout, stderr}; never rejects on a non-zero exit.
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

// verify.sh is the repo's copy, not the one in the receipt.
function verifyBoth(dir) {
  const sh = spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8' })
  const lib = verifyReceipt({
    receipt: readJson(dir, 'manifest.json'),
    ait: readJson(dir, 'ait.json'),
    chain: readJson(dir, 'attestation_chain.json'),
    keys: readJson(dir, 'public_keys.json'),
  })
  return { sh, lib }
}

test('crew_ops run: 5 example events -> block -> receipt, all three verifiers ok; a PII event is refused', async () => {
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const capabilities = Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities)
  assert.equal(capabilities.length, 4)

  // Constraints from the example AIT, so the profile's constraints schema runs.
  const example = readJson(PROFILE_DIR, 'examples/ait.json')
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'crew-ops',
    profile: PROFILE,
    operator: 'OAI-2026-0010001',
    capabilities,
    constraints: example.constraints,
    attestationPolicy: example.attestation_policy,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  assert.equal(ait.profile, PROFILE)
  assert.deepEqual(ait.constraints, example.constraints)

  const examples = readJson(PROFILE_DIR, 'examples/witness-events.json')
  assert.equal(examples.length, 5)
  assert.deepEqual(new Set(examples.map(e => e.event_type)), new Set([
    'crew_ops:autonomy_decision', 'crew_ops:ratification', 'crew_ops:intake_decision',
    'crew_ops:owner_command',
  ]))
  // Midway, the email_as_agent PII case is refused before signing: non-zero
  // exit, store untouched. Proof of the latter: the next example event still
  // chains from the pre-refusal head.
  const { must_reject } = readJson(PROFILE_DIR, 'tests/pii-rejection.json')
  const pii = must_reject.find(c => c.name === 'email_as_agent')
  assert.ok(pii, 'email_as_agent case missing from pii-rejection.json')
  let last
  for (const [i, { event_type, payload }] of examples.entries()) {
    if (i === 2) {
      const refused = await run(['event', '--ait', ait.id, ...common], JSON.stringify(pii.event))
      assert.notEqual(refused.code, 0, 'event accepted a PII payload')
      assert.match(refused.stderr, /witness-events\.schema\.json/)
      assert.ok(!refused.stderr.includes('jane@example.com'), 'refusal echoed the PII value')
    }
    const ev = await ok(['event', '--ait', ait.id, ...common], JSON.stringify({ event_type, payload }))
    assert.equal(ev.event_type, event_type)
    if (last) assert.equal(ev.prev_event_hash, last.self_hash)
    last = ev
  }

  // Counts over the 5 examples, per the profile's period-summary schema.
  const summary = {
    autonomy_decisions: { allow: 1, refuse: 0, grant: 0, expired: 0, request: 1, approved: 0, rejected: 0 },
    intake_decisions: { act: 1, park: 0, drop: 0 },
    ratifications: 1,
    owner_commands: {
      crew_stop: { done: 1, refused: 0, failed: 0 },
      crew_start: { done: 0, refused: 0, failed: 0 },
      ratify_yes: { done: 0, refused: 0, failed: 0 },
      ratify_no: { done: 0, refused: 0, failed: 0 },
    },
  }
  const block = await ok(['block', '--ait', ait.id, ...common], JSON.stringify(summary))
  assert.equal(block.event_count, examples.length)
  assert.equal(block.chain_head_hash, last.self_hash)

  const out = join(ctx.tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')

  const { sh, lib } = verifyBoth(out)
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
  assert.equal(lib.ok, true, lib.reason)
  assert.equal((await ok(['verify', out])).ok, true)
})

test('crew_ops autonomy_decision matches the rails ledger: grant/ratify actions, expired, Class 4 only as refuse', async () => {
  // Coordinator 2026-10-09 (a5 review): the enums follow agent-crew autonomy.py's real values.
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const example = readJson(PROFILE_DIR, 'examples/ait.json')
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'crew-ops', profile: PROFILE, operator: 'OAI-2026-0010001',
    capabilities: Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities),
    constraints: example.constraints, attestationPolicy: example.attestation_policy,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  const event = (p) => JSON.stringify({ event_type: 'crew_ops:autonomy_decision', payload: {
    timestamp: new Date().toISOString(), evidence: 'asserted', agent: 'crew-merchant',
    target_sha256: 'a'.repeat(64), ...p } })
  const accepted = [
    { class: 3, action: 'grant', decision: 'grant' },
    { class: 3, action: 'ratify', decision: 'expired' },
    { class: 4, action: 'pay', decision: 'refuse' },
  ]
  for (const p of accepted) {
    const r = await run(['event', '--ait', ait.id, ...common], event(p))
    assert.equal(r.code, 0, `${JSON.stringify(p)} refused: ${r.stderr}`)
  }
  const refused = [
    { class: 4, action: 'pay', decision: 'allow' },     // Class 4 is never allowed
    { class: 3, action: 'ratify', decision: 'expire' }, // the ledger writes `expired`
  ]
  for (const p of refused) {
    const r = await run(['event', '--ait', ait.id, ...common], event(p))
    assert.notEqual(r.code, 0, `${JSON.stringify(p)} was signed`)
  }
})

test('crew_ops owner_command: done and refused per command, both verifiers pass, PII cases refused', async () => {
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const example = readJson(PROFILE_DIR, 'examples/ait.json')
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'crew-ops', profile: PROFILE, operator: 'OAI-2026-0010001',
    capabilities: Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities),
    constraints: example.constraints, attestationPolicy: example.attestation_policy,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))

  // Mail commands are anchored on the Message-ID digest; CLI commands are
  // asserted and carry none. crew_start and ratify_no come in over the CLI.
  const commands = ['crew_stop', 'crew_start', 'ratify_yes', 'ratify_no']
  const payloads = commands.flatMap(command => ['done', 'refused'].map(outcome => ({
    timestamp: new Date().toISOString(), role: 'owner', command, outcome,
    target_sha256: 'b'.repeat(64),
    ...(command === 'crew_start' || command === 'ratify_no'
      ? { channel: 'cli', evidence: 'asserted' }
      : { channel: 'mail', evidence: 'anchored', message_sha256: 'c'.repeat(64) }),
  })))
  assert.equal(payloads.length, 8)

  // Halfway, every owner_command PII case is refused before signing; the next
  // event still chaining from the pre-refusal head proves the store untouched.
  const pii = readJson(PROFILE_DIR, 'tests/pii-rejection.json').must_reject
    .filter(c => c.event.event_type === 'crew_ops:owner_command')
  assert.equal(pii.length, 9)
  let last
  for (const [i, payload] of payloads.entries()) {
    if (i === 4) {
      for (const c of pii) {
        const r = await run(['event', '--ait', ait.id, ...common], JSON.stringify(c.event))
        assert.notEqual(r.code, 0, `${c.name} was signed`)
        assert.match(r.stderr, /witness-events\.schema\.json/, c.name)
        for (const v of Object.values(c.event.payload)) {
          if (/[@<]|\s/.test(v)) assert.ok(!r.stderr.includes(v), `${c.name} echoed ${v}`)
        }
      }
    }
    const ev = await ok(['event', '--ait', ait.id, ...common],
      JSON.stringify({ event_type: 'crew_ops:owner_command', payload }))
    if (last) assert.equal(ev.prev_event_hash, last.self_hash)
    last = ev
  }

  const outcomes = { done: 1, refused: 1, failed: 0 }
  const summary = {
    autonomy_decisions: { allow: 0, refuse: 0, grant: 0, expired: 0, request: 0, approved: 0, rejected: 0 },
    intake_decisions: { act: 0, park: 0, drop: 0 },
    ratifications: 0,
    owner_commands: Object.fromEntries(commands.map(c => [c, outcomes])),
  }
  const block = await ok(['block', '--ait', ait.id, ...common], JSON.stringify(summary))
  assert.equal(block.event_count, payloads.length)
  assert.equal(block.chain_head_hash, last.self_hash)

  const out = join(ctx.tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  const { sh, lib } = verifyBoth(out)
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
  assert.equal(lib.ok, true, lib.reason)
  assert.equal((await ok(['verify', out])).ok, true)
})
