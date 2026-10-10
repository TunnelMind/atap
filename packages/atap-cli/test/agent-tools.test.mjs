// tunnelmind:agent_tools:v1 through the atap-witness bin with no CLI change:
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

const PROFILE = 'tunnelmind:agent_tools:v1'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-agent-tools-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))

function setup() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-agent-tools-'))
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

async function declare(common) {
  const capabilities = Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities)
  assert.equal(capabilities.length, 4)
  // Constraints from the example AIT, so the profile's constraints schema runs.
  const example = readJson(PROFILE_DIR, 'examples/ait.json')
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'agent-tools',
    profile: PROFILE,
    operator: 'OAI-2026-0010001',
    capabilities,
    constraints: example.constraints,
    attestationPolicy: example.attestation_policy,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  assert.equal(ait.profile, PROFILE)
  assert.deepEqual(ait.constraints, example.constraints)
  return ait
}

test('agent_tools run: one event per type -> block -> receipt, all three verifiers ok; every PII case is refused', async () => {
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const ait = await declare(common)

  const examples = readJson(PROFILE_DIR, 'examples/witness-events.json')
  assert.equal(examples.length, 5)
  assert.deepEqual(new Set(examples.map(e => e.event_type)), new Set([
    'agent_tools:session_started', 'agent_tools:tool_called', 'agent_tools:model_called',
    'agent_tools:handoff', 'agent_tools:human_decision',
  ]))
  // Midway, every PII case is refused before signing: non-zero exit, store
  // untouched. Proof of the latter: the next example event still chains from
  // the pre-refusal head.
  const { must_reject } = readJson(PROFILE_DIR, 'tests/pii-rejection.json')
  assert.equal(must_reject.length, 19)
  let last
  for (const [i, { event_type, payload }] of examples.entries()) {
    if (i === 2) {
      for (const c of must_reject) {
        const r = await run(['event', '--ait', ait.id, ...common], JSON.stringify(c.event))
        assert.notEqual(r.code, 0, `${c.name} was signed`)
        assert.match(r.stderr, /witness-events\.schema\.json/, c.name)
        for (const v of Object.values(c.event.payload)) {
          if (typeof v === 'string' && v.includes('@')) assert.ok(!r.stderr.includes(v), `${c.name} echoed ${v}`)
        }
      }
    }
    const ev = await ok(['event', '--ait', ait.id, ...common], JSON.stringify({ event_type, payload }))
    assert.equal(ev.event_type, event_type)
    if (last) assert.equal(ev.prev_event_hash, last.self_hash)
    last = ev
  }

  // Counts over the 5 examples, per the profile's period-summary schema.
  const payloadOf = t => examples.find(e => e.event_type === `agent_tools:${t}`).payload
  const tool = payloadOf('tool_called')
  const model = payloadOf('model_called')
  const summary = {
    events: { session_started: 1, tool_called: 1, model_called: 1, handoff: 1, human_decision: 1 },
    tool_outcomes: { ok: 0, error: 0, denied: 0, [tool.outcome]: 1 },
    total_tokens: (model.input_tokens ?? 0) + (model.output_tokens ?? 0),
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

test('agent_tools: an event type outside the profile is refused', async () => {
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const ait = await declare(common)
  const r = await run(['event', '--ait', ait.id, ...common], JSON.stringify({
    event_type: 'agent_tools:nope', payload: { timestamp: new Date().toISOString(), evidence: 'asserted' } }))
  assert.notEqual(r.code, 0, 'an unknown event type was signed')
  assert.match(r.stderr, /not defined by profile tunnelmind:agent_tools:v1/)
})
