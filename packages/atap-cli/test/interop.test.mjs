// End-to-end interop: a crew-shaped run through the atap-witness bin, then
// the receipt checked by both the repo's verify.sh and the library's
// verifyReceipt. Throwaway keys and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyReceipt } from '@tunnelmindai/atap'

const PROFILE = 'tunnelmind:code_crew:v1'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))

function setup() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-interop-'))
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

// Both verifiers on one dir. verify.sh is the repo's copy, not the one in
// the receipt, so a tampered receipt can't swap its own verifier.
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

test('crew-shaped run: all 8 code_crew events -> block -> receipt, verify.sh and verifyReceipt agree', async () => {
  const ctx = setup()
  const common = ['--dir', ctx.store, '--key', ctx.keyPath, '--witness-oai', WITNESS]
  const capabilities = Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities)
  assert.equal(capabilities.length, 9)

  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'code-crew',
    profile: PROFILE,
    operator: 'OAI-2026-0010001',
    capabilities,
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  assert.equal(ait.profile, PROFILE)

  const examples = readJson(PROFILE_DIR, 'examples/witness-events.json')
  const types = examples.map(e => e.event_type)
  assert.deepEqual(types, [
    'code_crew:task_claimed', 'code_crew:change_committed', 'code_crew:verify_run', 'code_crew:qa_verdict',
    'code_crew:review_verdict', 'code_crew:approval', 'code_crew:merged', 'code_crew:deployed',
  ])
  let last
  for (const { event_type, payload } of examples) {
    last = await ok(['event', '--ait', ait.id, ...common], JSON.stringify({ event_type, payload }))
    assert.equal(last.event_type, event_type)
  }

  const block = await ok(['block', '--ait', ait.id, ...common], JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 1, tokens: 0, overturns: {} }))
  assert.equal(block.event_count, 8)
  assert.equal(block.chain_head_hash, last.self_hash)

  const out = join(ctx.tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  const listing = execFileSync('unzip', ['-Z1', `${out}.zip`], { encoding: 'utf8' }).split('\n')
  for (const f of ['manifest.json', 'ait.json', 'attestation_chain.json', 'summary.json', 'public_keys.json', 'verify.sh']) {
    assert.ok(listing.includes(f), `${f} missing from zip`)
  }

  const clean = verifyBoth(out)
  assert.equal(clean.sh.status, 0, clean.sh.stdout + clean.sh.stderr)
  assert.equal(clean.lib.ok, true, clean.lib.reason)

  // Events are not in the receipt (ATAP §7.5 file set); the block's
  // chain_head_hash is the receipt's commitment to them. Flip one hex
  // character of it, in place, on a copy.
  const bad = join(ctx.tmp, 'tampered')
  cpSync(out, bad, { recursive: true })
  const chainPath = join(bad, 'attestation_chain.json')
  const original = readFileSync(chainPath, 'utf8')
  const i = original.indexOf(block.chain_head_hash) + block.chain_head_hash.length - 1
  assert.ok(i > 0, 'chain_head_hash not found in attestation_chain.json')
  writeFileSync(chainPath, original.slice(0, i) + (original[i] === '0' ? '1' : '0') + original.slice(i + 1))

  const tampered = verifyBoth(bad)
  assert.notEqual(tampered.sh.status, 0, 'verify.sh accepted a tampered chain_head_hash')
  assert.equal(tampered.lib.ok, false, 'verifyReceipt accepted a tampered chain_head_hash')

  // Reverting the flip makes both pass again: the flip alone is what failed them.
  writeFileSync(chainPath, original)
  const reverted = verifyBoth(bad)
  assert.equal(reverted.sh.status, 0, reverted.sh.stdout + reverted.sh.stderr)
  assert.equal(reverted.lib.ok, true, reverted.lib.reason)

  // The events themselves ship in profile_artifacts/witness_events.json.
  // Flip one hex character of the last event's self_hash, in place, on a
  // fresh copy: the CLI verify recomputes self_hash, and verify.sh catches
  // the file no longer matching its manifest sha256.
  const badEvents = join(ctx.tmp, 'tampered-events')
  cpSync(out, badEvents, { recursive: true })
  const eventsPath = join(badEvents, 'profile_artifacts/witness_events.json')
  const eventsText = readFileSync(eventsPath, 'utf8')
  const j = eventsText.indexOf(last.self_hash) + last.self_hash.length - 1
  assert.ok(j > 0, 'last self_hash not found in witness_events.json')
  writeFileSync(eventsPath, eventsText.slice(0, j) + (eventsText[j] === '0' ? '1' : '0') + eventsText.slice(j + 1))

  const cliBad = await run(['verify', badEvents])
  assert.notEqual(cliBad.code, 0, 'CLI verify accepted a tampered witness event')
  assert.equal(JSON.parse(cliBad.stdout).ok, false)
  const shBad = verifyBoth(badEvents).sh
  assert.notEqual(shBad.status, 0, 'verify.sh accepted a witness_events.json that no longer matches the manifest')
  assert.match(shBad.stdout + shBad.stderr, /witness_events\.json sha256 mismatch/)

  writeFileSync(eventsPath, eventsText)
  await ok(['verify', badEvents])
  const shOk = verifyBoth(badEvents).sh
  assert.equal(shOk.status, 0, shOk.stdout + shOk.stderr)
})
