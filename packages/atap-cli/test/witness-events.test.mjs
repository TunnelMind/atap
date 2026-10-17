// The receipt's profile_artifacts/witness_events.json: written by `receipt`,
// checked by `verify` against the signed blocks' chain_head_hash. Throwaway
// keys and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeBytes } from '@tunnelmindai/atap'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'
const ARTIFACT = 'profile_artifacts/witness_events.json'
const EXAMPLES = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
  .map(({ event_type, payload }) => ({ event_type, payload }))
const SUMMARY = { tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
const sha256 = bytes => `0x${createHash('sha256').update(bytes).digest('hex')}`

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

const verifySh = dir => spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8' })

// Two blocks of 3 + 2 events, then one pending event the receipt must leave out.
async function twoBlockReceipt() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-events-'))
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyPath = join(tmp, 'witness.pem')
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  const common = ['--dir', join(tmp, 'store'), '--key', keyPath, '--witness-oai', WITNESS]
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  const event = i => ok(['event', '--ait', ait.id, ...common], JSON.stringify(EXAMPLES[i % EXAMPLES.length]))
  const events = []
  for (const i of [0, 1, 2]) events.push(await event(i))
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  for (const i of [3, 4]) events.push(await event(i))
  await ok(['block', '--ait', ait.id, ...common], JSON.stringify(SUMMARY))
  await event(5)
  const out = join(tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  return { tmp, out, events, privateKey }
}

// Rewrites the artifact, refreshes its manifest hash and re-signs the Receipt
// (§7.7: Ed25519 over the canonical bytes minus witness_signature), so the
// manifest and signature checks pass and only the event check can object.
function tamper(src, dst, edit, privateKey) {
  cpSync(src, dst, { recursive: true })
  const events = edit(readJson(dst, ARTIFACT))
  const bytes = Buffer.from(JSON.stringify(events, null, 2) + '\n')
  writeFileSync(join(dst, ARTIFACT), bytes)
  const { witness_signature: _, ...rcpt } = readJson(dst, 'manifest.json')
  rcpt.files = rcpt.files.map(f => (f.path === ARTIFACT ? { ...f, sha256: sha256(bytes) } : f))
  const sig = sign(null, canonicalizeBytes(rcpt), privateKey).toString('hex')
  writeFileSync(join(dst, 'manifest.json'), JSON.stringify({ ...rcpt, witness_signature: `ed25519:0x${sig}` }, null, 2) + '\n')
  return dst
}

test('receipt carries the covered events; verify checks them against the blocks', async () => {
  const { tmp, out, events, privateKey } = await twoBlockReceipt()

  // Five covered events in chain order; the pending sixth is left out.
  assert.deepEqual(readJson(out, ARTIFACT), events)
  const entry = readJson(out, 'manifest.json').files.find(f => f.path === ARTIFACT)
  assert.equal(entry.sha256, sha256(readFileSync(join(out, ARTIFACT))))
  const listing = execFileSync('unzip', ['-Z1', `${out}.zip`], { encoding: 'utf8' }).split('\n')
  assert.ok(listing.includes(ARTIFACT), `${ARTIFACT} missing from zip`)

  // Untouched: both verifiers pass.
  const good = await run(['verify', out])
  assert.equal(good.code, 0, good.stdout)
  assert.equal(JSON.parse(good.stdout).blocks, 2)
  assert.equal(verifySh(out).status, 0, verifySh(out).stdout)

  // The re-signing helper alone (no edit) still verifies.
  const resigned = tamper(out, join(tmp, 'resigned'), e => e, privateKey)
  assert.equal((await run(['verify', resigned])).code, 0)

  // A plain edit without refreshing the manifest trips the file hash.
  const plain = join(tmp, 'plain')
  cpSync(out, plain, { recursive: true })
  writeFileSync(join(plain, ARTIFACT), JSON.stringify(events.slice(1)))
  const p = await run(['verify', plain])
  assert.equal(p.code, 1)
  assert.match(JSON.parse(p.stdout).reason, /witness_events\.json sha256 mismatch/)

  const cases = {
    removed: [e => e.toSpliced(1, 1), /event 1 .*prev_event_hash/],
    'removed last': [e => e.slice(0, -1), /event 4 .*last_event|covers events/],
    altered: [e => (e[2].witnessed_at = '2020-01-01T00:00:00Z', e), /event 2 .*self_hash mismatch/],
    reordered: [e => ([e[3], e[4]] = [e[4], e[3]], e), /event 3 .*prev_event_hash/],
    // The last event edited and re-hashed: its own hash and link hold, but it
    // is no longer the event the signed block's chain_head_hash names.
    'rehashed head': [e => {
      const { self_hash, witness_signature, ...u } = { ...e[4], witnessed_at: '2020-01-01T00:00:00.000Z' }
      e[4] = { ...u, self_hash: sha256(canonicalizeBytes(u)), witness_signature }
      return e
    }, /event 4 .*chain_head_hash/],
  }
  for (const [name, [edit, reason]] of Object.entries(cases)) {
    const dir = tamper(out, join(tmp, name.replace(' ', '-')), edit, privateKey)
    const r = await run(['verify', dir])
    assert.equal(r.code, 1, `${name}: ${r.stdout}`)
    const v = JSON.parse(r.stdout)
    assert.equal(v.ok, false)
    assert.match(v.reason, reason, name)
    // A006 (T3): verify.sh walks the event chain too, for this OAI witness.
    const sh = verifySh(dir)
    assert.notEqual(sh.status, 0, `${name}: verify.sh accepted it`)
    assert.match(sh.stderr, /FAIL: .*(event|covers events)/, name)
  }
})
