// `ait rotate` swaps the store's AIT for a fresh 365-day one; the old AIT's
// receipts keep verifying. Same harness as defaults.test.mjs: the built bin,
// run with cwd in a fresh temp dir.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const [EV] = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
const EVENT = JSON.stringify({ event_type: EV.event_type, payload: EV.payload })
const SUMMARY = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })
const DAY = 86400_000

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
const snapshot = dir => Object.fromEntries(readdirSync(dir).map(f => [f, readFileSync(join(dir, f), 'utf8')]))
const daysOut = ait => (Date.parse(ait.expires_at) - Date.parse(ait.issued_at)) / DAY

test('init declares a 365-day AIT', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-rotate-'))
  await ok(cwd, ['init'])
  const [ait] = lines(join(cwd, '.atap'), 'aits.jsonl')
  assert.ok(Math.abs(daysOut(ait) - 365) < 1 / 24, `${daysOut(ait)} days`)
})

test('rotate moves config to a new AIT; old and new receipts both verify', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-rotate-'))
  const store = join(cwd, '.atap')
  const before = await ok(cwd, ['init'])
  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  const oldEvents = readFileSync(join(store, 'events.jsonl'), 'utf8')
  const oldBlocks = readFileSync(join(store, 'blocks.jsonl'), 'utf8')

  const after = await ok(cwd, ['ait', 'rotate'])
  assert.notEqual(after.ait, before.ait)
  assert.deepEqual({ ...after, ait: before.ait }, before)
  assert.deepEqual(JSON.parse(readFileSync(join(store, 'config.json'), 'utf8')), after)
  const aits = lines(store, 'aits.jsonl')
  assert.equal(aits.length, 2)
  const [oldAit, newAit] = aits
  assert.equal(newAit.id, after.ait)
  assert.ok(Math.abs(daysOut(newAit) - 365) < 1 / 24, `${daysOut(newAit)} days`)
  for (const k of ['profile', 'operator', 'capabilities', 'attestation_policy']) assert.deepEqual(newAit[k], oldAit[k])
  // The old AIT's chain is untouched.
  assert.equal(readFileSync(join(store, 'events.jsonl'), 'utf8'), oldEvents)
  assert.equal(readFileSync(join(store, 'blocks.jsonl'), 'utf8'), oldBlocks)

  await ok(cwd, ['receipt', '--ait', before.ait, '--out', 'old'])
  assert.equal((await ok(cwd, ['verify', 'old'])).ok, true)

  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  assert.equal(lines(store, 'events.jsonl').at(-1).ait, after.ait)
  assert.equal(lines(store, 'blocks.jsonl').at(-1).ait, after.ait)
  await ok(cwd, ['receipt', '--out', 'new'])
  const v = await ok(cwd, ['verify', 'new'])
  assert.equal(v.ok, true)
  assert.equal(v.blocks, 1)
})

test('rotate refuses, writing nothing, without a config or with an unknown AIT', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-rotate-'))
  const config = await ok(cwd, ['init'])
  const store = join(cwd, '.atap')

  // A valid key and OAI, but no config.json to rotate.
  const bare = mkdtempSync(join(tmpdir(), 'atap-rotate-'))
  const r = await run(bare, ['ait', 'rotate', '--key', join(store, 'witness.pem'), '--witness-oai', config.witness_oai, '--ait', config.ait])
  assert.equal(r.code, 1)
  assert.match(r.stderr, /config\.json/)
  assert.deepEqual(readdirSync(bare), [])

  const was = snapshot(store)
  const u = await run(cwd, ['ait', 'rotate', '--ait', 'AIT-00000000-0000-7000-8000-000000000000'])
  assert.equal(u.code, 1)
  assert.match(u.stderr, /unknown AIT/)
  assert.deepEqual(snapshot(store), was)

  // A subdir with no .atap of its own still finds the parent's and rotates it.
  mkdirSync(join(cwd, 'sub'))
  assert.notEqual((await ok(join(cwd, 'sub'), ['ait', 'rotate'])).ait, JSON.parse(was['config.json']).ait)
})
