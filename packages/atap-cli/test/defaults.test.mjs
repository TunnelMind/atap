// Commands take --dir/--key/--witness-oai/--ait from the nearest
// .atap/config.json when the flags are left out. Same harness as init.test.mjs:
// the built bin, run with cwd in a fresh temp dir.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const [EV] = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
const EVENT = JSON.stringify({ event_type: EV.event_type, payload: EV.payload })
const SUMMARY = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })

// Resolves with {code, stdout, stderr}; never rejects on a non-zero exit.
function run(cwd, args, stdin = '', env = {}) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env: { PATH: process.env.PATH, ...env } })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
}

async function ok(cwd, args, stdin, env) {
  const r = await run(cwd, args, stdin, env)
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout)
}

const lines = (dir, f) => readFileSync(join(dir, f), 'utf8').trim().split('\n').map(l => JSON.parse(l))

test('event, block, receipt and scitt export need no flags inside an init\'d dir, and from a subdir', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-defaults-'))
  const config = await ok(cwd, ['init'])
  const store = join(cwd, '.atap')

  await ok(cwd, ['event'], EVENT)
  const sub = join(cwd, 'a', 'b')
  mkdirSync(sub, { recursive: true })
  await ok(sub, ['event'], EVENT)
  await ok(sub, ['block'], SUMMARY)
  await ok(sub, ['receipt', '--out', 'r'])

  const events = lines(store, 'events.jsonl')
  assert.equal(events.length, 2)
  assert.ok(events.every(e => e.ait === config.ait))
  assert.equal(lines(store, 'blocks.jsonl').length, 1)
  assert.ok(!existsSync(join(sub, '.atap-witness')))
  assert.equal((await ok(cwd, ['verify', join(sub, 'r')])).ok, true)

  await ok(sub, ['scitt', 'export', 'r', '--issuer', config.witness_oai])
  assert.equal((await ok(sub, ['scitt', 'verify', 'r'])).ok, true)
})

test('explicit flags beat config; ATAP_WITNESS_OAI beats config but not the flag', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-defaults-'))
  const config = await ok(cwd, ['init'])
  const other = mkdtempSync(join(tmpdir(), 'atap-defaults-other-'))
  const otherCfg = await ok(other, ['init'])
  const otherStore = join(other, '.atap')

  // --dir and --ait other (with its key and OAI): the event lands in the other
  // store under the other AIT, not in this one.
  await ok(cwd, ['event', '--dir', otherStore, '--ait', otherCfg.ait, '--key', join(otherStore, otherCfg.key), '--witness-oai', otherCfg.witness_oai], EVENT)
  assert.equal(lines(otherStore, 'events.jsonl').length, 1)
  assert.ok(!existsSync(join(cwd, '.atap', 'events.jsonl')))

  // --ait other: refused because that AIT is not in this store.
  const badAit = await run(cwd, ['event', '--ait', 'ait-nope'], EVENT)
  assert.equal(badAit.code, 1)
  assert.match(badAit.stderr, /unknown AIT ait-nope/)

  // --key other.pem: a missing file, so the flag was used rather than config.
  const badKey = await run(cwd, ['event', '--key', 'other.pem'], EVENT)
  assert.equal(badKey.code, 1)
  assert.match(badKey.stderr, /cannot read the --key file/)

  // The AIT names its witness, so a different OAI is refused by name: the
  // refusal shows which value won.
  const env = { ATAP_WITNESS_OAI: 'OAI-0000-2222222' }
  const flagged = await run(cwd, ['event', '--witness-oai', 'OAI-0000-1111111'], EVENT, env)
  assert.equal(flagged.code, 1)
  assert.match(flagged.stderr, /not witnessed by OAI-0000-1111111/)
  const fromEnv = await run(cwd, ['event'], EVENT, env)
  assert.equal(fromEnv.code, 1)
  assert.match(fromEnv.stderr, /not witnessed by OAI-0000-2222222/)
  const fromConfig = await ok(cwd, ['event'], EVENT)
  assert.equal(fromConfig.ait, config.ait)
})

test('no .atap above cwd, or an unparseable config: unchanged behaviour', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-defaults-'))
  const r = await run(cwd, ['event'], EVENT)
  assert.equal(r.code, 1)
  assert.match(r.stderr, /--witness-oai <OAI> \(or ATAP_WITNESS_OAI\) is required/)

  mkdirSync(join(cwd, '.atap'))
  writeFileSync(join(cwd, '.atap', 'config.json'), '{not json')
  const bad = await run(cwd, ['event'], EVENT)
  assert.equal(bad.code, 1)
  assert.match(bad.stderr, /--witness-oai <OAI> \(or ATAP_WITNESS_OAI\) is required/)
})
