// `atap-witness init`: one command to a working local witness. Runs the built
// bin with cwd set to a fresh temp dir, so the default ./.atap lands there.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))

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

// Every file under dir with its bytes, so "nothing changed" is one deepEqual.
function snapshot(dir) {
  return Object.fromEntries(
    readdirSync(dir, { recursive: true }).sort().map(f => [f, statSync(join(dir, f)).isFile() ? readFileSync(join(dir, f), 'hex') : 'dir']),
  )
}

async function initOk(cwd, args = []) {
  const r = await run(cwd, ['init', ...args])
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout)
}

test('init creates only ./.atap with key, .gitignore, config and a declared AIT', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-init-'))
  const out = await initOk(cwd)
  assert.deepEqual(readdirSync(cwd), ['.atap'])
  const dir = join(cwd, '.atap')
  assert.deepEqual(readdirSync(dir).sort(), ['.gitignore', 'aits.jsonl', 'config.json', 'witness.pem'])

  assert.equal(statSync(join(dir, 'witness.pem')).mode & 0o777, 0o600)
  assert.match(readFileSync(join(dir, 'witness.pem'), 'utf8'), /^-----BEGIN PRIVATE KEY-----/)
  assert.ok(readFileSync(join(dir, '.gitignore'), 'utf8').split('\n').includes('witness.pem'))

  const config = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8'))
  assert.deepEqual(out, config)
  assert.equal(config.profile, 'tunnelmind:code_crew:v1')
  assert.equal(config.key, 'witness.pem')
  assert.match(config.witness_oai, /^OAI-0000-[0-9]{7}$/)
  assert.equal(config.oai_origin, 'self-asserted')
  assert.ok(!JSON.stringify(out).includes('PRIVATE KEY'))

  const aits = readFileSync(join(dir, 'aits.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l))
  assert.equal(aits.length, 1)
  const [ait] = aits
  assert.equal(ait.id, config.ait)
  assert.equal(ait.witness, config.witness_oai)
  assert.equal(ait.operator, config.witness_oai)
  assert.deepEqual(ait.capabilities, Object.keys(JSON.parse(readFileSync(join(PROFILE_DIR, 'capabilities.json'), 'utf8')).capabilities))
  // §7.6: no local path in the signed AIT.
  assert.ok(!JSON.stringify(ait).includes(cwd))
})

test('a second init without --force exits 1 and changes nothing', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-init-'))
  await initOk(cwd)
  const before = snapshot(cwd)
  const r = await run(cwd, ['init'])
  assert.equal(r.code, 1)
  assert.match(r.stderr, /^\{"error":".*--force/)
  assert.deepEqual(snapshot(cwd), before)
})

test('--force re-inits an event-free store but refuses once it holds events', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-init-'))
  const first = await initOk(cwd)
  const second = await initOk(cwd, ['--force'])
  assert.notEqual(second.ait, first.ait)
  const dir = join(cwd, '.atap')
  assert.equal(readFileSync(join(dir, 'aits.jsonl'), 'utf8').trim().split('\n').length, 1)

  const [ev] = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
  const added = await run(cwd, ['event', '--dir', '.atap', '--ait', second.ait, '--key', join(dir, second.key), '--witness-oai', second.witness_oai],
    JSON.stringify({ event_type: ev.event_type, payload: ev.payload }))
  assert.equal(added.code, 0, added.stderr)

  const before = snapshot(cwd)
  const r = await run(cwd, ['init', '--force'])
  assert.equal(r.code, 1)
  assert.match(r.stderr, /events/)
  assert.deepEqual(snapshot(cwd), before)
})

test('unknown --profile exits 1 and leaves no dir', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-init-'))
  const r = await run(cwd, ['init', '--profile', 'nobody:nothing:v1'])
  assert.equal(r.code, 1)
  assert.match(r.stderr, /registry/)
  assert.deepEqual(readdirSync(cwd), [])
})

test('--dir picks another location and nothing lands outside it', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-init-'))
  const out = await initOk(cwd, ['--dir', 'w', '--profile', 'tunnelmind:crew_ops:v1'])
  assert.equal(out.profile, 'tunnelmind:crew_ops:v1')
  assert.deepEqual(readdirSync(cwd), ['w'])
  assert.ok(!existsSync(join(cwd, '.atap')))
})
