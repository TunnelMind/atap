// ATAP_OFF=1 kill switch and uninstall: event/block become no-ops, and
// removing .atap leaves nothing behind.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const EVENT = '{"event_type":"code_crew:task_claimed","payload":{"timestamp":"2026-10-08T12:00:01.500Z","evidence":"asserted","task_id":"A101","role":"coder","model":"claude-opus-5-5"}}'
const BLOCK = '{"tasks_accepted":1,"tasks_rework":0,"merged_changes":0,"tokens":0,"overturns":{}}'

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

// Every file under dir with its bytes, so "nothing changed" is one deepEqual.
function snapshot(dir) {
  return Object.fromEntries(
    readdirSync(dir, { recursive: true }).sort().map(f => [f, statSync(join(dir, f)).isFile() ? readFileSync(join(dir, f), 'hex') : 'dir']),
  )
}

async function ok(cwd, args, stdin, env) {
  const r = await run(cwd, args, stdin, env)
  assert.equal(r.code, 0, r.stderr)
  return r
}

function assertOff(r, cmd) {
  assert.equal(r.code, 0, r.stderr)
  assert.equal(r.stdout, '')
  const lines = r.stderr.split('\n').filter(Boolean)
  assert.equal(lines.length, 1, r.stderr)
  assert.equal(r.stderr, lines[0] + '\n')
  assert.match(lines[0], new RegExp(`ATAP_OFF=1.*${cmd}`))
}

test('ATAP_OFF=1: event and block are no-ops that leave .atap byte-identical', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-off-'))
  await ok(cwd, ['init'])
  const before = snapshot(join(cwd, '.atap'))
  assertOff(await run(cwd, ['event'], EVENT, { ATAP_OFF: '1' }), 'event')
  assertOff(await run(cwd, ['block'], BLOCK, { ATAP_OFF: '1' }), 'block')
  assert.deepEqual(snapshot(join(cwd, '.atap')), before)
})

test('ATAP_OFF=1 with no .atap and no stdin: exit 0, nothing created', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-off-'))
  assertOff(await run(cwd, ['event'], '', { ATAP_OFF: '1' }), 'event')
  assertOff(await run(cwd, ['block'], '', { ATAP_OFF: '1' }), 'block')
  assert.deepEqual(readdirSync(cwd), [])
})

test('ATAP_OFF=0 or unset still writes events', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-off-'))
  await ok(cwd, ['init'])
  const count = () => readFileSync(join(cwd, '.atap', 'events.jsonl'), 'utf8').trim().split('\n').length
  await ok(cwd, ['event'], EVENT, { ATAP_OFF: '0' })
  assert.equal(count(), 1)
  await ok(cwd, ['event'], EVENT.replace('01.500Z', '02.500Z'))
  assert.equal(count(), 2)
  // Other commands ignore the switch.
  const s = await ok(cwd, ['status'], '', { ATAP_OFF: '1' })
  assert.equal(JSON.parse(s.stdout).events, 2)
})

test('uninstall: init + event + block create only .atap, and removing it empties the dir', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-off-'))
  assert.deepEqual(readdirSync(cwd), [])
  await ok(cwd, ['init'])
  assert.deepEqual(readdirSync(cwd), ['.atap'])
  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], BLOCK)
  assert.deepEqual(readdirSync(cwd), ['.atap'])
  rmSync(join(cwd, '.atap'), { recursive: true })
  assert.deepEqual(readdirSync(cwd), [])
})
