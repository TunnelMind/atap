// init's detection + next steps on stderr, and `atap-witness status`. Same
// harness as init.test.mjs: the built bin, cwd in a fresh temp dir.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const SUMMARY = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })

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

test('init prints detection and next steps on stderr, and the event recipe runs as written', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-status-'))
  mkdirSync(join(cwd, '.git'))
  writeFileSync(join(cwd, 'pyproject.toml'), '')
  const r = await run(cwd, ['init'])
  assert.equal(r.code, 0, r.stderr)
  JSON.parse(r.stdout)
  assert.deepEqual(readdirSync(cwd).sort(), ['.atap', '.git', 'pyproject.toml'])
  assert.match(r.stderr, /^git: yes$/m)
  assert.match(r.stderr, /^python: yes$/m)
  assert.match(r.stderr, /^github: no$/m)
  assert.match(r.stderr, /not released yet/)
  assert.doesNotMatch(r.stderr, /pip install|npm i|claude plugin|uses: /)
  for (const step of ['| atap-witness block', 'atap-witness receipt --out DIR', 'atap-witness verify DIR']) assert.ok(r.stderr.includes(step), step)

  // Pull the payload out of the printed `echo '...' | atap-witness event` line.
  const line = r.stderr.split('\n').find(l => l.includes('| atap-witness event'))
  const stdin = line.match(/echo '(.*)' \| atap-witness event/)[1]
  assert.equal((await ok(cwd, ['event'], stdin)).event_type, 'code_crew:task_claimed')
  const block = r.stderr.split('\n').find(l => l.includes('| atap-witness block')).match(/echo '(.*)' \|/)[1]
  await ok(cwd, ['block'], block)
})

test('status reports config, counts and the last receipt; outside any .atap it exits 1', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-status-'))
  const config = await ok(cwd, ['init'])
  const sub = join(cwd, 'a', 'b')
  mkdirSync(sub, { recursive: true })

  const fresh = await ok(sub, ['status'])
  assert.deepEqual(fresh, {
    profile: config.profile, ait: config.ait, witness_oai: config.witness_oai, dir: join(cwd, '.atap'),
    events: 0, blocks: 0, last_receipt: null,
  })

  const ev = JSON.stringify({ event_type: 'code_crew:task_claimed', payload: { timestamp: '2026-10-08T12:00:01.500Z', evidence: 'asserted', task_id: 'A1', role: 'coder', model: 'm' } })
  await ok(sub, ['event'], ev)
  await ok(sub, ['block'], SUMMARY)
  const before = await ok(sub, ['status'])
  assert.equal(before.last_receipt, null)
  const rcpt = await ok(sub, ['receipt', '--out', 'r'])

  const s = await ok(sub, ['status'])
  assert.equal(s.events, 1)
  assert.equal(s.blocks, 1)
  assert.equal(s.last_receipt.out, join(sub, 'r'))
  assert.equal(s.last_receipt.id, rcpt.id)
  assert.ok(!Number.isNaN(Date.parse(s.last_receipt.at)))

  const outside = await run(mkdtempSync(join(tmpdir(), 'atap-status-none-')), ['status'])
  assert.equal(outside.code, 1)
  assert.match(outside.stderr, /^\{"error":".*init/)
})
