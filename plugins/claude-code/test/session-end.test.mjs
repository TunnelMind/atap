// P803: SessionEnd closes a block over the AIT's pending events with an
// integer period summary; SessionStart does nothing. A stub `atap-witness`
// (set via ATAP_WITNESS) appends {args, stdin} per call to a file.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('../scripts/atap-hook.mjs', import.meta.url))
const AIT = 'ait:test'

function project(t, { config = { ait: AIT }, events = [], cleared = [], stub = true } = {}) {
  const d = mkdtempSync(join(tmpdir(), 'atap-se-'))
  t.after(() => rmSync(d, { recursive: true, force: true }))
  mkdirSync(join(d, '.atap'))
  writeFileSync(join(d, '.atap', 'config.json'), JSON.stringify(config))
  const jsonl = (rows) => rows.map((r) => JSON.stringify(r) + '\n').join('')
  if (events.length) writeFileSync(join(d, '.atap', 'events.jsonl'), jsonl(events))
  if (cleared.length) writeFileSync(join(d, '.atap', 'cleared.jsonl'), jsonl(cleared))
  const bin = join(d, 'stub-witness.cjs')
  writeFileSync(
    bin,
    `#!${process.execPath}\nlet s='';process.stdin.on('data',c=>s+=c).on('end',()=>require('fs').appendFileSync(${JSON.stringify(join(d, 'calls.jsonl'))},JSON.stringify({args:process.argv.slice(2),stdin:JSON.parse(s)})+'\\n'))\n`,
  )
  chmodSync(bin, 0o755)
  return { dir: d, stub: stub ? bin : join(d, 'missing-witness') }
}

function hook(p, event = 'session-end', extraEnv = {}) {
  const { ATAP_OFF, ...env } = process.env
  const r = spawnSync(process.execPath, [script, event], {
    cwd: p.dir,
    input: JSON.stringify({ session_id: 's', cwd: p.dir, hook_event_name: 'SessionEnd' }),
    env: { ...env, ATAP_WITNESS: p.stub, ...extraEnv },
    encoding: 'utf8',
  })
  assert.equal(r.status, 0)
  assert.equal(r.stdout, '')
  assert.equal(r.stderr, '')
}

const calls = (p) => {
  const f = join(p.dir, 'calls.jsonl')
  return existsSync(f) ? readFileSync(f, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : []
}
const hookLog = (p) => {
  const f = join(p.dir, '.atap', 'hook.log')
  return existsSync(f) ? readFileSync(f, 'utf8').trim().split('\n') : []
}

const commit = (id, ait = AIT) => ({ id, ait, event_type: 'code_crew:change_committed', payload: { commit_sha: 'a'.repeat(40) } })
const verify = (id, exit_code, ait = AIT) => ({ id, ait, event_type: 'code_crew:verify_run', payload: { exit_code } })
const SESSION = [commit('e1'), verify('e2', 0), verify('e3', 7), commit('e4'), verify('e5', 0)]

// The period-summary schema: exactly these keys, integer counts >= 0, overturns an object.
function assertSchema(s) {
  assert.deepEqual(Object.keys(s).sort(), ['merged_changes', 'overturns', 'tasks_accepted', 'tasks_rework', 'tokens'])
  for (const k of ['tasks_accepted', 'tasks_rework', 'merged_changes', 'tokens']) assert.ok(Number.isInteger(s[k]) && s[k] >= 0, k)
  assert.ok(s.overturns && typeof s.overturns === 'object' && !Array.isArray(s.overturns))
}

test('pending events: one `block` call with the counted summary', (t) => {
  const p = project(t, { events: SESSION })
  hook(p)
  const c = calls(p)
  assert.equal(c.length, 1)
  assert.deepEqual(c[0].args, ['block'])
  assert.deepEqual(c[0].stdin, { tasks_accepted: 2, tasks_rework: 1, merged_changes: 2, tokens: 0, overturns: {} })
  assertSchema(c[0].stdin)
  assert.deepEqual(hookLog(p), [])
})

test('cleared marker: only events after it are counted', (t) => {
  const p = project(t, { events: SESSION, cleared: [{ ait: 'ait:other', after: 'e5' }, { ait: AIT, after: 'e1' }, { ait: AIT, after: 'e3' }] })
  hook(p)
  const c = calls(p)
  assert.equal(c.length, 1)
  assert.deepEqual(c[0].stdin, { tasks_accepted: 1, tasks_rework: 0, merged_changes: 1, tokens: 0, overturns: {} })
  assertSchema(c[0].stdin)
})

test('other AIT events ignored; nothing pending means no CLI call', (t) => {
  const other = project(t, { events: [commit('x1', 'ait:other'), verify('x2', 0, 'ait:other')] })
  hook(other)
  assert.deepEqual(calls(other), [])
  const cleared = project(t, { events: SESSION, cleared: [{ ait: AIT, after: 'e5' }] })
  hook(cleared)
  assert.deepEqual(calls(cleared), [])
  const empty = project(t)
  hook(empty)
  assert.deepEqual(calls(empty), [])
  assert.deepEqual(hookLog(empty), [])
})

test('session-start is a silent no-op', (t) => {
  const p = project(t, { events: SESSION })
  hook(p, 'session-start')
  assert.deepEqual(calls(p), [])
  assert.deepEqual(hookLog(p), [])
})

test('ATAP_OFF=1: no CLI call', (t) => {
  const p = project(t, { events: SESSION })
  hook(p, 'session-end', { ATAP_OFF: '1' })
  assert.deepEqual(calls(p), [])
})

test('no ait in config, missing CLI and bad JSONL: one fixed-text log line each', (t) => {
  const noAit = project(t, { config: {}, events: SESSION })
  hook(noAit)
  assert.equal(hookLog(noAit).length, 1)
  assert.match(hookLog(noAit)[0], / session-end no ait in config$/)

  const missing = project(t, { events: SESSION, stub: false })
  hook(missing)
  assert.equal(hookLog(missing).length, 1)
  assert.match(hookLog(missing)[0], / session-end atap-witness not found$/)

  const bad = project(t, { events: SESSION })
  writeFileSync(join(bad.dir, '.atap', 'events.jsonl'), '{"secret": tru\n')
  hook(bad)
  assert.deepEqual(calls(bad), [])
  assert.equal(hookLog(bad).length, 1)
  assert.match(hookLog(bad)[0], / session-end Error: bad line in events\.jsonl$/)
})

test('failing CLI: fixed text with the exit code, no CLI output', (t) => {
  const p = project(t, { events: SESSION })
  writeFileSync(p.stub, `#!${process.execPath}\nprocess.stdout.write('secret');process.stderr.write('secret');process.exit(3)\n`)
  hook(p)
  assert.deepEqual(hookLog(p).map((l) => l.replace(/^\S+ /, '')), ['session-end atap-witness block failed: exit 3'])
})
