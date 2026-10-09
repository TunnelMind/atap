// P802: PostToolUse turns a successful `git commit` into change_committed and a
// test command into verify_run. A stub `atap-witness` (set via ATAP_WITNESS)
// appends each stdin it gets to a file, so no real CLI, network or ~/.claude.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('../scripts/atap-hook.mjs', import.meta.url))
const HEX64 = /^[0-9a-f]{64}$/

// A project with .atap/config.json and a stub CLI writing to calls.jsonl.
function project(t, config = {}) {
  const d = mkdtempSync(join(tmpdir(), 'atap-ptu-'))
  t.after(() => rmSync(d, { recursive: true, force: true }))
  mkdirSync(join(d, '.atap'))
  writeFileSync(join(d, '.atap', 'config.json'), JSON.stringify(config))
  // CommonJS (.cjs) so the one-liner can use require.
  const stub = join(d, 'stub-witness.cjs')
  writeFileSync(
    stub,
    `#!${process.execPath}\nlet s='';process.stdin.on('data',c=>s+=c).on('end',()=>require('fs').appendFileSync(${JSON.stringify(join(d, 'calls.jsonl'))},s+'\\n'))\n`,
  )
  chmodSync(stub, 0o755)
  return { dir: d, stub }
}

function hook(p, input) {
  const { ATAP_OFF, ...env } = process.env
  const r = spawnSync(process.execPath, [script, 'post-tool-use'], {
    cwd: p.dir,
    input: JSON.stringify({ session_id: 's', cwd: p.dir, tool_name: 'Bash', ...input }),
    env: { ...env, ATAP_WITNESS: p.stub },
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

const git = (cwd, ...args) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...args], { cwd, encoding: 'utf8' }).trim()

function repoWithCommit(p, origin) {
  git(p.dir, 'init', '-q')
  if (origin) git(p.dir, 'remote', 'add', 'origin', origin)
  writeFileSync(join(p.dir, 'f'), 'x')
  git(p.dir, 'add', 'f')
  git(p.dir, 'commit', '-qm', 'secret message')
  return git(p.dir, 'rev-parse', 'HEAD')
}

test('successful git commit: one change_committed with the HEAD sha and owner/repo', (t) => {
  const p = project(t)
  const sha = repoWithCommit(p, 'git@github.com:owner/repo.git')
  hook(p, { tool_input: { command: 'git add . && git -c core.x=y commit -m "secret message"' }, tool_response: { stdout: 'ok', stderr: '' } })
  const c = calls(p)
  assert.equal(c.length, 1)
  assert.equal(c[0].event_type, 'code_crew:change_committed')
  assert.deepEqual(Object.keys(c[0]).sort(), ['event_type', 'payload'])
  const { timestamp, ...rest } = c[0].payload
  assert.ok(!Number.isNaN(Date.parse(timestamp)))
  assert.deepEqual(rest, { evidence: 'anchored', repo: 'owner/repo', commit_sha: sha })
})

test('failed commit, git commit --dry-run and ls: no CLI call', (t) => {
  const p = project(t)
  repoWithCommit(p, 'https://github.com/owner/repo.git')
  hook(p, { tool_input: { command: 'git commit -m x' }, tool_response: { stdout: '', stderr: '', exit_code: 1 } })
  hook(p, { tool_input: { command: 'git commit --dry-run' }, tool_response: { stdout: '' } })
  hook(p, { tool_input: { command: 'ls' }, tool_response: { stdout: 'f' } })
  assert.deepEqual(calls(p), [])
  assert.deepEqual(hookLog(p), [])
})

test('commit with no origin, or a path origin: no CLI call, one fixed log line', (t) => {
  for (const origin of [null, '/srv/git/owner/repo.git']) {
    const p = project(t)
    repoWithCommit(p, origin)
    hook(p, { tool_input: { command: 'git commit -m "secret message"' }, tool_response: { stdout: '' } })
    assert.deepEqual(calls(p), [])
    const lines = hookLog(p)
    assert.equal(lines.length, 1)
    assert.match(lines[0], / post-tool-use no owner\/repo$/)
  }
})

function assertVerifyRun(c, command, exit_code, output) {
  assert.equal(c.event_type, 'code_crew:verify_run')
  const { timestamp, command_sha256, output_sha256, ...rest } = c.payload
  assert.ok(!Number.isNaN(Date.parse(timestamp)))
  assert.match(command_sha256, HEX64)
  assert.match(output_sha256, HEX64)
  assert.deepEqual(rest, { evidence: 'asserted', exit_code })
  const h = (s) => createHash('sha256').update(s).digest('hex')
  assert.equal(command_sha256, h(command))
  assert.equal(output_sha256, h(output))
}

test('default test command: verify_run via tool_response (failing) and tool_output (string, object)', (t) => {
  const p = project(t)
  hook(p, { tool_input: { command: 'npm test' }, tool_response: { stdout: 'out', stderr: 'err', exit_code: 1 } })
  hook(p, { tool_input: { command: 'cd x && pytest -q' }, tool_output: 'passed' })
  hook(p, { tool_input: { command: 'npm test -- --foo' }, tool_output: { stdout: 'a', stderr: 'b', exitCode: 2 } })
  hook(p, { tool_input: { command: 'npm testing' }, tool_output: 'x' })
  const c = calls(p)
  assert.equal(c.length, 3)
  assertVerifyRun(c[0], 'npm test', 1, 'outerr')
  assertVerifyRun(c[1], 'cd x && pytest -q', 0, 'passed')
  assertVerifyRun(c[2], 'npm test -- --foo', 2, 'ab')
})

test('config test_commands replaces the default list', (t) => {
  const p = project(t, { test_commands: ['make check'] })
  hook(p, { tool_input: { command: 'make check' }, tool_response: { stdout: '' } })
  hook(p, { tool_input: { command: 'npm test' }, tool_response: { stdout: '' } })
  const c = calls(p)
  assert.equal(c.length, 1)
  assertVerifyRun(c[0], 'make check', 0, '')
})

test('missing CLI or failing CLI: fixed log line, still silent', (t) => {
  const p = project(t)
  p.stub = join(p.dir, 'nope')
  hook(p, { tool_input: { command: 'npm test' }, tool_response: { stdout: '' } })
  const fail = join(p.dir, 'fail.cjs')
  writeFileSync(fail, `#!${process.execPath}\nprocess.stderr.write('leak');process.exit(3)\n`)
  chmodSync(fail, 0o755)
  p.stub = fail
  hook(p, { tool_input: { command: 'npm test' }, tool_response: { stdout: '' } })
  const lines = hookLog(p)
  assert.equal(lines.length, 2)
  assert.match(lines[0], /atap-witness not found$/)
  assert.match(lines[1], /atap-witness event failed: exit 3$/)
})
