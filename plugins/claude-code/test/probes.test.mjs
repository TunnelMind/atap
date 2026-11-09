// The probe table: one row per "got" case from the owner's review of the
// constraints guard, each with the result it should have, run through the real
// hook script and the real CLI (harness as in constraints.test.mjs).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('../scripts/atap-hook.mjs', import.meta.url))
const CLI = fileURLToPath(new URL('../../../packages/atap-cli/dist/cli.js', import.meta.url))
const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()
const noCli = { skip: !existsSync(CLI) }

// The child's environment: the test runner's minus every switch the rows set
// themselves, so a strict flag in the developer's shell cannot leak into a control row.
function env(extra) {
  const { ATAP_OFF, ATAP_CONSTRAINTS_REQUIRED, ATAP_OPERATOR, ATAP_OPERATOR_KEY, ATAP_CONSTRAINTS, CLAUDE_PROJECT_DIR, ...base } = process.env
  return { ...base, ...extra }
}

// Run `node args...` with `raw` on stdin; the hook must exit 0 with an empty stderr.
// Returns the parsed stdout, or null when it printed nothing.
function spawn(args, cwd, raw, extra) {
  const r = spawnSync(process.execPath, args, { cwd, input: raw, env: env(extra), encoding: 'utf8' })
  assert.equal(r.status, 0)
  assert.equal(r.stderr, '')
  return r.stdout ? JSON.parse(r.stdout) : null
}

// A directory with no .atap/ at or above it (os.tmpdir() has none).
function bare(t) {
  const dir = mkdtempSync(join(tmpdir(), 'atap-probe-bare-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

// A git repo with `atap-witness init` run in it, and the hook pointed at the real CLI.
function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'atap-probe-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const wrapper = join(root, 'atap-witness')
  writeFileSync(wrapper, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(CLI)} "$@"\n`)
  chmodSync(wrapper, 0o755)
  const repo = join(root, 'repo')
  mkdirSync(repo)
  git(repo, 'init', '-q')
  const r = spawnSync(process.execPath, [CLI, 'init'], { cwd: repo, input: '', encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  const raw = (input) => JSON.stringify({ session_id: 's', cwd: repo, ...input })
  const hook = (event, stdin, extra = {}) => spawn([script, event], repo, stdin, { ATAP_WITNESS: wrapper, ...extra })
  return { repo, raw, hook }
}

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } })
const assertDeny = (d) => {
  assert.equal(d?.hookSpecificOutput?.hookEventName, 'PreToolUse')
  assert.equal(d.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /^ATAP: /)
}

// ---------------------------------------------------------------- A002 fail-open

test('A002: no .atap/ + ATAP_CONSTRAINTS_REQUIRED=1 denies', (t) => {
  const dir = bare(t)
  assertDeny(spawn([script, 'pre-tool-use'], dir, JSON.stringify({ session_id: 's', cwd: dir, ...bash('ls') }), { CLAUDE_PROJECT_DIR: dir, ATAP_CONSTRAINTS_REQUIRED: '1' }))
})

test('A002: no .atap/ + ATAP_OPERATOR denies', (t) => {
  const dir = bare(t)
  assertDeny(spawn([script, 'pre-tool-use'], dir, JSON.stringify({ session_id: 's', cwd: dir, ...bash('ls') }), { CLAUDE_PROJECT_DIR: dir, ATAP_OPERATOR: 'x' }))
})

test('A002: malformed stdin + ATAP_OPERATOR denies', noCli, (t) => {
  const { hook } = setup(t)
  assertDeny(hook('pre-tool-use', 'not json', { ATAP_OPERATOR: 'x' }))
})

test('A002: a throwing pre-tool-use handler in strict mode denies', noCli, (t) => {
  const { repo, raw } = setup(t)
  // The real main() with its pre-tool-use handler replaced in-process by one that throws:
  // no condition a real .atap/ can produce makes the handler throw, and an env-var seam
  // would be reachable in production.
  const code = `import { main, handlers } from ${JSON.stringify(new URL('../scripts/atap-hook.mjs', import.meta.url).href)}
handlers['pre-tool-use'] = async () => { throw new Error('boom') }
await main('pre-tool-use')`
  const d = spawn(['--input-type=module', '-e', code], repo, raw(bash('ls')), { ATAP_CONSTRAINTS_REQUIRED: '1' })
  assertDeny(d)
  assert.ok(!d.hookSpecificOutput.permissionDecisionReason.includes('boom'), 'the reason is fixed text, not the error')
})

test('A002 control: no .atap/ and neither flag set prints nothing', (t) => {
  const dir = bare(t)
  for (const event of ['session-start', 'pre-tool-use', 'post-tool-use', 'session-end']) {
    assert.equal(spawn([script, event], dir, JSON.stringify({ session_id: 's', cwd: dir, ...bash('ls') }), { CLAUDE_PROJECT_DIR: dir }), null, event)
  }
})

test('A002 control: malformed stdin with .atap/ and neither flag set prints nothing', noCli, (t) => {
  const { hook } = setup(t)
  assert.equal(hook('pre-tool-use', 'not json'), null)
})
