// P801: the plugin scaffold. Manifests have the right shape and the hook script
// is a silent exit-0 no-op in every case it can't act. Nothing here installs the
// plugin or touches ~/.claude.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const script = join(root, 'scripts', 'atap-hook.mjs')
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'))

// Runs the hook as Claude Code would: event in argv, JSON on stdin, cwd = project.
function hook(event, stdin, { cwd, env = {} } = {}) {
  const { ATAP_OFF, ...base } = process.env
  return spawnSync(process.execPath, [script, event], { cwd, input: stdin, env: { ...base, ...env }, encoding: 'utf8' })
}

function tempDir(t) {
  const d = mkdtempSync(join(tmpdir(), 'atap-plugin-'))
  t.after(() => rmSync(d, { recursive: true, force: true }))
  return d
}

function assertSilentExit0(r) {
  assert.equal(r.status, 0)
  assert.equal(r.stdout, '')
  assert.equal(r.stderr, '')
}

test('plugin.json names the plugin atap', () => {
  const m = readJson(join(root, '.claude-plugin', 'plugin.json'))
  assert.equal(m.name, 'atap')
  assert.ok(m.description)
  assert.ok(m.version)
})

test('hooks.json wires the three events to the script, each within 10 s', () => {
  const { hooks } = readJson(join(root, 'hooks', 'hooks.json'))
  assert.deepEqual(Object.keys(hooks).sort(), ['PostToolUse', 'SessionEnd', 'SessionStart'])
  assert.equal(hooks.PostToolUse[0].matcher, 'Bash')
  const args = { SessionStart: 'session-start', PostToolUse: 'post-tool-use', SessionEnd: 'session-end' }
  for (const [event, groups] of Object.entries(hooks)) {
    for (const h of groups.flatMap((g) => g.hooks)) {
      assert.equal(h.type, 'command')
      assert.ok(h.timeout > 0 && h.timeout <= 10, `${event} timeout ${h.timeout}`)
      assert.ok(h.command.includes('${CLAUDE_PLUGIN_ROOT}/scripts/atap-hook.mjs'), h.command)
      assert.ok(h.command.endsWith(` ${args[event]}`), h.command)
    }
  }
})

test('marketplace.json lists atap from ./plugins/claude-code', () => {
  const m = readJson(join(root, '..', '..', '.claude-plugin', 'marketplace.json'))
  assert.ok(m.owner?.name)
  const entry = m.plugins.find((p) => p.name === 'atap')
  assert.equal(entry?.source, './plugins/claude-code')
})

test('malformed stdin: exit 0, silent', (t) => {
  assertSilentExit0(hook('post-tool-use', '{not json', { cwd: tempDir(t) }))
})

test('ATAP_OFF=1: exit 0, silent, nothing logged even with .atap/', (t) => {
  const d = tempDir(t)
  mkdirSync(join(d, '.atap'))
  writeFileSync(join(d, '.atap', 'config.json'), '{}')
  assertSilentExit0(hook('post-tool-use', '{not json', { cwd: d, env: { ATAP_OFF: '1' } }))
  assert.throws(() => readFileSync(join(d, '.atap', 'hook.log')))
})

test('no .atap/ at or above cwd: exit 0, silent, for every event', (t) => {
  const d = tempDir(t)
  for (const event of ['session-start', 'post-tool-use', 'session-end']) {
    assertSilentExit0(hook(event, JSON.stringify({ session_id: 's', cwd: d }), { cwd: d }))
  }
})

test('malformed stdin with .atap/: exit 0, silent, one hook.log line without the input', (t) => {
  const d = tempDir(t)
  mkdirSync(join(d, '.atap'))
  writeFileSync(join(d, '.atap', 'config.json'), '{}')
  assertSilentExit0(hook('post-tool-use', '{"secret": ', { cwd: d }))
  const lines = readFileSync(join(d, '.atap', 'hook.log'), 'utf8').trim().split('\n')
  assert.equal(lines.length, 1)
  assert.match(lines[0], /post-tool-use malformed stdin$/)
})

test('claude plugin validate --strict', (t) => {
  const v = spawnSync('claude', ['plugin', 'validate', '--strict', root], { encoding: 'utf8' })
  if (v.error?.code === 'ENOENT') return t.skip('claude is not on PATH')
  assert.equal(v.status, 0, v.stdout + v.stderr)
})
