// GATE F probe table for atap-constraints-1: one row per "got" case from the
// owner's review of the constraints guard, each with the result it should have,
// run through the real hook script and the real CLI (harness as in
// constraints.test.mjs), or through evaluateCall directly. Covers:
//   A002 fail-open (strict mode)      A003 other shells
//   A004 Windows paths                A005 the guard cannot edit itself
//   A006 command forms                A007 paths on shells / search reach
//   A008 false denials
// Rows are top-level test() calls plus the loop-generated ones (A006, A007, A008).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateKeyPairSync, createPublicKey } from 'node:crypto'
import { signConstraintSet, foldConstraints, evaluateCall, didKeyFromPublicKey } from '../../../packages/atap-js/dist/index.js'

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
  return { repo, raw, hook, wrapper }
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

// ---------------------------------------------------------------- A003 other shells
// evaluateCall rows: a rule keyed on a shell command applies to any tool with a string
// `command` or `script`, not only tool_name Bash.

const ROOT = '/work/proj'
const ctx = { projectRoot: ROOT, protectedPaths: [`${ROOT}/.atap`, `${ROOT}/.claude/settings.json`] }
const call = (tool_name, tool_input) => ({ tool_name, tool_input, cwd: ROOT })
const opKey = generateKeyPairSync('ed25519').privateKey
const opDid = didKeyFromPublicKey(new Uint8Array(Buffer.from(createPublicKey(opKey).export({ format: 'jwk' }).x, 'base64url')))
const rules = (...r) => foldConstraints([signConstraintSet({ constraint_id: 'a003', scope: '*', prose: 'A003 probe.', rules: r }, opKey)], opDid, '*').active

test('A003: PowerShell Remove-Item .atap/constraints.jsonl denies', () => {
  assert.equal(evaluateCall([], call('PowerShell', { command: 'Remove-Item .atap/constraints.jsonl' }), ctx).decision, 'deny')
})

test('A003: mcp__wsl__run rm .atap/constraints.jsonl denies', () => {
  assert.equal(evaluateCall([], call('mcp__wsl__run', { command: 'rm .atap/constraints.jsonl' }), ctx).decision, 'deny')
})

test('A003: {tools:["mcp__*"], commands:["git push*"]} denies mcp__wsl__run git push', () => {
  const active = rules({ id: 'push', effect: 'forbid', tools: ['mcp__*'], commands: ['git push*'] })
  assert.equal(evaluateCall(active, call('mcp__wsl__run', { command: 'git push' }), ctx).decision, 'deny')
})

test('A003: a tool with {script: "git push"} under commands git push* denies', () => {
  const active = rules({ id: 'push', effect: 'forbid', tools: ['*'], commands: ['git push*'] })
  assert.equal(evaluateCall(active, call('RunScript', { script: 'git push' }), ctx).decision, 'deny')
})

test('A003: a non-shell MCP tool with a path arg is still path-checked', () => {
  const active = rules({ id: 'secrets', effect: 'forbid', tools: ['mcp__*'], paths: ['secrets/**'] })
  assert.equal(evaluateCall(active, call('mcp__fs__read_file', { path: 'secrets/k.txt' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('mcp__fs__read_file', { path: 'src/a.ts' }), ctx).decision, 'allow')
})

// ---------------------------------------------------------------- A004 Windows paths
// evaluateCall rows (Windows behaviour is proven on this POSIX host): a drive-letter project root turns
// windows mode on, so `\` separates, drive and case fold, and a relative path resolves against a Windows cwd.

const WIN = 'C:\\p'
const winCtx = { projectRoot: WIN, protectedPaths: [`${WIN}\\.atap`, `${WIN}\\.claude\\settings.json`] }
const winCall = (tool_name, tool_input) => ({ tool_name, tool_input, cwd: WIN })

test('A004: Write C:\\p\\.atap\\constraints.jsonl denies', () => {
  assert.equal(evaluateCall([], winCall('Write', { file_path: `${WIN}\\.atap\\constraints.jsonl` }), winCtx).decision, 'deny')
})

test('A004: secrets\\k and c:/P/Secrets/k under secrets/** deny', () => {
  const active = rules({ id: 'secrets', effect: 'forbid', tools: ['*'], paths: ['secrets/**'] })
  assert.equal(evaluateCall(active, winCall('Write', { file_path: 'secrets\\k' }), winCtx).decision, 'deny')
  assert.equal(evaluateCall(active, winCall('Write', { file_path: 'c:/P/Secrets/k' }), winCtx).decision, 'deny')
  assert.equal(evaluateCall(active, winCall('Write', { file_path: `${WIN}\\docs\\a` }), winCtx).decision, 'allow')
})

// ---------------------------------------------------------------- A005 the guard cannot edit itself
// Through the real hook: a copy of the hook inside the project (a project that contains the plugin),
// so the plugin root it passes the CLI is <repo>/plugins/claude-code.

function withPlugin(t) {
  const s = setup(t)
  const scripts = join(s.repo, 'plugins', 'claude-code', 'scripts')
  mkdirSync(scripts, { recursive: true })
  const own = join(scripts, 'atap-hook.mjs')
  copyFileSync(script, own)
  const home = join(s.repo, '..', 'home')
  mkdirSync(home)
  // ATAP_OPERATOR turns the guard on with no store; HOME moves ~/.claude.json into the sandbox.
  const pre = (input) => spawn([own, 'pre-tool-use'], s.repo, s.raw(input), { ATAP_WITNESS: s.wrapper, ATAP_OPERATOR: opDid, HOME: home })
  return { ...s, own, home, pre }
}
const selfDeny = (d) => {
  assert.equal(d?.hookSpecificOutput?.permissionDecision, 'deny', JSON.stringify(d))
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /atap\.self-protect\/store-write/)
}

test('A005: Edit of the plugin\'s scripts/atap-hook.mjs denies', noCli, (t) => {
  const { own, pre } = withPlugin(t)
  selfDeny(pre({ tool_name: 'Edit', tool_input: { file_path: own, old_string: 'a', new_string: 'b' } }))
})

test('A005: Write ~/.claude.json denies', noCli, (t) => {
  const { home, pre } = withPlugin(t)
  selfDeny(pre({ tool_name: 'Write', tool_input: { file_path: join(home, '.claude.json'), content: '{}' } }))
})

test('A005: Write of the ATAP_WITNESS file denies', noCli, (t) => {
  const { wrapper, pre } = withPlugin(t)
  selfDeny(pre({ tool_name: 'Write', tool_input: { file_path: wrapper, content: '' } }))
})

test('A005: Bash npm --prefix plugins/claude-code test in a project containing the plugin is allowed', noCli, (t) => {
  const { pre } = withPlugin(t)
  // The hook prints nothing on allow.
  assert.equal(pre(bash('npm --prefix plugins/claude-code test')), null)
})

// ---------------------------------------------------------------- A006 segment normaliser
// evaluateCall rows: shell keywords, wrapper flags, /dir/cmd, `\\cmd` and empty quotes cannot hide a `git push`.
const A006_PUSHES = [
  'if true; then git push; fi',
  'for i in 1; do git push; done',
  'true || { git push; }',
  '! git push',
  'sudo -u me git push',
  'env -i git push',
  'nice -n 5 git push',
  'time -p git push',
  '/usr/bin/git push',
  '\\git push',
  'g""it push',
]
for (const command of A006_PUSHES) {
  test(`A006: {commands:["git push*"]} denies Bash ${command}`, () => {
    const active = rules({ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] })
    assert.equal(evaluateCall(active, call('Bash', { command }), ctx).decision, 'deny')
  })
}

// A006 part 2: `sh -c` strings (up to 3 deep), xargs and git global options cannot hide a `git push`.
const A006_PART2_PUSHES = ["bash -c 'git push'", 'sh -c "git push"', "bash -lc 'git push'", 'xargs git push', 'echo x | xargs -n1 git push', 'git -C . push', 'git -c a=b push', 'git --git-dir=x push', `bash -c "sh -c 'git push'"`]
for (const command of A006_PART2_PUSHES) {
  test(`A006: {commands:["git push*"]} denies Bash ${command}`, () => {
    const active = rules({ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] })
    assert.equal(evaluateCall(active, call('Bash', { command }), ctx).decision, 'deny')
  })
}

test('A006 control: {commands:["git push*"]} allows Bash bash -c \'git status\' and git -C . status', () => {
  const active = rules({ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] })
  assert.equal(evaluateCall(active, call('Bash', { command: "bash -c 'git status'" }), ctx).decision, 'allow')
  assert.equal(evaluateCall(active, call('Bash', { command: 'git -C . status' }), ctx).decision, 'allow')
})

test('A006 control: {commands:["git push*"]} allows Bash git status and echo git push', () => {
  const active = rules({ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] })
  assert.equal(evaluateCall(active, call('Bash', { command: 'git status' }), ctx).decision, 'allow')
  assert.equal(evaluateCall(active, call('Bash', { command: 'echo git push' }), ctx).decision, 'allow')
})

// ---------------------------------------------------------------- A007 paths on shell calls
// A `paths` rule naming Bash sees the path-like words of each command segment (a tripwire, not a parser).
for (const [command, want] of [['cat secrets/x', 'deny'], ['cat docs/x', 'allow'], ['echo hi && cat "secrets/x"', 'deny']]) {
  test(`A007: {tools:["Bash"], paths:["secrets/**"]} ${want === 'deny' ? 'denies' : 'allows'} Bash ${command}`, () => {
    const active = rules({ id: 'sec', effect: 'forbid', tools: ['Bash'], paths: ['secrets/**'] })
    assert.equal(evaluateCall(active, call('Bash', { command }), ctx).decision, want)
  })
}

// ---------------------------------------------------------------- A007 search reach
// A search at or below a glob's static prefix reaches it when the rest of the glob has `**`.
for (const [path, glob, want] of [['src', '**/.env', 'deny'], ['src/a', 'src/**/x', 'deny'], ['docs', 'secrets/**', 'allow'], ['secrets/sub', 'secrets/*.key', 'allow']]) {
  test(`A007: {tools:["Grep"], paths:["${glob}"]} ${want === 'deny' ? 'denies' : 'allows'} Grep path: ${path}`, () => {
    const active = rules({ id: 'reach', effect: 'forbid', tools: ['Grep'], paths: [glob] })
    assert.equal(evaluateCall(active, call('Grep', { pattern: 'x', path }), ctx).decision, want)
  })
}

// ---------------------------------------------------------------- A008 false denials
// Prose in file text, a settings.json that is not the agent's, and a quoted commit message are not
// self-protection hits; a real path field, a message that runs a command, and a chained rm still are.
for (const [tool_name, tool_input, want] of [
  ['Write', { file_path: 'src/a.txt', content: 'see foo/.atap/config.json' }, 'allow'],
  ['Bash', { command: 'jq . .vscode/settings.json' }, 'allow'],
  ['Bash', { command: 'git commit -m "ignore .atap"' }, 'allow'],
  ['Bash', { command: "git commit -m 'ignore .atap'" }, 'allow'],
  ['Write', { file_path: '.atap/config.json' }, 'deny'],
  ['Bash', { command: 'git commit -m "$(rm .atap/x)"' }, 'deny'],
  ['Bash', { command: 'cat .claude/settings.json > /dev/null; rm .claude/settings.json' }, 'deny'],
  ['Bash', { command: "git commit -m 'x'; rm .atap/x" }, 'deny'],
]) {
  test(`A008: ${tool_name} ${JSON.stringify(tool_input)} ${want === 'deny' ? 'denies' : 'is allowed'}`, () => {
    assert.equal(evaluateCall([], call(tool_name, tool_input), ctx).decision, want)
  })
}
