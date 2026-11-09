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

// ---------------------------------------------------------------- T012 GATE F review rows
// evaluateCall rows for the review at 9041acb6: (a) whitespace in an absolute path, (b) Win32 name
// trimming and streams, (e) `~/` forms and trailing-slash directory targets.

test('T012 (a): mcp__fs__write_file {target: "/Users/Josh Moore/proj/.atap/constraints.jsonl"} denies', () => {
  const mac = { projectRoot: '/Users/Josh Moore/proj', protectedPaths: ['/Users/Josh Moore/proj/.atap'] }
  const d = evaluateCall([], { tool_name: 'mcp__fs__write_file', tool_input: { target: '/Users/Josh Moore/proj/.atap/constraints.jsonl' }, cwd: '/Users/Josh Moore/proj' }, mac)
  assert.equal(d.rule_id, 'store-write')
})

test('T012 (a): Write whose content mentions foo/.atap/config.json, or a multi-line text starting with /, is allowed', () => {
  assert.equal(evaluateCall([], call('Write', { file_path: 'src/a.md', content: 'see foo/.atap/config.json' }), ctx).decision, 'allow')
  assert.equal(evaluateCall([], call('mcp__fs__write_file', { path: 'src/a.md', text: `${ROOT}/.atap/x\nis the store` }), ctx).decision, 'allow')
})

test('T012 (a): mcp__x__note {text: "~ approx 5 /p/.atap/x items"} is allowed (a bare ~ is not a path)', () => {
  assert.equal(evaluateCall([], call('mcp__x__note', { text: '~ approx 5 /p/.atap/x items' }), ctx).decision, 'allow')
})

test('T012 (b): a stream on the key (C:\\k\\op.pem::$DATA) denies key-access in windows mode', () => {
  const d = evaluateCall([], winCall('Write', { file_path: 'C:\\k\\op.pem::$DATA' }), { ...winCtx, secretPaths: ['C:\\k\\op.pem'] })
  assert.equal(d.rule_id, 'key-access')
})

test('T012 (b): a stream on a file (C:\\p\\secrets\\a.key:x) denies under secrets/*.key in windows mode', () => {
  const active = rules({ id: 'keys', effect: 'forbid', tools: ['*'], paths: ['secrets/*.key'] })
  assert.equal(evaluateCall(active, winCall('Write', { file_path: `${WIN}\\secrets\\a.key:x` }), winCtx).decision, 'deny')
})

for (const file_path of [`${WIN}\\secrets\\k:x`, `${WIN}\\.atap.\\constraints.jsonl`, `${WIN}\\.atap\\constraints.jsonl::$DATA`, `${WIN}\\secrets.\\k`]) {
  test(`T012 (b): Write ${file_path} denies in windows mode`, () => {
    const active = rules({ id: 'secrets', effect: 'forbid', tools: ['*'], paths: ['secrets/**'] })
    assert.equal(evaluateCall(active, winCall('Write', { file_path }), winCtx).decision, 'deny')
  })
}

test('T012 (e): Bash echo x > ~/.claude.json denies', () => {
  const home = { ...ctx, home: '/home/op', protectedPaths: [...ctx.protectedPaths, '/home/op/.claude.json'], absoluteOnlyPaths: ['/home/op/.claude.json'] }
  assert.equal(evaluateCall([], call('Bash', { command: 'echo x > ~/.claude.json' }), home).decision, 'deny')
})

test('T012 (e): Bash echo x > ~/.claude.json denies through the real hook (HOME from the environment)', noCli, (t) => {
  const { pre } = withPlugin(t)
  const d = pre(bash('echo x > ~/.claude.json'))
  assert.equal(d?.hookSpecificOutput?.permissionDecision, 'deny', JSON.stringify(d))
})

test('T012 (e): Bash cp a secrets/ under secrets/** denies', () => {
  const active = rules({ id: 'secrets', effect: 'forbid', tools: ['*'], paths: ['secrets/**'] })
  assert.equal(evaluateCall(active, call('Bash', { command: 'cp a secrets/' }), ctx).decision, 'deny')
})

// ---------------------------------------------------------------- T013 (a) project lookup
// A session started in a parent with no .atap/ (CLAUDE_PROJECT_DIR=root), working in repo/ that has one.

// setup() plus a signed no-prod constraint in repo/.atap; the root above repo/ has no .atap/.
function pinnedParent(t) {
  const s = setup(t)
  const root = join(s.repo, '..')
  const key = join(root, 'operator', 'operator.pem')
  const cli = (args, input) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: s.repo, input: JSON.stringify(input ?? ''), encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
  }
  cli(['constraints', 'keygen', '--out', key])
  cli(['constraints', 'set', '--operator-key', key], { constraint_id: 'no-prod', prose: 'Never deploy to production.', rules: [{ id: 'deploy', effect: 'forbid', tools: ['Bash'], commands: ['wrangler deploy*'] }] })
  return { ...s, root }
}

test('T013 (a) control: CLAUDE_PROJECT_DIR without .atap/, cwd in a repo with one, not strict: the repo\'s guard denies', noCli, (t) => {
  const { root, raw, hook } = pinnedParent(t)
  const d = hook('pre-tool-use', raw(bash('wrangler deploy')), { CLAUDE_PROJECT_DIR: root })
  assert.equal(d?.hookSpecificOutput?.permissionDecision, 'deny', JSON.stringify(d))
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /no-prod\/deploy/)
})

for (const flag of [{ ATAP_CONSTRAINTS_REQUIRED: '1' }, { ATAP_OPERATOR: 'x' }]) {
  test(`T013 (a): the same layout with ${Object.keys(flag)[0]} does not fall back and fails closed`, noCli, (t) => {
    const { root, raw, hook } = pinnedParent(t)
    const d = hook('pre-tool-use', raw(bash('ls')), { CLAUDE_PROJECT_DIR: root, ...flag })
    assertDeny(d)
    assert.match(d.hookSpecificOutput.permissionDecisionReason, /guard could not run \(no \.atap\/\)/)
  })
}

// ---------------------------------------------------------------- T014 (a) which events the pin covers
// /mono and /mono/child both hold .atap/, CLAUDE_PROJECT_DIR=/mono, the agent works in /mono/child. Which
// store the hook chose shows in whose hook.log its fixed-text line lands: a `git commit` outside a git
// repo logs "no commit sha", a session-end with no AIT logs "no ait in config", and a guard event with
// /mono's constraints on and no CLI logs "atap-witness not found" (and denies).
function mono(t) {
  const top = bare(t)
  const child = join(top, 'child')
  mkdirSync(join(top, '.atap'), { recursive: true })
  mkdirSync(join(child, '.atap'), { recursive: true })
  writeFileSync(join(top, '.atap', 'config.json'), JSON.stringify({ constraints_operator: 'x' }))
  writeFileSync(join(child, '.atap', 'config.json'), '{}')
  const logged = (dir) => existsSync(join(dir, '.atap', 'hook.log'))
  const run = (event, input, extra = {}) =>
    spawn([script, event], child, JSON.stringify({ session_id: 's', cwd: child, ...input }), { CLAUDE_PROJECT_DIR: top, ATAP_WITNESS: join(top, 'no-such-atap-witness'), ...extra })
  return { top, child, logged, run }
}

for (const event of ['post-tool-use', 'session-end']) {
  test(`T014 (a): non-strict ${event} in /mono/child records in /mono/child/.atap, not the pinned /mono`, (t) => {
    const { top, child, logged, run } = mono(t)
    assert.equal(run(event, bash('git commit -m x')), null)
    assert.ok(logged(child), 'the cwd-found store got the line')
    assert.ok(!logged(top), 'the pinned store did not')
  })
}

test('T014 (a): strict post-tool-use in /mono/child still uses the pinned /mono', (t) => {
  const { top, child, logged, run } = mono(t)
  assert.equal(run('post-tool-use', bash('git commit -m x'), { ATAP_CONSTRAINTS_REQUIRED: '1' }), null)
  assert.ok(logged(top) && !logged(child))
})

test('T014 (a): pre-tool-use in /mono/child still uses the pinned /mono (its constraints are on)', (t) => {
  const { top, child, logged, run } = mono(t)
  assertDeny(run('pre-tool-use', bash('ls')))
  assert.ok(logged(top) && !logged(child))
})

// ---------------------------------------------------------------- T014 (c) (d) evaluateCall rows
test('T014 (c): Bash git status with a description naming /proj/.atap/x is allowed; file_path /proj/.atap/x denies', () => {
  const proj = { projectRoot: '/proj', protectedPaths: ['/proj/.atap'] }
  const at = (tool_name, tool_input) => evaluateCall([], { tool_name, tool_input, cwd: '/proj' }, proj).decision
  assert.equal(at('Bash', { command: 'git status', description: '/proj/.atap/x is mentioned' }), 'allow')
  assert.equal(at('Write', { file_path: '/proj/.atap/x', content: '' }), 'deny')
})

test('T014 (c): mcp__fs__write_file {target and description both "/proj/.atap/x y"} denies', () => {
  const proj = { projectRoot: '/proj', protectedPaths: ['/proj/.atap'] }
  const d = evaluateCall([], { tool_name: 'mcp__fs__write_file', tool_input: { target: '/proj/.atap/x y', description: '/proj/.atap/x y', content: 'a' }, cwd: '/proj' }, proj)
  assert.equal(d.rule_id, 'store-write')
})

for (const [command, want] of [["bash -euxo pipefail -c 'git push'", 'deny'], ["bash +o pipefail -c 'git push'", 'deny'], ["bash -euxo pipefail -c 'git status'", 'allow']]) {
  test(`T014 (d): {commands:["git push*"]} ${want === 'deny' ? 'denies' : 'allows'} Bash ${command}`, () => {
    const active = rules({ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] })
    assert.equal(evaluateCall(active, call('Bash', { command }), ctx).decision, want)
  })
}

// ---------------------------------------------------------------- T013 (b) the guard's packages
const CLI_PKG = fileURLToPath(new URL('../../../packages/atap-cli/', import.meta.url))
const ATAP_PKG = fileURLToPath(new URL('../../../packages/atap-js/', import.meta.url))
for (const [what, file] of [['the CLI\'s dist/constraints.js beside its entry', join(CLI_PKG, 'dist', 'constraints.js')], ['the atap-js package\'s dist/constraints.js', join(ATAP_PKG, 'dist', 'constraints.js')]]) {
  test(`T013 (b): Edit of ${what} denies`, noCli, (t) => {
    const { pre } = withPlugin(t)
    selfDeny(pre({ tool_name: 'Edit', tool_input: { file_path: file, old_string: 'a', new_string: 'b' } }))
  })
}
