// Operator constraints through the real CLI: the guard denies what a signed
// constraint forbids, stays silent on everything else, survives compaction via
// SessionStart, ignores a forged rescind, and fails closed when it cannot run.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('../scripts/atap-hook.mjs', import.meta.url))
const CLI = fileURLToPath(new URL('../../../packages/atap-cli/dist/cli.js', import.meta.url))
const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'atap-guard-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const wrapper = join(root, 'atap-witness')
  writeFileSync(wrapper, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(CLI)} "$@"\n`)
  chmodSync(wrapper, 0o755)
  const repo = join(root, 'repo')
  mkdirSync(repo)
  git(repo, 'init', '-q')
  git(repo, 'config', 'user.name', 't')
  git(repo, 'config', 'user.email', 't@t')
  git(repo, 'remote', 'add', 'origin', 'git@github.com:owner/repo.git')
  const cli = (args, input) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: repo, input: input === undefined ? '' : JSON.stringify(input), encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
    return r.stdout
  }
  cli(['init'])
  const opKey = join(root, 'operator', 'operator.pem') // outside the repo
  cli(['constraints', 'keygen', '--out', opKey])
  const hook = (event, input, env = {}) => {
    const { ATAP_OFF, ...base } = process.env
    const r = spawnSync(process.execPath, [script, event], {
      cwd: repo,
      input: JSON.stringify({ session_id: 's', cwd: repo, ...input }),
      env: { ...base, ATAP_WITNESS: wrapper, ...env },
      encoding: 'utf8',
    })
    assert.equal(r.status, 0)
    assert.equal(r.stderr, '')
    return r.stdout ? JSON.parse(r.stdout) : null
  }
  return { root, repo, cli, hook, opKey }
}

const NO_PROD = {
  constraint_id: 'no-prod',
  prose: 'Never deploy to production.',
  rules: [{ id: 'deploy', effect: 'forbid', tools: ['Bash'], commands: ['wrangler deploy*'] }],
}
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } })

test('no constraint store: the guard and SessionStart stay silent', { skip: !existsSync(CLI) }, (t) => {
  const { hook } = setup(t)
  assert.equal(hook('pre-tool-use', bash('wrangler deploy')), null)
  assert.equal(hook('session-start', { source: 'startup' }), null)
})

test('a signed constraint denies its calls, allows the rest silently, and records the denial', { skip: !existsSync(CLI) }, (t) => {
  const { repo, cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  const d = hook('pre-tool-use', bash('npm ci && wrangler deploy --env production'))
  assert.equal(d.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /no-prod\/deploy forbids/)
  assert.equal(hook('pre-tool-use', bash('npm test')), null) // allow prints nothing: normal permissions still apply
  const events = readFileSync(join(repo, '.atap', 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  assert.deepEqual(events.map((e) => e.event_type), ['code_crew:constraint_set', 'code_crew:tool_gate'])
  assert.equal(events[1].payload.decision, 'deny')
  assert.ok(!JSON.stringify(events).includes('wrangler'), 'the command text never reaches an event')
})

test('SessionStart re-injects the constraints at startup and after a compaction', { skip: !existsSync(CLI) }, (t) => {
  const { cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  for (const source of ['startup', 'compact']) {
    const out = hook('session-start', { source })
    assert.equal(out.hookSpecificOutput.hookEventName, 'SessionStart')
    assert.match(out.hookSpecificOutput.additionalContext, /\[no-prod\] Never deploy to production\./)
    assert.match(out.hookSpecificOutput.additionalContext, /Only a rescind signed with the operator key/)
  }
})

test('a forged rescind line blocks every call instead of lifting the constraint', { skip: !existsSync(CLI) }, (t) => {
  const { repo, cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  const [line] = readFileSync(join(repo, '.atap', 'constraints.jsonl'), 'utf8').trim().split('\n')
  const forged = { ...JSON.parse(line), type: 'constraint_rescind' }
  delete forged.prose
  delete forged.rules
  appendFileSync(join(repo, '.atap', 'constraints.jsonl'), JSON.stringify(forged) + '\n')
  for (const call of [bash('wrangler deploy'), bash('npm test')]) {
    const d = hook('pre-tool-use', call)
    assert.equal(d.hookSpecificOutput.permissionDecision, 'deny')
  }
  assert.match(hook('session-start', { source: 'compact' }).hookSpecificOutput.additionalContext, /every tool call is blocked/)
})

test('a signed rescind lifts the constraint', { skip: !existsSync(CLI) }, (t) => {
  const { cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  cli(['constraints', 'rescind', '--operator-key', opKey, '--id', 'no-prod'])
  assert.equal(hook('pre-tool-use', bash('wrangler deploy')), null)
})

test('deleting the store does not switch the guard off', { skip: !existsSync(CLI) }, (t) => {
  const { repo, cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  rmSync(join(repo, '.atap', 'constraints.jsonl'))
  const d = hook('pre-tool-use', bash('wrangler deploy'))
  assert.equal(d.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /atap.store\/missing-statement/)
})

test('the guard fails closed when the CLI cannot run', { skip: !existsSync(CLI) }, (t) => {
  const { root, cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  const d = hook('pre-tool-use', bash('npm test'), { ATAP_WITNESS: join(root, 'no-such-binary') })
  assert.equal(d.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /could not run/)
})

test('a commit under constraints carries the in-force hash', { skip: !existsSync(CLI) }, (t) => {
  const { repo, cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  writeFileSync(join(repo, 'a.txt'), 'a')
  git(repo, 'add', '.')
  git(repo, 'commit', '-qm', 'x')
  hook('post-tool-use', { tool_name: 'Bash', tool_input: { command: 'git commit -m x' }, tool_response: { exit_code: 0 } })
  const status = JSON.parse(cli(['constraints', 'status']))
  const events = readFileSync(join(repo, '.atap', 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  const commit = events.find((e) => e.event_type === 'code_crew:change_committed')
  assert.equal(commit.payload.in_force_sha256, status.in_force_sha256)
})

test('review: the agent cannot edit .atap/ or link to it to drop a statement', { skip: !existsSync(CLI) }, (t) => {
  const { hook, cli, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  for (const call of [
    bash('ln -s .atap a'),
    { tool_name: 'Write', tool_input: { file_path: '.atap/events.jsonl', content: '' } },
    { tool_name: 'Edit', tool_input: { file_path: '.atap/config.json', old_string: 'a', new_string: 'b' } },
    { tool_name: 'Write', tool_input: { file_path: '.claude/settings.local.json', content: '{}' } },
    { tool_name: 'Write', tool_input: { file_path: 'sub/.atap/config.json', content: '{}' } },
  ]) {
    assert.equal(hook('pre-tool-use', call).hookSpecificOutput.permissionDecision, 'deny', JSON.stringify(call))
  }
})

test('review: a nested .atap/ under the agent cwd does not re-root the guard when CLAUDE_PROJECT_DIR is set', { skip: !existsSync(CLI) }, (t) => {
  const { repo, cli, hook, opKey } = setup(t)
  cli(['constraints', 'set', '--operator-key', opKey], NO_PROD)
  mkdirSync(join(repo, 'sub', '.atap'), { recursive: true })
  writeFileSync(join(repo, 'sub', '.atap', 'config.json'), '{}')
  const sub = join(repo, 'sub')
  const d = hook('pre-tool-use', { ...bash('wrangler deploy'), cwd: sub }, { CLAUDE_PROJECT_DIR: repo })
  assert.equal(d.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(d.hookSpecificOutput.permissionDecisionReason, /no-prod\/deploy/)
})
