// atap-witness constraints: keys, trust settings, fail-closed store checks, and
// a receipt over constraint events that both verifiers accept.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync, execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, statSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))

function project(t) {
  const root = mkdtempSync(join(tmpdir(), 'atap-cons-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const repo = join(root, 'repo')
  execFileSync('mkdir', ['-p', repo])
  const run = (args, input, env = {}) =>
    spawnSync(process.execPath, [CLI, ...args], { cwd: repo, input: input === undefined ? '' : JSON.stringify(input), env: { ...process.env, ...env }, encoding: 'utf8' })
  const ok = (args, input, env) => {
    const r = run(args, input, env)
    assert.equal(r.status, 0, r.stderr)
    return r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout
  }
  ok(['init'])
  return { root, repo, run, ok }
}

const SET = { constraint_id: 'no-prod', prose: 'Never deploy to production.', rules: [{ id: 'deploy', effect: 'forbid', tools: ['Bash'], commands: ['wrangler deploy*'] }] }
const check = (ok, command, env) => ok(['constraints', 'check'], { tool_name: 'Bash', tool_input: { command } }, env)

test('keygen writes a 0600 Ed25519 key and refuses to overwrite it', (t) => {
  const { root, ok, run } = project(t)
  const key = join(root, 'op', 'k.pem')
  const out = ok(['constraints', 'keygen', '--out', key])
  assert.match(out.operator, /^did:key:z6Mk/)
  assert.equal(statSync(key).mode & 0o777, 0o600)
  assert.notEqual(run(['constraints', 'keygen', '--out', key]).status, 0)
})

test('the first set pins its operator; another key is refused', (t) => {
  const { root, repo, ok, run } = project(t)
  const a = join(root, 'a.pem'), b = join(root, 'b.pem')
  const opA = ok(['constraints', 'keygen', '--out', a]).operator
  ok(['constraints', 'keygen', '--out', b])
  assert.equal(ok(['constraints', 'set', '--operator-key', a], SET).configured_operator, true)
  assert.equal(JSON.parse(readFileSync(join(repo, '.atap', 'config.json'), 'utf8')).constraints_operator, opA)
  const r = run(['constraints', 'set', '--operator-key', b], SET)
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /not the trusted operator/)
})

test('ATAP_OPERATOR in the environment beats the config: a store signed by another key fails closed', (t) => {
  const { root, ok } = project(t)
  const a = join(root, 'a.pem'), b = join(root, 'b.pem')
  ok(['constraints', 'keygen', '--out', a])
  const opB = ok(['constraints', 'keygen', '--out', b]).operator
  ok(['constraints', 'set', '--operator-key', a], SET)
  assert.equal(check(ok, 'wrangler deploy').decision, 'deny')
  const d = check(ok, 'npm test', { ATAP_OPERATOR: opB })
  assert.equal(d.decision, 'deny')
  assert.equal(d.rule_id, 'tampered')
})

test('ATAP_CONSTRAINTS_REQUIRED=1 denies everything while no constraint is in force', (t) => {
  const { ok } = project(t)
  assert.equal(check(ok, 'npm test').decision, 'allow')
  const d = check(ok, 'npm test', { ATAP_CONSTRAINTS_REQUIRED: '1' })
  assert.equal(d.decision, 'deny')
  assert.equal(d.rule_id, 'required')
})

test('ATAP_CONSTRAINTS moves the store outside the project', (t) => {
  const { root, repo, ok } = project(t)
  const key = join(root, 'a.pem')
  const store = join(root, 'operator', 'constraints.jsonl')
  ok(['constraints', 'keygen', '--out', key])
  ok(['constraints', 'set', '--operator-key', key], SET, { ATAP_CONSTRAINTS: store })
  assert.ok(readFileSync(store, 'utf8').includes('"no-prod"'))
  assert.throws(() => statSync(join(repo, '.atap', 'constraints.jsonl')))
  assert.equal(check(ok, 'wrangler deploy', { ATAP_CONSTRAINTS: store }).decision, 'deny')
})

test('a statement deleted from the store is caught by its witness event', (t) => {
  const { root, repo, ok } = project(t)
  const key = join(root, 'a.pem')
  ok(['constraints', 'keygen', '--out', key])
  ok(['constraints', 'set', '--operator-key', key], SET)
  writeFileSync(join(repo, '.atap', 'constraints.jsonl'), '')
  const d = check(ok, 'wrangler deploy')
  assert.equal(d.decision, 'deny')
  assert.equal(d.rule_id, 'missing-statement')
})

test('a receipt over set, gate and rescind events verifies in both verifiers', (t) => {
  const { root, repo, ok } = project(t)
  const key = join(root, 'a.pem')
  ok(['constraints', 'keygen', '--out', key])
  ok(['constraints', 'set', '--operator-key', key], SET)
  const d = ok(['constraints', 'check', '--record'], { tool_name: 'Bash', tool_input: { command: 'wrangler deploy' } })
  assert.match(d.recorded, /^ATAP-WE-/)
  ok(['constraints', 'rescind', '--operator-key', key, '--id', 'no-prod'])
  ok(['block'], { tasks_accepted: 0, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })
  ok(['receipt', '--out', join(root, 'r')])
  assert.equal(ok(['verify', join(root, 'r')]).ok, true)
  const sh = spawnSync('bash', [VERIFY_SH, join(root, 'r')], { encoding: 'utf8' })
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
  const types = JSON.parse(readFileSync(join(root, 'r', 'profile_artifacts', 'witness_events.json'), 'utf8')).map((e) => e.event_type)
  assert.deepEqual(types, ['code_crew:constraint_set', 'code_crew:tool_gate', 'code_crew:constraint_rescind'])
  // The prose and the command stay out of the receipt; only hashes travel.
  const all = readFileSync(join(root, 'r', 'profile_artifacts', 'witness_events.json'), 'utf8')
  assert.ok(!all.includes('Never deploy') && !all.includes('wrangler'))
  assert.ok(readFileSync(join(repo, '.atap', 'constraints.jsonl'), 'utf8').includes('Never deploy'))
})
