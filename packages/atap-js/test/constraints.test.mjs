// Operator-signed constraints: signing, folding, the forged-rescind cases and
// the tool-call evaluator.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createPublicKey } from 'node:crypto'
import {
  signConstraintSet,
  signConstraintRescind,
  statementProblem,
  statementHash,
  foldConstraints,
  evaluateCall,
  renderConstraints,
  globToRegExp,
  didKeyFromPublicKey,
} from '../dist/index.js'

const keypair = () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  const x = createPublicKey(privateKey).export({ format: 'jwk' }).x
  return { privateKey, did: didKeyFromPublicKey(new Uint8Array(Buffer.from(x, 'base64url'))) }
}
const op = keypair()
const intruder = keypair()
const AIT = 'urn:uuid:01890000-0000-7000-8000-000000000001'
const ROOT = '/work/proj'
const ctx = { projectRoot: ROOT, protectedPaths: [`${ROOT}/.atap/constraints.jsonl`, '/home/op/.atap-operator/operator.pem'] }
const call = (tool_name, tool_input, cwd = ROOT) => ({ tool_name, tool_input, cwd })

const noProdDeploy = (at = '2026-11-02T10:00:00.000Z', key = op.privateKey) =>
  signConstraintSet(
    {
      constraint_id: 'no-prod',
      scope: '*',
      issued_at: at,
      prose: 'Do not deploy to production or touch the prod Terraform workspace.',
      rules: [
        { id: 'deploy', effect: 'forbid', tools: ['Bash'], commands: ['wrangler deploy*', 'terraform * -var-file=prod*', 'terraform destroy*'] },
        { id: 'prod-files', effect: 'forbid', tools: ['Write', 'Edit'], paths: ['infra/prod/**'] },
      ],
    },
    key,
  )

test('a signed set verifies; any edit to it breaks the signature', () => {
  const s = noProdDeploy()
  assert.equal(statementProblem(s), null)
  assert.equal(s.operator, op.did)
  const edited = { ...s, prose: 'Deploy freely.' }
  assert.equal(statementProblem(edited), 'operator signature does not verify')
  const loosened = structuredClone(s)
  loosened.rules[0].effect = 'require_approval'
  assert.equal(statementProblem(loosened), 'operator signature does not verify')
  assert.match(statementProblem({ ...s, extra: 1 }), /unknown field extra/)
})

test('shape rules refuse to sign a malformed set', () => {
  assert.throws(() => signConstraintSet({ constraint_id: 'Bad Id', scope: '*', prose: 'x', rules: [] }, op.privateKey), /constraint_id/)
  assert.throws(() => signConstraintSet({ constraint_id: 'a', scope: '*', prose: '', rules: [] }, op.privateKey), /prose/)
  assert.throws(
    () => signConstraintSet({ constraint_id: 'a', scope: '*', prose: 'p', rules: [{ id: 'r', effect: 'block', tools: ['Bash'] }] }, op.privateKey),
    /effect/,
  )
  assert.throws(
    () => signConstraintSet({ constraint_id: 'a', scope: '*', prose: 'p', rules: [{ id: 'r', effect: 'forbid', tools: ['Bash'] }, { id: 'r', effect: 'forbid', tools: ['Write'] }] }, op.privateKey),
    /duplicate rule id/,
  )
})

test('fold: a set is in force until the same operator rescinds it', () => {
  const set = noProdDeploy()
  const f1 = foldConstraints([set], op.did, AIT)
  assert.deepEqual(f1.rejected, [])
  assert.deepEqual(f1.active.map((c) => c.constraint_id), ['no-prod'])
  const rescind = signConstraintRescind({ constraint_id: 'no-prod', scope: '*', issued_at: '2026-11-02T11:00:00.000Z' }, op.privateKey)
  const f2 = foldConstraints([rescind, set], op.did, AIT) // order in the store does not matter
  assert.deepEqual(f2.active, [])
  assert.notEqual(f1.in_force, f2.in_force)
})

test('forged rescind: one signed by another key is rejected, not obeyed', () => {
  const set = noProdDeploy()
  const forged = signConstraintRescind({ constraint_id: 'no-prod', scope: '*', issued_at: '2026-11-02T11:00:00.000Z' }, intruder.privateKey)
  const f = foldConstraints([set, forged], op.did, AIT)
  assert.deepEqual(f.active.map((c) => c.constraint_id), ['no-prod'])
  assert.equal(f.rejected.length, 1)
  assert.match(f.rejected[0].reason, /does not trust/)
})

test('forged rescind: a hand-written one with the right operator but no valid signature is rejected', () => {
  const set = noProdDeploy()
  const real = signConstraintRescind({ constraint_id: 'other', scope: '*' }, op.privateKey)
  const fake = { ...real, constraint_id: 'no-prod' } // reuse a real signature on new words
  const f = foldConstraints([set, fake], op.did, AIT)
  assert.deepEqual(f.active.map((c) => c.constraint_id), ['no-prod'])
  assert.equal(f.rejected[0].reason, 'operator signature does not verify')
})

test('a set scoped to another AIT is rejected; "*" applies everywhere', () => {
  const other = signConstraintSet({ constraint_id: 'x', scope: 'urn:uuid:01890000-0000-7000-8000-000000000999', prose: 'p', rules: [] }, op.privateKey)
  const f = foldConstraints([other], op.did, AIT)
  assert.equal(f.active.length, 0)
  assert.match(f.rejected[0].reason, /another AIT/)
})

test('a newer set replaces the older one with the same constraint_id', () => {
  const v1 = noProdDeploy('2026-11-01T00:00:00.000Z')
  const v2 = signConstraintSet({ constraint_id: 'no-prod', scope: '*', issued_at: '2026-11-02T00:00:00.000Z', prose: 'v2', rules: [] }, op.privateKey)
  const f = foldConstraints([v2, v1], op.did, AIT)
  assert.equal(f.active.length, 1)
  assert.equal(f.active[0].prose, 'v2')
})

test('no trusted operator configured fails closed, unless there is nothing to trust', () => {
  const f = foldConstraints([noProdDeploy()], '', AIT)
  assert.equal(f.active.length, 0)
  assert.equal(f.rejected.length, 1)
  assert.deepEqual(foldConstraints([], '', AIT).rejected, [])
})

test('evaluate: forbidden commands, segments and paths are denied; others allowed', () => {
  const { active } = foldConstraints([noProdDeploy()], op.did, AIT)
  assert.equal(evaluateCall(active, call('Bash', { command: 'npm test && wrangler deploy --env production' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Bash', { command: 'terraform  destroy -auto-approve' }), ctx).rule_id, 'deploy')
  assert.equal(evaluateCall(active, call('Bash', { command: 'npm test' }), ctx).decision, 'allow')
  assert.equal(evaluateCall(active, call('Write', { file_path: 'infra/prod/main.tf' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Write', { file_path: `${ROOT}/infra/prod/a/b.tf` }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Edit', { file_path: 'infra/staging/main.tf' }), ctx).decision, 'allow')
  // ../ cannot walk around a path rule
  assert.equal(evaluateCall(active, call('Edit', { file_path: 'src/../infra/prod/x.tf' }), ctx).decision, 'deny')
  const d = evaluateCall(active, call('Write', { file_path: 'infra/prod/x.tf' }), ctx)
  assert.equal(d.reason, active[0].prose)
})

test('evaluate: forbid beats require_approval; outside_project and hosts match', () => {
  const s = signConstraintSet(
    {
      constraint_id: 'scope',
      scope: '*',
      prose: 'Stay in the project; ask before fetching from unknown hosts.',
      rules: [
        { id: 'outside', effect: 'forbid', tools: ['Write', 'Edit', 'Read'], outside_project: true },
        { id: 'fetch', effect: 'require_approval', tools: ['WebFetch'] },
        { id: 'evil', effect: 'forbid', tools: ['WebFetch'], hosts: ['*.evil.example'] },
      ],
    },
    op.privateKey,
  )
  const { active } = foldConstraints([s], op.did, AIT)
  assert.equal(evaluateCall(active, call('Read', { file_path: '/etc/passwd' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Read', { file_path: '../other/x' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Read', { file_path: 'src/x' }), ctx).decision, 'allow')
  assert.equal(evaluateCall(active, call('WebFetch', { url: 'https://docs.example.com/a' }), ctx).decision, 'ask')
  assert.equal(evaluateCall(active, call('WebFetch', { url: 'https://a.EVIL.example/x' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('WebFetch', { url: 'not a url' }), ctx).decision, 'ask')
})

test('self-protection: the store and operator key cannot be written or named in a command', () => {
  const { active } = foldConstraints([], op.did, AIT)
  assert.equal(evaluateCall(active, call('Write', { file_path: '.atap/constraints.jsonl' }), ctx).constraint_id, 'atap.self-protect')
  assert.equal(evaluateCall(active, call('Bash', { command: 'echo {} >> .atap/constraints.jsonl' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Bash', { command: 'cat /home/op/.atap-operator/operator.pem' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Bash', { command: 'ls .atap' }), ctx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Bash', { command: 'ls src' }), ctx).decision, 'allow')
})

const keyCtx = { ...ctx, protectedPaths: [`${ROOT}/.atap`, `${ROOT}/.claude/settings.json`], secretPaths: ['/home/op/.atap-operator/operator.pem'] }

test('review: a nested .atap/, agent settings and MCP writes are protected; the key is not even readable', () => {
  const none = []
  assert.equal(evaluateCall(none, call('Write', { file_path: 'sub/.atap/config.json', content: '{}' }), keyCtx).decision, 'deny')
  assert.equal(evaluateCall(none, call('Edit', { file_path: '.claude/settings.json' }), keyCtx).decision, 'deny')
  assert.equal(evaluateCall(none, call('mcp__fs__write_file', { path: `${ROOT}/.atap/events.jsonl` }), keyCtx).decision, 'deny')
  assert.equal(evaluateCall(none, call('mcp__fs__write_file', { args: { target: '.atap/constraints.jsonl' } }), keyCtx).decision, 'deny')
  assert.equal(evaluateCall(none, call('Read', { file_path: '/home/op/.atap-operator/operator.pem' }), keyCtx).rule_id, 'key-access')
  assert.equal(evaluateCall(none, call('Read', { file_path: '.atap/constraints.jsonl' }), keyCtx).decision, 'allow')
  assert.equal(evaluateCall(none, call('Bash', { command: 'ln -s .atap a' }), keyCtx).decision, 'deny')
})

test('review: symlinks resolve through ctx.realpath; case folds when asked', () => {
  const { active } = foldConstraints([noProdDeploy()], op.did, AIT)
  const realpath = (p) => p.replace(`${ROOT}/link`, `${ROOT}/infra/prod`).replace(`${ROOT}/a/`, `${ROOT}/.atap/`)
  const c = { ...keyCtx, realpath }
  assert.equal(evaluateCall(active, call('Write', { file_path: 'link/main.tf' }), c).rule_id, 'prod-files')
  assert.equal(evaluateCall([], call('Write', { file_path: 'a/constraints.jsonl' }), c).decision, 'deny')
  const ci = { ...keyCtx, caseInsensitive: true }
  assert.equal(evaluateCall(active, call('Write', { file_path: 'INFRA/Prod/x.tf' }), ci).decision, 'deny')
  assert.equal(evaluateCall([], call('Write', { file_path: '.ATAP/constraints.jsonl' }), ci).decision, 'deny')
})

test('review: a paths rule on search tools covers searches without a path and of ancestors', () => {
  const s = signConstraintSet({ constraint_id: 'secrets', scope: '*', prose: 'Do not look in secrets/.', rules: [{ id: 'look', effect: 'forbid', tools: ['Read', 'Grep', 'Glob'], paths: ['secrets/**'] }] }, op.privateKey)
  const { active } = foldConstraints([s], op.did, AIT)
  for (const input of [{ pattern: 'KEY' }, { pattern: 'KEY', path: '.' }, { pattern: 'KEY', path: ROOT }, { pattern: 'x', path: 'secrets' }]) {
    assert.equal(evaluateCall(active, call('Grep', input), keyCtx).decision, 'deny', JSON.stringify(input))
  }
  assert.equal(evaluateCall(active, call('Glob', { pattern: 'secrets/**' }), keyCtx).decision, 'deny')
  assert.equal(evaluateCall(active, call('Grep', { pattern: 'x', path: 'src' }), keyCtx).decision, 'allow')
  assert.equal(evaluateCall(active, call('Read', { file_path: 'src/a.ts' }), keyCtx).decision, 'allow')
})

test('review: background jobs, subshells, assignments and wrappers are split out; trailing-dot hosts match', () => {
  const s = signConstraintSet(
    { constraint_id: 'push', scope: '*', prose: 'No pushes; no evil host.', rules: [
      { id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] },
      { id: 'host', effect: 'forbid', tools: ['WebFetch'], hosts: ['evil.com', '*.evil.com'] }] },
    op.privateKey,
  )
  const { active } = foldConstraints([s], op.did, AIT)
  for (const command of ['true & git push', '(git push)', 'echo $(git push)', 'echo `git push`', 'GIT_X=1 git push', 'sudo env A=b git push origin']) {
    assert.equal(evaluateCall(active, call('Bash', { command }), keyCtx).decision, 'deny', command)
  }
  assert.equal(evaluateCall(active, call('WebFetch', { url: 'https://evil.com./x' }), keyCtx).decision, 'deny')
  assert.equal(evaluateCall(active, call('WebFetch', { url: 'https://a.evil.com./' }), keyCtx).decision, 'deny')
})

test('glob: * stays in a path segment, ** crosses them, regex characters are literal', () => {
  assert.ok(globToRegExp('src/*.ts', true).test('src/a.ts'))
  assert.ok(!globToRegExp('src/*.ts', true).test('src/a/b.ts'))
  assert.ok(globToRegExp('src/**/*.ts', true).test('src/a/b.ts'))
  assert.ok(globToRegExp('src/**/*.ts', true).test('src/b.ts'))
  assert.ok(!globToRegExp('a.b', false).test('axb'))
  assert.ok(globToRegExp('mcp__github__*', false).test('mcp__github__create_issue'))
})

test('render: the re-injected text names each constraint and how a rescind is made', () => {
  const f = foldConstraints([noProdDeploy()], op.did, AIT)
  const text = renderConstraints(f, op.did)
  assert.match(text, /\[no-prod\] Do not deploy/)
  assert.match(text, /Only a rescind signed with the operator key/)
  assert.equal(renderConstraints(foldConstraints([], op.did, AIT), op.did), '')
  assert.match(statementHash(noProdDeploy()), /^0x[0-9a-f]{64}$/)
})
