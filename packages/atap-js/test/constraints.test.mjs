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
  commandSegments,
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

test('A003: every shell tool gets the commands rules and the name tripwire, not only Bash', () => {
  const s = signConstraintSet(
    { constraint_id: 'shells', scope: '*', prose: 'No pushes from any shell; stay out of secrets/.', rules: [
      { id: 'push', effect: 'forbid', tools: ['mcp__*', 'PowerShell', 'RunScript'], commands: ['git push*'] },
      { id: 'secrets', effect: 'forbid', tools: ['mcp__*'], paths: ['secrets/**'] }] },
    op.privateKey,
  )
  const { active } = foldConstraints([s], op.did, AIT)
  const tripped = (d) => d.decision === 'deny' && d.rule_id === 'store-command'
  assert.ok(tripped(evaluateCall([], call('PowerShell', { command: 'Remove-Item .atap/constraints.jsonl' }), keyCtx)))
  assert.ok(tripped(evaluateCall([], call('mcp__wsl__run', { command: 'rm .atap/constraints.jsonl' }), keyCtx)))
  assert.ok(tripped(evaluateCall([], call('RunScript', { script: 'cat /home/op/.atap-operator/operator.pem' }), keyCtx)))
  assert.equal(evaluateCall(active, call('mcp__wsl__run', { command: 'git push' }), keyCtx).rule_id, 'push')
  assert.equal(evaluateCall(active, call('RunScript', { script: 'git push origin' }), keyCtx).rule_id, 'push')
  assert.equal(evaluateCall(active, call('mcp__wsl__run', { command: 'git status' }), keyCtx).decision, 'allow')
  // A non-shell MCP tool: no command, so no commands match, but its path argument is still checked.
  assert.equal(evaluateCall(active, call('mcp__fs__read_file', { path: 'secrets/k.txt' }), keyCtx).rule_id, 'secrets')
  assert.equal(evaluateCall(active, call('mcp__fs__read_file', { path: 'src/a.ts' }), keyCtx).decision, 'allow')
  // A shell tool's path arguments stay path-checked too.
  assert.equal(evaluateCall([], call('mcp__x__run', { command: 'ls', file_path: '.atap/constraints.jsonl' }), keyCtx).rule_id, 'store-write')
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

test('windows paths: drive letters and backslashes fold; POSIX keeps a backslash literal', () => {
  const secrets = foldConstraints(
    [signConstraintSet({ constraint_id: 'sec', scope: '*', prose: 'No secrets.', rules: [{ id: 'sec', effect: 'forbid', tools: ['*'], paths: ['secrets/**'] }] }, op.privateKey)],
    op.did,
    AIT,
  ).active
  // Windows mode from the drive-letter root alone (no `windows` flag), and with the flag set.
  for (const extra of [{}, { windows: true }]) {
    const w = { projectRoot: 'C:\\p', protectedPaths: ['C:\\p\\.atap\\constraints.jsonl'], ...extra }
    const at = (file_path, cwd = 'C:\\p') => evaluateCall(secrets, call('Write', { file_path }, cwd), w)
    assert.equal(at('C:\\p\\.atap\\constraints.jsonl').rule_id, 'store-write')
    assert.equal(at('c:/P/.ATAP/constraints.jsonl').decision, 'deny')
    assert.equal(at('C:\\p\\secrets\\k').rule_id, 'sec')
    assert.equal(at('c:/P/Secrets/k').rule_id, 'sec')
    assert.equal(at('secrets\\k').rule_id, 'sec')
    assert.equal(at('..\\secrets\\k', 'C:\\p\\docs').rule_id, 'sec')
    assert.equal(at('C:\\p\\docs\\a').decision, 'allow')
    // A drive-less rooted path takes the project's drive.
    assert.equal(at('\\p\\.atap\\constraints.jsonl').rule_id, 'store-write')
    assert.equal(at('\\p\\secrets\\k').rule_id, 'sec')
    assert.equal(at('/p/secrets/k').rule_id, 'sec')
    assert.equal(at('\\\\srv\\x').decision, 'allow')
    // Extended-length and device prefixes are stripped; `\\?\UNC\` stays UNC, outside the project.
    assert.equal(at('\\\\?\\C:\\p\\.atap\\constraints.jsonl').rule_id, 'store-write')
    assert.equal(at('\\\\?\\C:\\p\\secrets\\k').rule_id, 'sec')
    assert.equal(at('\\\\.\\C:\\p\\secrets\\k').rule_id, 'sec')
    assert.equal(at('\\\\?\\UNC\\srv\\x').decision, 'allow')
    // A UNC path is absolute, so it is outside the project rather than under C:\p.
    const outside = foldConstraints([signConstraintSet({ constraint_id: 'out', scope: '*', prose: 'Stay in.', rules: [{ id: 'out', effect: 'forbid', tools: ['*'], outside_project: true }] }, op.privateKey)], op.did, AIT).active
    assert.equal(evaluateCall(outside, call('Read', { file_path: '\\\\srv\\share\\k' }, 'C:\\p'), w).rule_id, 'out')
    assert.equal(evaluateCall(outside, call('Read', { file_path: 'docs\\a' }, 'C:\\p'), w).decision, 'allow')
    assert.equal(evaluateCall(outside, call('Read', { file_path: '\\\\?\\UNC\\srv\\x' }, 'C:\\p'), w).rule_id, 'out')
    // The tripwire sees a backslashed, re-cased store path in a command.
    assert.equal(evaluateCall([], call('PowerShell', { command: 'Remove-Item C:\\P\\.ATAP\\Constraints.jsonl' }, 'C:\\p'), w).decision, 'deny')
  }
  // POSIX: `\` is a filename character, so `secrets/a\..\..\b` is a file under secrets/, not an escape.
  assert.equal(evaluateCall(secrets, call('Write', { file_path: 'secrets/a\\..\\..\\b' }), ctx).rule_id, 'sec')
  assert.equal(evaluateCall(secrets, call('Write', { file_path: `${ROOT}/secrets/a\\..\\..\\b` }), ctx).rule_id, 'sec')
  // POSIX: an extended-length prefix is just a filename (relative, in the project root, not under secrets/).
  assert.equal(evaluateCall(secrets, call('Write', { file_path: '\\\\?\\C:\\p\\secrets\\k' }), ctx).decision, 'allow')
})

test('absoluteOnlyPaths: guarded for writes, but the tripwire matches only their absolute path', () => {
  const plugin = `${ROOT}/plugins/claude-code`
  const c = { ...keyCtx, protectedPaths: [...keyCtx.protectedPaths, plugin], absoluteOnlyPaths: [plugin] }
  assert.equal(evaluateCall([], call('Edit', { file_path: `${plugin}/scripts/atap-hook.mjs` }), c).rule_id, 'store-write')
  assert.equal(evaluateCall([], call('Bash', { command: `rm ${plugin}/scripts/atap-hook.mjs` }), c).rule_id, 'store-command')
  assert.equal(evaluateCall([], call('Bash', { command: 'npm --prefix plugins/claude-code test' }), c).decision, 'allow')
  // Without the mark the same entry gets its project-relative name in the tripwire, as before.
  assert.equal(evaluateCall([], call('Bash', { command: 'npm --prefix plugins/claude-code test' }), { ...c, absoluteOnlyPaths: [] }).rule_id, 'store-command')
})

// A006 part 1: keywords, wrapper flags, /dir/cmd, a leading backslash and empty quotes normalise away.
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

test('A006: commandSegments reduces each disguised push to `git push`', () => {
  for (const cmd of A006_PUSHES) assert.ok(commandSegments(cmd).includes('git push'), `${cmd} -> ${JSON.stringify(commandSegments(cmd))}`)
  // more wrapper flag shapes
  for (const cmd of ['sudo -iu me git push', 'sudo -uroot git push', 'env -u HOME X=1 git push', 'timeout -s KILL 5 git push', "exec -a x git push", "command -p git push", "nohup nice -5 ./git push"])
    assert.ok(commandSegments(cmd).includes('git push'), `${cmd} -> ${JSON.stringify(commandSegments(cmd))}`)
})

test('A006 control: ordinary commands are unchanged', () => {
  assert.deepEqual(commandSegments('echo git push'), ['echo git push'])
  assert.deepEqual(commandSegments('git status'), ['git status'])
  assert.deepEqual(commandSegments('git  log -- src/a.ts'), ['git log -- src/a.ts'])
  assert.deepEqual(commandSegments('time'), ['time'])
})

test('A006: Object.prototype names as a first word neither throw nor hide a later push', () => {
  assert.ok(commandSegments('toString -x; git push').includes('git push'))
  assert.ok(commandSegments('constructor -x; git push').includes('git push'))
  // valueOf is not a wrapper, so the segment keeps it (the prototype bug used to strip it to `git push`).
  assert.deepEqual(commandSegments('valueOf git push'), ['valueOf git push'])
})

// A006 part 2: `sh -c '...'` strings (3 deep), xargs and git global options.
const A006_PART2_PUSHES = [
  "bash -c 'git push'",
  'sh -c "git push"',
  "bash -lc 'git push'",
  "bash -e -c 'git status; git push'",
  "/bin/bash -c 'git push'",
  'sudo bash -c "cd /x && git push"',
  'xargs git push',
  'echo x | xargs -n1 git push',
  'xargs -I {} git push',
  'git -C . push',
  'git -c a=b push',
  'git --git-dir=x push',
  'git --work-tree y -C . push',
  `bash -c "sh -c 'git push'"`,
]
// `n` shells deep, each a double-quoted `bash -c "..."` with the inner string escaped as a shell would need.
const nest = (cmd, n) => (n === 0 ? cmd : `bash -c "${nest(cmd, n - 1).replace(/[\\"]/g, '\\$&')}"`)

test('A006 part 2: {commands:["git push*"]} denies shell -c strings, xargs and git global options', () => {
  const { active } = foldConstraints(
    [signConstraintSet({ constraint_id: 'push', scope: '*', prose: 'No push.', rules: [{ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] }] }, op.privateKey)],
    op.did,
    AIT,
  )
  const decide = (command) => evaluateCall(active, call('Bash', { command }), ctx).decision
  for (const cmd of [...A006_PART2_PUSHES, nest('git push', 2), nest('git push', 3)]) assert.equal(decide(cmd), 'deny', `${cmd} -> ${JSON.stringify(commandSegments(cmd))}`)
  // The depth cap is 3: a push four shells deep is not followed (a documented limit, not a promise).
  assert.equal(decide(nest('git push', 4)), 'allow')
  for (const cmd of ["bash -c 'git status'", 'git -C . status', 'xargs git status', 'echo "bash -c"', 'bash -c']) assert.equal(decide(cmd), 'allow', cmd)
})

test('A006 part 2: the line itself still splits as before; -c strings only add segments', () => {
  assert.deepEqual(commandSegments("bash -c 'git push'"), ["bash -c 'git push'", 'git push'])
  assert.deepEqual(commandSegments('git -C . status'), ['git status'])
  assert.deepEqual(commandSegments('xargs'), ['xargs'])
  // Prototype names neither throw nor unwrap.
  assert.deepEqual(commandSegments('constructor -c x'), ['constructor -c x'])
  assert.deepEqual(commandSegments('toString'), ['toString'])
  assert.deepEqual(commandSegments("hasOwnProperty -c 'git push'"), ["hasOwnProperty -c 'git push'"])
})

test('A006 part 2: long flag runs and repeated git options stay fast (no regex blow-up)', () => {
  const { active } = foldConstraints(
    [signConstraintSet({ constraint_id: 'push', scope: '*', prose: 'No push.', rules: [{ id: 'push', effect: 'forbid', tools: ['Bash'], commands: ['git push*'] }] }, op.privateKey)],
    op.did,
    AIT,
  )
  const timed = (fn) => {
    const t0 = performance.now()
    const r = fn()
    return [r, performance.now() - t0]
  }
  // `--x` once matched two ways in SHELL_C, doubling the time per word (40 words would take days).
  const [d, ms] = timed(() => evaluateCall(active, call('Bash', { command: 'echo bash ' + '--x '.repeat(40) + '-c; git push' }), ctx).decision)
  assert.equal(d, 'deny')
  assert.ok(ms < 200, `${ms} ms`)
  for (const cmd of ['bash ' + '--x '.repeat(40) + "-c 'git push", 'bash ' + '--x '.repeat(20000) + "-c 'git push", 'git ' + '-C . '.repeat(20000) + 'push']) {
    const [, t] = timed(() => commandSegments(cmd))
    assert.ok(t < 200, `${cmd.slice(0, 30)}... (${cmd.length} chars): ${t} ms`)
  }
})
