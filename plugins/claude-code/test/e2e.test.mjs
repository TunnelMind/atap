// P804: the hook end to end against the REAL atap-witness (packages/atap-cli/dist/cli.js):
// a commit and a test run become events, session-end closes a block, the
// receipt verifies under both verifiers, nothing private reaches .atap/, and
// every hook call stays under 2 s. Build the CLI first with
// `npm --prefix packages/atap-cli run build`; without it the test is skipped.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('../scripts/atap-hook.mjs', import.meta.url))
const CLI = fileURLToPath(new URL('../../../packages/atap-cli/dist/cli.js', import.meta.url))
const SECRET_MSG = 'e2e-secret-commit-message-7f3a'
const SECRET_CMD = 'npm test -- /home/e2e-fake/secret-path-91c2'

const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim()
const cli = (cwd, ...args) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  return JSON.parse(r.stdout)
}

// Spawns the hook with the wrapper as ATAP_WITNESS; asserts silence, exit 0 and < 2000 ms.
function hook(root, repo, event, input) {
  const { ATAP_OFF, ...env } = process.env
  const t0 = performance.now()
  const r = spawnSync(process.execPath, [script, event], {
    cwd: repo,
    input: JSON.stringify({ session_id: 's', cwd: repo, ...input }),
    env: { ...env, ATAP_WITNESS: join(root, 'atap-witness') },
    encoding: 'utf8',
  })
  const ms = performance.now() - t0
  assert.equal(r.status, 0)
  assert.equal(r.stdout, '')
  assert.equal(r.stderr, '')
  assert.ok(ms < 2000, `${event} took ${Math.round(ms)} ms`)
}

const jsonl = (f) => (existsSync(f) ? readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [])

test('real CLI: commit + test run -> events, block, receipt verifies twice, no leak', { skip: !existsSync(CLI) && `no ${CLI}; run npm --prefix packages/atap-cli run build` }, (t) => {
  const root = mkdtempSync(join(tmpdir(), 'atap-e2e-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  // dist/cli.js is not executable and the hook execFile's ATAP_WITNESS, so wrap it.
  const wrapper = join(root, 'atap-witness')
  writeFileSync(wrapper, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(CLI)} "$@"\n`)
  chmodSync(wrapper, 0o755)
  const repo = join(root, 'repo')
  mkdirSync(repo)
  git(repo, 'init', '-q')
  git(repo, 'config', 'user.name', 't')
  git(repo, 'config', 'user.email', 't@t')
  git(repo, 'remote', 'add', 'origin', 'git@github.com:owner/repo.git')
  // init's default profile is code_crew, which declares change_committed and verify_run.
  const config = cli(repo, 'init')
  assert.equal(config.profile, 'tunnelmind:code_crew:v1')
  writeFileSync(join(repo, 'f'), 'x')
  git(repo, 'add', 'f')
  git(repo, 'commit', '-qm', SECRET_MSG)
  const sha = git(repo, 'rev-parse', 'HEAD')
  const store = join(repo, '.atap')

  hook(root, repo, 'post-tool-use', { tool_name: 'Bash', tool_input: { command: `git commit -m "${SECRET_MSG}"` }, tool_response: { stdout: 'ok', stderr: '' } })
  hook(root, repo, 'post-tool-use', { tool_name: 'Bash', tool_input: { command: SECRET_CMD }, tool_response: { stdout: 'pass', stderr: '', exit_code: 0 } })
  const events = jsonl(join(store, 'events.jsonl'))
  const commits = events.filter((e) => e.event_type === 'code_crew:change_committed')
  assert.equal(commits.length, 1)
  assert.equal(commits[0].payload.commit_sha, sha)
  assert.equal(events.filter((e) => e.event_type === 'code_crew:verify_run').length, 1)

  hook(root, repo, 'session-end', { hook_event_name: 'SessionEnd' })
  assert.equal(jsonl(join(store, 'blocks.jsonl')).length, 1)
  assert.ok(!existsSync(join(store, 'hook.log')))

  // Every non-key file the three hook calls left in the store: no commit message,
  // command text or temp path. Scanned before `receipt`, whose last-receipt.json
  // records the --out path we choose.
  for (const f of readdirSync(store, { recursive: true })) {
    const p = join(store, f)
    if (f.endsWith('.pem') || !statSync(p).isFile()) continue
    const text = readFileSync(p, 'utf8')
    for (const s of [SECRET_MSG, SECRET_CMD, '/home/e2e-fake', root, repo]) assert.ok(!text.includes(s), `${f} contains ${s}`)
  }

  // receipt from config's key/witness/ait, then the JS verifier and the shipped verify.sh.
  cli(repo, 'receipt', '--ait', config.ait, '--out', join(root, 'r'))
  assert.equal(cli(repo, 'verify', join(root, 'r')).ok, true)
  const sh = spawnSync('bash', ['verify.sh'], { cwd: join(root, 'r'), encoding: 'utf8' })
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
})
