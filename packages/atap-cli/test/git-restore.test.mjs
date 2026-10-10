// `atap-witness git restore`: a fresh clone rebuilds .atap/ (minus the key and
// config) from atap/records, and a receipt made from it verifies in both
// verifiers. Same harness as git-sync.test.mjs.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const EVENT = JSON.stringify({ event_type: 'code_crew:task_claimed', payload: { timestamp: '2026-10-08T12:00:01.500Z', evidence: 'asserted', task_id: 'A1', role: 'coder', model: 'm' } })
const SUMMARY = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })
const ID = { GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' }
const JSONL = ['aits.jsonl', 'blocks.jsonl', 'cleared.jsonl', 'events.jsonl']

function run(cwd, args, stdin = '') {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env: { PATH: process.env.PATH } })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
}

async function ok(cwd, args, stdin) {
  const r = await run(cwd, args, stdin)
  assert.equal(r.code, 0, r.stderr)
  return { ...r, out: JSON.parse(r.stdout) }
}

const git = (cwd, args) => execFileSync('git', args, { cwd, env: { PATH: process.env.PATH, HOME: cwd, ...ID } }).toString()

// Repo A: an init'd store with an event and a block, synced to atap/records.
// B: a plain clone of A, so it has only refs/remotes/origin/atap/records.
async function cloned() {
  const a = mkdtempSync(join(tmpdir(), 'atap-restore-a-'))
  git(a, ['init', '-q', '-b', 'main'])
  writeFileSync(join(a, 'a.txt'), 'one\n')
  git(a, ['add', 'a.txt'])
  git(a, ['commit', '-q', '-m', 'first'])
  const config = (await ok(a, ['init'])).out
  await ok(a, ['event'], EVENT)
  await ok(a, ['block'], SUMMARY)
  const sync = (await ok(a, ['git', 'sync'])).out
  const b = join(mkdtempSync(join(tmpdir(), 'atap-restore-b-')), 'b')
  git(a, ['clone', '-q', a, b])
  return { a, b, config, sync }
}

const snapshot = cwd => ({
  status: git(cwd, ['status', '--porcelain', '--untracked-files=all', '--', ':!.atap']),
  cached: git(cwd, ['diff', '--cached']),
  head: git(cwd, ['rev-parse', 'HEAD']),
  branches: git(cwd, ['for-each-ref', '--format=%(refname) %(objectname)']),
})

test('restore in a fresh clone rebuilds the records byte-for-byte, and its receipt verifies in both verifiers', async () => {
  const { a, b, config, sync } = await cloned()
  assert.notEqual(spawnSync('git', ['rev-parse', '-q', '--verify', 'refs/heads/atap/records'], { cwd: b }).status, 0, 'clone has no local atap/records')
  const before = snapshot(b)

  const r = await ok(b, ['git', 'restore'])
  assert.equal(r.stderr, '')
  assert.deepEqual(r.out, { restored: JSONL, dir: join(b, '.atap'), commit: sync.commit })
  assert.deepEqual(readdirSync(join(b, '.atap')).sort(), ['.gitignore', ...JSONL])
  for (const f of JSONL) assert.ok(readFileSync(join(b, '.atap', f)).equals(readFileSync(join(a, '.atap', f))), f)
  assert.equal(readFileSync(join(b, '.atap', '.gitignore'), 'utf8'), 'witness.pem\n')
  assert.equal(existsSync(join(b, '.atap', 'witness.pem')), false)
  assert.deepEqual(snapshot(b), before)

  // A's key, kept outside the store as an operator would.
  const key = join(b, '..', 'witness.pem')
  writeFileSync(key, readFileSync(join(a, '.atap', 'witness.pem')))
  await ok(b, ['receipt', '--key', key, '--dir', '.atap', '--ait', config.ait, '--witness-oai', config.witness_oai, '--out', 'r'])
  const cli = spawnSync(process.execPath, [CLI, 'verify', join(b, 'r')], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  assert.equal(cli.status, 0, cli.stdout + cli.stderr)
  assert.equal(JSON.parse(cli.stdout).ok, true)
  const sh = spawnSync('bash', [VERIFY_SH, join(b, 'r')], { encoding: 'utf8' })
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
})

test('a second identical restore is a no-op; a differing file is refused and nothing is written', async () => {
  const { b, sync } = await cloned()
  // --into, and the local branch this time.
  git(b, ['fetch', '-q', 'origin', 'atap/records:atap/records'])
  const first = await ok(b, ['git', 'restore', '--into', 'store'])
  const again = await ok(b, ['git', 'restore', '--into', 'store'])
  assert.deepEqual(again.out, first.out)
  assert.equal(first.out.commit, sync.commit)

  const target = mkdtempSync(join(tmpdir(), 'atap-restore-t-'))
  writeFileSync(join(target, 'events.jsonl'), '{"other":1}\n')
  const r = await run(b, ['git', 'restore', '--into', target])
  assert.notEqual(r.code, 0)
  assert.equal(r.stdout, '')
  assert.match(r.stderr, /events\.jsonl exists and differs/)
  assert.deepEqual(readdirSync(target), ['events.jsonl'])
})

test('restore with no atap/records anywhere says how to fetch it', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-restore-none-'))
  git(cwd, ['init', '-q', '-b', 'main'])
  const r = await run(cwd, ['git', 'restore'])
  assert.notEqual(r.code, 0)
  assert.match(r.stderr, /no atap\/records branch; fetch it first: git fetch origin atap\/records:atap\/records/)
  assert.equal(existsSync(join(cwd, '.atap')), false)
})

test('restore ignores other names on a hostile branch', async () => {
  const { b } = await cloned()
  const tip = git(b, ['rev-parse', 'origin/atap/records']).trim()
  const evil = execFileSync('git', ['hash-object', '-w', '--stdin'], { cwd: b, input: 'pwned\n' }).toString().trim()
  const tree = execFileSync('git', ['mktree'], {
    cwd: b,
    input: git(b, ['ls-tree', tip]) + `100644 blob ${evil}\twitness.pem\n100644 blob ${evil}\tconfig.json\n`,
  }).toString().trim()
  const forged = execFileSync('git', ['commit-tree', tree, '-p', tip, '-m', 'forged'], { cwd: b, env: { PATH: process.env.PATH, ...ID } }).toString().trim()
  git(b, ['update-ref', 'refs/heads/atap/records', forged])
  const r = await ok(b, ['git', 'restore'])
  assert.equal(r.out.commit, forged)
  assert.deepEqual(readdirSync(join(b, '.atap')).sort(), ['.gitignore', ...JSONL])
})
