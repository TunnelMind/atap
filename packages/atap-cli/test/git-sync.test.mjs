// `atap-witness git sync`: the store's JSONL files land on atap/records via
// plumbing only, leaving the user's worktree, index and HEAD untouched. Same
// harness as status.test.mjs: the built bin, cwd in a fresh temp dir.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const EVENT = JSON.stringify({ event_type: 'code_crew:task_claimed', payload: { timestamp: '2026-10-08T12:00:01.500Z', evidence: 'asserted', task_id: 'A1', role: 'coder', model: 'm' } })
const ID = { GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' }

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

const git = (cwd, args, input) => execFileSync('git', args, { cwd, input, env: { PATH: process.env.PATH, HOME: cwd, ...ID } }).toString()

// An init'd project inside a git repo with one commit, so HEAD exists.
async function repo() {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-git-'))
  git(cwd, ['init', '-q', '-b', 'main'])
  writeFileSync(join(cwd, 'a.txt'), 'one\n')
  git(cwd, ['add', 'a.txt'])
  git(cwd, ['commit', '-q', '-m', 'first'])
  await ok(cwd, ['init'])
  return cwd
}

const snapshot = cwd => ({
  status: git(cwd, ['status', '--porcelain', '--untracked-files=all']),
  cached: git(cwd, ['diff', '--cached']),
  head: git(cwd, ['rev-parse', 'HEAD']),
  a: readFileSync(join(cwd, 'a.txt')),
  b: readFileSync(join(cwd, 'b.txt')),
})

test('sync commits only the store JSONL files and leaves a dirty worktree and index untouched', async () => {
  const cwd = await repo()
  await ok(cwd, ['event'], EVENT)
  // Staged change, unstaged change on top, and an untracked file.
  writeFileSync(join(cwd, 'a.txt'), 'two\n')
  git(cwd, ['add', 'a.txt'])
  writeFileSync(join(cwd, 'a.txt'), 'three\n')
  writeFileSync(join(cwd, 'b.txt'), 'untracked\n')
  const before = snapshot(cwd)

  const r = await ok(cwd, ['git', 'sync'])
  assert.equal(r.out.synced, true)
  assert.equal(r.out.events, 1)
  assert.equal(r.out.blocks, 0)
  assert.match(r.stderr, /git push origin atap\/records/)
  assert.deepEqual(snapshot(cwd), before)

  const files = git(cwd, ['ls-tree', '-r', '--name-only', 'atap/records']).trim().split('\n')
  assert.deepEqual(files, ['aits.jsonl', 'events.jsonl'])
  for (const f of files) assert.equal(git(cwd, ['show', `atap/records:${f}`]), readFileSync(join(cwd, '.atap', f), 'utf8'))
  assert.doesNotMatch(files.join('\n'), /witness\.pem|config\.json/)
  assert.equal(git(cwd, ['log', '-1', '--format=%s', 'atap/records']).trim(), 'atap: 1 events, 0 blocks')
  // Orphan history: no parent from main.
  assert.equal(git(cwd, ['rev-list', '--count', 'atap/records']).trim(), '1')
})

test('a second sync with no store change is a no-op; a new event adds one child commit', async () => {
  const cwd = await repo()
  const first = await ok(cwd, ['git', 'sync'])
  const again = await ok(cwd, ['git', 'sync'])
  assert.equal(again.out.synced, false)
  assert.equal(again.out.commit, first.out.commit)
  assert.doesNotMatch(again.stderr, /git push/)
  assert.equal(git(cwd, ['rev-list', '--count', 'atap/records']).trim(), '1')

  await ok(cwd, ['event'], EVENT)
  const next = await ok(cwd, ['git', 'sync'])
  assert.equal(next.out.synced, true)
  assert.equal(git(cwd, ['rev-parse', `${next.out.commit}^`]).trim(), first.out.commit)
  assert.equal(git(cwd, ['log', '-1', '--format=%s', 'atap/records']).trim(), 'atap: 1 events, 0 blocks')
})

test('sync refuses when the branch holds lines the store lacks, and leaves the tip alone', async () => {
  const cwd = await repo()
  await ok(cwd, ['git', 'sync'])
  // Put an extra line on the branch's aits.jsonl via plumbing.
  const tip = git(cwd, ['rev-parse', 'atap/records']).trim()
  const blob = git(cwd, ['hash-object', '-w', '--stdin'], git(cwd, ['show', 'atap/records:aits.jsonl']) + '{"extra":1}\n').trim()
  const tree = git(cwd, ['mktree'], `100644 blob ${blob}\taits.jsonl\n`).trim()
  const forged = git(cwd, ['commit-tree', tree, '-p', tip, '-m', 'forged']).trim()
  git(cwd, ['update-ref', 'refs/heads/atap/records', forged])

  appendFileSync(join(cwd, '.atap', 'cleared.jsonl'), '{"x":1}\n')
  const r = await run(cwd, ['git', 'sync'])
  assert.notEqual(r.code, 0)
  assert.match(r.stderr, /lacks/)
  assert.equal(git(cwd, ['rev-parse', 'atap/records']).trim(), forged)
})

test('a store over 64 KB of multi-byte text syncs again after an append', async () => {
  const cwd = await repo()
  // Varying ASCII padding puts emoji at every byte alignment, so some chunk
  // boundary of git's output splits one.
  const line = i => JSON.stringify({ i, s: 'x'.repeat(i % 4) + '\u{1F600}'.repeat(50) }) + '\n'
  writeFileSync(join(cwd, '.atap', 'events.jsonl'), Array.from({ length: 1000 }, (_, i) => line(i)).join(''))
  assert.equal((await ok(cwd, ['git', 'sync'])).out.synced, true)
  appendFileSync(join(cwd, '.atap', 'events.jsonl'), line(1000))
  const r = await ok(cwd, ['git', 'sync'])
  assert.equal(r.out.synced, true)
  assert.equal(r.out.events, 1001)
})

test('sync outside a git repository gives a clear error', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-nogit-'))
  await ok(cwd, ['init'])
  const r = await run(cwd, ['git', 'sync'], '')
  assert.notEqual(r.code, 0)
  assert.match(r.stderr, /not inside a git repository/)
})
