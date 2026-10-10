// `init --git`: every `block` also runs `git sync`, best-effort. Same harness
// as git-sync.test.mjs: the built bin, cwd in a fresh temp dir.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const EVENT = JSON.stringify({ event_type: 'code_crew:task_claimed', payload: { timestamp: '2026-10-08T12:00:01.500Z', evidence: 'asserted', task_id: 'A1', role: 'coder', model: 'm' } })
const SUMMARY = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} })
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
const config = cwd => JSON.parse(readFileSync(join(cwd, '.atap', 'config.json'), 'utf8'))
const hasRecords = cwd => {
  try {
    git(cwd, ['rev-parse', '--verify', '-q', 'refs/heads/atap/records'])
    return true
  } catch {
    return false
  }
}

// A git repo with one commit, so HEAD exists, init'd with the given flags.
async function repo(initArgs) {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-gitblock-'))
  git(cwd, ['init', '-q', '-b', 'main'])
  writeFileSync(join(cwd, 'a.txt'), 'one\n')
  git(cwd, ['add', 'a.txt'])
  git(cwd, ['commit', '-q', '-m', 'first'])
  await ok(cwd, ['init', ...initArgs])
  return cwd
}

const snapshot = cwd => ({
  status: git(cwd, ['status', '--porcelain', '--untracked-files=all', '--', ':!.atap']),
  cached: git(cwd, ['diff', '--cached']),
  head: git(cwd, ['rev-parse', 'HEAD']),
  a: readFileSync(join(cwd, 'a.txt')),
})

test('init --git writes git_sync: true; plain init writes no git_sync key', async () => {
  assert.equal(config(await repo(['--git'])).git_sync, true)
  assert.equal('git_sync' in config(await repo([])), false)
})

test('with git_sync, block lands on atap/records and leaves worktree, index and HEAD alone', async () => {
  const cwd = await repo(['--git'])
  await ok(cwd, ['event'], EVENT)
  // Staged change with an unstaged one on top.
  writeFileSync(join(cwd, 'a.txt'), 'two\n')
  git(cwd, ['add', 'a.txt'])
  writeFileSync(join(cwd, 'a.txt'), 'three\n')
  const before = snapshot(cwd)

  const r = await ok(cwd, ['block'], SUMMARY)
  // stdout is only the block, and no publish hint on every block.
  assert.ok(r.out.id)
  assert.doesNotMatch(r.stderr, /git push/)
  assert.deepEqual(snapshot(cwd), before)

  const blocks = git(cwd, ['show', 'atap/records:blocks.jsonl'])
  assert.equal(blocks, readFileSync(join(cwd, '.atap', 'blocks.jsonl'), 'utf8'))
  assert.match(blocks, new RegExp(r.out.id))
})

test('without git_sync, block creates no atap/records branch', async () => {
  const cwd = await repo([])
  await ok(cwd, ['event'], EVENT)
  await ok(cwd, ['block'], SUMMARY)
  assert.equal(hasRecords(cwd), false)
})

test('a failed sync after block keeps exit 0 and the block JSON, and warns on stderr', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-gitblock-nogit-'))
  await ok(cwd, ['init'])
  writeFileSync(join(cwd, '.atap', 'config.json'), JSON.stringify({ ...config(cwd), git_sync: true }))
  await ok(cwd, ['event'], EVENT)
  const r = await ok(cwd, ['block'], SUMMARY)
  assert.ok(r.out.id)
  assert.match(r.stderr, /^git sync failed: .*not inside a git repository/m)
})
