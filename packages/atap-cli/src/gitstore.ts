// `atap-witness git sync`: mirrors the store's JSONL files onto the orphan
// branch atap/records using plumbing only (hash-object, mktree, commit-tree,
// update-ref). Nothing here reads or writes the index or worktree, so a user
// mid-edit, mid-rebase or with staged changes is never disturbed.

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { withLock } from './storage.js'

const REF = 'refs/heads/atap/records'
// Never witness.pem, config.json, last-receipt.json or .gitignore: only the records.
const FILES = ['aits.jsonl', 'blocks.jsonl', 'cleared.jsonl', 'events.jsonl']
// Fixed identity so sync works with no user.name configured.
const IDENTITY = {
  GIT_AUTHOR_NAME: 'atap-witness',
  GIT_AUTHOR_EMAIL: 'atap-witness@localhost',
  GIT_COMMITTER_NAME: 'atap-witness',
  GIT_COMMITTER_EMAIL: 'atap-witness@localhost',
}

type Out = { code: number; stdout: string; stderr: string }

// Only hash-object and mktree read stdin; the rest get none, since writing to
// a git that already exited is an EPIPE.
function git(cwd: string, args: string[], input?: string): Promise<Out> {
  return new Promise((resolve, reject) => {
    const stdin = input === undefined ? 'ignore' : 'pipe'
    const child = spawn('git', args, { cwd, env: { ...process.env, ...IDENTITY }, stdio: [stdin, 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    // Decode across chunks: a per-chunk += splits multi-byte UTF-8 at the 64 KB
    // pipe boundary, which would break the append-only prefix check.
    child.stdout!.setEncoding('utf8')
    child.stderr!.setEncoding('utf8')
    child.stdout!.on('data', d => (stdout += d))
    child.stderr!.on('data', d => (stderr += d))
    child.on('error', reject)
    child.on('close', code => resolve({ code: code ?? 1, stdout, stderr }))
    child.stdin?.end(input)
  })
}

async function gitOk(cwd: string, args: string[], input?: string): Promise<string> {
  const r = await git(cwd, args, input)
  if (r.code !== 0) throw new Error(`git ${args[0]} failed: ${r.stderr.trim()}`)
  return r.stdout.trim()
}

const lines = (s: string | undefined): number => (s ?? '').split('\n').filter(l => l !== '').length

export async function gitSync(dir: string): Promise<{ synced: boolean; commit: string; events: number; blocks: number }> {
  if (!existsSync(dir)) throw new Error(`no store at ${dir}; run atap-witness init`)
  if ((await git(dir, ['rev-parse', '--git-dir'])).code !== 0) {
    throw new Error(`${dir} is not inside a git repository; run git init first`)
  }
  // Snapshot under the store lock so a concurrent event/block cannot tear a file.
  const store: Record<string, string> = {}
  await withLock(dir, async () => {
    for (const f of FILES) {
      const p = join(dir, f)
      if (existsSync(p)) store[f] = await readFile(p, 'utf8')
    }
  })

  const tipRes = await git(dir, ['rev-parse', '--verify', '-q', `${REF}^{commit}`])
  const tip = tipRes.code === 0 ? tipRes.stdout.trim() : null
  if (tip) {
    // Append-only: each branch file must be a whole-line prefix of the store's,
    // else committing the store would drop history from the branch.
    for (const f of (await gitOk(dir, ['ls-tree', '--full-tree', '--name-only', tip])).split('\n').filter(Boolean)) {
      const r = await git(dir, ['cat-file', 'blob', `${tip}:${f}`])
      const now = store[f] ?? ''
      const prefix = now.startsWith(r.stdout) && (r.stdout === '' || r.stdout.endsWith('\n') || r.stdout === now)
      if (r.code !== 0 || !prefix) {
        throw new Error(`atap/records holds ${f} lines the store lacks; refusing to sync (would drop history)`)
      }
    }
  }

  let mktree = ''
  for (const [f, body] of Object.entries(store)) {
    mktree += `100644 blob ${await gitOk(dir, ['hash-object', '-w', '--stdin'], body)}\t${f}\n`
  }
  const tree = await gitOk(dir, ['mktree'], mktree)
  const events = lines(store['events.jsonl'])
  const blocks = lines(store['blocks.jsonl'])
  if (tip && tree === (await gitOk(dir, ['rev-parse', `${tip}^{tree}`]))) {
    return { synced: false, commit: tip, events, blocks }
  }
  const commit = await gitOk(dir, ['commit-tree', tree, ...(tip ? ['-p', tip] : []), '-m', `atap: ${events} events, ${blocks} blocks`])
  // Compare-and-swap on the old tip (all zeros = must not exist yet), so a
  // racing sync fails instead of being overwritten.
  await gitOk(dir, ['update-ref', REF, commit, tip ?? '0'.repeat(40)])
  return { synced: true, commit, events, blocks }
}
