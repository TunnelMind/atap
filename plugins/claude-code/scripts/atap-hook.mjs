#!/usr/bin/env node
// The one hook script for the ATAP Claude Code plugin. hooks/hooks.json runs it
// as `atap-hook.mjs <session-start|post-tool-use|session-end>` with the hook's
// JSON on stdin.
//
// The rule above all: never break a session. The script always exits 0 and
// never writes to stdout or stderr (SessionStart stdout lands in Claude's
// context, PostToolUse stderr is shown to Claude). Anything that goes wrong is
// appended to the project's .atap/hook.log instead. A project without .atap/,
// or ATAP_OFF=1, makes the script a silent no-op.
//
// Node built-ins only: the plugin ships with no dependencies.

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFile, readFile, stat } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

const LOG_CAP = 1024 * 1024 // hook.log stops growing at 1 MB
const run = promisify(execFile)
const DEFAULT_TEST_COMMANDS = ['npm test', 'pnpm test', 'pytest', 'python -m unittest', 'cargo test', 'go test']

// The nearest .atap/config.json at or above `from`, the same walk as
// atap-cli's findAtap (packages/atap-cli/src/cli.ts). A missing or unparseable
// config counts as no .atap/.
async function findAtap(from) {
  for (let d = resolve(from); ; ) {
    const dir = join(d, '.atap')
    const config = await readFile(join(dir, 'config.json'), 'utf8').then(JSON.parse).catch(() => null)
    if (config && typeof config === 'object' && !Array.isArray(config)) return { dir, config }
    const up = resolve(d, '..')
    if (up === d) return null
    d = up
  }
}

// One line to .atap/hook.log. Never throws: logging is the last resort.
async function log(atap, event, msg) {
  try {
    const file = join(atap.dir, 'hook.log')
    // ponytail: past the cap new lines are dropped, not rotated; rotate if the log ever matters.
    const size = await stat(file).then((s) => s.size, () => 0)
    if (size >= LOG_CAP) return
    await appendFile(file, `${new Date().toISOString()} ${event} ${String(msg).slice(0, 300)}\n`)
  } catch {}
}

async function readStdin() {
  if (process.stdin.isTTY) return ''
  const chunks = []
  for await (const c of process.stdin) chunks.push(c)
  return Buffer.concat(chunks).toString('utf8')
}

// The shell segments of a command line: split on && ; || | and newlines.
// ponytail: no quoting awareness; a separator inside quotes splits there too, which only adds segments.
const segments = (cmd) => cmd.split(/&&|\|\||[;|\n]/).map((s) => s.trim()).filter(Boolean)

// `git [-C dir] [-c k=v] [--flag] commit ...` in one segment, minus --dry-run.
function isGitCommit(segment) {
  const w = segment.split(/\s+/)
  if (w[0] !== 'git') return false
  let i = 1
  while (i < w.length && w[i].startsWith('-')) i += w[i] === '-C' || w[i] === '-c' ? 2 : 1
  return w[i] === 'commit' && !w.includes('--dry-run')
}

// A segment that starts with a test command at a word boundary: `pytest -q` yes, `npm testing` no.
const startsWithCommand = (segment, test) => segment === test || (segment.startsWith(test) && /\s/.test(segment[test.length]))

// The Bash result arrives as `tool_response` or `tool_output`, an object or a
// plain string. No exit code means 0: PostToolUse fires after a successful call.
function exitCodeOf(result) {
  if (!result || typeof result !== 'object') return 0
  for (const k of ['exit_code', 'exitCode', 'returncode', 'code']) {
    if (Number.isInteger(result[k])) return result[k]
  }
  return result.interrupted === true ? 1 : 0
}

// Output hashed for verify_run: stdout then stderr joined with no separator
// for an object result, the string itself for a string result.
function outputOf(result) {
  if (typeof result === 'string') return result
  if (!result || typeof result !== 'object') return ''
  const str = (v) => (typeof v === 'string' ? v : '')
  return str(result.stdout) + str(result.stderr)
}

const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex')

// owner/repo from an https, ssh:// or scp-style (git@host:owner/repo) remote.
// Local paths and file:// remotes don't parse: the repo field is never a path.
function ownerRepo(url) {
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/[^/]+\/|[^@/\s]+@[^:/\s]+:)(.+?)(?:\.git)?\/?$/i.exec(url.trim())
  return m && /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(m[1]) ? m[1] : null
}

// One `atap-witness event` with {event_type, payload} on stdin. No shell, and
// killed well inside the 10 s hook timeout. Failures log fixed text only: the
// CLI's own output may quote payload fields.
async function emit(atap, cwd, event_type, payload) {
  const bin = process.env.ATAP_WITNESS || (typeof atap.config.cli === 'string' ? atap.config.cli : 'atap-witness')
  const p = run(bin, ['event'], { cwd, timeout: 8000 })
  p.child.stdin.on('error', () => {}) // EPIPE if the binary dies before reading
  p.child.stdin.end(JSON.stringify({ event_type, payload }))
  try {
    await p
  } catch (e) {
    await log(atap, 'post-tool-use', e?.code === 'ENOENT' ? 'atap-witness not found' : `atap-witness event failed: exit ${Number.isInteger(e?.code) ? e.code : 'killed'}`)
  }
}

// Per-event handlers: (input, atap) where input is the parsed hook JSON and
// atap is { dir, config } from findAtap. Stubs until P803.
const handlers = {
  'session-start': async (_input, _atap) => {
    // P803: nothing, or one line to hook.log.
  },
  'post-tool-use': async (input, atap) => {
    const command = input.tool_input?.command
    if (input.tool_name !== 'Bash' || typeof command !== 'string') return
    const cwd = typeof input.cwd === 'string' ? input.cwd : process.cwd()
    const result = input.tool_response ?? input.tool_output
    const exit_code = exitCodeOf(result)
    const segs = segments(command)
    const timestamp = new Date().toISOString()

    if (segs.some(isGitCommit)) {
      if (exit_code !== 0) return
      const git = (...args) => run('git', args, { cwd, timeout: 5000 }).then((r) => r.stdout.trim(), () => '')
      const commit_sha = await git('rev-parse', 'HEAD')
      if (!/^[0-9a-f]{40}$/.test(commit_sha)) return log(atap, 'post-tool-use', 'no commit sha')
      const repo = ownerRepo(await git('remote', 'get-url', 'origin'))
      if (!repo) return log(atap, 'post-tool-use', 'no owner/repo')
      return emit(atap, cwd, 'code_crew:change_committed', { timestamp, evidence: 'anchored', repo, commit_sha })
    }

    const configured = atap.config.test_commands
    const tests = Array.isArray(configured) && configured.every((c) => typeof c === 'string') ? configured : DEFAULT_TEST_COMMANDS
    if (!segs.some((s) => tests.some((t) => t.trim() && startsWithCommand(s, t.trim())))) return
    // Failing runs are recorded too: P803's period summary counts them.
    return emit(atap, cwd, 'code_crew:verify_run', {
      timestamp,
      evidence: 'asserted',
      command_sha256: sha256(command),
      exit_code: Math.max(-255, Math.min(255, exit_code)),
      output_sha256: sha256(outputOf(result)),
    })
  },
  'session-end': async (_input, _atap) => {
    // P803: close a block with this session's period summary.
  },
}

export async function main(event = process.argv[2]) {
  if (process.env.ATAP_OFF === '1') return
  const raw = await readStdin()
  let input = null
  try {
    input = JSON.parse(raw)
  } catch {}
  const valid = input && typeof input === 'object' && !Array.isArray(input)
  // The hook's `cwd` is the session's project; fall back to our own cwd when stdin is unusable.
  const atap = await findAtap(valid && typeof input.cwd === 'string' ? input.cwd : process.cwd())
  if (!atap) return
  // Fixed text, not the parse error: JSON.parse messages quote the input.
  if (!valid) return log(atap, event, 'malformed stdin')
  const handler = handlers[event]
  if (!handler) return log(atap, event, 'unknown event')
  try {
    await handler(input, atap)
  } catch (e) {
    await log(atap, event, `${e?.name ?? 'Error'}: ${e?.message ?? e}`)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Whatever happens, exit 0 and say nothing.
  main()
    .catch(() => {})
    .finally(() => {
      process.exitCode = 0
    })
}
