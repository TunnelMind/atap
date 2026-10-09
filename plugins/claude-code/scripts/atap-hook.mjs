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

import { appendFile, readFile, stat } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const LOG_CAP = 1024 * 1024 // hook.log stops growing at 1 MB

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

// Per-event handlers: (input, atap) where input is the parsed hook JSON and
// atap is { dir, config } from findAtap. Stubs until P802/P803.
const handlers = {
  'session-start': async (_input, _atap) => {
    // P803: nothing, or one line to hook.log.
  },
  'post-tool-use': async (_input, _atap) => {
    // P802: a successful `git commit` -> change_committed; a test command -> verify_run.
    // The tool's result may arrive as `tool_response` or `tool_output`; accept both.
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
