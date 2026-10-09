// The README's Quickstart block, run as written: the 5-minute bar, measured.
// An `atap-witness` shim on PATH runs the built bin; cwd is a fresh temp dir.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { performance } from 'node:perf_hooks'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8')

// Never rejects; the caller asserts on the exit code.
function run(cmd, args, cwd, env) {
  return new Promise(resolve => {
    const child = spawn(cmd, args, { cwd, env })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
  })
}

test('README Quickstart runs as written, both verifiers pass, under 10 s', async () => {
  const block = README.match(/^## Quickstart\n[\s\S]*?^```sh\n([\s\S]*?)^```$/m)?.[1]
  assert.ok(block, 'README.md has no ## Quickstart ```sh block')

  // Guard against the doc being hollowed out: every step, three events.
  const cmds = block.split('\n').map(l => l.match(/atap-witness (\w+)/)?.[1]).filter(Boolean)
  for (const c of ['init', 'event', 'block', 'receipt', 'verify']) assert.ok(cmds.includes(c), c)
  assert.equal(cmds.filter(c => c === 'event').length, 3)
  assert.match(block, /^atap-witness verify receipt$/m)

  const bin = mkdtempSync(join(tmpdir(), 'atap-qs-bin-'))
  writeFileSync(join(bin, 'atap-witness'), `#!/bin/sh\nexec node "${CLI}" "$@"\n`)
  chmodSync(join(bin, 'atap-witness'), 0o755)
  const cwd = mkdtempSync(join(tmpdir(), 'atap-qs-'))
  const env = { PATH: `${bin}:${process.env.PATH}` }

  const t0 = performance.now()
  const r = await run('sh', ['-e', '-c', block], cwd, env)
  const ms = performance.now() - t0
  assert.equal(r.code, 0, r.stderr)
  assert.ok(ms < 10_000, `quickstart took ${Math.round(ms)} ms`)

  // First verifier: `atap-witness verify receipt`, the block's last line and
  // so the last pretty-printed JSON object (a `{` at column 0) on stdout.
  const out = JSON.parse(r.stdout.split(/^(?=\{)/m).at(-1))
  assert.equal(out.ok, true)
  assert.equal(out.blocks, 1)

  // Second verifier: the verify.sh `receipt` bundled into the receipt.
  assert.ok(existsSync(join(cwd, 'receipt', 'manifest.json')))
  assert.ok(existsSync(join(cwd, 'receipt.zip')))
  const sh = await run(join(cwd, 'receipt', 'verify.sh'), ['receipt'], cwd, env)
  assert.equal(sh.code, 0, sh.stdout + sh.stderr)
  assert.match(sh.stdout, /==> Receipt verifies \(blocks=1,/)
})
