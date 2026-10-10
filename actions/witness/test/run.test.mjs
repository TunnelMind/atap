// Smoke test: run.mjs under a fake GitHub env with a passing and a failing
// command, then a broken profile. Temp dirs only; no network, no ~/.crew.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const RUN = fileURLToPath(new URL('../run.mjs', import.meta.url))
const CLI = fileURLToPath(new URL('../../../packages/atap-cli/dist/cli.js', import.meta.url))
const VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const MARKER = 'witness-smoke-output-marker'
const PROBE = 'env-secret-probe-7f3a'

function action(command, extra = {}) {
  const temp = mkdtempSync(join(tmpdir(), 'atap-action-test-'))
  const outFile = join(temp, 'github_output')
  const env = {
    PATH: process.env.PATH,
    RUNNER_TEMP: temp,
    GITHUB_OUTPUT: outFile,
    GITHUB_REPOSITORY: 'example-org/example-repo',
    GITHUB_SHA: '3f1c2a9e8b7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f',
    INPUT_TEST_COMMAND: command,
    ...extra,
  }
  const r = spawnSync(process.execPath, [RUN], { env, encoding: 'utf8' })
  const outputs = Object.fromEntries(readFileSync(outFile, 'utf8').trim().split('\n').map(l => l.split(/=(.*)/s).slice(0, 2)))
  return { r, outputs, temp }
}

// The probe env var is echoed too, so it would leak if output text were stored.
for (const [command, code] of [[`echo ${MARKER} "$WITNESS_SECRET_PROBE"; true`, 0], [`echo ${MARKER} "$WITNESS_SECRET_PROBE"; exit 3`, 3]]) {
  test(`exit code ${code} passes through and the receipt verifies`, () => {
    const { r, outputs, temp } = action(command, { WITNESS_SECRET_PROBE: PROBE })
    assert.equal(r.status, code, r.stderr)
    assert.ok(r.stdout.includes(MARKER) && r.stdout.includes(PROBE), 'the test output streams to the log')
    assert.equal(outputs.verified, 'true', r.stdout)
    assert.match(outputs.did, /^did:key:z/)
    const receipt = outputs['receipt-path']
    assert.ok(!existsSync(join(receipt, 'witness.pem')))
    const events = readFileSync(join(receipt, 'profile_artifacts/witness_events.json'), 'utf8')
    assert.deepEqual(JSON.parse(events).map(e => [e.event_type, e.payload.evidence]),
      [['code_crew:change_committed', 'anchored'], ['code_crew:verify_run', 'witnessed']])
    const store = join(temp, readdirSync(temp).find(d => d.startsWith('atap-witness-')), 'store')
    for (const text of [events, readFileSync(join(store, 'events.jsonl'), 'utf8')]) {
      assert.ok(!text.includes(MARKER) && !text.includes(temp) && !text.includes('witness.pem'))
      assert.ok(!text.includes(PROBE))
    }
    // Bytes, not text, so a binary file in the receipt is checked too.
    for (const f of readdirSync(receipt, { recursive: true, withFileTypes: true }).filter(d => d.isFile())) {
      assert.ok(!readFileSync(join(f.parentPath, f.name)).includes(PROBE), f.name)
    }
    // Both verifiers again, run by the test itself rather than trusting run.mjs's verdict.
    assert.equal(spawnSync('bash', [VERIFY_SH, receipt], { encoding: 'utf8' }).status, 0)
    assert.equal(spawnSync(process.execPath, [CLI, 'verify', receipt], { encoding: 'utf8' }).status, 0)
  })
}

test('an Action error keeps the test code, and fails the step only with fail-on-error', () => {
  assert.equal(action('exit 3', { INPUT_PROFILE: 'nope' }).r.status, 3)
  const bad = action('true', { INPUT_PROFILE: 'nope' })
  assert.equal(bad.r.status, 0)
  assert.equal(bad.outputs.verified, 'false')
  assert.match(bad.r.stdout, /::warning::/)
  assert.equal(action('true', { INPUT_PROFILE: 'nope', INPUT_FAIL_ON_ERROR: 'true' }).r.status, 1)
})

test('the step summary holds the did and verdicts, never the command or its output', () => {
  const summary = join(mkdtempSync(join(tmpdir(), 'atap-action-summary-')), 'summary.md')
  const { r, outputs } = action(`echo ${MARKER}; true`, { GITHUB_STEP_SUMMARY: summary })
  assert.equal(r.status, 0, r.stderr)
  const text = readFileSync(summary, 'utf8')
  assert.ok(text.includes(outputs.did))
  assert.match(text, /change_committed 1, verify_run 1, block 1/)
  assert.ok(text.includes('verify.sh: PASS') && text.includes('atap-witness verify: PASS'), text)
  assert.ok(!text.includes(MARKER) && !text.includes('echo'), text)
  // An unwritable summary (here a directory) is a warning, not a new exit code.
  const bad = action('true', { GITHUB_STEP_SUMMARY: tmpdir(), INPUT_FAIL_ON_ERROR: 'true' })
  assert.equal(bad.r.status, 0)
  assert.match(bad.r.stdout, /::warning::atap-witness: cannot write step summary/)
})

test('a pull_request run anchors the PR head, not the temporary test merge', async () => {
  const { commitUnderTest } = await import(new URL('../run.mjs', import.meta.url))
  const { mkdtempSync, writeFileSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const d = mkdtempSync(join(tmpdir(), 'atap-ev-'))
  const head = 'a'.repeat(40), merge = 'b'.repeat(40)
  writeFileSync(join(d, 'event.json'), JSON.stringify({ pull_request: { head: { sha: head } } }))
  assert.equal(commitUnderTest({ GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: join(d, 'event.json'), GITHUB_SHA: merge }), head)
  assert.equal(commitUnderTest({ GITHUB_EVENT_NAME: 'push', GITHUB_SHA: merge }), merge)
  assert.equal(commitUnderTest({ GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: join(d, 'missing.json'), GITHUB_SHA: merge }), merge)
})
