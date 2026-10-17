// Regression pins from the real world (R001): the fixtures under
// fixtures/v01-real/ are real sealed v0.1 receipts the crew produced, copied
// byte-identical (manifest.json plus its files[], never a4's scitt/). Every
// one must keep verifying in both the repo's verify.sh and the CLI verifier.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto'
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { WitnessService, InMemoryStorage, toHex, verifyReceipt } from '@tunnelmindai/atap'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const FIXTURES = fileURLToPath(new URL('./fixtures/v01-real/', import.meta.url))
const NAMES = readdirSync(FIXTURES)

// cwd is the tmp root, outside the receipt dir, so neither verifier can lean
// on relative paths.
const verifySh = dir => spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8', cwd: tmpdir() })
const cliVerify = dir => spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', cwd: tmpdir() })

// The library verifier on a receipt dir, as `atap-witness verify` reads it.
const read = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
const jsVerify = dir => verifyReceipt({
  receipt: read(dir, 'manifest.json'),
  ait: read(dir, 'ait.json'),
  chain: read(dir, 'attestation_chain.json'),
  keys: read(dir, 'public_keys.json'),
})

// A tmp copy, so a verifier (or a mutation) can never touch the fixture.
function copy(name) {
  const dir = mkdtempSync(join(tmpdir(), 'atap-v01-real-'))
  cpSync(join(FIXTURES, name), dir, { recursive: true })
  return dir
}

test('the real fixtures are all present', () => {
  assert.deepEqual(NAMES.sort(), ['a3-overturn-atap', 'a4-scitt-export', 'a5b-owner-command', 'a7-atap-init'])
})

test('every real sealed v0.1 receipt verifies in verify.sh and atap-witness verify', () => {
  for (const name of NAMES) {
    const dir = copy(name)
    const sh = verifySh(dir)
    assert.equal(sh.status, 0, `verify.sh rejected ${name}: ${sh.stderr}`)
    const cli = cliVerify(dir)
    assert.equal(cli.status, 0, `atap-witness verify rejected ${name}: ${cli.stderr}`)
  }
})

// A002: the manifest's witness_signature is checked for OAI witnesses too, so
// an edited period, count, files[] or summary no longer passes. Every edit
// leaves the files the manifest lists untouched, so only the signature can
// catch it.
test('the untouched real OAI receipt passes the manifest signature check in both verifiers', () => {
  const dir = copy('a7-atap-init')
  const sh = verifySh(dir)
  assert.equal(sh.status, 0, sh.stderr)
  assert.match(sh.stdout, /OK {3}manifest signature/)
  const js = jsVerify(dir)
  assert.equal(js.ok, true, js.reason)
})

for (const [what, fn] of [
  ['period_end', m => { m.period_end = '2026-10-10T00:00:00.000Z' }],
  ['block_count', m => { m.block_count += 1 }],
  ['summary', m => { m.summary = 'forged' }],
  ['files', m => { m.files = m.files.filter(f => f.path !== 'summary.json') }],
]) {
  test(`a real OAI receipt with an edited manifest ${what} fails both verifiers`, () => {
    const dir = copy('a7-atap-init')
    const m = read(dir, 'manifest.json')
    fn(m)
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(m))
    const sh = verifySh(dir)
    assert.notEqual(sh.status, 0, 'verify.sh accepted an edited manifest')
    assert.match(sh.stderr, /manifest signature invalid/)
    const js = jsVerify(dir)
    assert.equal(js.ok, false, 'verifyReceipt accepted an edited manifest')
    assert.match(js.reason, /receipt signature invalid/)
  })
}

// One flipped hex digit in a block's witness_signature (prefix and length
// kept). The manifest's files[] sha256 is rewritten to match, otherwise the
// file-hash check rejects it first and the block-signature walk is never
// reached (the weaker check this test used to pin). The manifest signature
// is left alone, so the block signature is what fails.
test('a real receipt with a corrupted block witness_signature fails both verifiers', () => {
  const dir = copy('a7-atap-init')
  const path = join(dir, 'attestation_chain.json')
  const chain = JSON.parse(readFileSync(path, 'utf8'))
  const sig = chain[0].witness_signature
  chain[0].witness_signature = sig.slice(0, -1) + (sig.at(-1) === '0' ? '1' : '0')
  writeFileSync(path, JSON.stringify(chain))
  const mpath = join(dir, 'manifest.json')
  const manifest = JSON.parse(readFileSync(mpath, 'utf8'))
  manifest.files.find(f => f.path === 'attestation_chain.json').sha256 =
    '0x' + createHash('sha256').update(readFileSync(path)).digest('hex')
  writeFileSync(mpath, JSON.stringify(manifest))
  for (const [name, r] of [['verify.sh', verifySh(dir)], ['atap-witness verify', cliVerify(dir)]]) {
    assert.notEqual(r.status, 0, `${name} accepted a corrupted witness_signature`)
    assert.doesNotMatch(r.stdout + r.stderr, /sha256 mismatch/, `${name} failed on a file hash, not the signature`)
  }
})

// An AIT that expired before its receipt was generated stays receiptable, with
// the key's valid_until at ait.expires_at as the CLI writes it.
test('a v0.1 OAI receipt generated after the AIT expired verifies in both verifiers', async () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  let t = Date.parse('2026-10-09T12:00:00.000Z')
  const svc = new WitnessService({ witnessOAI: 'OAI-2026-0010002', privateKey, storage: new InMemoryStorage(), now: () => new Date(t) })
  const ait = await svc.declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(t + 86400_000).toISOString(),
  })
  const ev = await svc.witness(ait.id, 'code_crew:approval', {})
  const block = await svc.rollUp(ait.id, {})
  t += 2 * 86400_000
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  const keys = {
    keys: [{
      witness: ait.witness,
      key_id: 'k1',
      algorithm: 'ed25519',
      public_key: '0x' + toHex(new Uint8Array(der.subarray(der.length - 32))),
      valid_from: ait.issued_at,
      valid_until: ait.expires_at,
      status: 'active',
      rotated_to: null,
      compromise_notice: null,
    }],
    updated_at: new Date(t).toISOString(),
  }
  // The §7.5 layout, every file listed with its hash, as the CLI writes it.
  const dir = mkdtempSync(join(tmpdir(), 'atap-v01-expired-'))
  const bodies = { 'ait.json': JSON.stringify(ait), 'attestation_chain.json': JSON.stringify([block]), 'public_keys.json': JSON.stringify(keys), 'verify.sh': readFileSync(REPO_VERIFY_SH), 'profile_artifacts/witness_events.json': JSON.stringify([ev]) }
  mkdirSync(join(dir, 'profile_artifacts'))
  for (const [f, b] of Object.entries(bodies)) writeFileSync(join(dir, f), b)
  const files = [{ path: 'manifest.json', sha256: null }, ...Object.entries(bodies).map(([path, b]) => ({ path, sha256: '0x' + createHash('sha256').update(b).digest('hex') }))]
  const receipt = await svc.generateReceipt(ait.id, block.period_start, block.period_end, 'full', files)
  assert.ok(receipt.generated_at > ait.expires_at)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(receipt))
  const sh = verifySh(dir)
  assert.equal(sh.status, 0, sh.stderr)
  const cli = cliVerify(dir)
  assert.equal(cli.status, 0, cli.stderr)
})
