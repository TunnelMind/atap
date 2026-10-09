// Regression pins from the real world (R001): the fixtures under
// fixtures/v01-real/ are real sealed v0.1 receipts the crew produced, copied
// byte-identical (manifest.json plus its files[], never a4's scitt/). Every
// one must keep verifying in both the repo's verify.sh and the CLI verifier.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto'
import { cpSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { WitnessService, InMemoryStorage, toHex } from '@tunnelmindai/atap'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const FIXTURES = fileURLToPath(new URL('./fixtures/v01-real/', import.meta.url))
const NAMES = readdirSync(FIXTURES)

// cwd is the tmp root, outside the receipt dir, so neither verifier can lean
// on relative paths.
const verifySh = dir => spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8', cwd: tmpdir() })
const cliVerify = dir => spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', cwd: tmpdir() })

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

// One flipped hex digit in a block's witness_signature (prefix and length
// kept). The manifest's files[] sha256 is rewritten to match, otherwise the
// file-hash check rejects it first and the block-signature walk is never
// reached (the weaker check this test used to pin). The manifest signature
// is left alone: a manifest-signature edit is the known v0.1 gap.
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
  await svc.witness(ait.id, 'code_crew:approval', {})
  const block = await svc.rollUp(ait.id, {})
  t += 2 * 86400_000
  const receipt = await svc.generateReceipt(ait.id, '2000-01-01T00:00:00.000Z', '2100-01-01T00:00:00.000Z')
  assert.ok(receipt.generated_at > ait.expires_at)
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
  const dir = mkdtempSync(join(tmpdir(), 'atap-v01-expired-'))
  const files = { 'manifest.json': receipt, 'ait.json': ait, 'attestation_chain.json': [block], 'public_keys.json': keys }
  for (const [f, v] of Object.entries(files)) writeFileSync(join(dir, f), JSON.stringify(v))
  const sh = verifySh(dir)
  assert.equal(sh.status, 0, sh.stderr)
  const cli = cliVerify(dir)
  assert.equal(cli.status, 0, cli.stderr)
})
