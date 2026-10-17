// verify.sh on ATAP v0.2 receipts with a did:key witness (ATAP-v0.2 §3): the
// key binding, the self-asserted rule and the version rule. Throwaway keys
// and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { cpSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  WitnessService,
  InMemoryStorage,
  didKeyFromPublicKey,
  publicKeyFromDidKey,
  toHex,
  ed25519Sign,
  canonicalizeBytes,
  fromHex,
  sha256,
} from '@tunnelmindai/atap'

const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const EVENTS = 'profile_artifacts/witness_events.json'
const POLICY = { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' }

function rawPub(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  return new Uint8Array(der.subarray(der.length - 32))
}

// A did:key-witnessed receipt dir as `atap-witness receipt` lays it out, or an
// OAI-witnessed one when `oai` is given. With `afterExpiry` the AIT lives one
// day, three days ago, and the receipt is generated two days after its
// expires_at, under a key entry whose valid_until is that expires_at.
async function didReceiptDir(oai, { afterExpiry = false } = {}) {
  const { privateKey } = generateKeyPairSync('ed25519')
  const witness = oai ?? didKeyFromPublicKey(rawPub(privateKey))
  let t = Date.now() - 3 * 86400_000
  const clock = afterExpiry ? { now: () => new Date(t) } : {}
  const svc = new WitnessService({ witnessOAI: witness, privateKey, storage: new InMemoryStorage(), ...clock })
  const ait = await svc.declareAit({
    agentType: 'crew-ops',
    profile: 'tunnelmind:crew_ops:v1',
    operator: witness,
    capabilities: ['crew_ops:ratify'],
    attestationPolicy: POLICY,
    expiresAt: new Date(afterExpiry ? t + 86400_000 : Date.now() + 30 * 86400_000).toISOString(),
  })
  await svc.witness(ait.id, 'crew_ops:ratify', { n: 1 })
  const block = await svc.rollUp(ait.id, { ratifications: 1 })
  t += 2 * 86400_000
  const receipt = await svc.generateReceipt(ait.id, '2000-01-01T00:00:00.000Z', '2100-01-01T00:00:00.000Z')
  const keys = {
    keys: [{
      witness,
      key_id: 'k1',
      algorithm: 'ed25519',
      public_key: '0x' + toHex(rawPub(privateKey)),
      valid_from: '2000-01-01T00:00:00Z',
      valid_until: afterExpiry ? ait.expires_at : '2100-01-01T00:00:00Z',
      status: 'active',
      attestation_strength: 'self-asserted',
      rotated_to: null,
      compromise_notice: null,
    }],
    updated_at: new Date().toISOString(),
  }
  const dir = mkdtempSync(join(tmpdir(), 'atap-v02-'))
  const files = { 'manifest.json': receipt, 'ait.json': ait, 'attestation_chain.json': [block], 'public_keys.json': keys }
  for (const [f, v] of Object.entries(files)) writeFileSync(join(dir, f), JSON.stringify(v))
  return { dir, privateKey, witness, ait, block, receipt }
}

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
function edit(dir, f, fn) { writeFileSync(join(dir, f), JSON.stringify(fn(readJson(dir, f)))) }
const verifySh = dir => spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8' })
// `atap-witness verify DIR`: the CLI's verify, i.e. verifyReceipt plus the
// file-integrity and witness-events checks.
function cliVerify(dir) {
  const r = spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  return { status: r.status, ...JSON.parse(r.stdout) }
}

function assertFails(r, re) {
  assert.notEqual(r.status, 0, r.stdout)
  assert.match(r.stderr, /FAIL: /)
  assert.match(r.stderr, re)
}

test('a valid v0.2 did:key receipt verifies', async () => {
  const { dir } = await didReceiptDir()
  assert.equal(readJson(dir, 'ait.json').ait_version, '0.2')
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /Receipt verifies \(blocks=1, attestation_strength=self-asserted\)/)
})

// The did:key alone does not replace the key entry (as verifyReceipt).
for (const [what, fn] of [
  ['no key entry', k => ({ ...k, keys: [] })],
  ['only a compromised key entry', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at: '2001-01-01T00:00:00Z' } }] })],
]) {
  test(`a did:key receipt with ${what} fails`, async () => {
    const { dir } = await didReceiptDir()
    edit(dir, 'public_keys.json', fn)
    assertFails(verifySh(dir), /no key for/)
  })
}

test('a tampered did:key witness fails', async () => {
  const { dir, witness } = await didReceiptDir()
  // Still a well-formed Ed25519 did:key, but of another key.
  const last = witness.at(-1)
  const forged = witness.slice(0, -1) + (last === 'a' ? 'b' : 'a')
  edit(dir, 'ait.json', a => ({ ...a, witness: forged }))
  edit(dir, 'manifest.json', m => ({ ...m, witness: forged }))
  // An honest key entry for the forged did:key, so the signature check is what fails.
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], witness: forged, public_key: '0x' + toHex(publicKeyFromDidKey(forged)) }] }))
  assertFails(verifySh(dir), /AIT signature invalid/)
})

test('a did:key receipt claiming tee-tpm fails', async () => {
  const { dir } = await didReceiptDir()
  edit(dir, 'manifest.json', m => ({ ...m, attestation_strength: 'tee-tpm' }))
  assertFails(verifySh(dir), /§3\.2/)
})

test('a did:key receipt with no attestation_strength fails', async () => {
  const { dir } = await didReceiptDir()
  edit(dir, 'manifest.json', ({ attestation_strength, ...m }) => m)
  assertFails(verifySh(dir), /'self-asserted', got 'MISSING'.*§3\.2/)
})

test('a key entry whose public_key is not the did:key fails', async () => {
  const { dir } = await didReceiptDir()
  const other = toHex(rawPub(generateKeyPairSync('ed25519').privateKey))
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], public_key: '0x' + other }] }))
  assertFails(verifySh(dir), /§3\.1/)
})

test('a did:key AIT declaring ait_version 0.1 fails, even when re-signed', async () => {
  const { dir, privateKey } = await didReceiptDir()
  edit(dir, 'ait.json', ({ witness_signature, ...a }) => {
    const u = { ...a, ait_version: '0.1' }
    return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
  })
  assertFails(verifySh(dir), /ait_version '0\.1'.*§3\.3/)
})

test('a block declaring ab_version 0.1 under a did:key AIT fails, even when re-signed', async () => {
  const { dir, privateKey } = await didReceiptDir()
  let head
  edit(dir, 'attestation_chain.json', ([{ self_hash, witness_signature, ...b }]) => {
    const u = { ...b, ab_version: '0.1' }
    head = sha256(canonicalizeBytes(u))
    return [{ ...u, self_hash: head, witness_signature: ed25519Sign(fromHex(head), privateKey) }]
  })
  edit(dir, 'manifest.json', m => ({ ...m, chain_head_hash: head }))
  assertFails(verifySh(dir), /ab_version '0\.1'.*§3\.3/)
})

test('an OAI-witnessed AIT paired with a did:key manifest and blocks fails', async () => {
  const did = await didReceiptDir()
  const oai = await didReceiptDir('OAI-2026-0010002')
  // The AIT verifies under its OAI key entry; the blocks under the did:key.
  writeFileSync(join(did.dir, 'ait.json'), readFileSync(join(oai.dir, 'ait.json')))
  writeFileSync(join(did.dir, 'public_keys.json'), readFileSync(join(oai.dir, 'public_keys.json')))
  assertFails(verifySh(did.dir), /manifest witness did:key:\S+ != AIT witness OAI-2026-0010002/)
})

// The manifest/AIT witness equality rule is did:key-only (ATAP-v0.2 §3.4), as
// in verifyReceipt: an OAI manifest naming another OAI witness with a key verifies.
test('an OAI manifest naming a different OAI witness than its AIT verifies', async () => {
  const { dir } = await didReceiptDir('OAI-2026-0010002')
  edit(dir, 'manifest.json', m => ({ ...m, witness: 'OAI-2026-0010003' }))
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [...k.keys, { ...k.keys[0], witness: 'OAI-2026-0010003', key_id: 'k2' }] }))
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
})

test('a did:key AIT whose operator is a non-Ed25519 did:key fails, even when re-signed', async () => {
  const { dir, privateKey } = await didReceiptDir()
  edit(dir, 'ait.json', ({ witness_signature, ...a }) => {
    // W3C secp256k1 did:key (multicodec 0xe701).
    const u = { ...a, operator: 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme' }
    return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
  })
  assertFails(verifySh(dir), /AIT identifier did:key:zQ3s\S+ is not an Ed25519 did:key/)
})

test('a did:key key entry valid at a block but not self-asserted fails', async () => {
  const { dir, block } = await didReceiptDir()
  // The AIT-period entry stays self-asserted; a second entry for the same key
  // covers the block's period_end and claims tee-tpm.
  edit(dir, 'public_keys.json', k => ({
    ...k,
    keys: [
      { ...k.keys[0], valid_until: block.period_end },
      { ...k.keys[0], key_id: 'k2', valid_from: block.period_end, attestation_strength: 'tee-tpm' },
    ],
  }))
  assertFails(verifySh(dir), /key entry for did:key:\S+ must declare attestation_strength 'self-asserted', got 'tee-tpm'/)
})

// ATAP-v0.2 §3.1: a did:key's key has no validity window (R008).
test('a did:key key entry outside its validity window still verifies', async () => {
  const { dir } = await didReceiptDir()
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], valid_until: '2001-01-01T00:00:00Z' }] }))
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
})

test('a did:key receipt generated after the AIT expired verifies in both verifiers', async () => {
  const { dir, ait, receipt } = await didReceiptDir(undefined, { afterExpiry: true })
  assert.ok(receipt.generated_at > ait.expires_at)
  assert.equal(readJson(dir, 'public_keys.json').keys[0].valid_until, ait.expires_at)
  const sh = verifySh(dir)
  assert.equal(sh.status, 0, sh.stderr)
  const cli = cliVerify(dir)
  assert.equal(cli.status, 0, cli.reason)
  assert.equal(cli.ok, true)
})

test('the same receipt fails both verifiers once its key is disclosed compromised before generated_at', async () => {
  const { dir, ait, block, receipt } = await didReceiptDir(undefined, { afterExpiry: true })
  // Disclosed after the AIT and block were signed, before the receipt was.
  const disclosed_at = ait.expires_at
  assert.ok(block.period_end < disclosed_at && disclosed_at < receipt.generated_at)
  edit(dir, 'public_keys.json', k => ({
    ...k,
    keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at, detected_at: disclosed_at } }],
  }))
  assertFails(verifySh(dir), /no key for/)
  const cli = cliVerify(dir)
  assert.equal(cli.status, 1)
  assert.equal(cli.ok, false)
  assert.match(cli.reason, /no key for/)
})

// §3.1: the manifest's own witness_signature binds it to the did:key.
for (const [what, fn, cliReason] of [
  ['a tampered manifest witness_signature', m => ({ ...m, witness_signature: m.witness_signature.slice(0, -1) + (m.witness_signature.endsWith('0') ? '1' : '0') }), /receipt signature invalid/],
  ['an edited event_count, signature left as is', m => ({ ...m, event_count: m.event_count + 1 }), /receipt signature invalid/],
]) {
  test(`a did:key receipt with ${what} fails both verifiers`, async () => {
    const { dir } = await didReceiptDir()
    edit(dir, 'manifest.json', fn)
    assertFails(verifySh(dir), /manifest signature invalid/)
    const cli = cliVerify(dir)
    assert.equal(cli.status, 1)
    assert.match(cli.reason, cliReason)
  })
}

// A did:key receipt as the bin writes it (init, event, block, receipt), so it
// carries profile_artifacts/witness_events.json.
function cliReceipt() {
  const cwd = mkdtempSync(join(tmpdir(), 'atap-v02-cli-'))
  const run = (args, input = '') => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd, input, encoding: 'utf8', env: { PATH: process.env.PATH } })
    assert.equal(r.status, 0, r.stderr)
  }
  const [ev] = JSON.parse(readFileSync(join(PROFILE_DIR, 'examples/witness-events.json'), 'utf8'))
  run(['init'])
  for (let i = 0; i < 2; i++) run(['event'], JSON.stringify({ event_type: ev.event_type, payload: ev.payload }))
  run(['block'], JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }))
  run(['receipt', '--out', 'r'])
  return { dir: join(cwd, 'r'), key: readFileSync(join(cwd, '.atap', 'witness.pem')) }
}

// Rewrites the events, refreshes their manifest hash and re-signs the manifest,
// so only the event checks can object (as witness-events.test.mjs's tamper).
function tamperEvents(src, dst, fn, key) {
  cpSync(src, dst, { recursive: true })
  const bytes = Buffer.from(JSON.stringify(fn(readJson(dst, EVENTS))))
  writeFileSync(join(dst, EVENTS), bytes)
  edit(dst, 'manifest.json', ({ witness_signature, ...m }) => {
    m.files = m.files.map(f => (f.path === EVENTS ? { ...f, sha256: '0x' + createHash('sha256').update(bytes).digest('hex') } : f))
    return { ...m, witness_signature: `ed25519:0x${sign(null, canonicalizeBytes(m), key).toString('hex')}` }
  })
  return dst
}

test('a did:key receipt with a tampered witness event signature fails both verifiers', async () => {
  const { dir, key } = cliReceipt()
  assert.equal(verifySh(dir).status, 0, verifySh(dir).stderr)
  assert.equal(cliVerify(dir).ok, true)
  // The re-signing helper alone (no edit) still verifies in both.
  const same = tamperEvents(dir, dir + '-same', e => e, key)
  assert.equal(verifySh(same).status, 0, verifySh(same).stderr)
  assert.equal(cliVerify(same).ok, true)

  // A signature by the same key over another hash: well-formed, wrong.
  const wrongSig = e => {
    e[1].witness_signature = `ed25519:0x${sign(null, fromHex(e[0].self_hash), key).toString('hex')}`
    return e
  }
  const bad = tamperEvents(dir, dir + '-sig', wrongSig, key)
  assertFails(verifySh(bad), /event signature invalid on ATAP-WE-/)
  const cli = cliVerify(bad)
  assert.equal(cli.status, 1)
  assert.match(cli.reason, /event 1 .*signature invalid/)

  // An event edited under its old hash and signature: verify.sh rehashes it.
  const altered = tamperEvents(dir, dir + '-alt', e => (e[0].witnessed_at = '2020-01-01T00:00:00.000Z', e), key)
  assertFails(verifySh(altered), /self_hash mismatch on event ATAP-WE-/)
  assert.match(cliVerify(altered).reason, /event 0 .*self_hash mismatch/)
})

// verify.sh reads untrusted receipt content, and agent-crew runs it as
// `bash verify.sh .` from inside the receipt. python3 puts the cwd on sys.path,
// so it must never cd into the receipt or import from it.
test('verify.sh run from inside the receipt verifies and never imports receipt python', async () => {
  const { dir } = await didReceiptDir()
  const run = cwd => spawnSync('bash', [REPO_VERIFY_SH, cwd === dir ? '.' : dir], { cwd, encoding: 'utf8' })
  const good = run(dir)
  assert.equal(good.status, 0, good.stderr)
  assert.equal(run(tmpdir()).status, 0)

  const marker = join(mkdtempSync(join(tmpdir(), 'atap-marker-')), 'marker')
  for (const mod of ['json.py', 're.py']) writeFileSync(join(dir, mod), `open(${JSON.stringify(marker)}, 'w').write('${mod}')\n`)
  const planted = run(dir)
  assert.equal(planted.status, 0, planted.stderr)
  assert.equal(existsSync(marker), false, existsSync(marker) && `ran receipt ${readFileSync(marker, 'utf8')}`)
})

test('atap-py ships a byte-identical copy of verify.sh', () => {
  const pyCopy = fileURLToPath(new URL('../../atap-py/src/atap/verify.sh', import.meta.url))
  assert.deepEqual(readFileSync(pyCopy), readFileSync(REPO_VERIFY_SH))
})
