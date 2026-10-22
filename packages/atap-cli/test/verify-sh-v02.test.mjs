// verify.sh on ATAP v0.2 receipts with a did:key witness (ATAP-v0.2 §3): the
// key binding, the self-asserted rule and the version rule. Throwaway keys
// and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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
// With `late` the first event is witnessed a minute after the AIT is issued.
async function didReceiptDir(oai, { afterExpiry = false, late = false } = {}) {
  const { privateKey } = generateKeyPairSync('ed25519')
  const witness = oai ?? didKeyFromPublicKey(rawPub(privateKey))
  let t = Date.now() - 3 * 86400_000
  const clock = afterExpiry || late ? { now: () => new Date(t) } : {}
  const svc = new WitnessService({ witnessOAI: witness, privateKey, storage: new InMemoryStorage(), ...clock })
  const ait = await svc.declareAit({
    agentType: 'crew-ops',
    profile: 'tunnelmind:crew_ops:v1',
    operator: witness,
    capabilities: ['crew_ops:ratify'],
    attestationPolicy: POLICY,
    expiresAt: new Date(afterExpiry ? t + 86400_000 : Date.now() + 30 * 86400_000).toISOString(),
  })
  if (late) t += 60_000
  await svc.witness(ait.id, 'crew_ops:ratify', { n: 1 })
  const block = await svc.rollUp(ait.id, { ratifications: 1 })
  t += 2 * 86400_000
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
  // The §7.5 layout, every file listed with its hash (A006), as the CLI writes it.
  const dir = mkdtempSync(join(tmpdir(), 'atap-v02-'))
  const bodies = { 'ait.json': JSON.stringify(ait), 'attestation_chain.json': JSON.stringify([block]), 'public_keys.json': JSON.stringify(keys), 'verify.sh': readFileSync(REPO_VERIFY_SH) }
  for (const [f, b] of Object.entries(bodies)) writeFileSync(join(dir, f), b)
  const files = [{ path: 'manifest.json', sha256: null }, ...Object.entries(bodies).map(([path, b]) => ({ path, sha256: sha256(Buffer.from(b)) }))]
  const receipt = await svc.generateReceipt(ait.id, block.period_start, block.period_end, 'full', files)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(receipt))
  SIGNERS.set(dir, privateKey)
  return { dir, privateKey, witness, ait, block, receipt }
}

// Each receipt dir's witness key, so put() can re-sign its manifest.
const SIGNERS = new Map()
const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
// Writes a receipt file other than manifest.json, refreshes (or adds) its
// files[] hash and re-signs the manifest, so only the check a test aims at can
// object, not the file hash or a stale manifest signature.
function put(dir, f, bytes) {
  writeFileSync(join(dir, f), bytes)
  const { witness_signature, ...m } = readJson(dir, 'manifest.json')
  const entry = { path: f, sha256: sha256(Buffer.from(bytes)) }
  m.files = m.files.some(e => e.path === f) ? m.files.map(e => (e.path === f ? entry : e)) : [...m.files, entry]
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ ...m, witness_signature: ed25519Sign(canonicalizeBytes(m), SIGNERS.get(dir)) }))
}
function edit(dir, f, fn) {
  const body = JSON.stringify(fn(readJson(dir, f)))
  if (f === 'manifest.json') writeFileSync(join(dir, f), body)
  else put(dir, f, body)
}
const verifySh = (dir, ...args) => spawnSync('bash', [REPO_VERIFY_SH, dir, ...args], { encoding: 'utf8' })
// `atap-witness verify DIR`: the CLI's verify, i.e. verifyReceipt plus the
// file-integrity and witness-events checks.
function cliVerify(dir, ...args) {
  const r = spawnSync(process.execPath, [CLI, 'verify', dir, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } })
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
  put(did.dir, 'ait.json', readFileSync(join(oai.dir, 'ait.json')))
  put(did.dir, 'public_keys.json', readFileSync(join(oai.dir, 'public_keys.json')))
  assertFails(verifySh(did.dir), /manifest witness did:key:\S+ != AIT witness OAI-2026-0010002/)
})

// The manifest/AIT witness equality rule is did:key-only (ATAP-v0.2 §3.4), as
// in verifyReceipt: an OAI manifest naming another OAI witness with a key verifies.
test('an OAI manifest naming a different OAI witness than its AIT verifies', async () => {
  const { dir, privateKey } = await didReceiptDir('OAI-2026-0010002')
  // Re-signed: the manifest signature is checked for OAI witnesses too.
  edit(dir, 'manifest.json', ({ witness_signature, ...m }) => {
    const u = { ...m, witness: 'OAI-2026-0010003' }
    return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
  })
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

// A did:key compromise notice compares as instants (A103). The afterExpiry
// receipt's last checked time is generated_at G, so the key is good only if
// disclosed_at is after G. The offset forms are the same instants as the Z
// ones but sort the other way as strings, so a string compare flips them.
function offsetIso(ms, minutes) {
  const a = Math.abs(minutes)
  const hhmm = `${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`
  return new Date(ms + minutes * 60_000).toISOString().slice(0, 23) + (minutes < 0 ? '-' : '+') + hhmm
}
for (const [what, disclosed, passes] of [
  ['1s after generated_at, Z', G => new Date(G + 1000).toISOString(), true],
  ['1s after generated_at, -05:00', G => offsetIso(G + 1000, -300), true],
  ['1s after generated_at, +00:00 with extra fractional digits', G => new Date(G + 1000).toISOString().replace('Z', '000+00:00'), true],
  ['at generated_at, Z', G => new Date(G).toISOString(), false],
  ['at generated_at, +01:00', G => offsetIso(G, 60), false],
  ['at generated_at, extra fractional digits', G => new Date(G).toISOString().replace('Z', '000Z'), false],
  ['1s before generated_at, +01:00', G => offsetIso(G - 1000, 60), false],
]) {
  test(`a did:key compromise notice disclosed ${what} ${passes ? 'verifies' : 'fails'}`, async () => {
    const { dir, receipt } = await didReceiptDir(undefined, { afterExpiry: true })
    const disclosed_at = disclosed(Date.parse(receipt.generated_at))
    edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at } }] }))
    const r = verifySh(dir)
    if (passes) assert.equal(r.status, 0, r.stderr)
    else assertFails(r, /no key for/)
  })
}

test('a did:key compromise notice with an unparseable time fails closed', async () => {
  const bad = await didReceiptDir(undefined, { afterExpiry: true })
  edit(bad.dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at: '2100-01-01 00:00:00' } }] }))
  assertFails(verifySh(bad.dir), /RFC 3339/)
  // An unparseable time on the receipt's side: the AIT's issued_at (its key
  // lookup runs before its signature check, so only the compare can object).
  const { dir } = await didReceiptDir(undefined, { afterExpiry: true })
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at: '2100-01-01T00:00:00Z' } }] }))
  edit(dir, 'ait.json', a => ({ ...a, issued_at: 'yesterday' }))
  assertFails(verifySh(dir), /RFC 3339/)
})

// One RFC 3339 grammar in verify.sh and atap-js: a disclosed_at written as a
// leap second, as 24:00, with an offset past 23:59 or on a day the month
// lacks fails both (each passed one verifier and failed the other, or both);
// a fraction finer than a millisecond is compared exactly (atap-js cut it to
// milliseconds and voided a key that was still good at generated_at).
test('a did:key compromise notice gets one time grammar in verify.sh and the CLI', async () => {
  for (const bad of ['2099-12-31T23:59:60Z', '2099-12-31T24:00:00Z', '2099-12-31T00:00:00+99:99', '2099-02-30T00:00:00Z']) {
    const { dir } = await didReceiptDir(undefined, { afterExpiry: true })
    edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at: bad } }] }))
    assertFails(verifySh(dir), /RFC 3339/)
    const cli = cliVerify(dir)
    assert.equal(cli.ok, false, bad)
    assert.match(cli.reason, /cannot compare the compromise notice/)
  }
  const { dir, receipt } = await didReceiptDir(undefined, { afterExpiry: true })
  const disclosed_at = receipt.generated_at.replace('Z', '1Z') // 0.1 ms after generated_at
  edit(dir, 'public_keys.json', k => ({ ...k, keys: [{ ...k.keys[0], status: 'compromised', compromise_notice: { disclosed_at } }] }))
  const sh = verifySh(dir)
  assert.equal(sh.status, 0, sh.stderr)
  const cli = cliVerify(dir)
  assert.equal(cli.ok, true, cli.reason)
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
  // Listed in files[] (A006 fails an unlisted file), so the receipt still verifies.
  for (const mod of ['json.py', 're.py']) put(dir, mod, `open(${JSON.stringify(marker)}, 'w').write('${mod}')\n`)
  const planted = run(dir)
  assert.equal(planted.status, 0, planted.stderr)
  assert.equal(existsSync(marker), false, existsSync(marker) && `ran receipt ${readFileSync(marker, 'utf8')}`)
})

test('atap-py ships a byte-identical copy of verify.sh', () => {
  const pyCopy = fileURLToPath(new URL('../../atap-py/src/atap/verify.sh', import.meta.url))
  assert.deepEqual(readFileSync(pyCopy), readFileSync(REPO_VERIFY_SH))
})

// A003: a receipt's public_keys.json is chosen by whoever made the receipt, so
// for an OAI witness it proves nothing about who signed. --keys names the
// keys the verifier trusts instead.
const OAI = 'OAI-2026-0010002'
// The receipt's genuine key file, copied outside the receipt.
function keysOutside(dir) {
  const f = join(mkdtempSync(join(tmpdir(), 'atap-keys-')), 'keys.json')
  writeFileSync(f, readFileSync(join(dir, 'public_keys.json')))
  return f
}

test('an OAI receipt re-signed under swapped bundled keys passes with a WARNING, and fails with --keys', async () => {
  const genuine = keysOutside((await didReceiptDir(OAI)).dir)
  // Same witness, every record signed by the attacker's key, which the
  // attacker's bundled public_keys.json lists.
  const { dir } = await didReceiptDir(OAI)
  const bundled = verifySh(dir)
  assert.equal(bundled.status, 0, bundled.stderr)
  assert.match(bundled.stderr, /WARNING: .*public_keys\.json inside the\nWARNING: receipt itself/)
  assert.match(bundled.stdout, /OK {3}keys file sha256=[0-9a-f]{64} \(from receipt's bundled public_keys\.json\)/)
  assertFails(verifySh(dir, '--keys', genuine), /AIT signature invalid/)

  const cli = cliVerify(dir)
  assert.equal(cli.ok, true)
  assert.match(cli.warnings.join('\n'), /receipt's own public_keys\.json/)
  const pinned = cliVerify(dir, '--keys', genuine)
  assert.equal(pinned.status, 1)
  assert.match(pinned.reason, /AIT signature invalid/)
})

test('verify.sh --keys GENUINE passes a genuine OAI receipt and prints the keys fingerprint', async () => {
  const { dir } = await didReceiptDir(OAI)
  const keys = keysOutside(dir)
  const want = createHash('sha256').update(readFileSync(keys)).digest('hex')
  for (const args of [[dir, '--keys', keys], ['--keys', keys, dir], [dir, `--keys=${keys}`]]) {
    const r = spawnSync('bash', [REPO_VERIFY_SH, ...args], { encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
    assert.ok(r.stdout.includes(`keys file sha256=${want} (from --keys ${keys})`), r.stdout)
    assert.doesNotMatch(r.stderr, /WARNING/)
  }
  const cli = cliVerify(dir, '--keys', keys)
  assert.equal(cli.ok, true, cli.reason)
  assert.doesNotMatch((cli.warnings ?? []).join('\n'), /public_keys/)
})

test('a missing, unreadable or non-JSON --keys fails', async () => {
  const { dir } = await didReceiptDir(OAI)
  const tmp = mkdtempSync(join(tmpdir(), 'atap-badkeys-'))
  writeFileSync(join(tmp, 'garbage.json'), 'not json')
  writeFileSync(join(tmp, 'nokeys.json'), '{"keys": 1}')
  assertFails(verifySh(dir, '--keys', join(tmp, 'absent.json')), /cannot read --keys/)
  assertFails(verifySh(dir, '--keys', tmp), /cannot read --keys/)
  assertFails(verifySh(dir, '--keys', join(tmp, 'garbage.json')), /not JSON with a \.keys array/)
  assertFails(verifySh(dir, '--keys', join(tmp, 'nokeys.json')), /not JSON with a \.keys array/)
  assertFails(verifySh(dir, '--keys'), /--keys needs/)
})

test('a did:key receipt verifies unchanged without --keys, with no warning', async () => {
  const { dir } = await didReceiptDir()
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
  assert.doesNotMatch(r.stderr, /WARNING/)
  assert.doesNotMatch(r.stdout, /keys file sha256/)
  assert.doesNotMatch((cliVerify(dir).warnings ?? []).join('\n'), /public_keys/)
})

// A004: parse failures are failures. The manifest's head is moved to genesis
// and re-signed, so an empty chain is otherwise self-consistent: verify.sh's
// block loop used to walk zero blocks (its jq exit status is lost in the
// process substitution) and pass.
for (const [name, body] of [
  ['Z1: []', '[]'],
  ['Z2: invalid JSON', '{'],
  ['Z2: a string', '"x"'],
  ['Z2: an object', '{"a":1}'],
]) {
  test(`attestation_chain.json ${name} fails verify.sh and the CLI`, async () => {
    const { dir, privateKey } = await didReceiptDir()
    edit(dir, 'manifest.json', m => {
      const { witness_signature, ...u } = { ...m, chain_head_hash: '0x' + '00'.repeat(32) }
      return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
    })
    put(dir, 'attestation_chain.json', body)
    assertFails(verifySh(dir), /attestation_chain\.json is not a non-empty JSON array/)
    const r = spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', env: { PATH: process.env.PATH } })
    assert.equal(r.status, 1, r.stdout + r.stderr)
    assert.doesNotMatch(r.stderr, /^\s+at /m) // a reason, not a stack trace
    const out = JSON.parse(r.stdout || r.stderr)
    if (out.error) assert.match(out.error, /cannot read attestation_chain\.json/)
    else assert.deepEqual([out.ok, out.reason], [false, 'attestation chain is not a non-empty array'])
  })
}

// A005 (T9): the manifest and every block belong to the AIT. Each record is
// re-signed by the witness, so signatures, self_hash and chain head are valid
// and only the binding is wrong.
const OTHER_AIT = 'AIT-00000000-0000-7000-8000-000000000000'
for (const [what, field, value, re] of [
  ['another AIT', 'ait', OTHER_AIT, new RegExp(`block ATAP-AB-\\S+ ait ${OTHER_AIT} != AIT id AIT-`)],
  ['another profile', 'profile', 'tunnelmind:other:v1', /block ATAP-AB-\S+ profile tunnelmind:other:v1 != AIT profile tunnelmind:crew_ops:v1/],
]) {
  test(`a re-signed block bound to ${what} fails verify.sh`, async () => {
    const { dir, privateKey } = await didReceiptDir()
    let head
    edit(dir, 'attestation_chain.json', ([{ self_hash, witness_signature, ...b }]) => {
      const u = { ...b, [field]: value }
      head = sha256(canonicalizeBytes(u))
      return [{ ...u, self_hash: head, witness_signature: ed25519Sign(fromHex(head), privateKey) }]
    })
    edit(dir, 'manifest.json', ({ witness_signature, ...m }) => {
      const u = { ...m, chain_head_hash: head }
      return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
    })
    assertFails(verifySh(dir), re)
  })
}

test('a re-signed manifest bound to another AIT fails verify.sh', async () => {
  const { dir, privateKey } = await didReceiptDir()
  edit(dir, 'manifest.json', ({ witness_signature, ...m }) => {
    const u = { ...m, ait: OTHER_AIT }
    return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
  })
  assertFails(verifySh(dir), new RegExp(`manifest ait ${OTHER_AIT} != AIT id AIT-`))
})

// A006 (T3): verify.sh and the CLI walk the event chain. Each tampered event is
// re-hashed and re-signed by the witness, so only the chain check can object.
const resignEvent = (e, key) => {
  const { self_hash, witness_signature, ...u } = e
  const h = sha256(canonicalizeBytes(u))
  return { ...u, self_hash: h, witness_signature: `ed25519:0x${sign(null, fromHex(h), key).toString('hex')}` }
}
test('a did:key receipt with a tampered event chain fails both verifiers', () => {
  const { dir, key } = cliReceipt()
  for (const [name, fn, shRe, cliRe] of [
    ['prev_event_hash', e => (e[1] = resignEvent({ ...e[1], prev_event_hash: e[1].self_hash }, key), e), /event 1 \S+ prev_event_hash breaks the chain/, /event 1 .*prev_event_hash breaks the chain/],
    ['swapped order', e => [e[1], e[0]], /event 0 \S+ prev_event_hash breaks the chain/, /event 0 .*prev_event_hash breaks the chain/],
    ['an event dropped', e => e.slice(0, 1), /covers events 0\.\.1; only 1 present/, /covers events 0\.\.1; only 1 present/],
    ['a re-hashed head', e => (e[1] = resignEvent({ ...e[1], witnessed_at: '2020-01-01T00:00:00.000Z' }, key), e), /event 1 \S+ does not match block \S+ chain_head_hash/, /event 1 .*chain_head_hash/],
  ]) {
    const bad = tamperEvents(dir, `${dir}-${name.replaceAll(' ', '-')}`, fn, key)
    assertFails(verifySh(bad), shRe)
    const cli = cliVerify(bad)
    assert.equal(cli.status, 1, name)
    assert.match(cli.reason, cliRe, name)
  }
})

// A006 (T7): every file in the receipt is listed in files[], the events file
// included; dropping it from files[] no longer skips the event check.
test('an events file present but dropped from files[] fails both verifiers', () => {
  const { dir, key } = cliReceipt()
  edit(dir, 'manifest.json', ({ witness_signature, ...m }) => {
    m.files = m.files.filter(f => f.path !== EVENTS)
    return { ...m, witness_signature: `ed25519:0x${sign(null, canonicalizeBytes(m), key).toString('hex')}` }
  })
  assertFails(verifySh(dir), /profile_artifacts\/witness_events\.json is in the receipt but not listed/)
  assert.match(cliVerify(dir).reason, /profile_artifacts\/witness_events\.json is in the receipt but not listed/)
})

test('a code_crew receipt with its events file deleted and unlisted fails both verifiers', () => {
  const { dir, key } = cliReceipt()
  rmSync(join(dir, EVENTS))
  edit(dir, 'manifest.json', ({ witness_signature, ...m }) => {
    m.files = m.files.filter(f => f.path !== EVENTS)
    return { ...m, witness_signature: `ed25519:0x${sign(null, canonicalizeBytes(m), key).toString('hex')}` }
  })
  assertFails(verifySh(dir), /witness_events\.json missing/)
  const r = spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  assert.equal(r.status, 1)
  assert.match(r.stdout + r.stderr, /witness_events\.json/)
})

const resignManifest = (dir, privateKey, fn) => edit(dir, 'manifest.json', ({ witness_signature, ...m }) => {
  const u = fn(m)
  return { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
})

for (const oai of [undefined, OAI]) {
  const kind = oai ? 'OAI' : 'did:key'
  test(`a ${kind} receipt with an unlisted extra file fails both verifiers; scitt/ is ignored`, async () => {
    const { dir } = await didReceiptDir(oai)
    mkdirSync(join(dir, 'scitt'))
    writeFileSync(join(dir, 'scitt', 'index.json'), '[]')
    assert.equal(verifySh(dir).status, 0, verifySh(dir).stderr)
    assert.equal(cliVerify(dir).ok, true)
    writeFileSync(join(dir, 'extra.txt'), 'x')
    assertFails(verifySh(dir), /extra\.txt is in the receipt but not listed/)
    assert.match(cliVerify(dir).reason, /extra\.txt is in the receipt but not listed/)
  })

  // A006 (T8): a mandatory §7.5 file unlisted or with a null hash, re-signed.
  for (const [what, fn, re] of [
    ['public_keys.json listed with a null sha256', m => ({ ...m, files: m.files.map(f => (f.path === 'public_keys.json' ? { ...f, sha256: null } : f)) }), /public_keys\.json is listed with no sha256/],
    ['verify.sh unlisted', m => ({ ...m, files: m.files.filter(f => f.path !== 'verify.sh') }), /verify\.sh is not listed in manifest\.files\[\]/],
  ]) {
    test(`a re-signed ${kind} manifest with ${what} fails both verifiers`, async () => {
      const { dir, privateKey } = await didReceiptDir(oai)
      resignManifest(dir, privateKey, fn)
      assertFails(verifySh(dir), re)
      assert.match(cliVerify(dir).reason, re)
    })
  }

  // A006 (T8): the manifest's period and counts as the chain has them.
  test(`a re-signed ${kind} manifest misdescribing its chain fails both verifiers`, async () => {
    const { dir, privateKey, block } = await didReceiptDir(oai)
    for (const [field, value] of [
      ['period_start', '2000-01-01T00:00:00.000Z'],
      ['period_end', '2100-01-01T00:00:00.000Z'],
      ['block_count', 2],
      ['event_count', 7],
      ['first_block', 'ATAP-AB-00000000-0000-7000-8000-000000000000'],
      ['last_block', 'ATAP-AB-00000000-0000-7000-8000-000000000000'],
    ]) {
      const d = mkdtempSync(join(tmpdir(), 'atap-a006-'))
      cpSync(dir, d, { recursive: true })
      SIGNERS.set(d, privateKey)
      resignManifest(d, privateKey, m => ({ ...m, [field]: value }))
      const want = field === 'block_count' ? 1 : field === 'event_count' ? block.event_count : field.endsWith('block') ? block.id : block[field]
      const msg = `${field} mismatch (want ${JSON.stringify(want)}, got ${JSON.stringify(value)})`
      assertFails(verifySh(d), new RegExp(`manifest ${msg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
      assert.equal(cliVerify(d).reason, `receipt ${msg}`)
    }
  })
}

// 2026-10-21: both verifiers hold the receipt's strength to the key of the
// witness named by the manifest (verify.sh step 5); atap-js read the AIT
// witness's key, so a receipt re-signed by a weaker witness passed one and
// failed the other.
test("a receipt re-signed by a weaker OAI witness fails the strength ceiling in both verifiers", async () => {
  const { dir, witness, privateKey } = await didReceiptDir('OAI-2026-0010002')
  const OTHER = 'OAI-2026-0010003'
  const keys = readJson(dir, 'public_keys.json')
  const k = keys.keys[0]
  put(dir, 'public_keys.json', JSON.stringify({ ...keys, keys: [{ ...k, attestation_strength: 'silicon-root' }, { ...k, witness: OTHER, key_id: 'k2', attestation_strength: 'self-asserted' }] }))
  const { witness_signature: _, ...m } = readJson(dir, 'manifest.json')
  assert.equal(m.witness, witness)
  const asOther = { ...m, witness: OTHER, attestation_strength: 'silicon-root' }
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ ...asOther, witness_signature: ed25519Sign(canonicalizeBytes(asOther), privateKey) }))
  assertFails(verifySh(dir), /attestation_strength=silicon-root exceeds key\.attestation_strength=self-asserted/)
  const js = cliVerify(dir)
  assert.notEqual(js.status, 0)
  assert.match(js.reason, /attestation_strength=silicon-root exceeds key attestation_strength=self-asserted/)
})

// Review 2026-10-21 C1: with no key for the manifest's witness at the AIT's
// issued_at both verifiers fell into the "key omits the field" warning and
// passed the inflated claim. Now a failure in both.
test("a weaker OAI witness whose key starts after the AIT's issue fails in both verifiers", async () => {
  const { dir, ait, privateKey } = await didReceiptDir('OAI-2026-0010002', { late: true })
  const OTHER = 'OAI-2026-0010003'
  const keys = readJson(dir, 'public_keys.json')
  const k = keys.keys[0]
  const after = new Date(Date.parse(ait.issued_at) + 1).toISOString()
  put(dir, 'public_keys.json', JSON.stringify({ ...keys, keys: [{ ...k, attestation_strength: 'silicon-root' }, { ...k, witness: OTHER, key_id: 'k2', attestation_strength: 'self-asserted', valid_from: after }] }))
  const { witness_signature: _, ...m } = readJson(dir, 'manifest.json')
  const asOther = { ...m, witness: OTHER, attestation_strength: 'silicon-root' }
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ ...asOther, witness_signature: ed25519Sign(canonicalizeBytes(asOther), privateKey) }))
  assertFails(verifySh(dir), /no key for receipt witness OAI-2026-0010003 at/)
  const js = cliVerify(dir)
  assert.notEqual(js.status, 0)
  assert.match(js.reason, /no key for receipt witness OAI-2026-0010003 at/)
})
