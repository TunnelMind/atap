// ATAP §8.2 hardening of both verifiers (verify.sh and verifyReceipt / the
// CLI): exactly one key in force, key validity compared as instants, manifest
// paths kept inside the receipt, control characters kept off the terminal.
// Throwaway keys and temp dirs only.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { WitnessService, InMemoryStorage, toHex, ed25519Sign, canonicalizeBytes, sha256, verifyReceipt } from '@tunnelmindai/atap'

const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const POLICY = { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' }
const OAI = 'OAI-2026-0010002'

function rawPub(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  return new Uint8Array(der.subarray(der.length - 32))
}

// An OAI-witnessed receipt dir as `atap-witness receipt` lays it out, with
// `keyEntries(k1, ait)` as its public_keys.json entries (k1: the one honest entry).
async function receiptDir(keyEntries = k1 => [k1]) {
  const { privateKey } = generateKeyPairSync('ed25519')
  const svc = new WitnessService({ witnessOAI: OAI, privateKey, storage: new InMemoryStorage() })
  const ait = await svc.declareAit({
    agentType: 'crew-ops',
    profile: 'tunnelmind:crew_ops:v1',
    operator: OAI,
    capabilities: ['crew_ops:ratify'],
    attestationPolicy: POLICY,
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  })
  await svc.witness(ait.id, 'crew_ops:ratify', { n: 1 })
  const block = await svc.rollUp(ait.id, { ratifications: 1 })
  const k1 = {
    witness: OAI,
    key_id: 'k1',
    algorithm: 'ed25519',
    public_key: '0x' + toHex(rawPub(privateKey)),
    valid_from: '2000-01-01T00:00:00Z',
    valid_until: '2100-01-01T00:00:00Z',
    status: 'active',
    attestation_strength: 'self-asserted',
    rotated_to: null,
    compromise_notice: null,
  }
  const keys = { keys: keyEntries(k1, ait), updated_at: new Date().toISOString() }
  const dir = mkdtempSync(join(tmpdir(), 'atap-hard-'))
  const bodies = { 'ait.json': JSON.stringify(ait), 'attestation_chain.json': JSON.stringify([block]), 'public_keys.json': JSON.stringify(keys), 'verify.sh': readFileSync(REPO_VERIFY_SH) }
  for (const [f, b] of Object.entries(bodies)) writeFileSync(join(dir, f), b)
  const files = [{ path: 'manifest.json', sha256: null }, ...Object.entries(bodies).map(([path, b]) => ({ path, sha256: sha256(Buffer.from(b)) }))]
  const receipt = await svc.generateReceipt(ait.id, block.period_start, block.period_end, 'full', files)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(receipt))
  return { dir, privateKey }
}

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
// Edits the manifest and re-signs it, so only the check a test aims at objects.
function editManifest({ dir, privateKey }, fn) {
  const { witness_signature, ...m } = readJson(dir, 'manifest.json')
  const u = fn(m)
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }))
}
const verifySh = dir => spawnSync('bash', [REPO_VERIFY_SH, dir], { encoding: 'utf8' })
const lib = dir => verifyReceipt({ receipt: readJson(dir, 'manifest.json'), ait: readJson(dir, 'ait.json'), chain: readJson(dir, 'attestation_chain.json'), keys: readJson(dir, 'public_keys.json') })
function cliVerify(dir) {
  const r = spawnSync(process.execPath, [CLI, 'verify', dir], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  return { status: r.status, ...JSON.parse(r.stdout) }
}
function assertFails(r, re) {
  assert.notEqual(r.status, 0, r.stdout)
  assert.match(r.stderr, /FAIL: /)
  assert.match(r.stderr, re)
}
// `ms` as RFC 3339 in a +hh:mm / -hh:mm offset: the same instant, another string.
function withOffset(ms, minutes) {
  const sign = minutes < 0 ? '-' : '+'
  const a = Math.abs(minutes)
  const hhmm = `${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`
  return new Date(ms + minutes * 60_000).toISOString().slice(0, 23) + sign + hhmm
}

test('an honest OAI receipt verifies in both verifiers', async () => {
  const { dir } = await receiptDir()
  const r = verifySh(dir)
  assert.equal(r.status, 0, r.stderr)
  assert.equal(lib(dir).ok, true)
  assert.equal(cliVerify(dir).ok, true)
})

test('two keys in force for the witness at t is ambiguous, not first-match', async () => {
  const { dir } = await receiptDir(k1 => [k1, { ...k1, key_id: 'k2' }])
  assertFails(verifySh(dir), /ambiguous: 2 keys for OAI-2026-0010002 valid at /)
  const r = lib(dir)
  assert.equal(r.ok, false)
  assert.match(r.reason, /^ambiguous: 2 keys for OAI-2026-0010002/)
})

test('a second key that is not in force at t is not ambiguous', async () => {
  const { dir } = await receiptDir(k1 => [k1, { ...k1, key_id: 'k0', valid_until: '2001-01-01T00:00:00Z' }])
  assert.equal(verifySh(dir).status, 0)
  assert.equal(lib(dir).ok, true)
})

test('no key in force still fails as "no key for"', async () => {
  const { dir } = await receiptDir(k1 => [{ ...k1, valid_until: '2001-01-01T00:00:00Z' }])
  assertFails(verifySh(dir), /no key for AIT witness/)
  assert.match(lib(dir).reason, /^no key for AIT witness/)
})

test('key validity is compared as instants, not strings', async () => {
  // valid_from one second before issued_at, written +01:00: the string sorts
  // after issued_at's "Z" form, the instant is before it. Must verify.
  const early = await receiptDir((k1, ait) => [{ ...k1, valid_from: withOffset(Date.parse(ait.issued_at) - 1000, 60) }])
  const r = verifySh(early.dir)
  assert.equal(r.status, 0, r.stderr)
  assert.equal(lib(early.dir).ok, true)
  // valid_until an hour before issued_at, written +02:00: the string sorts
  // after issued_at, the instant is before it. The key has expired.
  const late = await receiptDir((k1, ait) => [{ ...k1, valid_until: withOffset(Date.parse(ait.issued_at) - 3600_000, 120) }])
  assertFails(verifySh(late.dir), /no key for AIT witness/)
  assert.match(lib(late.dir).reason, /^no key for AIT witness/)
  // Fractional seconds of any length and an explicit +00:00 parse too.
  const frac = await receiptDir(k1 => [{ ...k1, valid_from: '2000-01-01T00:00:00.123456+00:00', valid_until: '2100-01-01T00:00:00.5Z' }])
  assert.equal(verifySh(frac.dir).status, 0)
  assert.equal(lib(frac.dir).ok, true)
})

test('an unparsable key validity time is a rejection, not a pass', async () => {
  // Zoneless (host-local in bare Date.parse), date-only and lowercase t/z are
  // refused by both verifiers alike, not read as some instant.
  for (const bad of ['yesterday', null, '2000-01-01T00:00:00', '2000-01-01', '2000-01-01t00:00:00z']) {
    const { dir } = await receiptDir(k1 => [{ ...k1, valid_from: bad }])
    assertFails(verifySh(dir), /not RFC 3339|RFC 3339 times/)
    const r = lib(dir)
    assert.equal(r.ok, false)
    assert.match(r.reason, /RFC 3339/)
  }
})

test('a compromise notice is compared by time too', async () => {
  // Disclosed an hour after issued_at, written -05:00 so the string sorts
  // before it: the key was still good at t.
  const { dir } = await receiptDir((k1, ait) => [{ ...k1, status: 'compromised', compromise_notice: { disclosed_at: withOffset(Date.parse(ait.issued_at) + 3600_000, -300) } }])
  assert.equal(verifySh(dir).status, 0, verifySh(dir).stderr)
  assert.equal(lib(dir).ok, true)
})

// Each case lists a path whose hash matches a file outside the receipt, so
// only the containment checks can refuse it.
const outside = mkdtempSync(join(tmpdir(), 'atap-outside-'))
writeFileSync(join(outside, 'x'), 'outside')
const OUTSIDE_SHA = sha256(Buffer.from('outside'))
for (const [what, path, setup] of [
  ['a .. path', () => `../${basename(outside)}/x`],
  ['a .. segment that normalises back inside', () => 'a/../verify.sh'],
  ['an absolute path', () => join(outside, 'x')],
  ['a backslash', () => 'a\\x'],
  ['a drive prefix', () => 'C:x'],
  ['a symlinked file', () => 'link', dir => symlinkSync(join(outside, 'x'), join(dir, 'link'))],
  ['a file under a symlinked directory', () => 'sub/x', dir => symlinkSync(outside, join(dir, 'sub'))],
  ['a file under a symlinked directory, two deep', () => 'real/sub/x', dir => { mkdirSync(join(dir, 'real')); symlinkSync(outside, join(dir, 'real', 'sub')) }],
]) {
  test(`a manifest path with ${what} is refused by both verifiers`, async () => {
    const r = await receiptDir()
    setup?.(r.dir)
    const p = path(r.dir)
    // The symlink-only cases would hash through the link and pass without the check.
    editManifest(r, m => ({ ...m, files: [...m.files, { path: p, sha256: p === 'a/../verify.sh' ? m.files.find(f => f.path === 'verify.sh').sha256 : OUTSIDE_SHA }] }))
    const sh = verifySh(r.dir)
    assertFails(sh, /is not a relative path|has a \.\. segment|is or is under a symlink/)
    const cli = cliVerify(r.dir)
    assert.equal(cli.ok, false)
    assert.notEqual(cli.status, 0)
    assert.match(cli.reason, /escapes the receipt directory|is or is under a symlink/)
  })
}

test('a symlink listed with no sha256 is refused too', async () => {
  const r = await receiptDir()
  symlinkSync(join(outside, 'x'), join(r.dir, 'link'))
  editManifest(r, m => ({ ...m, files: [...m.files, { path: 'link', sha256: null }] }))
  assertFails(verifySh(r.dir), /link is or is under a symlink/)
  assert.match(cliVerify(r.dir).reason, /link is or is under a symlink/)
})

test('control characters in ids and paths never reach the terminal', async () => {
  const ESC = '\x1b'
  // An id in a failure message.
  const r = await receiptDir()
  editManifest(r, m => ({ ...m, ait: `AIT-${ESC}[31mEVIL\nFAKE: line` }))
  const sh = verifySh(r.dir)
  assertFails(sh, /manifest ait AIT-\[31mEVILFAKE: line != AIT id/)
  assert.ok(!sh.stderr.includes(ESC) && !sh.stdout.includes(ESC), 'ESC reached the terminal')
  const res = lib(r.dir)
  assert.equal(res.ok, false)
  assert.match(res.reason, /^receipt ait AIT-\[31mEVILFAKE: line != AIT id/)
  // A path in a failure message, from verify.sh and the CLI (whose reasons
  // come from checkManifestFiles and its own symlink check).
  for (const p of [`${ESC}[2J../x`, `link${ESC}[2J`]) {
    const q = await receiptDir()
    if (p.startsWith('link')) symlinkSync(join(outside, 'x'), join(q.dir, p))
    editManifest(q, m => ({ ...m, files: [...m.files, { path: p, sha256: OUTSIDE_SHA }] }))
    const s = verifySh(q.dir)
    assertFails(s, /\[2J/)
    assert.ok(!s.stderr.includes(ESC) && !s.stdout.includes(ESC), 'ESC reached the terminal')
    const c = cliVerify(q.dir)
    assert.equal(c.ok, false)
    assert.ok(!c.reason.includes(ESC), c.reason)
  }
})
