// The receipt rules both atap-witness verify and the viewer share:
// checkWitnessEvents, normaliseReceiptPath and checkManifestFiles.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import {
  WitnessService,
  InMemoryStorage,
  checkManifestFiles,
  checkWitnessEvents,
  canonicalizeBytes,
  ed25519Sign,
  normaliseReceiptPath,
  sha256,
  toHex,
  verifyReceipt,
  WITNESS_EVENTS,
} from '../dist/index.js'

// Two blocks of 2 + 1 events, as the CLI's receipt would carry them.
async function chainFixture() {
  const { privateKey } = generateKeyPairSync('ed25519')
  const svc = new WitnessService({ witnessOAI: 'OAI-2026-0010002', privateKey, storage: new InMemoryStorage() })
  const ait = await svc.declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  })
  const events = []
  const chain = []
  for (const n of [2, 1]) {
    for (let i = 0; i < n; i++) events.push(await svc.witness(ait.id, 'code_crew:approval', { i: events.length }))
    chain.push(await svc.rollUp(ait.id, {}))
  }
  return { events, chain, ait, keys: { keys: [] } }
}

test('checkWitnessEvents accepts events that match the blocks', async () => {
  const { events, chain, ait, keys } = await chainFixture()
  assert.equal(checkWitnessEvents(events, chain, ait, keys), null)
})

test('checkWitnessEvents refuses a tampered self_hash', async () => {
  const { events, chain, ait, keys } = await chainFixture()
  events[1] = { ...events[1], payload: { i: 99 } }
  assert.equal(checkWitnessEvents(events, chain, ait, keys), `event 1 (${events[1].id}) self_hash mismatch`)
})

test('checkWitnessEvents refuses a broken prev_event_hash link', async () => {
  const { events, chain, ait, keys } = await chainFixture()
  events.splice(1, 1)
  assert.equal(checkWitnessEvents(events, chain, ait, keys), `event 1 (${events[1].id}) prev_event_hash breaks the chain`)
})

test('checkWitnessEvents refuses events that do not match the blocks', async () => {
  const { events, chain, ait, keys } = await chainFixture()
  assert.equal(checkWitnessEvents(events.slice(0, 2), chain.slice(0, 1), ait, keys), null)
  assert.equal(checkWitnessEvents(events, chain.slice(0, 1), ait, keys), '3 events but the blocks cover 2')
  chain[0] = { ...chain[0], event_count: 1 }
  assert.equal(
    checkWitnessEvents(events, chain, ait, keys),
    `event 0 (${events[0].id}) is not block ${chain[0].id}'s last_event`,
  )
})

test('checkWitnessEvents refuses a non-array', async () => {
  const { chain, ait, keys } = await chainFixture()
  assert.equal(checkWitnessEvents({}, chain, ait, keys), `${WITNESS_EVENTS} is not an array`)
})

test('normaliseReceiptPath keeps paths inside the receipt root', () => {
  assert.equal(normaliseReceiptPath('a/./b//c'), 'a/b/c')
  assert.equal(normaliseReceiptPath('a/../b'), 'b')
  for (const p of ['../x', 'a/../../x', '/etc/passwd', 'a/..', '.', '', '..\\x', 'C:/x']) assert.equal(normaliseReceiptPath(p), null, p)
})

test('checkManifestFiles: escape, missing, hash mismatch, null sha', () => {
  const files = new Map([['ait.json', new TextEncoder().encode('{}')]])
  const read = rel => files.get(rel)
  const check = list => checkManifestFiles({ files: list }, read)
  const good = { path: 'ait.json', sha256: sha256(files.get('ait.json')) }
  // A006: the §7.5 mandatory files must be listed (see the test below).
  assert.equal(check([good, { path: 'manifest.json', sha256: null }]), 'attestation_chain.json is not listed in manifest.files[] (ATAP §7.5)')
  assert.equal(check([]), 'manifest.json is not listed in manifest.files[] (ATAP §7.5)')
  assert.equal(checkManifestFiles({}, read), 'manifest.json is not listed in manifest.files[] (ATAP §7.5)')
  for (const path of ['../x', '/abs', 'a/..', '..\\x', 'C:/x']) assert.equal(check([{ path, sha256: null }]), `${path} escapes the receipt directory`)
  assert.equal(check([{ path: 'gone.json', sha256: good.sha256 }]), 'gone.json missing')
  assert.equal(check([{ path: './ait.json', sha256: sha256(new Uint8Array(1)) }]), './ait.json sha256 mismatch')
  // The first failure wins, in manifest order.
  assert.equal(check([{ path: 'gone.json', sha256: good.sha256 }, { path: '../x', sha256: null }]), 'gone.json missing')
})

// A006 (T7/T8): the §7.5 mandatory files are listed, all but manifest.json with
// a sha256, and every file the receipt carries is listed.
test('checkManifestFiles: mandatory files and unlisted files', () => {
  const names = ['ait.json', 'attestation_chain.json', 'public_keys.json', 'verify.sh', WITNESS_EVENTS]
  const files = new Map(names.map(n => [n, new TextEncoder().encode(n)]))
  const read = rel => files.get(rel)
  const listed = [{ path: 'manifest.json', sha256: null }, ...names.map(path => ({ path, sha256: sha256(files.get(path)) }))]
  const present = ['manifest.json', ...names]
  assert.equal(checkManifestFiles({ files: listed }, read, present), null)
  assert.equal(checkManifestFiles({ files: listed }, read), null)
  for (const m of ['manifest.json', 'ait.json', 'verify.sh']) {
    assert.equal(checkManifestFiles({ files: listed.filter(f => f.path !== m) }, read), `${m} is not listed in manifest.files[] (ATAP §7.5)`)
  }
  const nulled = listed.map(f => (f.path === 'public_keys.json' ? { ...f, sha256: null } : f))
  assert.equal(checkManifestFiles({ files: nulled }, read), 'public_keys.json is listed with no sha256 (ATAP §7.5)')
  // The events file present but dropped from files[], and a stray extra file.
  assert.equal(
    checkManifestFiles({ files: listed.filter(f => f.path !== WITNESS_EVENTS) }, read, present),
    `${WITNESS_EVENTS} is in the receipt but not listed in manifest.files[]`,
  )
  assert.equal(checkManifestFiles({ files: listed }, read, [...present, 'extra.txt']), 'extra.txt is in the receipt but not listed in manifest.files[]')
})

// A006 (T3), OAI witness: the chain is checked with no event signatures.
test('checkWitnessEvents refuses a re-hashed head event and a non-integer event_count', async () => {
  const { events, chain, ait, keys } = await chainFixture()
  const { self_hash, witness_signature, ...u } = { ...events[2], payload: { i: 99 } }
  const rehashed = [...events.slice(0, 2), { ...u, self_hash: sha256(canonicalizeBytes(u)), witness_signature }]
  assert.equal(checkWitnessEvents(rehashed, chain, ait, keys), `event 2 (${events[2].id}) does not match block ${chain[1].id}'s chain_head_hash`)
  assert.equal(checkWitnessEvents([events[1], events[0], events[2]], chain, ait, keys), `event 0 (${events[1].id}) prev_event_hash breaks the chain`)
  assert.equal(checkWitnessEvents(events, [{ ...chain[0], event_count: '2' }, chain[1]], ait, keys), `block ${chain[0].id} event_count is not a positive integer`)
})

// A006 (T8): a re-signed receipt whose period or counts disagree with the chain.
test('verifyReceipt refuses a re-signed receipt that misdescribes its chain', async () => {
  const { privateKey } = generateKeyPairSync('ed25519')
  const svc = new WitnessService({ witnessOAI: 'OAI-2026-0010002', privateKey, storage: new InMemoryStorage() })
  const ait = await svc.declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  })
  const chain = []
  for (let b = 0; b < 2; b++) {
    await svc.witness(ait.id, 'code_crew:approval', { b })
    chain.push(await svc.rollUp(ait.id, {}))
  }
  const receipt = await svc.generateReceipt(ait.id, chain[0].period_start, chain[1].period_end)
  const pub = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  const keys = { keys: [{ witness: ait.witness, key_id: 'k1', algorithm: 'ed25519', public_key: '0x' + toHex(new Uint8Array(pub.subarray(pub.length - 32))), valid_from: '2000-01-01T00:00:00Z', valid_until: '2100-01-01T00:00:00Z', status: 'active', rotated_to: null, compromise_notice: null }] }
  assert.equal(verifyReceipt({ receipt, ait, chain, keys }).ok, true)
  for (const [field, value] of [
    ['period_start', '2000-01-01T00:00:00.000Z'],
    ['period_end', '2100-01-01T00:00:00.000Z'],
    ['block_count', 3],
    ['event_count', 1],
    ['first_block', chain[1].id],
    ['last_block', chain[0].id],
  ]) {
    const { witness_signature, ...u } = { ...receipt, [field]: value }
    const forged = { ...u, witness_signature: ed25519Sign(canonicalizeBytes(u), privateKey) }
    const r = verifyReceipt({ receipt: forged, ait, chain, keys })
    assert.equal(r.ok, false, field)
    assert.equal(r.reason, `receipt ${field} mismatch (want ${JSON.stringify(receipt[field])}, got ${JSON.stringify(value)})`)
  }
})
