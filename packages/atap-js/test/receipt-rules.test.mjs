// The receipt rules both atap-witness verify and the viewer share:
// checkWitnessEvents, normaliseReceiptPath and checkManifestFiles.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import {
  WitnessService,
  InMemoryStorage,
  checkManifestFiles,
  checkWitnessEvents,
  normaliseReceiptPath,
  sha256,
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
  assert.equal(check([good, { path: 'manifest.json', sha256: null }]), null)
  assert.equal(check([]), null)
  assert.equal(checkManifestFiles({}, read), null)
  for (const path of ['../x', '/abs', 'a/..', '..\\x', 'C:/x']) assert.equal(check([{ path, sha256: null }]), `${path} escapes the receipt directory`)
  assert.equal(check([{ path: 'gone.json', sha256: good.sha256 }]), 'gone.json missing')
  assert.equal(check([{ path: './ait.json', sha256: sha256(new Uint8Array(1)) }]), './ait.json sha256 mismatch')
  // The first failure wins, in manifest order.
  assert.equal(check([{ path: 'gone.json', sha256: good.sha256 }, { path: '../x', sha256: null }]), 'gone.json missing')
})
