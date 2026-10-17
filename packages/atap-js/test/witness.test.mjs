// WitnessService.witness refuses an event_type outside the ATAP §7.2 pattern
// and writes nothing; a namespaced one is signed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createPublicKey } from 'node:crypto'
import { WitnessService, InMemoryStorage, verifyReceipt, toHex } from '../dist/index.js'

const WITNESS = 'OAI-2026-0010002'

async function setup() {
  const storage = new InMemoryStorage()
  const { privateKey } = generateKeyPairSync('ed25519')
  const svc = new WitnessService({ witnessOAI: WITNESS, privateKey, storage })
  const ait = await svc.declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  })
  return { svc, storage, ait }
}

test('witness rejects event_types outside the §7.2 pattern before any write', async () => {
  const { svc, storage, ait } = await setup()
  for (const t of ['approval', 'Code_Crew:x', 'code_crew:', ':x', 'a:b c']) {
    await assert.rejects(svc.witness(ait.id, t, {}), /§7\.2/, t)
  }
  assert.deepEqual(await storage.pendingEvents(ait.id), [])
})

test('witness accepts a namespaced event_type', async () => {
  const { svc, storage, ait } = await setup()
  const e = await svc.witness(ait.id, 'code_crew:approval', {})
  assert.equal(e.event_type, 'code_crew:approval')
  assert.equal((await storage.pendingEvents(ait.id)).length, 1)
})

test('declareAit refuses an unparseable expiresAt instead of skipping the lifetime checks', async () => {
  const storage = new InMemoryStorage()
  const { privateKey } = generateKeyPairSync('ed25519')
  const svc = new WitnessService({ witnessOAI: WITNESS, privateKey, storage })
  await assert.rejects(
    svc.declareAit({
      agentType: 'code-crew',
      profile: 'tunnelmind:code_crew:v1',
      operator: 'OAI-2026-0010001',
      capabilities: ['code_crew:code'],
      attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
      expiresAt: 'garbage',
    }),
    /expiresAt must be an ISO 8601 date-time/,
  )
})

// BEAST's wall clock steps back ~1.5 s; the chain must not go back with it.
test('a clock that steps back never dates an event, block or receipt before the last event', async () => {
  const storage = new InMemoryStorage()
  const { privateKey } = generateKeyPairSync('ed25519')
  let t = Date.parse('2026-10-09T12:00:00.000Z')
  const svc = new WitnessService({ witnessOAI: WITNESS, privateKey, storage, now: () => new Date(t) })
  const ait = await svc.declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(t + 30 * 86400_000).toISOString(),
  })
  const e1 = await svc.witness(ait.id, 'code_crew:approval', {})
  t -= 1500
  const e2 = await svc.witness(ait.id, 'code_crew:approval', {})
  assert.ok(e2.witnessed_at >= e1.witnessed_at, `${e2.witnessed_at} < ${e1.witnessed_at}`)
  const b1 = await svc.rollUp(ait.id, {})
  assert.ok(b1.period_start <= b1.period_end, `${b1.period_start} > ${b1.period_end}`)
  t -= 1500
  const e3 = await svc.witness(ait.id, 'code_crew:approval', {})
  assert.ok(e3.witnessed_at >= e2.witnessed_at)
  const b2 = await svc.rollUp(ait.id, {})
  assert.ok(b2.period_start <= b2.period_end)
  const r = await svc.generateReceipt(ait.id, b1.period_start, b2.period_end)
  assert.equal(r.block_count, 2)
  assert.equal(r.event_count, 3)
  assert.ok(r.generated_at >= e3.witnessed_at, `${r.generated_at} < ${e3.witnessed_at}`)
})

// The CLI's keys document ends the key's validity at the AIT's expires_at, and
// an expired AIT stays receiptable. A v0.1 receipt is not signature-checked
// (only did:key ones are, ATAP-v0.2 §3.1), so it still verifies, as in verify.sh.
test('a v0.1 receipt generated after the AIT (and its key) expired still verifies', async () => {
  const storage = new InMemoryStorage()
  const { privateKey } = generateKeyPairSync('ed25519')
  let t = Date.parse('2026-10-09T12:00:00.000Z')
  const svc = new WitnessService({ witnessOAI: WITNESS, privateKey, storage, now: () => new Date(t) })
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
  const receipt = await svc.generateReceipt(ait.id, block.period_start, block.period_end)
  assert.ok(receipt.generated_at > ait.expires_at)
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  const keys = {
    keys: [{
      witness: WITNESS,
      key_id: 'k1',
      algorithm: 'ed25519',
      public_key: '0x' + toHex(new Uint8Array(der.subarray(der.length - 32))),
      valid_from: ait.issued_at,
      valid_until: ait.expires_at,
      status: 'active',
      rotated_to: null,
      compromise_notice: null,
    }],
    updated_at: receipt.generated_at,
  }
  const r = verifyReceipt({ ait, chain: [block], receipt, keys })
  assert.equal(r.ok, true, r.reason)
})
