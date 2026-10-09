// WitnessService.witness refuses an event_type outside the ATAP §7.2 pattern
// and writes nothing; a namespaced one is signed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { WitnessService, InMemoryStorage } from '../dist/index.js'

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
