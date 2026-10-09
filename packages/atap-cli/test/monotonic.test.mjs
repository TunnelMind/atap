// DirStorage hands the previous event's witnessed_at to a fresh WitnessService
// (one per CLI process), so a clock that stepped back cannot date an event
// before the one stored. Temp dirs only; the clock is injected, never slept on.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { WitnessService } from '@tunnelmindai/atap'
import { DirStorage } from '../dist/storage.js'

const WITNESS = 'OAI-2026-0010002'

test('a new service with an earlier clock still witnesses monotonically through DirStorage', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'atap-mono-')), 'store')
  const { privateKey } = generateKeyPairSync('ed25519')
  const t0 = Date.parse('2026-10-09T12:00:00.000Z')
  const service = t => new WitnessService({ witnessOAI: WITNESS, privateKey, storage: new DirStorage(dir), now: () => new Date(t) })

  const first = service(t0)
  const ait = await first.declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(t0 + 30 * 86400_000).toISOString(),
  })
  const e1 = await first.witness(ait.id, 'code_crew:approval', {})

  // "Next process": fresh service and storage objects, clock 1.5 s behind e1.
  const second = service(t0 - 1500)
  const e2 = await second.witness(ait.id, 'code_crew:approval', {})
  assert.ok(e2.witnessed_at >= e1.witnessed_at, `${e2.witnessed_at} < ${e1.witnessed_at}`)
  const block = await second.rollUp(ait.id, {})
  assert.ok(block.period_start <= block.period_end, `${block.period_start} > ${block.period_end}`)

  const third = service(t0 - 3000)
  const r = await third.generateReceipt(ait.id, block.period_start, block.period_end)
  assert.equal(r.block_count, 1)
  assert.equal(r.event_count, 2)
  assert.ok(r.generated_at >= e2.witnessed_at, `${r.generated_at} < ${e2.witnessed_at}`)
  const stored = await new DirStorage(dir).eventsOf(ait.id)
  assert.deepEqual(stored.map(e => e.id), [e1.id, e2.id])
})
