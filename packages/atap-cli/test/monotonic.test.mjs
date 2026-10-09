// DirStorage hands the previous event's witnessed_at to a fresh WitnessService
// (one per CLI process), so a clock that stepped back cannot date an event
// before the one stored. Temp dirs only; the clock is injected, never slept on.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { WitnessService, verifyReceipt } from '@tunnelmindai/atap'
import { DirStorage } from '../dist/storage.js'

const WITNESS = 'OAI-2026-0010002'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))

// What a store looked like before witness() clamped: no previous event time,
// so a clock that steps back dates events (and blocks) backwards.
class LegacyStorage extends DirStorage {
  async lastEventAt() { return null }
}

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

test('receipt covers a legacy chain with non-monotonic block periods by order', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-mono-'))
  const dir = join(tmp, 'store')
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyPath = join(tmp, 'witness.pem')
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  // In the past so the CLI's real-clock receipt comes after every block.
  const t0 = Date.now() - 3600_000
  const service = t => new WitnessService({ witnessOAI: WITNESS, privateKey, storage: new LegacyStorage(dir), now: () => new Date(t) })

  const ait = await service(t0).declareAit({
    agentType: 'code-crew',
    profile: 'tunnelmind:code_crew:v1',
    operator: 'OAI-2026-0010001',
    capabilities: ['code_crew:code'],
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(t0 + 30 * 86400_000).toISOString(),
  })
  // Blocks at t0, t0+20s, then t0+10s: the clock stepped back before the third.
  for (const dt of [0, 20_000, 10_000]) {
    const svc = service(t0 + dt)
    await svc.witness(ait.id, 'code_crew:approval', {})
    await svc.rollUp(ait.id, {})
  }
  const chain = await new DirStorage(dir).blocksOf(ait.id)
  assert.equal(chain.length, 3)
  assert.ok(chain[2].period_end < chain[1].period_end, 'chain is not non-monotonic')

  // The old time-filtered call over the chain's first..last span drops block 2.
  const filtered = await service(t0).generateReceipt(ait.id, chain[0].period_start, chain[2].period_end)
  assert.equal(filtered.block_count, 2)

  const out = join(tmp, 'receipt')
  const r = spawnSync(process.execPath, [CLI, 'receipt', '--ait', ait.id, '--out', out, '--dir', dir, '--key', keyPath, '--witness-oai', WITNESS], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  assert.equal(r.status, 0, r.stderr)
  const manifest = readJson(out, 'manifest.json')
  assert.equal(manifest.block_count, chain.length)
  assert.equal(manifest.event_count, 3)
  assert.equal(manifest.first_block, chain[0].id)
  assert.equal(manifest.last_block, chain[2].id)

  const lib = verifyReceipt({ receipt: manifest, ait: readJson(out, 'ait.json'), chain: readJson(out, 'attestation_chain.json'), keys: readJson(out, 'public_keys.json') })
  assert.ok(lib.ok, lib.reason)
  assert.equal(lib.blocks, 3)
  const sh = spawnSync('bash', [REPO_VERIFY_SH, out], { encoding: 'utf8' })
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)
})
