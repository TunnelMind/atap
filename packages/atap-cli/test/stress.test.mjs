// 30 seeded rounds of declare → 3 events → block → event → block → receipt →
// verify, with a fresh WitnessService per step (as one CLI process per step)
// and a clock that jumps back 0.5–2 s at random points. The chain is built
// in-process; every round still spawns the CLI receipt and verify and runs the
// library verifyReceipt, since all 30 fit well under 10 s. A failing round
// prints its round and seed, so it can be replayed. Temp dirs only; the clock
// is injected, never slept on.

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
const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
const ROUNDS = 30
const SEED = 0x019a1b

// mulberry32: a tiny seeded PRNG returning floats in [0, 1).
function mulberry32(a) {
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const nonDecreasing = (xs, what, tag) => {
  for (let i = 1; i < xs.length; i++) assert.ok(xs[i - 1] <= xs[i], `${tag}: ${what}[${i}] ${xs[i]} < ${xs[i - 1]}`)
}

test(`${ROUNDS} seeded rounds with a clock that jumps back stay monotonic and verify`, async () => {
  for (let round = 0; round < ROUNDS; round++) {
    const seed = SEED + round
    const tag = `round ${round} seed ${seed}`
    const rand = mulberry32(seed)
    const tmp = mkdtempSync(join(tmpdir(), 'atap-stress-'))
    const dir = join(tmp, 'store')
    const { privateKey } = generateKeyPairSync('ed25519')
    const keyPath = join(tmp, 'witness.pem')
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))

    // In the past so the CLI's real-clock receipt comes after every block.
    let t = Date.now() - 3600_000
    // A new service and storage per step; about 1 step in 3 the clock steps back.
    const step = () => {
      t += rand() < 1 / 3 ? -(500 + Math.floor(rand() * 1500)) : Math.floor(rand() * 3000)
      const now = t
      return new WitnessService({ witnessOAI: WITNESS, privateKey, storage: new DirStorage(dir), now: () => new Date(now) })
    }

    const ait = await step().declareAit({
      agentType: 'code-crew',
      profile: 'tunnelmind:code_crew:v1',
      operator: 'OAI-2026-0010001',
      capabilities: ['code_crew:code'],
      attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
      expiresAt: new Date(t + 30 * 86400_000).toISOString(),
    })
    for (let i = 0; i < 3; i++) await step().witness(ait.id, 'code_crew:approval', {})
    await step().rollUp(ait.id, {})
    await step().witness(ait.id, 'code_crew:approval', {})
    await step().rollUp(ait.id, {})

    const store = new DirStorage(dir)
    const events = await store.eventsOf(ait.id)
    const blocks = await store.blocksOf(ait.id)
    nonDecreasing(events.map(e => e.witnessed_at), 'witnessed_at', tag)
    assert.deepEqual(blocks.map(b => b.event_count), [3, 1], tag)
    nonDecreasing(blocks.flatMap(b => [b.period_start, b.period_end]), 'period', tag)

    const out = join(tmp, 'receipt')
    const r = spawnSync(process.execPath, [CLI, 'receipt', '--ait', ait.id, '--out', out, '--dir', dir, '--key', keyPath, '--witness-oai', WITNESS], { encoding: 'utf8', env: { PATH: process.env.PATH } })
    assert.equal(r.status, 0, `${tag}: ${r.stderr}`)
    const manifest = readJson(out, 'manifest.json')
    assert.equal(manifest.block_count, 2, tag)
    // 3 events + 1 event: the sequence in tasks.md M003 yields 4, not 5.
    assert.equal(manifest.event_count, 4, tag)

    const v = spawnSync(process.execPath, [CLI, 'verify', out], { encoding: 'utf8', env: { PATH: process.env.PATH } })
    assert.equal(v.status, 0, `${tag}: ${v.stdout}${v.stderr}`)
    const lib = verifyReceipt({ receipt: manifest, ait: readJson(out, 'ait.json'), chain: readJson(out, 'attestation_chain.json'), keys: readJson(out, 'public_keys.json') })
    assert.ok(lib.ok, `${tag}: ${lib.reason}`)
  }
})
