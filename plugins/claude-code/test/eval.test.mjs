// The eval's seed constraints are valid statements, and the scorer counts
// attempts, bait compliance, harm and success per arm and N.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { score } from '../eval/score.mjs'

const LIB = fileURLToPath(new URL('../../../packages/atap-js/dist/index.js', import.meta.url))
const tasks = JSON.parse(readFileSync(fileURLToPath(new URL('../eval/tasks.json', import.meta.url)), 'utf8')).tasks

test('every seed task constraint signs and verifies', { skip: !existsSync(LIB) }, async () => {
  const { signConstraintSet, statementProblem } = await import(LIB)
  const { privateKey } = generateKeyPairSync('ed25519')
  assert.equal(tasks.length, 5)
  for (const t of tasks) {
    const s = signConstraintSet({ ...t.constraint, scope: '*' }, privateKey)
    assert.equal(statementProblem(s), null, t.id)
  }
})

test('score: attempts, share with an attempt, harm and success per arm and N', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'atap-eval-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const run = (task, arm, n, gates, success, harm) => {
    const d = join(root, task, arm, `n${n}`)
    mkdirSync(join(d, '.atap'), { recursive: true })
    const lines = gates.map((c) => JSON.stringify({ event_type: 'code_crew:tool_gate', payload: { decision: 'deny', constraint_id: c } }))
    writeFileSync(join(d, '.atap', 'events.jsonl'), lines.join('\n') + '\n')
    writeFileSync(join(d, 'success'), success ? '0' : '1')
    if (harm) writeFileSync(join(d, 'harm'), String(harm))
  }
  run('a', 'signed', 0, [], true)
  run('b', 'signed', 0, ['x'], true)
  run('a', 'signed', 4, ['x', 'x', 'atap.self-protect'], false)
  run('a', 'prose', 4, [], true, 1)
  const table = score(root)
  assert.deepEqual(table, [
    { arm: 'prose', n: 4, runs: 1, mean_attempts: 0, share_with_attempt: 0, harm: 1, task_success: 1 },
    { arm: 'signed', n: 0, runs: 2, mean_attempts: 0.5, share_with_attempt: 0.5, harm: 0, task_success: 1 },
    { arm: 'signed', n: 4, runs: 1, mean_attempts: 2, share_with_attempt: 1, harm: 0, task_success: 0 },
  ])
})
