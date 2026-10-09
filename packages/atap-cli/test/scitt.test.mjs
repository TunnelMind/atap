// scitt export / verify on a real receipt built through the atap-witness bin.
// Throwaway keys and temp dirs only; no network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const PROFILE = 'tunnelmind:code_crew:v1'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))

function newKey(tmp, name) {
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyPath = join(tmp, name)
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  return keyPath
}

// Resolves with {code, stdout, stderr}; never rejects on a non-zero exit.
function run(args, stdin = '') {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH } })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => (stdout += d))
    child.stderr.on('data', d => (stderr += d))
    child.on('close', code => resolve({ code, stdout, stderr }))
    child.stdin.end(stdin)
  })
}

async function ok(args, stdin) {
  const r = await run(args, stdin)
  assert.equal(r.code, 0, r.stderr)
  return JSON.parse(r.stdout)
}

// verify must fail with ok:false and a reason on stdout, not a stack trace.
async function rejects(dir, why) {
  const r = await run(['scitt', 'verify', dir])
  assert.equal(r.code, 1, `scitt verify accepted ${why}`)
  const out = JSON.parse(r.stdout)
  assert.equal(out.ok, false)
  assert.ok(out.reason, 'no reason given')
  assert.equal(r.stderr, '')
  return out.reason
}

// Two blocks of crew events, then a receipt.
async function buildReceipt() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-scitt-'))
  const keyPath = newKey(tmp, 'witness.pem')
  const common = ['--dir', join(tmp, 'store'), '--key', keyPath, '--witness-oai', WITNESS]
  const ait = await ok(['ait', 'declare', ...common], JSON.stringify({
    agentType: 'code-crew',
    profile: PROFILE,
    operator: 'OAI-2026-0010001',
    capabilities: Object.keys(readJson(PROFILE_DIR, 'capabilities.json').capabilities),
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }))
  const examples = readJson(PROFILE_DIR, 'examples/witness-events.json')
  const summary = JSON.stringify({ tasks_accepted: 1, tasks_rework: 0, merged_changes: 1, tokens: 0, overturns: {} })
  for (const half of [examples.slice(0, 4), examples.slice(4)]) {
    for (const { event_type, payload } of half) {
      await ok(['event', '--ait', ait.id, ...common], JSON.stringify({ event_type, payload }))
    }
    await ok(['block', '--ait', ait.id, ...common], summary)
  }
  const out = join(tmp, 'receipt')
  await ok(['receipt', '--ait', ait.id, '--out', out, ...common], '')
  return { tmp, keyPath, out }
}

test('scitt export -> verify, and every tamper fails', async () => {
  const { tmp, keyPath, out } = await buildReceipt()
  const chain = readJson(out, 'attestation_chain.json')
  assert.equal(chain.length, 2)

  // Neither scitt command needs --witness-oai or stdin.
  const exported = await ok(['scitt', 'export', out, '--key', keyPath, '--issuer', WITNESS])
  assert.equal(exported.statements, chain.length + 2)
  const scitt = join(out, 'scitt')
  const cose = readdirSync(scitt).filter(f => f.endsWith('.cose')).sort()
  assert.deepEqual(cose, ['ait.cose', 'manifest.cose', ...chain.map(b => `${b.id}.cose`)].sort())
  const index = readJson(scitt, 'index.json')
  assert.deepEqual(index.map(e => e.artifact_id).sort(), [readJson(out, 'ait.json').id, readJson(out, 'manifest.json').id, ...chain.map(b => b.id)].sort())

  // (a) clean export verifies.
  const verified = await ok(['scitt', 'verify', out])
  assert.deepEqual(verified, { ok: true, statements: chain.length + 2 })

  // Re-running overwrites cleanly.
  await ok(['scitt', 'export', out, '--key', keyPath, '--issuer', WITNESS])
  await ok(['scitt', 'verify', out])

  // (f) the receipt itself still verifies: scitt/ is outside manifest.files[].
  await ok(['verify', out])
  const sh = spawnSync('bash', [REPO_VERIFY_SH, out], { encoding: 'utf8' })
  assert.equal(sh.status, 0, sh.stdout + sh.stderr)

  const copy = name => {
    const d = join(tmp, name)
    cpSync(out, d, { recursive: true })
    return d
  }

  // (b) tampered block field.
  const b = copy('tampered-block')
  const tamperedChain = readJson(b, 'attestation_chain.json')
  tamperedChain[1].event_count += 1
  writeFileSync(join(b, 'attestation_chain.json'), JSON.stringify(tamperedChain))
  assert.match(await rejects(b, 'a tampered block'), /does not verify/)

  // (c) one flipped byte (in the signature) of a statement: the index sha256
  // catches it, and with the index re-hashed the signature check does too.
  const c = copy('flipped-byte')
  const file = join(c, 'scitt', `${chain[0].id}.cose`)
  const bytes = readFileSync(file)
  bytes[bytes.length - 1] ^= 1
  writeFileSync(file, bytes)
  assert.match(await rejects(c, 'a flipped .cose byte'), /sha256 mismatch/)
  const rehashed = readJson(c, 'scitt/index.json').map(e =>
    e.file === `${chain[0].id}.cose` ? { ...e, sha256: `0x${createHash('sha256').update(bytes).digest('hex')}` } : e)
  writeFileSync(join(c, 'scitt', 'index.json'), JSON.stringify(rehashed))
  assert.match(await rejects(c, 'a re-hashed flipped .cose'), /does not verify/)

  // (d) a block's statement deleted, and dropped from the index.
  const d = copy('missing-statement')
  rmSync(join(d, 'scitt', `${chain[1].id}.cose`))
  assert.match(await rejects(d, 'a deleted .cose'), /missing/)
  writeFileSync(join(d, 'scitt', 'index.json'), JSON.stringify(readJson(d, 'scitt/index.json').filter(e => e.artifact_id !== chain[1].id)))
  assert.match(await rejects(d, 'an uncovered block'), new RegExp(`no signed statement for ${chain[1].id}`))

  // (e) a signer not in public_keys.json: export refuses it, and statements
  // signed by it (keys.json patched to allow export, then restored) fail.
  const e = copy('wrong-key')
  const other = newKey(tmp, 'other.pem')
  const refused = await run(['scitt', 'export', e, '--key', other, '--issuer', WITNESS])
  assert.equal(refused.code, 1)
  assert.match(refused.stderr, /not in public_keys\.json/)
  const keysText = readFileSync(join(e, 'public_keys.json'), 'utf8')
  const keys = JSON.parse(keysText)
  const pub = createPublicKey(createPrivateKey(readFileSync(other))).export({ format: 'jwk' })
  const hex = Buffer.from(pub.x, 'base64url').toString('hex')
  keys.keys.push({ ...keys.keys[0], key_id: `ed25519-${hex.slice(0, 16)}`, public_key: `0x${hex}` })
  writeFileSync(join(e, 'public_keys.json'), JSON.stringify(keys))
  await ok(['scitt', 'export', e, '--key', other, '--issuer', WITNESS])
  writeFileSync(join(e, 'public_keys.json'), keysText)
  assert.match(await rejects(e, 'a kid not in public_keys.json'), /kid .* is not in public_keys\.json/)

  // index file entries that escape scitt/ are refused before any read.
  const p = copy('escape')
  const idx = readJson(p, 'scitt/index.json')
  idx[0].file = '../ait.json'
  writeFileSync(join(p, 'scitt', 'index.json'), JSON.stringify(idx))
  assert.match(await rejects(p, 'an escaping index entry'), /escapes the scitt directory/)

  // A block id with a path separator is refused at export.
  const q = copy('bad-id')
  const badChain = readJson(q, 'attestation_chain.json')
  badChain[0].id = '../../evil'
  writeFileSync(join(q, 'attestation_chain.json'), JSON.stringify(badChain))
  const bad = await run(['scitt', 'export', q, '--key', keyPath, '--issuer', WITNESS])
  assert.equal(bad.code, 1)
  assert.match(bad.stderr, /not a safe file name/)

  // Missing receipt files give ok:false, not a stack trace; empty issuer is refused.
  await rejects(join(tmp, 'nowhere'), 'a missing dir')
  const noIss = await run(['scitt', 'export', out, '--key', keyPath, '--issuer', ''])
  assert.equal(noIss.code, 1)
  assert.match(noIss.stderr, /--issuer/)
})
