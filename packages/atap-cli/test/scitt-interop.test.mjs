// SCITT statements checked by something other than our own code:
//  A. pycose (an independent COSE implementation, installed into a throwaway
//     venv) verifies every statement `scitt export` writes, and rejects a
//     flipped byte. Skipped with a printed reason when pycose cannot install.
//  B. A known-answer test: fixed key + record -> exact statement bytes, walked
//     by hand without cborDecode, so a header label or order change fails here.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash, createPrivateKey, generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeBytes, toSignedStatement } from '@tunnelmindai/atap'

const PROFILE = 'tunnelmind:code_crew:v1'
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const PROFILE_DIR = fileURLToPath(new URL('../../../profiles/profiles/tunnelmind-code-crew-v1/', import.meta.url))
const WITNESS = 'OAI-2026-0010002'

const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'))
const sha256hex = b => createHash('sha256').update(b).digest('hex')

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

// Two blocks of crew events, then a receipt.
async function buildReceipt() {
  const tmp = mkdtempSync(join(tmpdir(), 'atap-scitt-interop-'))
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

// Reads cases.json (path, pubkey hex, expected payload hex) and prints one
// {file, payload_ok, verified, error} per case. Exceptions are reported, not
// swallowed, so a decode failure in pycose shows up in the assertion message.
// --- Known-answer fixture (used by A and B) ---------------------------------

// RFC 8410 PKCS#8 wrapper for a raw 32-byte Ed25519 seed.
const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' // RFC 8032 §7.1 test 1
const KEY = createPrivateKey({ key: Buffer.from(`302e020100300506032b657004220420${SEED}`, 'hex'), format: 'der', type: 'pkcs8' })
const KA_ISS = 'OAI-2026-0010002'
const KA_KID = 'ed25519-d75a980182b10ab7'
const KA_PUB = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a' // RFC 8032 §7.1 test 1
const KA_SUB = 'AIT-2026-0000001'
const KA_RECORD = { '@type': 'AgentIdentityToken', id: KA_SUB, agent_type: 'code-crew', issued_at: '2026-10-09T00:00:00Z' }

// Generated once from scitt.ts toSignedStatement(KA_RECORD, KEY, KA_ISS, KA_KID)
// and pinned here; Ed25519 is deterministic, so any change to the encoding,
// header labels or their order changes these bytes. Part A also has pycose
// verify this exact statement (it did, with pycose 1.1.0, when it was pinned).
const KA_HEX =
  'd284586aa50127045818656432353531392d643735613938303138326231306162370fa201704f41492d323032362d3030313030303202704149542d323032362d30303030303031190102' +
  '2f190103781d6170706c69636174696f6e2f766e642e617461702e6169742b6a736f6ea05820a61b9d471b8e887c6775c7e0733951f4265c6e80ed5971945acb7ef253bf29645840b8036a' +
  'b62844cd02c4c8fef5e1dc6c20eb1e66c4d3d12d986b4363002d2473050a8e1c969cceede697828dc278176136762033ed8154c1c988fa64c59c9f960e'

const PYCOSE_CHECK = `
import json, sys
from pycose.messages import Sign1Message
from pycose.keys.okp import OKPKey
from pycose.keys.curves import Ed25519
out = []
for c in json.load(open(sys.argv[1])):
    r = {"file": c["file"]}
    try:
        msg = Sign1Message.decode(open(c["file"], "rb").read())
        msg.key = OKPKey(crv=Ed25519, x=bytes.fromhex(c["pub"]))
        r["payload_ok"] = msg.payload.hex() == c["digest"]
        r["verified"] = bool(msg.verify_signature())
    except Exception as e:
        r["error"] = type(e).__name__ + ": " + str(e)
    out.append(r)
print(json.dumps(out))
`

test('pycose verifies every exported statement and rejects a flipped byte', async t => {
  const work = mkdtempSync(join(tmpdir(), 'atap-pycose-'))
  t.after(() => rmSync(work, { recursive: true, force: true }))
  const venv = join(work, 'venv')
  const step = (cmd, args) => spawnSync(cmd, args, { encoding: 'utf8', timeout: 120_000 })
  // cbor2<6: pycose 1.1.0's decode checks isinstance(value, list), but cbor2 6
  // returns arrays as tuples, so every message fails as 'cannot be decoded'.
  let r = step('python3', ['-m', 'venv', venv])
  if (r.status === 0) r = step(join(venv, 'bin', 'pip'), ['install', '--quiet', '--disable-pip-version-check', 'pycose', 'cbor2<6'])
  if (r.status !== 0) {
    const why = `pycose unavailable (${r.error?.message ?? (r.stderr || '').trim().split('\n').pop() ?? `exit ${r.status}`})`
    console.log(`skip: ${why}`)
    t.skip(why)
    return
  }

  const { tmp, keyPath, out } = await buildReceipt()
  t.after(() => rmSync(tmp, { recursive: true, force: true }))
  await ok(['scitt', 'export', out, '--key', keyPath, '--issuer', WITNESS])

  // Expected payloads come from canonicalizeBytes, not from the statements.
  const ait = readJson(out, 'ait.json')
  const chain = readJson(out, 'attestation_chain.json')
  const manifest = readJson(out, 'manifest.json')
  const artifacts = { 'ait.cose': ait, 'manifest.cose': manifest }
  for (const b of chain) artifacts[`${b.id}.cose`] = b
  const pub = readJson(out, 'public_keys.json').keys[0].public_key.replace(/^0x/, '')
  const scitt = join(out, 'scitt')
  const files = readdirSync(scitt).filter(f => f.endsWith('.cose')).sort()
  assert.deepEqual(files, Object.keys(artifacts).sort())

  // Script and data live in separate dirs; python runs isolated (-I).
  const data = join(work, 'data')
  const script = join(work, 'script')
  mkdirSync(data)
  mkdirSync(script)
  const cases = files.map(f => ({ file: join(scitt, f), pub, digest: sha256hex(canonicalizeBytes(artifacts[f])) }))
  const flipped = readFileSync(join(scitt, files[0]))
  flipped[flipped.length - 1] ^= 1
  writeFileSync(join(data, 'flipped.cose'), flipped)
  writeFileSync(join(data, 'known-answer.cose'), Buffer.from(KA_HEX, 'hex'))
  cases.push({ file: join(data, 'known-answer.cose'), pub: KA_PUB, digest: sha256hex(canonicalizeBytes(KA_RECORD)) })
  cases.push({ file: join(data, 'flipped.cose'), pub, digest: cases[0].digest })
  writeFileSync(join(data, 'cases.json'), JSON.stringify(cases))
  writeFileSync(join(script, 'check.py'), PYCOSE_CHECK)
  const py = step(join(venv, 'bin', 'python'), ['-I', join(script, 'check.py'), join(data, 'cases.json')])
  assert.equal(py.status, 0, py.stderr)
  const results = JSON.parse(py.stdout)

  for (const res of results.slice(0, -1)) {
    assert.deepEqual(res, { file: res.file, payload_ok: true, verified: true }, `pycose on ${res.file}`)
  }
  const bad = results.at(-1)
  assert.equal(bad.error, undefined, `pycose could not decode the flipped statement: ${bad.error}`)
  assert.equal(bad.verified, false, 'pycose accepted a flipped signature byte')
  console.log(`pycose verified ${results.length - 1} statements (incl. the known answer) and rejected the flipped one`)
})

// --- B. Known answer ----------------------------------------------------------

test('known answer: exact statement bytes, decoded by hand', () => {
  const bytes = Buffer.from(toSignedStatement(KA_RECORD, KEY, KA_ISS, KA_KID))
  assert.equal(bytes.toString('hex'), KA_HEX)

  let pos = 0
  const take = n => {
    assert.ok(pos + n <= bytes.length, 'truncated')
    return bytes.subarray(pos, (pos += n))
  }
  const expect = (hex, what) => assert.equal(take(hex.length / 2).toString('hex'), hex, what)
  const text = s => Buffer.from(s, 'utf8').toString('hex')

  expect('d2', 'tag 18 (COSE_Sign1)')
  expect('84', 'array of 4')

  // Protected header: a bstr wrapping a 5-entry map, keys in deterministic order.
  const iss = text(KA_ISS) // 16 chars -> tstr head 70
  const sub = text(KA_SUB) // 16 chars -> tstr head 70
  const kid = text(KA_KID) // 24 bytes -> bstr head 58 18
  const ctype = text('application/vnd.atap.ait+json') // 29 chars -> tstr head 78 1d
  const protectedHex =
    'a5' +
    '01' + '27' + //                         1 alg: -8 EdDSA
    '04' + '5818' + kid + //                 4 kid: bstr
    '0f' + 'a2' + '01' + '70' + iss + '02' + '70' + sub + // 15 CWT claims {1 iss, 2 sub}
    '190102' + '2f' + //                     258 payload_hash_alg: -16 SHA-256
    '190103' + '781d' + ctype //             259 preimage content type
  const plen = protectedHex.length / 2
  expect(plen < 24 ? (0x40 + plen).toString(16) : `58${plen.toString(16).padStart(2, '0')}`, 'protected bstr head')
  expect(protectedHex, 'protected header map')

  expect('a0', 'unprotected: empty map')
  expect('5820', 'payload: bstr of 32')
  assert.equal(take(32).toString('hex'), sha256hex(canonicalizeBytes(KA_RECORD)), 'payload = sha256(JCS(record))')
  expect('5840', 'signature: bstr of 64')
  take(64)
  assert.equal(pos, bytes.length, 'no trailing bytes')
})
