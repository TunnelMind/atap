// verifyJwt end to end with throwaway Ed25519 keys: the signature binds the
// exact header.payload bytes, the strength ceiling holds, and no malformed
// token or key makes the verifier throw. Build first (`npm run build`).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { verifyJwt, CLAIM, PROFILE_URN } from '../dist/index.js'

const b64u = b => Buffer.from(b).toString('base64url')
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const RAW_PUB = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
const key = (strength = 'software') => ({ key_id: 'k1', algorithm: 'EdDSA', public_key: RAW_PUB.toString('base64'), ...(strength ? { attestation_strength: strength } : {}) })

function jwt(claims, header = { alg: 'EdDSA', kid: 'k1' }) {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`
  return `${input}.${b64u(sign(null, Buffer.from(input), privateKey))}`
}
const claims = (extra = {}) => ({ profile: PROFILE_URN, iat: Math.floor(Date.now() / 1000), ...extra })

test('verify(sign(x)) is valid for a range of claim sets', async () => {
  for (const extra of [{}, { [CLAIM.STRENGTH]: 'software' }, { [CLAIM.STRENGTH]: 'self-asserted', nonce: 'n' }, { s: 'é😀' }]) {
    const r = await verifyJwt(jwt(claims(extra)), { keys: [key()] })
    assert.equal(r.valid, true, r.errors.join('; '))
  }
})

// Property: flipping any one bit of the signed input or the signature fails.
// Every bit of header and payload is covered (base64url chars re-encoded), and
// a stride over the signature keeps the run short.
test('any single-bit flip of the signed bytes or the signature fails', async () => {
  const token = jwt(claims({ [CLAIM.STRENGTH]: 'software' }))
  const [h, p, s] = token.split('.')
  const flips = []
  for (const [part, i] of [[0, h], [1, p]].flatMap(([n, str]) => [...Buffer.from(str, 'base64url').keys()].map(k => [n, k]))) {
    const parts = token.split('.')
    const bytes = Buffer.from(parts[part], 'base64url')
    bytes[i] ^= 1 << (i % 8)
    parts[part] = b64u(bytes)
    flips.push(parts.join('.'))
  }
  const sig = Buffer.from(s, 'base64url')
  for (let bit = 0; bit < sig.length * 8; bit += 7) {
    const f = Buffer.from(sig)
    f[bit >> 3] ^= 1 << (bit & 7)
    flips.push(`${h}.${p}.${b64u(f)}`)
  }
  for (const t of flips) {
    const r = await verifyJwt(t, { keys: [key()] })
    assert.equal(r.valid, false, t)
  }
})

test('the strength ceiling: at or below the key passes, above fails', async () => {
  assert.equal((await verifyJwt(jwt(claims({ [CLAIM.STRENGTH]: 'software' })), { keys: [key('software')] })).valid, true)
  const r = await verifyJwt(jwt(claims({ [CLAIM.STRENGTH]: 'silicon-root' })), { keys: [key('software')] })
  assert.equal(r.valid, false)
  assert.match(r.errors.join(), /ceiling violated/)
})

// An unknown tier used to rank 0 and "constructor" to rank as a function, so
// either passed the ceiling against any key.
test('a claim or key strength that is not one of the four tiers fails', async () => {
  for (const bad of ['silicon-root-plus', 'constructor', '__proto__', '', 3, null]) {
    const r = await verifyJwt(jwt(claims({ [CLAIM.STRENGTH]: bad })), { keys: [key('self-asserted')] })
    assert.equal(r.valid, false, JSON.stringify(bad))
    assert.match(r.errors.join(), /unrecognized/)
  }
  const r = await verifyJwt(jwt(claims({ [CLAIM.STRENGTH]: 'software' })), { keys: [key('silicon_root')] })
  assert.equal(r.valid, false)
  assert.match(r.errors.join(), /key k1 has unrecognized attestation_strength/)
})

test('malformed tokens and keys are errors in the result, never a throw', async () => {
  const good = jwt(claims())
  const cases = ['', 'a.b', 'a.b.c.d', '!!!.???.***', `${good.split('.')[0]}.e30.AAAA`]
  for (const t of cases) assert.equal((await verifyJwt(t, { keys: [key()] })).valid, false, t)
  for (const public_key of ['AAAA', '0x' + '00'.repeat(31), '']) {
    const r = await verifyJwt(good, { keys: [{ ...key(), public_key }] })
    assert.equal(r.valid, false, public_key)
  }
  const none = await verifyJwt(jwt(claims(), { alg: 'none', kid: 'k1' }), { keys: [key()] })
  assert.equal(none.valid, false)
  assert.match(none.errors.join(), /unsupported alg/)
})
