// The frozen JCS wire vectors (test/vectors/jcs.json), byte-identical to
// receipt-verify's test/vectors/jcs.json; the sha256 pin test below enforces
// it. tollbooth carries the same copy. A change starts in receipt-verify and is
// mirrored here, pin included. verify.sh's python canonicalizer
// runs the same file in atap-cli's verify-sh-canon.test.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { canonicalize } from '../dist/index.js'

const raw = readFileSync(new URL('./vectors/jcs.json', import.meta.url))
const { vectors } = JSON.parse(raw.toString('utf8'))

// Hash the raw bytes, not the parsed JSON: whitespace or key-order drift from
// receipt-verify's copy must fail too.
test("jcs.json is byte-identical to receipt-verify's copy (sha256 pin)", () => {
  assert.equal(
    createHash('sha256').update(raw).digest('hex'),
    '81a79410874c5ed24ea0468a3d684e3a03111dc0a2fd2e8317ed3e3dfb978cdd',
  )
})

for (const v of vectors) {
  test(`frozen vector ${v.name}`, () => {
    if (v.throws) assert.throws(() => canonicalize(v.input), /lone surrogate/)
    else assert.equal(canonicalize(v.input), v.canonical)
  })
}
