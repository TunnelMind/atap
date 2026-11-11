// The frozen JCS wire vectors (test/vectors/jcs.json), byte-identical to
// receipt-verify's test/vectors/jcs.json at 1b6edd2 (sha256 recorded in its
// CHANGELOG, rv-strict-1); the sha256 pin test below enforces it. Fareseal
// carries the same copy. A change starts in receipt-verify and is
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
test("jcs.json is byte-identical to receipt-verify's test/vectors/jcs.json at 1b6edd2 (sha256 pin)", () => {
  assert.equal(
    createHash('sha256').update(raw).digest('hex'),
    'b294a60b53b743eedb6f77c2473abe9e1b1f1d2eec631ad8a36018a82cad3a2d',
  )
})

for (const v of vectors) {
  test(`frozen vector ${v.name}`, () => {
    if (v.throws) assert.throws(() => canonicalize(v.input), /lone surrogate/)
    else assert.equal(canonicalize(v.input), v.canonical)
  })
}
