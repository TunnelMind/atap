// The frozen JCS wire vectors (test/vectors/jcs.json), byte-identical to
// receipt-verify's test/vectors/jcs.json (sha256 81a79410874c5ed24ea0468a
// 3d684e3a03111dc0a2fd2e8317ed3e3dfb978cdd); tollbooth carries the same copy.
// A change starts there and is mirrored here. verify.sh's python canonicalizer
// runs the same file in atap-cli's verify-sh-canon.test.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canonicalize } from '../dist/index.js'

const { vectors } = JSON.parse(readFileSync(new URL('./vectors/jcs.json', import.meta.url), 'utf8'))

for (const v of vectors) {
  test(`frozen vector ${v.name}`, () => {
    if (v.throws) assert.throws(() => canonicalize(v.input), /lone surrogate/)
    else assert.equal(canonicalize(v.input), v.canonical)
  })
}
