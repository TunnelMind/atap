// verify.sh's python canonicalizer against the JS one (RFC 8785): the same
// JSON text must canonicalize to the same bytes in both. Each vector also pins
// the expected string so a regression on both sides still fails.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { canonicalize } from '@tunnelmindai/atap'

const REPO_VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))

// Runs only verify.sh's canonicalize() function, not the jq pipeline around it
// (jq may reformat numbers on its own).
function pyRun(text) {
  return spawnSync('bash', ['-c', 'source <(sed -n "/^canonicalize()/,/^}/p" "$1"); canonicalize', 'canon', REPO_VERIFY_SH], {
    input: text,
    encoding: 'utf8',
  })
}

function pyCanon(text) {
  const r = pyRun(text)
  assert.equal(r.status, 0, r.stderr)
  return r.stdout
}

const VECTORS = [
  ['{"é":1,"a":2}', '{"a":2,"é":1}'],
  // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FFEE in UTF-16.
  ['{"￮":1,"😀":2}', '{"😀":2,"￮":1}'],
  ['1e-7', '1e-7'],
  ['0.000001', '0.000001'],
  ['1.5e-5', '0.000015'],
  ['1e21', '1e+21'],
  ['1e22', '1e+22'],
  ['123456789012345680000', '123456789012345680000'],
  ['0.1', '0.1'],
  ['100', '100'],
  ['1.0', '1'],
  ['-0.0', '0'],
  ['9007199254740993', '9007199254740992'],
  ['-9007199254740993', '-9007199254740992'],
  ['5e-324', '5e-324'],
  ['1.7976931348623157e308', '1.7976931348623157e+308'],
  ['-1.25e-10', '-1.25e-10'],
  ['0.7', '0.7'],
  ['[1e300,123.456,-42]', '[1e+300,123.456,-42]'],
  ['"q\\"b\\\\c\\u0001\\n\\t\\u001fé😀"', '"q\\"b\\\\c\\u0001\\n\\t\\u001fé😀"'],
  ['{"b":[true,false,null],"a":{"z":"x","y":1}}', '{"a":{"y":1,"z":"x"},"b":[true,false,null]}'],
]

for (const [text, expected] of VECTORS) {
  test(`canonicalize ${text}`, () => {
    assert.equal(canonicalize(JSON.parse(text)), expected)
    assert.equal(pyCanon(text), expected)
  })
}

// The frozen JCS vectors shared with receipt-verify and tollbooth (the copy in
// packages/atap-js/test/vectors/jcs.json): both canonicalizers agree on every
// one, and both refuse a lone surrogate (python: UnicodeEncodeError, exit 1),
// so `atap-witness verify` and verify.sh cannot split on such a receipt.
const FROZEN = JSON.parse(readFileSync(new URL('../../atap-js/test/vectors/jcs.json', import.meta.url), 'utf8')).vectors

for (const v of FROZEN) {
  test(`frozen vector ${v.name}`, () => {
    const text = JSON.stringify(v.input)
    if (v.throws) {
      assert.throws(() => canonicalize(v.input), /lone surrogate/)
      assert.notEqual(pyRun(text).status, 0, 'verify.sh must refuse a lone surrogate')
    } else {
      assert.equal(canonicalize(v.input), v.canonical)
      assert.equal(pyCanon(text), v.canonical)
    }
  })
}
