// UUIDv7 (RFC 9562 §5.7): layout, timestamp prefix, uniqueness, validator.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { uuidv7, isValidUuidv7, UUIDV7_RE } from '../dist/index.js'

test('layout: version 7, variant 10xx, matches UUIDV7_RE', () => {
  for (let i = 0; i < 100; i++) {
    const id = uuidv7()
    assert.match(id, UUIDV7_RE)
    assert.equal(isValidUuidv7(id), true)
    assert.equal(id[14], '7')
    assert.match(id[19], /^[89ab]$/)
  }
})

test('first 48 bits are the passed-in ms timestamp', () => {
  const now = 1700000000000
  const id = uuidv7(now)
  const hex = id.replace(/-/g, '')
  assert.equal(hex.slice(0, 12), now.toString(16).padStart(12, '0'))
  assert.equal(parseInt(hex.slice(0, 12), 16), now)
  assert.equal(uuidv7(0).slice(0, 13), '00000000-0000')
})

test('1000 generated ids are unique', () => {
  const ids = new Set(Array.from({ length: 1000 }, () => uuidv7()))
  assert.equal(ids.size, 1000)
})

test('isValidUuidv7 rejects v4 and junk', () => {
  assert.equal(isValidUuidv7('9b2c6f1e-4d3a-4b8e-9f0a-1c2d3e4f5a6b'), false) // v4
  assert.equal(isValidUuidv7('not-a-uuid'), false)
  assert.equal(isValidUuidv7(''), false)
  assert.equal(isValidUuidv7('018bcfe5-6800-7000-8000-00000000000'), false) // short
  assert.equal(isValidUuidv7('018BCFE5-6800-7000-8000-000000000000'), false) // uppercase
})
