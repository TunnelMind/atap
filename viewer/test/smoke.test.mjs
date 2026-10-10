// Smoke check until V1402's real tests: the build wrote one HTML file whose CSP denies the network.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('dist/atap-viewer.html is built with a no-network CSP', () => {
  const html = readFileSync(new URL('../dist/atap-viewer.html', import.meta.url), 'utf8')
  assert.match(html, /<meta http-equiv="Content-Security-Policy" content="[^"]*connect-src 'none'/)
})
