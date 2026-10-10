// Builds dist/atap-viewer.html: src/index.html with every script inlined.
//
// A tiny concat bundler instead of a dependency: each module (atap-js's tsc
// output, then src/*.js) becomes a function in one registry, its ESM
// import/export lines rewritten to registry lookups. node:crypto resolves to
// src/shim.js. Anything it cannot rewrite fails the build. Output is a pure
// function of the inputs (no timestamps), so rebuilding gives the same bytes.

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const here = p => fileURLToPath(new URL(p, import.meta.url))
const ATAP_DIST = here('../packages/atap-js/dist/')

// Only what verifyReceipt needs; witness/scitt/uuid stay out.
const ATAP = ['types', 'canonicalize', 'crypto', 'didkey', 'verify']
const VIEWER = ['shim', 'zip', 'render', 'main']

if (!existsSync(ATAP_DIST + 'verify.js')) {
  throw new Error('packages/atap-js/dist is missing: run `npm install && npm run build` in packages/atap-js first')
}

function moduleRef(from, group) {
  if (from === 'node:crypto') return '__mods["viewer/shim"].nodeCrypto'
  if (from === '@atap') return `Object.assign({}, ${ATAP.map(m => `__mods["atap/${m}"]`).join(', ')})`
  const m = /^\.\/([\w-]+)\.js$/.exec(from)
  if (!m) throw new Error(`cannot resolve import '${from}'`)
  return `__mods["${group}/${m[1]}"]`
}

function wrap(group, name, src) {
  const exported = []
  src = src
    .replace(/^\/\/# sourceMappingURL=.*$/m, '')
    .replace(/^import\s*\{([^}]*)\}\s*from\s*'([^']+)';?/gm, (_, names, from) =>
      `const {${names.replace(/\s+as\s+/g, ': ')}} = ${moduleRef(from, group)};`)
    .replace(/^export\s+((?:async\s+)?function|const|let|class)\s+([\w$]+)/gm, (_, kw, id) => {
      exported.push(id)
      return `${kw} ${id}`
    })
    .replace(/^export\s*\{([^}]*)\};?/gm, (_, names) => {
      if (/\sas\s/.test(names)) throw new Error(`${group}/${name}: export ... as is not supported`)
      exported.push(...names.split(',').map(s => s.trim()).filter(Boolean))
      return ''
    })
  if (/^\s*(import|export)\b/m.test(src)) throw new Error(`${group}/${name}: unhandled import/export`)
  // crypto.ts uses the global Buffer; in the page it is the shim's.
  const prelude = /\bBuffer\b/.test(src) && group === 'atap' ? 'const { Buffer } = __mods["viewer/shim"];\n' : ''
  return `__mods["${group}/${name}"] = (function () {\n${prelude}${src.trim()}\nreturn { ${exported.join(', ')} };\n})();\n`
}

// The shim comes first: atap/crypto destructures node:crypto from it at load.
const script =
  '\n(function () {\n"use strict";\nconst __mods = {};\n' +
  wrap('viewer', 'shim', readFileSync(here('src/shim.js'), 'utf8')) +
  ATAP.map(m => wrap('atap', m, readFileSync(`${ATAP_DIST}${m}.js`, 'utf8'))).join('') +
  VIEWER.slice(1).map(m => wrap('viewer', m, readFileSync(here(`src/${m}.js`), 'utf8'))).join('') +
  '})();\n'
if (/<\/script/i.test(script)) throw new Error('the bundle contains </script')

const template = readFileSync(here('src/index.html'), 'utf8')
const style = /<style>([\s\S]*?)<\/style>/.exec(template)[1]
const hash = s => `'sha256-${createHash('sha256').update(s).digest('base64')}'`
const csp = [
  "default-src 'none'",
  `script-src ${hash(script)}`,
  `style-src ${hash(style)}`,
  "connect-src 'none'",
  "img-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ')

const html = template.replace('{{CSP}}', () => csp).replace('{{SCRIPT}}', () => script)
// --check: fail if the committed file differs from a fresh build (a stale download is a viewer that
// verifies with old rules; review medium, 2026-10-09). Writes nothing.
if (process.argv.includes('--check')) {
  const committed = existsSync(here('dist/atap-viewer.html')) ? readFileSync(here('dist/atap-viewer.html'), 'utf8') : ''
  if (committed !== html) {
    console.error('dist/atap-viewer.html is stale: run `npm run build` in viewer/ and commit it')
    process.exit(1)
  }
  console.log('dist/atap-viewer.html is current')
} else {
  mkdirSync(here('dist'), { recursive: true })
  writeFileSync(here('dist/atap-viewer.html'), html)
  console.log(`dist/atap-viewer.html ${html.length} bytes`)
}
