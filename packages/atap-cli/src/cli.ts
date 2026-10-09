#!/usr/bin/env node
// atap-witness: a file-backed ATAP v0.1 witness. Each command reads JSON on
// stdin and writes JSON on stdout, so any language can drive it. Errors go
// to stderr as one line of {"error": "..."} with a non-zero exit.
//
// Usage: see USAGE below (also printed by --help).
//
// Before signing, event payloads and block period_summaries are validated
// against the AIT's profile schemas; a refused call writes nothing.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { execFile } from 'node:child_process'
import { chmod, copyFile, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { delimiter, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs, promisify } from 'node:util'
import {
  ATTESTATION_STRENGTH_RANK,
  GENESIS_HASH,
  CborTag,
  WitnessService,
  canonicalizeBytes,
  cborDecode,
  publicKeyFromHex,
  toSignedStatement,
  verifyReceipt,
  verifySignedStatement,
  type AIT,
  type AIT_ID,
  type AitInput,
  type AttestationBlock,
  type AttestationStrength,
  type HexHash,
  type KeysDocument,
  type OAI,
  type Receipt,
  type VerifyResult,
  type WitnessEvent,
} from '@tunnelmindai/atap'
import { Profiles } from './profile.js'
import { DirStorage, withLock } from './storage.js'

// The reference verifier ships in the repo root. From dist/cli.js that is
// three levels up (dist -> atap-cli -> packages -> root).
// ponytail: only resolves from a source checkout; bundle a copy into the
// package when it is published to npm.
const VERIFY_SH = fileURLToPath(new URL('../../../verify.sh', import.meta.url))
// ponytail: same source-checkout ceiling as VERIFY_SH.
const PROFILES_DIR = fileURLToPath(new URL('../../../profiles', import.meta.url))

// tunnelmind:code_crew:v1 profile.md §9: every event the receipt's blocks cover.
const WITNESS_EVENTS = 'profile_artifacts/witness_events.json'

// §7.5 layout. manifest.json cannot carry its own hash, so it is listed with null.
const RECEIPT_FILES = [
  'manifest.json',
  'ait.json',
  'attestation_chain.json',
  'summary.json',
  'public_keys.json',
  'verify.sh',
  WITNESS_EVENTS,
] as const

const USAGE = `usage:
  atap-witness init [--profile ID] [--dir .atap] [--force]
  atap-witness status
  atap-witness ait declare            --key K --witness-oai OAI   < AitInput  [--unregistered-profile]
  atap-witness event   --ait ID       --key K --witness-oai OAI   < {"event_type","payload"}
  atap-witness block   --ait ID       --key K --witness-oai OAI   < period_summary (optional)
  atap-witness receipt --ait ID --out DIR --key K --witness-oai OAI
  atap-witness verify DIR
  atap-witness scitt export DIR --key K --issuer ISS
  atap-witness scitt verify DIR
  atap-witness scitt register DIR --service URL

Global: --dir (store, default ./.atap-witness), --strength (default self-asserted),
--profiles-dir (profile registry + schemas, default the repo's profiles/).
`

type Values = {
  help?: boolean
  key?: string
  dir?: string
  'witness-oai'?: string
  strength?: string
  ait?: string
  out?: string
  'profiles-dir'?: string
  'unregistered-profile'?: boolean
  issuer?: string
  service?: string
  profile?: string
  force?: boolean
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const c of process.stdin) chunks.push(c as Buffer)
  return Buffer.concat(chunks).toString('utf8')
}

async function stdinJson(allowEmpty: boolean): Promise<unknown> {
  const text = (await readStdin()).trim()
  if (text === '') {
    if (allowEmpty) return {}
    throw new Error('expected JSON on stdin')
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('stdin is not valid JSON')
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function json(v: unknown): string {
  return JSON.stringify(v, null, 2) + '\n'
}

// The key file's contents never reach an error message: every failure here is
// replaced with a fixed sentence.
async function loadKey(path: string | undefined): Promise<KeyObject> {
  if (!path) throw new Error('--key <path> is required')
  let pem: Buffer
  try {
    pem = await readFile(path)
  } catch {
    throw new Error('cannot read the --key file')
  }
  let key: KeyObject
  try {
    key = createPrivateKey({ key: pem, format: 'pem' })
  } catch {
    throw new Error('--key is not a PEM private key')
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('--key must be an Ed25519 private key')
  }
  return key
}

function parseStrength(s: string | undefined): AttestationStrength {
  const v = s ?? 'self-asserted'
  if (!Object.hasOwn(ATTESTATION_STRENGTH_RANK, v)) {
    throw new Error(
      `--strength must be one of ${Object.keys(ATTESTATION_STRENGTH_RANK).join(', ')}`,
    )
  }
  return v as AttestationStrength
}

function requireAit(v: Values): AIT_ID {
  if (!v.ait) throw new Error('--ait <id> is required')
  return v.ait as AIT_ID
}

function sha256(bytes: Uint8Array): HexHash {
  return `0x${createHash('sha256').update(bytes).digest('hex')}`
}

// summary.json: integers are summed key-wise, nested objects merge
// recursively, anything else keeps the latest block's value.
function mergeSummary(acc: Record<string, unknown>, s: Record<string, unknown>): Record<string, unknown> {
  for (const [k, v] of Object.entries(s)) {
    const prev = acc[k]
    if (Number.isInteger(v) && Number.isInteger(prev)) acc[k] = (prev as number) + (v as number)
    else if (isObject(v)) acc[k] = mergeSummary(isObject(prev) ? prev : {}, v)
    else acc[k] = v
  }
  return acc
}

function publicHex(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' })
  return Buffer.from(jwk.x!, 'base64url').toString('hex')
}

const keyId = (hex: string): string => `ed25519-${hex.slice(0, 16)}`

// One key entry, derived from the signing key. valid_from is the start of the
// AIT's issue day so it precedes issued_at. valid_until is the AIT's
// expires_at: verifiers look keys up at issued_at and at each block's
// period_end (its last event's witnessed_at), and witness() refuses events at
// or after expires_at, so every signature in the receipt falls inside it.
function keysDocument(
  privateKey: KeyObject,
  witness: OAI,
  ait: AIT,
  strength: AttestationStrength,
): KeysDocument {
  const hex = publicHex(privateKey)
  const from = new Date(ait.issued_at.slice(0, 10) + 'T00:00:00Z')
  const until = new Date(ait.expires_at)
  return {
    keys: [
      {
        witness,
        key_id: keyId(hex),
        algorithm: 'ed25519',
        public_key: `0x${hex}`,
        valid_from: from.toISOString(),
        valid_until: until.toISOString(),
        status: 'active',
        attestation_strength: strength,
        rotated_to: null,
        compromise_notice: null,
      },
    ],
    updated_at: new Date().toISOString(),
  }
}

async function zipDir(dir: string): Promise<string> {
  const zipPath = `${dir}.zip`
  // zip updates an existing archive in place; start clean so stale entries
  // from an earlier receipt never survive.
  await rm(zipPath, { force: true })
  try {
    await promisify(execFile)('zip', ['-q', '-X', '-r', zipPath, '.'], { cwd: dir })
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error('the zip binary is required to write the receipt .zip; install zip')
    }
    throw new Error(`zip failed: ${(e as Error).message}`)
  }
  return zipPath
}

async function receipt(svc: WitnessService, storage: DirStorage, v: Values, key: KeyObject, witness: OAI, strength: AttestationStrength): Promise<Receipt> {
  const aitId = requireAit(v)
  if (!v.out) throw new Error('--out <dir> is required')
  const out = resolve(v.out)
  // zipDir zips everything under out, so a non-empty dir would smuggle
  // unrelated files into receipt.zip. A missing dir is fine: mkdir makes it.
  const existing = await readdir(out).catch((e: NodeJS.ErrnoException) => {
    if (e.code === 'ENOENT') return []
    throw e
  })
  if (existing.length > 0) throw new Error(`--out ${out} is not empty; pick a new or empty directory`)
  const ait = await storage.loadAit(aitId)
  if (!ait) throw new Error(`unknown AIT ${aitId}`)
  const chain = await storage.blocksOf(aitId)
  if (chain.length === 0) throw new Error(`no blocks for ${aitId}; run block first`)
  // Events up to the last block's last event; later ones are still pending.
  const events = await storage.eventsOf(aitId)
  const covered = events.slice(0, events.findIndex(e => e.id === chain.at(-1)!.last_event) + 1)

  let verifySh: Buffer
  try {
    verifySh = await readFile(VERIFY_SH)
  } catch {
    throw new Error(`reference verifier not found at ${VERIFY_SH}`)
  }
  const contents: Record<string, Uint8Array> = {
    'ait.json': Buffer.from(json(ait)),
    'attestation_chain.json': Buffer.from(json(chain)),
    'summary.json': Buffer.from(
      json(chain.reduce((acc, b) => mergeSummary(acc, b.period_summary), {} as Record<string, unknown>)),
    ),
    'public_keys.json': Buffer.from(json(keysDocument(key, witness, ait, strength))),
    'verify.sh': verifySh,
    [WITNESS_EVENTS]: Buffer.from(json(covered)),
  }
  // The Receipt signs over files[], so every hash is fixed before signing and
  // the bytes written afterwards are exactly the bytes hashed.
  const files = RECEIPT_FILES.map(path => ({
    path,
    sha256: path === 'manifest.json' ? null : sha256(contents[path]!),
  }))
  const rcpt = await svc.generateReceipt(
    aitId,
    chain[0]!.period_start,
    chain.at(-1)!.period_end,
    'full',
    files,
    chain,
  )

  await mkdir(join(out, 'profile_artifacts'), { recursive: true })
  for (const [path, bytes] of Object.entries(contents)) {
    // copyFile keeps verify.sh's exec bit, so the unpacked receipt runs as-is.
    if (path === 'verify.sh') await copyFile(VERIFY_SH, join(out, path))
    else await writeFile(join(out, path), bytes)
  }
  await writeFile(join(out, 'manifest.json'), json(rcpt))
  await zipDir(out)
  return rcpt
}

async function readJsonFile<T>(dir: string, name: string): Promise<T> {
  try {
    return JSON.parse(await readFile(join(dir, name), 'utf8')) as T
  } catch {
    throw new Error(`cannot read ${name} in ${dir}`)
  }
}

// The block chain binds to the event chain only through chain_head_hash
// (ATAP §7.3, §10): each block's chain_head_hash is the self_hash of the last
// event it covers. Recompute every self_hash (§7.7), walk prev_event_hash from
// genesis, then slice the events by event_count and match each block's head.
// No signature check needed: the signed blocks' heads pin every earlier event
// through the prev_event_hash chain.
function checkWitnessEvents(events: WitnessEvent[], chain: AttestationBlock[], ait: AIT): string | null {
  if (!Array.isArray(events)) return `${WITNESS_EVENTS} is not an array`
  let prev: string = GENESIS_HASH
  for (const [i, e] of events.entries()) {
    if (!isObject(e)) return `event ${i} is not an object`
    const { self_hash, witness_signature: _, ...unsigned } = e
    if (e.ait !== ait.id) return `event ${i} (${e.id}) is not under ${ait.id}`
    if (sha256(canonicalizeBytes(unsigned)) !== self_hash) return `event ${i} (${e.id}) self_hash mismatch`
    if (e.prev_event_hash !== prev) return `event ${i} (${e.id}) prev_event_hash breaks the chain`
    prev = self_hash
  }
  let at = 0
  for (const b of chain) {
    const first = events[at]
    const last = events[at + b.event_count - 1]
    if (!first || !last) return `block ${b.id} covers events ${at}..${at + b.event_count - 1}; only ${events.length} present`
    if (first.id !== b.first_event) return `event ${at} (${first.id}) is not block ${b.id}'s first_event`
    if (last.id !== b.last_event) return `event ${at + b.event_count - 1} (${last.id}) is not block ${b.id}'s last_event`
    if (last.self_hash !== b.chain_head_hash) return `event ${at + b.event_count - 1} (${last.id}) does not match block ${b.id}'s chain_head_hash`
    at += b.event_count
  }
  if (at !== events.length) return `${events.length} events but the blocks cover ${at}`
  return null
}

// True if `rel`, resolved under `root`, lands outside it (or on it).
function escapes(root: string, rel: string): boolean {
  const r = relative(root, resolve(root, rel))
  return r === '' || r === '..' || r.startsWith('..' + sep) || isAbsolute(r)
}

// Same checks as verify.sh: manifest.files[] integrity first, then the
// signatures and chain via the library's verifyReceipt, then the profile's
// witness events if the manifest lists them.
async function verify(dir: string): Promise<VerifyResult> {
  const receipt = await readJsonFile<Receipt>(dir, 'manifest.json')
  const root = resolve(dir)
  for (const f of receipt.files ?? []) {
    // The manifest is untrusted input: refuse a path like ../x before reading
    // it, so a receipt cannot make us hash files outside its own directory.
    if (escapes(root, f.path)) {
      return { ok: false, blocks: 0, reason: `${f.path} escapes the receipt directory` }
    }
    const rel = relative(root, resolve(root, f.path))
    if (f.sha256 === null) continue
    let bytes: Buffer
    try {
      bytes = await readFile(join(root, rel))
    } catch {
      return { ok: false, blocks: 0, reason: `${f.path} missing` }
    }
    if (sha256(bytes) !== f.sha256) {
      return { ok: false, blocks: 0, reason: `${f.path} sha256 mismatch` }
    }
  }
  const ait = await readJsonFile<AIT>(dir, 'ait.json')
  const chain = await readJsonFile<AttestationBlock[]>(dir, 'attestation_chain.json')
  const result = verifyReceipt({
    receipt,
    ait,
    chain,
    keys: await readJsonFile<KeysDocument>(dir, 'public_keys.json'),
  })
  if (!result.ok || !receipt.files?.some(f => f.path === WITNESS_EVENTS)) return result
  const reason = checkWitnessEvents(await readJsonFile<WitnessEvent[]>(dir, WITNESS_EVENTS), chain, ait)
  return reason ? { ok: false, blocks: 0, reason } : result
}

// SCITT view of an unpacked receipt (RFC 9943): every artifact as a COSE_Sign1
// signed statement under DIR/scitt/. manifest.files[] does not list scitt/, so
// the receipt itself (and verify.sh) is unchanged by an export.
const SCITT_DIR = 'scitt'

type ScittIndexEntry = { file: string; artifact_id: string; sha256: HexHash }

// A statement file name comes from an artifact id; refuse anything that could
// leave scitt/ before it touches the filesystem.
function safeName(id: unknown): string {
  if (typeof id !== 'string' || id === '' || id.includes('..') || /[/\\]/.test(id)) {
    throw new Error(`artifact id ${JSON.stringify(id)} is not a safe file name`)
  }
  return id
}

// The receipt's artifacts keyed by id. The manifest falls back to its `ait`
// when it has no id.
async function scittArtifacts(dir: string): Promise<{ ait: AIT; chain: AttestationBlock[]; manifest: Receipt; manifestId: string }> {
  const ait = await readJsonFile<AIT>(dir, 'ait.json')
  const chain = await readJsonFile<AttestationBlock[]>(dir, 'attestation_chain.json')
  const manifest = await readJsonFile<Receipt>(dir, 'manifest.json')
  if (!isObject(ait) || !Array.isArray(chain) || !isObject(manifest)) throw new Error('receipt files have the wrong shape')
  return { ait, chain, manifest, manifestId: String(manifest.id) }
}

async function scittExport(dir: string, v: Values): Promise<{ dir: string; statements: number; issuer: string; kid: string }> {
  if (!v.issuer) throw new Error('--issuer <ISS> is required and must be non-empty')
  const key = await loadKey(v.key)
  const kid = keyId(publicHex(key))
  const keys = await readJsonFile<KeysDocument>(dir, 'public_keys.json')
  if (!keys.keys?.some(k => k.key_id === kid)) throw new Error(`--key ${kid} is not in public_keys.json`)
  const { ait, chain, manifest, manifestId } = await scittArtifacts(dir)
  const items: [string, unknown][] = [
    [ait.id, ait],
    ...chain.map(b => [b.id, b] as [string, unknown]),
    [manifestId, manifest],
  ]
  const files = ['ait.cose', ...chain.map(b => `${safeName(b.id)}.cose`), 'manifest.cose']
  // Sign everything before touching disk so a bad artifact leaves no half export.
  const statements = items.map(([, a]) => toSignedStatement(a, key, v.issuer!, kid))
  const out = join(dir, SCITT_DIR)
  await rm(out, { recursive: true, force: true })
  await mkdir(out)
  const index: ScittIndexEntry[] = []
  for (const [i, bytes] of statements.entries()) {
    await writeFile(join(out, files[i]!), bytes)
    index.push({ file: files[i]!, artifact_id: items[i]![0], sha256: sha256(bytes) })
  }
  await writeFile(join(out, 'index.json'), json(index))
  return { dir: out, statements: index.length, issuer: v.issuer, kid }
}

// Never throws: any malformed or missing input is ok:false with a reason.
async function scittVerify(dir: string): Promise<{ ok: boolean; statements: number; reason?: string }> {
  const fail = (reason: string) => ({ ok: false, statements: 0, reason })
  try {
    const root = resolve(dir, SCITT_DIR)
    const index = await readJsonFile<ScittIndexEntry[]>(root, 'index.json')
    if (!Array.isArray(index)) return fail('scitt/index.json is not an array')
    const { ait, chain, manifest, manifestId } = await scittArtifacts(dir)
    const keys = await readJsonFile<KeysDocument>(dir, 'public_keys.json')
    const artifacts = new Map<string, unknown>([[ait.id, ait], ...chain.map(b => [b.id, b] as [string, unknown]), [manifestId, manifest]])
    const covered = new Set<string>()
    for (const e of index) {
      if (!isObject(e) || typeof e.file !== 'string' || typeof e.artifact_id !== 'string') return fail('scitt/index.json has a malformed entry')
      if (escapes(root, e.file)) return fail(`${e.file} escapes the scitt directory`)
      let bytes: Buffer
      try {
        bytes = await readFile(join(root, e.file))
      } catch {
        return fail(`scitt/${e.file} missing`)
      }
      if (sha256(bytes) !== e.sha256) return fail(`scitt/${e.file} sha256 mismatch`)
      if (!artifacts.has(e.artifact_id)) return fail(`scitt/${e.file} covers unknown artifact ${e.artifact_id}`)
      const kid = statementKid(bytes)
      const entry = kid === null ? undefined : keys.keys?.find(k => k.key_id === kid)
      if (!entry) return fail(`scitt/${e.file} kid ${kid} is not in public_keys.json`)
      if (!verifySignedStatement(bytes, publicKeyFromHex(entry.public_key), artifacts.get(e.artifact_id))) {
        return fail(`scitt/${e.file} does not verify against ${e.artifact_id}`)
      }
      covered.add(e.artifact_id)
    }
    const missing = [...artifacts.keys()].find(id => !covered.has(id))
    if (missing) return fail(`no signed statement for ${missing}`)
    return { ok: true, statements: index.length }
  } catch (e) {
    return fail((e as Error).message)
  }
}

// Registration is the only command that touches the network, and only when
// called with --service. Refuses to post unless scitt verify passes first.
// SCRAPI = draft-ietf-scitt-scrapi-11.
async function scittRegister(dir: string, service: string | undefined): Promise<{ service: string; registered: number; receipts: string[] }> {
  let base: URL
  try {
    base = new URL(service ?? '')
  } catch {
    throw new Error('--service <URL> is required and must be an http(s) URL')
  }
  if (base.protocol !== 'http:' && base.protocol !== 'https:') throw new Error('--service must be an http: or https: URL')
  // fetch would echo a URL with credentials in its error; refuse them here.
  if (base.username || base.password) throw new Error('--service must not carry credentials')
  // Only origin + path are ever printed; credentials or a query stay out of output.
  const shown = base.origin + base.pathname
  const root = resolve(dir, SCITT_DIR)
  const index = await readJsonFile<ScittIndexEntry[]>(root, 'index.json')
  if (!Array.isArray(index)) throw new Error('scitt/index.json is not an array')
  const checked = await scittVerify(dir)
  if (!checked.ok) throw new Error(`scitt verify failed, nothing registered: ${checked.reason}`)
  // SCRAPI §2.3: "POST /entries". The path is a non-normative example, so
  // --service is taken as the service base and /entries appended to it.
  const endpoint = new URL(base.pathname.replace(/\/?$/, '/entries'), base)
  const receipts: string[] = []
  for (const e of index) {
    if (escapes(root, e.file)) throw new Error(`${e.file} escapes the scitt directory`)
    const res = await fetch(endpoint, {
      method: 'POST',
      // SCRAPI §2.3: the request body is the COSE_Sign1 as application/cose.
      headers: { 'content-type': 'application/cose', accept: 'application/cose' },
      body: await readFile(join(root, e.file)),
    })
    // SCRAPI §2.3.1: 201 carries the receipt as its body. §2.3.2's 202 means
    // registration is still running (receipt later via §2.4 Location polling);
    // ponytail: no polling or retry, 202 and every other status fail.
    if (res.status !== 201) throw new Error(`${shown} answered ${res.status} for scitt/${e.file}; no receipt written`)
    const body = Buffer.from(await res.arrayBuffer())
    const name = e.file.replace(/\.cose$/, '') + '.receipt'
    // Whole body read first, then tmp + rename, so a crash leaves no half receipt.
    await writeFile(join(root, `${name}.tmp`), body)
    await rename(join(root, `${name}.tmp`), join(root, name))
    receipts.push(name)
  }
  return { service: shown, registered: receipts.length, receipts }
}

// The kid from a COSE_Sign1's protected header (label 4), or null if the bytes
// are not a well-formed statement.
function statementKid(bytes: Uint8Array): string | null {
  try {
    const msg = cborDecode(bytes)
    if (!(msg instanceof CborTag) || !Array.isArray(msg.value) || !(msg.value[0] instanceof Uint8Array)) return null
    const hdr = cborDecode(msg.value[0])
    const kid = hdr instanceof Map ? hdr.get(4) : undefined
    return kid instanceof Uint8Array ? new TextDecoder().decode(kid) : null
  } catch {
    return null
  }
}

// A local witness's OAI, derived from its public key: OAI-0000-<7 digits of
// sha256(public key hex) mod 10^7>. Self-asserted; no registry issued it.
// D9: Josh: is the OAI-0000 local range acceptable, or should the standard
// reserve one explicitly?
function localOai(privateKey: KeyObject): OAI {
  const n = BigInt('0x' + createHash('sha256').update(publicHex(privateKey)).digest('hex')) % 10_000_000n
  return `OAI-0000-${n.toString().padStart(7, '0')}` as OAI
}

// The files init writes, plus the store's. --force deletes only these, never
// the whole dir, so `--dir . --force` cannot take user files with it.
const INIT_FILES = ['witness.pem', '.gitignore', 'config.json', 'aits.jsonl', 'events.jsonl', 'blocks.jsonl', 'cleared.jsonl', 'last-receipt.json']

// One event and one period_summary the default profile accepts, for the
// recipe init prints (both from tunnelmind:code_crew:v1's schemas).
const RECIPE_EVENT = {
  event_type: 'code_crew:task_claimed',
  payload: { timestamp: '2026-10-08T12:00:01.500Z', evidence: 'asserted', task_id: 'A101', role: 'coder', model: 'claude-opus-5-5' },
}
const RECIPE_SUMMARY = { tasks_accepted: 1, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }

// What init found around the project and what to run next, for a human on
// stderr (stdout stays the config JSON). Detection only reads files: no
// subprocess, no network, and it never acts on what it finds. The project is
// the parent of --dir, which is cwd for the default ./.atap.
async function nextSteps(dir: string, profile: string): Promise<string> {
  const project = resolve(dir, '..')
  const has = (f: string) => existsSync(join(project, f))
  const onPath = (bin: string) => (process.env.PATH ?? '').split(delimiter).some(d => d !== '' && existsSync(join(d, bin)))
  const gitConfig = await readFile(join(project, '.git', 'config'), 'utf8').catch(() => '')
  const yes = (b: boolean) => (b ? 'yes' : 'no')
  const q = (v: unknown) => `'${JSON.stringify(v)}'`
  const lines = [
    `git: ${yes(has('.git'))}`,
    `claude code: ${yes(has('.claude') || onPath('claude'))}`,
    `github: ${yes(has('.github') || gitConfig.includes('github.com'))}`,
    `python: ${yes(has('pyproject.toml') || has('requirements.txt'))}`,
    '',
    'next steps (run anywhere inside this project; no flags needed):',
    // ponytail: the recipe's payloads fit only the default profile; other
    // profiles get a pointer to their own schemas.
    profile === 'tunnelmind:code_crew:v1'
      ? `  echo ${q(RECIPE_EVENT)} | atap-witness event\n  echo ${q(RECIPE_SUMMARY)} | atap-witness block`
      : `  echo '{"event_type":...,"payload":{...}}' | atap-witness event   (payloads per ${profile}'s schemas)\n  echo '{...period_summary...}' | atap-witness block`,
    '  atap-witness receipt --out DIR',
    '  atap-witness verify DIR',
    '',
    'The Claude Code plugin, the GitHub Action and the Python package are not released yet.',
  ]
  return lines.join('\n') + '\n'
}

// `init`: one command from nothing to a witness with a declared AIT. Every
// check (dir, profile, capabilities) runs before the first write; a failure
// after that removes the dir if init created it.
async function init(v: Values): Promise<Record<string, string>> {
  const dir = resolve(v.dir ?? '.atap')
  const profile = v.profile ?? 'tunnelmind:code_crew:v1'
  const exists = await stat(dir).then(() => true, () => false)
  if (exists && !v.force) throw new Error(`${dir} exists; pass --force to re-initialise it`)
  if (exists && (await readFile(join(dir, 'events.jsonl'), 'utf8').catch(() => '')).trim() !== '') {
    throw new Error(`${dir} already holds witness events; refusing to re-initialise it`)
  }
  const profilesDir = resolve(v['profiles-dir'] ?? PROFILES_DIR)
  const profiles = await Profiles.load(profilesDir)
  if (!profiles.isRegistered(profile)) throw new Error(`profile ${profile} is not in the profile registry`)
  const { profiles: entries } = await readJsonFile<{ profiles: { id: string; path: string }[] }>(profilesDir, 'registry.json')
  const entry = entries.find(e => e.id === profile)!
  const caps = await readJsonFile<{ capabilities: Record<string, string> }>(join(profilesDir, entry.path), 'capabilities.json')

  const { privateKey } = generateKeyPairSync('ed25519')
  const witness = localOai(privateKey)
  // No constraints: they are optional in the core schema, and a profile's
  // constraints (allowed_repos, models, ...) are the operator's to declare.
  // ponytail: 30-day lifetime like the profile examples; re-run init (or
  // declare a new AIT) when it expires.
  const input: AitInput = {
    agentType: profile.split(':')[1] ?? profile,
    profile,
    operator: witness,
    capabilities: Object.keys(caps.capabilities),
    attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' },
    expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  }

  if (exists) for (const f of INIT_FILES) await rm(join(dir, f), { force: true })
  try {
    await mkdir(dir, { recursive: true })
    const keyPath = join(dir, 'witness.pem')
    await writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
    // writeFile's mode is masked by umask and ignored for an existing file.
    await chmod(keyPath, 0o600)
    await writeFile(join(dir, '.gitignore'), 'witness.pem\n')
    const storage = new DirStorage(dir, profiles.coreGuards())
    const svc = new WitnessService({ witnessOAI: witness, privateKey, storage, attestationStrength: 'self-asserted' })
    const ait = await withLock(dir, () => svc.declareAit(input))
    // key is relative to the dir, so the dir can move as a whole.
    const config = { profile, key: 'witness.pem', witness_oai: witness, oai_origin: 'self-asserted', ait: ait.id }
    await writeFile(join(dir, 'config.json'), json(config))
    return config
  } catch (e) {
    if (!exists) await rm(dir, { recursive: true, force: true })
    throw e
  }
}

// The nearest .atap/config.json at or above `from`, like git finding .git, so
// commands run anywhere inside an init'd project need no flags. A missing or
// unparseable config counts as no config: explicit flags still work.
async function findAtap(from = process.cwd()): Promise<{ dir: string; config: Record<string, unknown> } | null> {
  for (let d = resolve(from); ; ) {
    const dir = join(d, '.atap')
    const config = await readFile(join(dir, 'config.json'), 'utf8').then(JSON.parse).catch(() => null)
    if (isObject(config)) return { dir, config }
    const up = resolve(d, '..')
    if (up === d) return null
    d = up
  }
}

async function main(argv: string[]): Promise<number> {
  const { values: v, positionals: pos } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      key: { type: 'string' },
      dir: { type: 'string' },
      'witness-oai': { type: 'string' },
      strength: { type: 'string' },
      ait: { type: 'string' },
      out: { type: 'string' },
      'profiles-dir': { type: 'string' },
      'unregistered-profile': { type: 'boolean' },
      issuer: { type: 'string' },
      service: { type: 'string' },
      profile: { type: 'string' },
      force: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  }) as { values: Values; positionals: string[] }
  if (v.help) {
    process.stdout.write(USAGE)
    return 0
  }
  const cmd = pos[0] === 'ait' && pos[1] === 'declare' ? 'ait declare' : pos[0]

  // init makes its own key and OAI, so it runs before the witness/stdin checks.
  if (cmd === 'init') {
    const config = await init(v)
    process.stdout.write(json(config))
    // A hint must never fail an init that already succeeded.
    process.stderr.write(await nextSteps(resolve(v.dir ?? '.atap'), config.profile!).catch(() => ''))
    return 0
  }
  // Read-only summary of the nearest .atap: no stdin, key or lock.
  if (cmd === 'status') {
    const atap = await findAtap()
    if (!atap) throw new Error('no .atap/config.json here or in any parent dir; run atap-witness init')
    const { profile, ait, witness_oai } = atap.config
    const storage = new DirStorage(atap.dir, {})
    const lastReceipt = await readFile(join(atap.dir, 'last-receipt.json'), 'utf8').then(JSON.parse).catch(() => null)
    process.stdout.write(json({
      profile,
      ait,
      witness_oai,
      dir: atap.dir,
      events: (await storage.eventsOf(ait as AIT_ID)).length,
      blocks: (await storage.blocksOf(ait as AIT_ID)).length,
      last_receipt: lastReceipt,
    }))
    return 0
  }
  if (cmd === 'verify') {
    if (!pos[1]) throw new Error('usage: atap-witness verify <dir>')
    const result = await verify(pos[1])
    process.stdout.write(json(result))
    return result.ok ? 0 : 1
  }
  // Flags left out fall back to the nearest .atap/config.json (init's output).
  // Explicit flags win; for the OAI so does ATAP_WITNESS_OAI. scitt takes only
  // the key: its <dir> is a receipt dir, not the store.
  const atap = await findAtap()
  const str = (x: unknown): string | undefined => (typeof x === 'string' ? x : undefined)
  const atapKey = str(atap?.config.key)
  if (atap && atapKey) v.key ??= resolve(atap.dir, atapKey)
  if (atap && cmd !== 'scitt') {
    v.dir ??= atap.dir
    v['witness-oai'] ??= process.env.ATAP_WITNESS_OAI ?? str(atap.config.witness_oai)
    v.ait ??= str(atap.config.ait)
  }

  // Like verify, scitt reads only the receipt dir: no witness, stdin or lock.
  if (cmd === 'scitt') {
    if (!['export', 'verify', 'register'].includes(pos[1] ?? '') || !pos[2]) {
      throw new Error('usage: atap-witness scitt <export | verify | register> <dir>')
    }
    if (pos[1] === 'register') {
      process.stdout.write(json(await scittRegister(pos[2], v.service)))
      return 0
    }
    if (pos[1] === 'export') {
      process.stdout.write(json(await scittExport(pos[2], v)))
      return 0
    }
    const result = await scittVerify(pos[2])
    process.stdout.write(json(result))
    return result.ok ? 0 : 1
  }
  if (!['ait declare', 'event', 'block', 'receipt'].includes(cmd ?? '')) {
    throw new Error('usage: atap-witness <init | status | ait declare | event | block | receipt | verify | scitt> [options]')
  }

  const strength = parseStrength(v.strength)
  const witness = (v['witness-oai'] ?? process.env.ATAP_WITNESS_OAI) as OAI | undefined
  if (!witness) throw new Error('--witness-oai <OAI> (or ATAP_WITNESS_OAI) is required')
  const privateKey = await loadKey(v.key)
  const dir = resolve(v.dir ?? '.atap-witness')
  // Read stdin before taking the lock so a slow writer never holds it.
  const input = cmd === 'receipt' ? null : await stdinJson(cmd === 'block')
  const profiles = cmd === 'receipt' ? null : await Profiles.load(resolve(v['profiles-dir'] ?? PROFILES_DIR))
  // Every signed AIT, event and block is checked against its whole core schema
  // as it is written; `receipt` writes nothing, so it needs no guards.
  const storage = new DirStorage(dir, profiles?.coreGuards() ?? {})
  const svc = new WitnessService({ witnessOAI: witness, privateKey, storage, attestationStrength: strength })

  // Every check below runs before the svc call, so a refusal writes nothing.
  const profileOf = async (aitId: AIT_ID): Promise<string> => {
    const ait = await storage.loadAit(aitId)
    if (!ait) throw new Error(`unknown AIT ${aitId}`)
    return ait.profile
  }

  const result = await withLock(dir, async () => {
    switch (cmd) {
      case 'ait declare':
        if (!isObject(input)) throw new Error('stdin must be an AitInput object')
        if (!profiles!.isRegistered(input.profile) && !v['unregistered-profile']) {
          throw new Error('profile is not in the profile registry; pass --unregistered-profile to declare it anyway')
        }
        await profiles!.checkAit(input)
        return svc.declareAit(input as unknown as AitInput)
      case 'event': {
        const aitId = requireAit(v)
        if (!isObject(input) || typeof input.event_type !== 'string' || !isObject(input.payload)) {
          throw new Error('stdin must be {"event_type": string, "payload": object}')
        }
        await profiles!.checkEvent(await profileOf(aitId), { event_type: input.event_type, payload: input.payload })
        return svc.witness(aitId, input.event_type, input.payload)
      }
      case 'block': {
        const aitId = requireAit(v)
        if (!isObject(input)) throw new Error('stdin must be a period_summary object')
        await profiles!.checkSummary(await profileOf(aitId), input)
        return svc.rollUp(aitId, input)
      }
      default:
        return receipt(svc, storage, v, privateKey, witness, strength)
    }
  })
  // status reports the latest receipt; the record stays inside .atap, and
  // only when this receipt came from that store (not an explicit other --dir).
  if (cmd === 'receipt' && atap && dir === atap.dir) {
    const rcpt = result as Receipt
    await writeFile(join(atap.dir, 'last-receipt.json'), json({ out: resolve(v.out!), at: new Date().toISOString(), id: rcpt.id }))
  }
  process.stdout.write(json(result))
  return 0
}

main(process.argv.slice(2)).then(
  code => process.exit(code),
  (e: unknown) => {
    process.stderr.write(JSON.stringify({ error: (e as Error).message ?? String(e) }) + '\n')
    process.exit(1)
  },
)
