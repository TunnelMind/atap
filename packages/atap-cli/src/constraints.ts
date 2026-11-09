// `atap-witness constraints …`: the operator's side (keygen, set, rescind) and
// the harness's side (check, context, status) of operator-signed constraints.
// The signing, folding and evaluation live in @tunnelmindai/atap
// (constraints.ts); this file only finds the files, keys and settings.
//
// Where trust comes from, strongest first:
//   ATAP_OPERATOR      the operator did:key the harness trusts (user environment, not the repo)
//   ATAP_CONSTRAINTS   the constraint store file (put it outside the agent's write reach)
//   ATAP_CONSTRAINTS_REQUIRED=1  a missing or empty store denies every call instead of allowing it
// Without them, .atap/config.json's `constraints_operator` and .atap/constraints.jsonl are used.
// A committed config is chosen by whoever wrote the repo, so for a crew the
// environment variables are the real setting; the config is a convenience.

import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { appendFile, chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { existsSync, realpathSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import {
  canonicalizeBytes,
  didKeyFromPublicKey,
  evaluateCall,
  foldConstraints,
  isObject,
  renderConstraints,
  sha256,
  signConstraintRescind,
  signConstraintSet,
  statementHash,
  type ConstraintStatement,
  type Decision,
  type FoldResult,
  type WitnessEvent,
} from '@tunnelmindai/atap'

export interface ConstraintEnv {
  /** The .atap store dir and its parsed config. */
  atapDir: string
  config: Record<string, unknown>
}

const bare = (h: string): string => h.replace(/^0x/, '')

export function storePath(e: ConstraintEnv): string {
  const env = process.env.ATAP_CONSTRAINTS
  return env ? resolve(env) : join(e.atapDir, 'constraints.jsonl')
}

export function trustedOperator(e: ConstraintEnv): string {
  const env = process.env.ATAP_OPERATOR
  if (env) return env
  return typeof e.config.constraints_operator === 'string' ? e.config.constraints_operator : ''
}

const required = (): boolean => process.env.ATAP_CONSTRAINTS_REQUIRED === '1'

/** Lines of the store as parsed JSON; a line that does not parse is kept as a string so the fold rejects it. */
export async function readStore(path: string): Promise<{ exists: boolean; statements: unknown[] }> {
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === 'ENOENT') return { exists: false, statements: [] }
    throw new Error('cannot read the constraint store')
  }
  const statements = text
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => {
      try {
        return JSON.parse(l) as unknown
      } catch {
        return l
      }
    })
  return { exists: true, statements }
}

export interface StoreState {
  path: string
  exists: boolean
  operator: string
  fold: FoldResult
  /** Hashes recorded as constraint_set/rescind witness events but absent from the store: lines deleted from it. */
  missing: string[]
}

export async function loadState(e: ConstraintEnv, events: WitnessEvent[]): Promise<StoreState> {
  const path = storePath(e)
  const { exists, statements } = await readStore(path)
  const operator = trustedOperator(e)
  const scope = aitOf(e)
  const fold = foldConstraints(statements, operator, scope)
  const have = new Set(statements.filter(isObject).map((s) => bare(statementHash(s as unknown as ConstraintStatement))))
  const missing = events
    .filter((ev) => ev.event_type === 'code_crew:constraint_set' || ev.event_type === 'code_crew:constraint_rescind')
    .map((ev) => (ev.payload as Record<string, unknown>).statement_sha256)
    .filter((h): h is string => typeof h === 'string' && !have.has(h))
  return { path, exists, operator, fold, missing }
}

/** The store-level verdict that overrides any rule: fail closed on tamper, or on absence when required. */
export function storeVerdict(st: StoreState): Decision | null {
  if (st.fold.rejected.length > 0) {
    return { decision: 'deny', constraint_id: 'atap.store', rule_id: 'tampered', reason: `the operator constraint store has ${st.fold.rejected.length} statement(s) that fail verification (${st.fold.rejected[0]?.reason ?? 'unknown'}); the owner must repair it` }
  }
  if (st.missing.length > 0) {
    return { decision: 'deny', constraint_id: 'atap.store', rule_id: 'missing-statement', reason: `${st.missing.length} recorded constraint statement(s) are missing from the store; the owner must restore them` }
  }
  if (required() && (!st.exists || st.fold.active.length === 0)) {
    return { decision: 'deny', constraint_id: 'atap.store', rule_id: 'required', reason: 'ATAP_CONSTRAINTS_REQUIRED=1 and no operator constraints are in force' }
  }
  return null
}

/** The AIT the harness runs under: ATAP_AIT (user environment) beats the config. */
export function aitOf(e: ConstraintEnv): string {
  return process.env.ATAP_AIT || (typeof e.config.ait === 'string' ? e.config.ait : '')
}

/** What no tool but a read-only one may touch: the store, the whole .atap/, and the agent's settings files. */
export function protectedPaths(st: StoreState, atapDir: string): string[] {
  const root = dirname(atapDir)
  // The user's own ~/.claude settings too: a hook can be switched off from there as well as from the project's.
  const settings = [root, homedir()].flatMap((d) => [join(d, '.claude', 'settings.json'), join(d, '.claude', 'settings.local.json')])
  return [st.path, atapDir, ...settings]
}

/** What no tool may touch at all: the operator key, when its path is known. */
export function secretPaths(): string[] {
  return process.env.ATAP_OPERATOR_KEY ? [resolve(process.env.ATAP_OPERATOR_KEY)] : []
}

/** realpath of the longest existing prefix, with the rest appended: resolves a symlinked parent of a new file. */
export function realpathPrefix(abs: string): string {
  // A path this platform does not call absolute (a drive-letter path off Windows) would resolve against
  // the process cwd below; leave it as it is.
  if (!isAbsolute(abs)) return abs
  let head = abs
  const tail: string[] = []
  for (;;) {
    try {
      return join(realpathSync(head), ...tail.reverse())
    } catch {
      const up = dirname(head)
      if (up === head) return abs
      tail.push(basename(head))
      head = up
    }
  }
}

const DRIVE = /^[A-Za-z]:[\\/]/

/** The hook's question: may this tool call run? Input is the PreToolUse hook JSON. */
export function decide(st: StoreState, input: Record<string, unknown>, projectRoot: string, atapDir: string = join(projectRoot, '.atap')): Decision {
  const verdict = storeVerdict(st)
  if (verdict) return verdict
  const tool_name = typeof input.tool_name === 'string' ? input.tool_name : ''
  const tool_input = isObject(input.tool_input) ? (input.tool_input as Record<string, unknown>) : {}
  // An absolute cwd: POSIX `/…`, or in windows mode (win32, or a drive-letter root, as atap-js decides) a
  // drive-letter `C:\…` / `C:/…`; anything else falls back to the root.
  const windows = process.platform === 'win32'
  const abs = windows || DRIVE.test(projectRoot) ? /^(\/|[A-Za-z]:[\\/])/ : /^\//
  const cwd = typeof input.cwd === 'string' && abs.test(input.cwd) ? input.cwd : projectRoot
  return evaluateCall(st.fold.active, { tool_name, tool_input, cwd }, {
    projectRoot,
    protectedPaths: protectedPaths(st, atapDir),
    secretPaths: secretPaths(),
    realpath: realpathPrefix,
    caseInsensitive: process.platform === 'darwin' || process.platform === 'win32',
    windows,
  })
}

export function inputHash(v: unknown): string {
  try {
    return bare(sha256(canonicalizeBytes(v)))
  } catch {
    return bare(sha256(new TextEncoder().encode(JSON.stringify(v) ?? 'null')))
  }
}

export function gatePayload(st: StoreState, input: Record<string, unknown>, d: Decision): Record<string, unknown> {
  const tool = typeof input.tool_name === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(input.tool_name) ? input.tool_name : 'unknown'
  return {
    timestamp: new Date().toISOString(),
    evidence: 'witnessed',
    tool,
    decision: d.decision,
    constraint_id: d.constraint_id,
    rule_id: d.rule_id,
    input_sha256: inputHash(input.tool_input ?? null),
    in_force_sha256: bare(st.fold.in_force),
  }
}

export function contextText(st: StoreState): string {
  const v = storeVerdict(st)
  if (v) return `ATAP: every tool call is blocked: ${v.reason}.`
  return renderConstraints(st.fold, st.operator)
}

export function statusOf(st: StoreState): Record<string, unknown> {
  return {
    store: st.path,
    store_exists: st.exists,
    operator: st.operator || null,
    required: required(),
    in_force_sha256: bare(st.fold.in_force),
    active: st.fold.active.map((c) => ({ constraint_id: c.constraint_id, prose: c.prose, rules: c.rules.length, issued_at: c.issued_at, statement_sha256: bare(statementHash(c)) })),
    rejected: st.fold.rejected,
    ignored: st.fold.ignored,
    missing: st.missing,
    verdict: storeVerdict(st),
  }
}

// ------------------------------------------------------------------ operator side

export async function loadOperatorKey(path: string | undefined): Promise<KeyObject> {
  if (!path) throw new Error('--operator-key <path> is required (or ATAP_OPERATOR_KEY)')
  let pem: Buffer
  try {
    pem = await readFile(path)
  } catch {
    throw new Error('cannot read the operator key file')
  }
  let key: KeyObject
  try {
    key = createPrivateKey({ key: pem, format: 'pem' })
  } catch {
    throw new Error('the operator key is not a PEM private key')
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('the operator key must be Ed25519')
  return key
}

export function didOf(key: KeyObject): string {
  const x = (createPublicKey(key).export({ format: 'jwk' }) as { x: string }).x
  return didKeyFromPublicKey(new Uint8Array(Buffer.from(x, 'base64url')))
}

export async function keygen(out: string | undefined, force: boolean): Promise<{ operator: string; key: string }> {
  if (!out) throw new Error('--out <path> is required; keep it outside any project the agent can write')
  const path = resolve(out)
  if (existsSync(path) && !force) throw new Error('the key file exists; pass --force to replace it')
  const { privateKey } = generateKeyPairSync('ed25519')
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  await writeFile(`${path}.tmp`, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 })
  await chmod(`${path}.tmp`, 0o600)
  await rename(`${path}.tmp`, path)
  return { operator: didOf(privateKey), key: path }
}

/** Appends a signed statement to the store. */
export async function appendStatement(e: ConstraintEnv, statement: ConstraintStatement): Promise<void> {
  const path = storePath(e)
  await mkdir(dirname(path), { recursive: true })
  await appendFile(path, JSON.stringify(statement) + '\n', { mode: 0o600 })
}

/** Signs a set or rescind and refuses a key the harness does not trust. Writes nothing to the store. */
export async function signStatement(
  e: ConstraintEnv,
  key: KeyObject,
  kind: 'set' | 'rescind',
  input: Record<string, unknown>,
): Promise<{ statement: ConstraintStatement; configured_operator: boolean }> {
  const did = didOf(key)
  let operator = trustedOperator(e)
  let configured = false
  if (!operator) {
    // First statement in a store with no operator anywhere: this key becomes the config's operator.
    const cfgPath = join(e.atapDir, 'config.json')
    const next = { ...e.config, constraints_operator: did }
    await writeFile(`${cfgPath}.tmp`, JSON.stringify(next, null, 2) + '\n')
    await rename(`${cfgPath}.tmp`, cfgPath)
    e.config = next
    operator = did
    configured = true
  }
  if (operator !== did) throw new Error(`this key (${did}) is not the trusted operator (${operator})`)
  const scope = typeof input.scope === 'string' ? input.scope : '*'
  const statement =
    kind === 'set'
      ? signConstraintSet(
          { constraint_id: input.constraint_id as string, scope, prose: input.prose as string, rules: input.rules as never },
          key,
        )
      : signConstraintRescind({ constraint_id: input.constraint_id as string, scope }, key)
  return { statement, configured_operator: configured }
}

/** The witness payload for a statement about to be added: in_force is computed as if it were in the store. */
export async function changePayload(e: ConstraintEnv, statement: ConstraintStatement): Promise<Record<string, unknown>> {
  const { statements } = await readStore(storePath(e))
  const fold = foldConstraints([...statements, statement], trustedOperator(e), aitOf(e))
  return {
    timestamp: new Date().toISOString(),
    evidence: 'witnessed',
    constraint_id: statement.constraint_id,
    statement_sha256: bare(statementHash(statement)),
    operator: statement.operator,
    in_force_sha256: bare(fold.in_force),
  }
}
