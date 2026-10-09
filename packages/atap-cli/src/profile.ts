// Profile enforcement: what the witness refuses to sign. The registry and the
// schemas are the same files profiles/scripts/validate.mjs checks in CI, read
// from a profiles dir (the repo's profiles/ by default, or --profiles-dir).
//
// Error messages carry ajv's instancePath + message only, never payload
// values: a refused payload may be exactly the PII the schema exists to stop.

import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const CORE_EVENT_TYPE =
  'https://tunnelmind.ai/atap/schemas/v0.1/witness-event.schema.json#/properties/event_type'

const CORE_AIT = 'https://tunnelmind.ai/atap/schemas/v0.1/ait.schema.json#/properties/'
// The whole core schemas (ATAP v0.1). Every signed object is checked against
// its complete schema at the moment it is written (DirStorage), so no field
// list here can drift from the schema: a missing required field, a stray
// property, a witness OAI that is really an e-mail address — the schema says no.
const CORE_SCHEMA = {
  ait: 'https://tunnelmind.ai/atap/schemas/v0.1/ait.schema.json',
  event: 'https://tunnelmind.ai/atap/schemas/v0.1/witness-event.schema.json',
  block: 'https://tunnelmind.ai/atap/schemas/v0.1/attestation-block.schema.json',
} as const

/** Throws on a document the core schema refuses; the message carries ajv's
 *  instancePath + message only, never payload values. */
export type Guard = (doc: unknown) => void
export type CoreGuards = { ait: Guard; event: Guard; block: Guard }

type RegistryEntry = { id: string; path: string }

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch {
    throw new Error(`cannot read ${path}; pass --profiles-dir <dir>`)
  }
}

export class Profiles {
  private ajv = new Ajv2020({ allErrors: true, strict: false })
  private compiled = new Map<string, ValidateFunction>()

  private constructor(
    private dir: string,
    private entries: RegistryEntry[],
  ) {
    addFormats(this.ajv)
  }

  static async load(dir: string): Promise<Profiles> {
    const registry = (await readJson(join(dir, 'registry.json'))) as { profiles?: RegistryEntry[] }
    const p = new Profiles(dir, registry.profiles ?? [])
    const baseDir = join(dir, 'atap-v0.1-schemas')
    for (const f of (await readdir(baseDir)).filter(x => x.endsWith('.json'))) {
      p.ajv.addSchema((await readJson(join(baseDir, f))) as object)
    }
    return p
  }

  isRegistered(id: unknown): boolean {
    return this.entries.some(e => e.id === id)
  }

  // A profile with no registry entry gets no profile schema; the caller only
  // reaches here for one when the AIT was declared with --unregistered-profile.
  private async schema(profile: string, name: string): Promise<ValidateFunction | null> {
    const entry = this.entries.find(e => e.id === profile)
    if (!entry) return null
    const path = join(this.dir, entry.path, 'schemas', `${name}.schema.json`)
    let v = this.compiled.get(path)
    if (!v) {
      v = this.ajv.compile((await readJson(path)) as object)
      this.compiled.set(path, v)
    }
    return v
  }

  private check(v: ValidateFunction, doc: unknown, rule: string): void {
    if (!v(doc)) {
      throw new Error(`refused by ${rule}: ${this.ajv.errorsText(v.errors, { separator: '; ' })}`)
    }
  }

  async checkEvent(profile: string, event: { event_type: string; payload: unknown }): Promise<void> {
    // Core schema first, so the event_type is a safe token before it is named below.
    this.check(this.ajv.getSchema(CORE_EVENT_TYPE)!, event.event_type, 'ATAP v0.1 witness-event schema event_type')
    const { event_type } = event
    const v = await this.schema(profile, 'witness-events')
    if (!v || v(event)) return
    if (v.errors?.some(e => e.instancePath === '/event_type' && e.keyword === 'enum')) {
      throw new Error(`event_type ${event_type} is not defined by profile ${profile}`)
    }
    this.check(v, event, `${profile} witness-events.schema.json`)
  }

  // Whole-document validators for the three signed kinds. DirStorage runs them
  // on every write, after the library has signed and before anything is
  // appended, so a refused object never reaches the store.
  coreGuards(): CoreGuards {
    const guard = (name: keyof typeof CORE_SCHEMA): Guard => {
      const v = this.ajv.getSchema(CORE_SCHEMA[name])
      if (!v) throw new Error(`core schema ${CORE_SCHEMA[name]} is not loaded; pass --profiles-dir <dir>`)
      return (doc: unknown) => this.check(v, doc, `ATAP v0.1 ${name === 'event' ? 'witness-event' : name === 'block' ? 'attestation-block' : 'ait'} schema`)
    }
    return { ait: guard('ait'), event: guard('event'), block: guard('block') }
  }

  // The profile's constraints schema when one is registered. The core fields
  // of the AIT are not checked here: the complete signed AIT is checked
  // against the whole ait schema by DirStorage.saveAit (coreGuards).
  async checkAit(input: Record<string, unknown>): Promise<void> {
    // ponytail: constraints are optional in the core schema, so an AIT without
    // them is not refused; only a present constraints object is profile-checked.
    if (input.constraints === undefined) return
    this.check(this.ajv.getSchema(CORE_AIT + 'constraints')!, input.constraints, 'ATAP v0.1 ait schema constraints')
    const v = await this.schema(input.profile as string, 'constraints')
    if (v) this.check(v, input.constraints, `${input.profile} constraints.schema.json`)
  }

  async checkSummary(profile: string, summary: unknown): Promise<void> {
    const v = await this.schema(profile, 'period-summary')
    if (v) this.check(v, summary, `${profile} period-summary.schema.json`)
  }
}
