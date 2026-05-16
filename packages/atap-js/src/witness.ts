// Witness service helpers. The Witness class is what an application profile's
// witness service uses to sign and chain ATAP artifacts.

import { KeyObject } from 'node:crypto'
import {
  AIT,
  AIT_ID,
  AttestationBlock,
  AttestationPolicy,
  AB_ID,
  GENESIS_HASH,
  HexHash,
  OAI,
  RCPT_ID,
  Receipt,
  WitnessEvent,
  WE_ID,
  ATAP_CONTEXT,
  ATAP_VERSION,
  MAX_PAYLOAD_BYTES,
  MAX_CAPABILITIES,
  MIN_BLOCK_INTERVAL_S,
  MAX_BLOCK_INTERVAL_S,
  MAX_AIT_LIFETIME_DAYS,
} from './types.js'
import { canonicalizeBytes } from './canonicalize.js'
import { ed25519Sign, fromHex, sha256 } from './crypto.js'
import { uuidv7 } from './uuid.js'

export interface WitnessStorage {
  saveAit(ait: AIT): Promise<void>
  loadAit(id: AIT_ID): Promise<AIT | null>
  hasAitId(id: AIT_ID): Promise<boolean>
  saveEvent(event: WitnessEvent): Promise<void>
  lastEventHash(aitId: AIT_ID): Promise<HexHash>
  lastBlockHash(aitId: AIT_ID): Promise<HexHash>
  pendingEvents(aitId: AIT_ID): Promise<WitnessEvent[]>
  clearPendingEvents(aitId: AIT_ID): Promise<void>
  saveBlock(block: AttestationBlock): Promise<void>
  blocksInPeriod(
    aitId: AIT_ID,
    periodStart: string,
    periodEnd: string,
  ): Promise<AttestationBlock[]>
}

export interface AitInput {
  agentType: string
  profile: string
  operator: OAI
  capabilities: string[]
  constraints?: Record<string, unknown>
  attestationPolicy: AttestationPolicy
  expiresAt: string
}

export interface WitnessConfig {
  witnessOAI: OAI
  privateKey: KeyObject
  storage: WitnessStorage
  now?: () => Date
}

export class WitnessService {
  private cfg: WitnessConfig
  private now: () => Date

  constructor(cfg: WitnessConfig) {
    this.cfg = cfg
    this.now = cfg.now ?? (() => new Date())
  }

  async declareAit(input: AitInput): Promise<AIT> {
    if (input.capabilities.length === 0 || input.capabilities.length > MAX_CAPABILITIES) {
      throw new Error(`AIT capabilities must be 1..${MAX_CAPABILITIES} items`)
    }
    const bi = input.attestationPolicy.block_interval_seconds
    if (bi < MIN_BLOCK_INTERVAL_S || bi > MAX_BLOCK_INTERVAL_S) {
      throw new Error(
        `block_interval_seconds must be ${MIN_BLOCK_INTERVAL_S}..${MAX_BLOCK_INTERVAL_S}`,
      )
    }
    const issuedAt = this.now()
    const expiresAt = new Date(input.expiresAt)
    const lifeMs = expiresAt.getTime() - issuedAt.getTime()
    if (lifeMs > MAX_AIT_LIFETIME_DAYS * 86400_000) {
      throw new Error(`AIT lifetime exceeds ${MAX_AIT_LIFETIME_DAYS} days`)
    }
    if (lifeMs <= 0) throw new Error('expires_at must be after issued_at')

    const id = `AIT-${uuidv7(issuedAt.getTime())}` as AIT_ID
    if (await this.cfg.storage.hasAitId(id)) {
      throw new Error(`AIT collision: ${id}`)
    }

    const unsigned: Omit<AIT, 'witness_signature'> = {
      '@context': ATAP_CONTEXT,
      '@type': 'AgentIdentityToken',
      id,
      ait_version: ATAP_VERSION,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      agent_type: input.agentType,
      profile: input.profile,
      operator: input.operator,
      witness: this.cfg.witnessOAI,
      capabilities: input.capabilities,
      constraints: input.constraints,
      attestation_policy: input.attestationPolicy,
    }
    const sig = ed25519Sign(canonicalizeBytes(unsigned), this.cfg.privateKey)
    const ait: AIT = { ...unsigned, witness_signature: sig }
    await this.cfg.storage.saveAit(ait)
    return ait
  }

  async witness(
    aitId: AIT_ID,
    eventType: string,
    payload: Record<string, unknown>,
  ): Promise<WitnessEvent> {
    const ait = await this.cfg.storage.loadAit(aitId)
    if (!ait) throw new Error(`unknown AIT ${aitId}`)
    if (ait.witness !== this.cfg.witnessOAI) {
      throw new Error(`AIT ${aitId} is not witnessed by ${this.cfg.witnessOAI}`)
    }

    const now = this.now()
    if (now.toISOString() >= ait.expires_at) {
      throw new Error(`AIT ${aitId} expired at ${ait.expires_at}`)
    }

    const payloadBytes = canonicalizeBytes(payload).length
    if (payloadBytes > MAX_PAYLOAD_BYTES) {
      throw new Error(`event payload ${payloadBytes} bytes exceeds ${MAX_PAYLOAD_BYTES}`)
    }

    const prev = await this.cfg.storage.lastEventHash(aitId)

    const id = `ATAP-WE-${uuidv7(now.getTime())}` as WE_ID
    const unsigned: Omit<WitnessEvent, 'self_hash' | 'witness_signature'> = {
      '@context': ATAP_CONTEXT,
      '@type': 'WitnessEvent',
      id,
      ait: aitId,
      witnessed_at: now.toISOString(),
      event_type: eventType,
      payload,
      prev_event_hash: prev,
    }
    const selfHash = sha256(canonicalizeBytes(unsigned))
    // ATAP §7.7 step 4: sign the 32-byte SHA-256 digest that self_hash encodes.
    const sig = ed25519Sign(fromHex(selfHash), this.cfg.privateKey)
    const event: WitnessEvent = { ...unsigned, self_hash: selfHash, witness_signature: sig }
    await this.cfg.storage.saveEvent(event)
    return event
  }

  async rollUp(
    aitId: AIT_ID,
    periodSummary: Record<string, unknown>,
  ): Promise<AttestationBlock | null> {
    const ait = await this.cfg.storage.loadAit(aitId)
    if (!ait) throw new Error(`unknown AIT ${aitId}`)
    const pending = await this.cfg.storage.pendingEvents(aitId)
    if (pending.length === 0) return null
    const first = pending[0]!
    const last = pending[pending.length - 1]!
    const prev = await this.cfg.storage.lastBlockHash(aitId)

    const id = `ATAP-AB-${uuidv7()}` as AB_ID
    const unsigned: Omit<AttestationBlock, 'self_hash' | 'witness_signature'> = {
      '@context': ATAP_CONTEXT,
      '@type': 'AttestationBlock',
      id,
      ait: aitId,
      ab_version: ATAP_VERSION,
      profile: ait.profile,
      period_start: first.witnessed_at,
      period_end: last.witnessed_at,
      first_event: first.id,
      last_event: last.id,
      event_count: pending.length,
      chain_head_hash: last.self_hash,
      period_summary: periodSummary,
      prev_block_hash: prev,
    }
    const selfHash = sha256(canonicalizeBytes(unsigned))
    // ATAP §7.7 step 4: sign the 32-byte SHA-256 digest that self_hash encodes.
    const sig = ed25519Sign(fromHex(selfHash), this.cfg.privateKey)
    const block: AttestationBlock = {
      ...unsigned,
      self_hash: selfHash,
      witness_signature: sig,
    }
    await this.cfg.storage.saveBlock(block)
    await this.cfg.storage.clearPendingEvents(aitId)
    return block
  }

  async generateReceipt(
    aitId: AIT_ID,
    periodStart: string,
    periodEnd: string,
    format: 'full' | 'summary' = 'full',
    files: ReadonlyArray<{ path: string; sha256: HexHash | null }> = [],
  ): Promise<Receipt> {
    const ait = await this.cfg.storage.loadAit(aitId)
    if (!ait) throw new Error(`unknown AIT ${aitId}`)
    const blocks = await this.cfg.storage.blocksInPeriod(aitId, periodStart, periodEnd)
    if (blocks.length === 0) {
      throw new Error(`no blocks for ${aitId} in [${periodStart}, ${periodEnd}]`)
    }
    const first = blocks[0]!
    const last = blocks[blocks.length - 1]!
    const eventCount = blocks.reduce((sum, b) => sum + b.event_count, 0)
    const id = `ATAP-RCPT-${uuidv7()}` as RCPT_ID
    const unsigned: Omit<Receipt, 'witness_signature'> = {
      '@context': ATAP_CONTEXT,
      '@type': 'Receipt',
      id,
      ait: aitId,
      profile: ait.profile,
      period_start: periodStart,
      period_end: periodEnd,
      block_count: blocks.length,
      event_count: eventCount,
      first_block: first.id,
      last_block: last.id,
      chain_head_hash: last.self_hash,
      witness: this.cfg.witnessOAI,
      format,
      generated_at: this.now().toISOString(),
      verifier_url: 'https://tunnelmind.ai/atap/verify.sh',
      keys_url: 'https://tunnelmind.ai/atap/keys',
      files: [...files],
    }
    const sig = ed25519Sign(canonicalizeBytes(unsigned), this.cfg.privateKey)
    return { ...unsigned, witness_signature: sig }
  }
}

// In-memory storage suitable for tests. Production witnesses should implement
// WitnessStorage on a durable backend (Postgres, S3 + lock service, etc.).
export class InMemoryStorage implements WitnessStorage {
  private aits = new Map<AIT_ID, AIT>()
  private aitIds = new Set<string>()
  private events = new Map<AIT_ID, WitnessEvent[]>()
  private pending = new Map<AIT_ID, WitnessEvent[]>()
  private blocks = new Map<AIT_ID, AttestationBlock[]>()
  private lastEventHashes = new Map<AIT_ID, HexHash>()
  private lastBlockHashes = new Map<AIT_ID, HexHash>()

  async saveAit(ait: AIT): Promise<void> {
    this.aits.set(ait.id, ait)
    this.aitIds.add(ait.id)
  }
  async loadAit(id: AIT_ID): Promise<AIT | null> {
    return this.aits.get(id) ?? null
  }
  async hasAitId(id: AIT_ID): Promise<boolean> {
    return this.aitIds.has(id)
  }
  async saveEvent(event: WitnessEvent): Promise<void> {
    const list = this.events.get(event.ait) ?? []
    list.push(event)
    this.events.set(event.ait, list)
    const pending = this.pending.get(event.ait) ?? []
    pending.push(event)
    this.pending.set(event.ait, pending)
    this.lastEventHashes.set(event.ait, event.self_hash)
  }
  async lastEventHash(aitId: AIT_ID): Promise<HexHash> {
    return this.lastEventHashes.get(aitId) ?? GENESIS_HASH
  }
  async lastBlockHash(aitId: AIT_ID): Promise<HexHash> {
    return this.lastBlockHashes.get(aitId) ?? GENESIS_HASH
  }
  async pendingEvents(aitId: AIT_ID): Promise<WitnessEvent[]> {
    return [...(this.pending.get(aitId) ?? [])]
  }
  async clearPendingEvents(aitId: AIT_ID): Promise<void> {
    this.pending.set(aitId, [])
  }
  async saveBlock(block: AttestationBlock): Promise<void> {
    const list = this.blocks.get(block.ait) ?? []
    list.push(block)
    this.blocks.set(block.ait, list)
    this.lastBlockHashes.set(block.ait, block.self_hash)
  }
  async blocksInPeriod(
    aitId: AIT_ID,
    periodStart: string,
    periodEnd: string,
  ): Promise<AttestationBlock[]> {
    const all = this.blocks.get(aitId) ?? []
    return all.filter(b => b.period_start >= periodStart && b.period_end <= periodEnd)
  }
}
