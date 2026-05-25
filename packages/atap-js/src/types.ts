// ATAP v0.1 — TypeScript types
// Mirrors the JSON Schemas at https://tunnelmind.ai/atap/schemas/v0.1/

export type Iso8601 = string
export type HexHash = `0x${string}`
export type Ed25519Sig = `ed25519:0x${string}`
export type OAI = `OAI-${number}-${number}`
export type AIT_ID = `AIT-${string}`
export type WE_ID = `ATAP-WE-${string}`
export type AB_ID = `ATAP-AB-${string}`
export type RCPT_ID = `ATAP-RCPT-${string}`

/**
 * Attestation strength tier — the trust root the witness service ran under.
 * Ordered from weakest to strongest (ATAP §7.4.1).
 * Optional in v0.1.x (missing = treated as 'self-asserted'). Required at v0.2.
 */
export type AttestationStrength =
  | 'self-asserted'
  | 'software'
  | 'tee-tpm'
  | 'silicon-root'

export const ATTESTATION_STRENGTH_RANK: Record<AttestationStrength, number> = {
  'self-asserted': 0,
  software: 1,
  'tee-tpm': 2,
  'silicon-root': 3,
}

export interface AttestationPolicy {
  witness_granularity: 'per_action' | 'per_decision' | string
  block_interval_seconds: number
  receipt_generation: 'on_demand' | 'per_block' | 'per_period'
}

export interface AIT {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld'
  '@type': 'AgentIdentityToken'
  id: AIT_ID
  ait_version: '0.1'
  issued_at: Iso8601
  expires_at: Iso8601
  agent_type: string
  profile: string
  operator: OAI
  witness: OAI
  capabilities: string[]
  constraints?: Record<string, unknown>
  attestation_policy: AttestationPolicy
  witness_signature: Ed25519Sig
}

export interface WitnessEvent {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld'
  '@type': 'WitnessEvent'
  id: WE_ID
  ait: AIT_ID
  witnessed_at: Iso8601
  event_type: string
  payload: Record<string, unknown>
  prev_event_hash: HexHash
  self_hash: HexHash
  witness_signature: Ed25519Sig
}

export interface AttestationBlock {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld'
  '@type': 'AttestationBlock'
  id: AB_ID
  ait: AIT_ID
  ab_version: '0.1'
  profile: string
  period_start: Iso8601
  period_end: Iso8601
  first_event: WE_ID
  last_event: WE_ID
  event_count: number
  chain_head_hash: HexHash
  period_summary: Record<string, unknown>
  log_index?: number
  prev_block_hash: HexHash
  self_hash: HexHash
  witness_signature: Ed25519Sig
}

export interface ReceiptFile {
  path: string
  sha256: HexHash | null
}

export interface Receipt {
  '@context': 'https://tunnelmind.ai/atap/context.jsonld'
  '@type': 'Receipt'
  id: RCPT_ID
  ait: AIT_ID
  profile: string
  period_start: Iso8601
  period_end: Iso8601
  block_count: number
  event_count: number
  first_block: AB_ID
  last_block: AB_ID
  chain_head_hash: HexHash
  witness: OAI
  format: 'full' | 'summary'
  generated_at: Iso8601
  verifier_url: string
  keys_url: string
  files: ReceiptFile[]
  /**
   * Trust root the witness service ran under for this receipt's period
   * (ATAP §7.4.1). Optional in v0.1.x; missing values are treated as
   * 'self-asserted'. REQUIRED at v0.2.
   */
  attestation_strength?: AttestationStrength
  witness_signature: Ed25519Sig
}

export interface PublicKey {
  witness: OAI
  key_id: string
  algorithm: 'ed25519'
  public_key: HexHash
  valid_from: Iso8601
  valid_until: Iso8601
  status: 'active' | 'rotated' | 'compromised'
  /**
   * Trust root the witness service ran under during this key's validity
   * window (ATAP §7.4.1, §8.1). Optional in v0.1.x; missing values are
   * treated as 'self-asserted'. REQUIRED at v0.2.
   */
  attestation_strength?: AttestationStrength
  rotated_to: string | null
  compromise_notice: {
    disclosed_at: Iso8601
    detected_at: Iso8601
    summary_url: string
  } | null
}

export interface KeysDocument {
  keys: PublicKey[]
  updated_at: Iso8601
}

export const GENESIS_HASH: HexHash = '0x0000000000000000000000000000000000000000000000000000000000000000'
export const ATAP_CONTEXT = 'https://tunnelmind.ai/atap/context.jsonld' as const
export const ATAP_VERSION = '0.1' as const
export const MAX_PAYLOAD_BYTES = 16_384
export const MAX_CONSTRAINTS_BYTES = 4_096
export const MAX_CAPABILITIES = 64
export const MIN_BLOCK_INTERVAL_S = 60
export const MAX_BLOCK_INTERVAL_S = 3_600
export const MAX_AIT_LIFETIME_DAYS = 365
export const REPLAY_WINDOW_SECONDS = 30
