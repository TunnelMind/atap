// @tunnelmindai/atap — reference TypeScript wrapper for ATAP v0.1.
// Standard: https://tunnelmind.ai/atap/standard

export * from './types.js'
export { canonicalize, canonicalizeBytes } from './canonicalize.js'
export {
  sha256,
  ed25519Sign,
  ed25519Verify,
  privateKeyFromRaw,
  publicKeyFromRaw,
  publicKeyFromHex,
  toHex,
  fromHex,
} from './crypto.js'
export { didKeyFromPublicKey, publicKeyFromDidKey, isDidKey } from './didkey.js'
export { uuidv7, isValidUuidv7, UUIDV7_RE } from './uuid.js'
export {
  WitnessService,
  InMemoryStorage,
  type WitnessConfig,
  type WitnessStorage,
  type AitInput,
} from './witness.js'
export {
  verifyReceipt,
  pickDidKeyKey,
  checkWitnessEvents,
  checkManifestFiles,
  normaliseReceiptPath,
  clean,
  isObject,
  WITNESS_EVENTS,
  type VerifyOptions,
  type VerifyResult,
} from './verify.js'
export { toSignedStatement, verifySignedStatement, cborDecode, CborTag } from './scitt.js'
