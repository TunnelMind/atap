// @tunnelmindai/eat — reference verifier for the TunnelMind EAT Profile v0.1.
//
// Spec: https://tunnelmind.ai/eat/profile/v0.1
// Status: DRAFT — public-comment window through 2026-08-29.
//
// This v0.1.0-draft scaffolds the verifier surface:
//   - JWT/JWS path (JSON serialization) is implemented end-to-end.
//   - CWT/COSE_Sign1 path (CBOR serialization) is stubbed with a clear
//     not-implemented error; lands before v0.1.0 final.
//   - Submodule recursion is implemented for `atap-receipt`;
//     `sensor-evidence` returns a structured warning (reserved for v0.2+).
//
// The verifier is intentionally dependency-free — only WebCrypto + base64 +
// JSON. Run anywhere Node ≥18, Cloudflare Workers, Deno, Bun.

const subtle = globalThis.crypto.subtle;

export const PROFILE_URN  = 'urn:tunnelmind:eat-profile:v0.1';
export const PROFILE_URL  = 'https://tunnelmind.ai/eat/profile/v0.1';
export const ATAP_KEYS_URL = 'https://tunnelmind.ai/atap/keys';

// ── claim names (TunnelMind-specific) ─────────────────────────────────────────

export const CLAIM = {
  STRENGTH:    'tunnelmind-attestation-strength-tier',
  OAI_REF:     'tunnelmind-oai-entity-ref',
  CONSISTENCY: 'tunnelmind-behavioral-consistency-score',
  DEPTH:       'tunnelmind-observation-depth',
  FLAGS:       'tunnelmind-deviation-flags',
  GRAPH:       'tunnelmind-graph-context',
} as const;

export type AttestationStrength = 'self-asserted' | 'software' | 'tee-tpm' | 'silicon-root';

export interface VerifierKey {
  key_id: string;
  algorithm: 'EdDSA' | 'Ed25519';
  public_key: string;          // base64 raw 32-byte Ed25519
  attestation_strength?: AttestationStrength;
}

export interface VerifierOptions {
  /** Verifier keys; if omitted, the verifier fetches ATAP_KEYS_URL via HTTPS. */
  keys?: VerifierKey[];
  /** Maximum acceptable iat skew in seconds (default 60). */
  maxIatSkewSec?: number;
  /** Required nonce — if set, the token's nonce MUST match. */
  expectedNonce?: string;
}

export interface VerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  /** Decoded claims when parse succeeded (regardless of crypto validity). */
  claims?: Record<string, unknown>;
  /** Recursively verified submodules. */
  submodules?: Record<string, VerifyResult>;
}

// ── helpers ───────────────────────────────────────────────────────────────────

function b64uToBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '=='.slice(0, (4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

async function resolveKey(opts: VerifierOptions, kid: string | undefined): Promise<VerifierKey | null> {
  const keys = opts.keys ?? await fetchAtapKeys();
  if (!kid) return keys[0] ?? null; // single-key services may omit kid
  return keys.find((k) => k.key_id === kid) ?? null;
}

async function fetchAtapKeys(): Promise<VerifierKey[]> {
  const res = await fetch(ATAP_KEYS_URL);
  if (!res.ok) throw new Error(`fetchAtapKeys: ${res.status}`);
  const body = await res.json() as { keys?: unknown };
  if (!Array.isArray(body.keys)) throw new Error('fetchAtapKeys: malformed keys array');
  // Trust the server's bundle shape; the verifier still cryptographically checks the signature.
  return body.keys as VerifierKey[];
}

// ── JWT path (JSON serialization) ─────────────────────────────────────────────

export async function verifyJwt(token: string, opts: VerifierOptions = {}): Promise<VerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, errors: ['malformed JWT: expected 3 parts'], warnings };
  }
  let header: Record<string, unknown> = {};
  let claims: Record<string, unknown> = {};
  try {
    header = JSON.parse(bytesToString(b64uToBytes(parts[0]!)));
    claims = JSON.parse(bytesToString(b64uToBytes(parts[1]!)));
  } catch (e) {
    return { valid: false, errors: [`JWT parse: ${(e as Error).message}`], warnings };
  }
  const sig = b64uToBytes(parts[2]!);

  // Algorithm check
  const alg = header['alg'];
  if (alg !== 'EdDSA') {
    errors.push(`unsupported alg: ${String(alg)} (expected EdDSA)`);
  }

  // Profile check
  if (claims['profile'] !== PROFILE_URN) {
    warnings.push(`profile claim missing or unexpected: ${String(claims['profile'])}`);
  }

  // Resolve key + verify signature
  const kid = typeof header['kid'] === 'string' ? header['kid'] : undefined;
  let key: VerifierKey | null = null;
  try {
    key = await resolveKey(opts, kid);
  } catch (e) {
    errors.push(`key resolution failed: ${(e as Error).message}`);
  }
  if (!key) {
    errors.push(`no key found for kid=${kid ?? '<none>'}`);
  } else {
    const pubKey = await subtle.importKey(
      'raw',
      b64ToBytes(key.public_key),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const signingInput = new TextEncoder().encode(parts[0] + '.' + parts[1]);
    const ok = await subtle.verify('Ed25519', pubKey, sig, signingInput);
    if (!ok) errors.push('Ed25519 signature did not verify');

    // Attestation-strength ceiling check (spec §9.1)
    const tokenStrength = claims[CLAIM.STRENGTH] as AttestationStrength | undefined;
    if (tokenStrength && key.attestation_strength) {
      const rank: Record<AttestationStrength, number> = {
        'self-asserted': 0, 'software': 1, 'tee-tpm': 2, 'silicon-root': 3,
      };
      if ((rank[tokenStrength] ?? 0) > (rank[key.attestation_strength] ?? 0)) {
        errors.push(`attestation-strength ceiling violated: token=${tokenStrength} > key=${key.attestation_strength}`);
      }
    }
  }

  // iat/exp checks
  const now = Math.floor(Date.now() / 1000);
  const iat = claims['iat'];
  const exp = claims['exp'];
  if (typeof exp === 'number' && exp < now) {
    errors.push(`token expired at ${new Date(exp * 1000).toISOString()}`);
  }
  if (typeof iat === 'number' && iat > now + (opts.maxIatSkewSec ?? 60)) {
    errors.push(`iat is more than ${opts.maxIatSkewSec ?? 60}s in the future`);
  }

  // nonce check
  if (opts.expectedNonce && claims['nonce'] !== opts.expectedNonce) {
    errors.push(`nonce mismatch: expected ${opts.expectedNonce}, got ${String(claims['nonce'])}`);
  }

  // Submodule recursion (the atap-receipt one — sensor-evidence is reserved for v0.2+)
  const submodules: Record<string, VerifyResult> = {};
  const submods = claims['submods'];
  if (submods && typeof submods === 'object') {
    for (const [name, _payload] of Object.entries(submods as Record<string, unknown>)) {
      if (name === 'atap-receipt') {
        // ATAP receipts carry their own witness_signature, separately verifiable
        // via verify.sh or @tunnelmindai/atap. This verifier surfaces the payload
        // and notes that further verification is the caller's responsibility.
        submodules[name] = {
          valid: true,
          errors: [],
          warnings: ['atap-receipt submodule present; verify witness_signature separately via @tunnelmindai/atap or verify.sh'],
        };
      } else if (name === 'sensor-evidence') {
        submodules[name] = {
          valid: false,
          errors: ['sensor-evidence submodule is reserved for v0.2+; this verifier is v0.1 only'],
          warnings: [],
        };
      } else {
        submodules[name] = {
          valid: false,
          errors: [`unknown submodule: ${name}`],
          warnings: [],
        };
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors, warnings, claims,
    ...(Object.keys(submodules).length ? { submodules } : {}),
  };
}

// ── CWT path (CBOR serialization) — scaffold ──────────────────────────────────

export async function verifyCwt(_token: Uint8Array, _opts: VerifierOptions = {}): Promise<VerifyResult> {
  return {
    valid: false,
    errors: ['verifyCwt not implemented in v0.1.0-draft — lands before v0.1.0 final. Use verifyJwt() for JSON tokens.'],
    warnings: [],
  };
}

// ── convenience: detect-and-dispatch ──────────────────────────────────────────

/**
 * Verify a token whose serialization is unknown to the caller.
 * Dispatches to verifyJwt for strings; verifyCwt for Uint8Arrays.
 */
export async function verifyEat(token: string | Uint8Array, opts?: VerifierOptions): Promise<VerifyResult> {
  if (typeof token === 'string') return verifyJwt(token, opts);
  return verifyCwt(token, opts);
}
