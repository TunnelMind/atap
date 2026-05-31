# @tunnelmindai/eat

> **Part of TunnelMind — the intelligence layer agents call before they trust the internet.**
> Three lenses on one signed corpus: **Scry** (*who is attacking?*) · **Sigil** (*who can you trust?*) · **Tracker Data API** (*who is watching?*).
> This package serves: **the EAT verifier.** Apache-2.0. See [tunnelmind.ai/eat/profile/v0.1](https://tunnelmind.ai/eat/profile/v0.1).

Reference TypeScript verifier for the [TunnelMind EAT Profile v0.1](https://tunnelmind.ai/eat/profile/v0.1) — an IETF RATS ([RFC 9711]) Entity Attestation Token serialization carrying TunnelMind ATAP receipts and Scry cross-lens enrichments.

## Status

**v0.1.0-draft** — JWT/JWS (JSON) path is implemented end-to-end. CWT (CBOR) path is scaffolded with a clear not-implemented error; lands before v0.1.0 final. Spec is in 90-day public comment until 2026-08-29.

## Install

```bash
npm install @tunnelmindai/eat
```

Zero runtime dependencies. Targets WebCrypto SubtleCrypto — Node ≥18, Cloudflare Workers, Deno, Bun.

## Quickstart

```ts
import { verifyEat, verifyJwt } from '@tunnelmindai/eat';

// Verify a JWT-serialized EAT token using the published TunnelMind ATAP key bundle.
const result = await verifyEat(jwtFromHeader);

if (!result.valid) {
  console.error('rejected:', result.errors);
} else {
  console.log('claims:', result.claims);
  console.log('attestation strength:',
    result.claims?.['tunnelmind-attestation-strength-tier']);
  console.log('entity OAI:',
    result.claims?.['tunnelmind-oai-entity-ref']);
}
```

### Verifying with a pinned key bundle

For high-throughput / offline verifiers, pre-fetch and pin the ATAP key bundle:

```ts
import { verifyJwt } from '@tunnelmindai/eat';

const keys = (await (await fetch('https://tunnelmind.ai/atap/keys')).json()).keys;

const result = await verifyJwt(token, {
  keys,
  expectedNonce: nonceFromRequest, // optional
  maxIatSkewSec: 60,                // optional, default 60
});
```

## What the verifier checks (per spec §12)

1. JWT structure (3-part base64url).
2. Header `alg === 'EdDSA'`.
3. `profile === urn:tunnelmind:eat-profile:v0.1` (warns if missing).
4. Resolves verifier key via `kid`; reports unresolved keys as errors.
5. Verifies Ed25519 signature against the canonical signing input.
6. **Attestation-strength ceiling**: rejects if the token's `tunnelmind-attestation-strength-tier` exceeds the key's declared strength.
7. `iat` not more than 60s in the future (configurable).
8. `exp` not in the past.
9. `nonce` matches if `expectedNonce` was supplied.
10. Submodule recursion — `atap-receipt` is surfaced (caller verifies witness signature separately via `@tunnelmindai/atap`); `sensor-evidence` flagged as v0.2+.

## What this v0.1.0-draft does NOT do yet

- `verifyCwt()` is scaffolded but returns `not implemented`. Will land before v0.1.0 final.
- No CBOR codec (would be needed for CWT).
- No COSE_Sign1 decoder (needed for CWT).
- No sensor-evidence submodule recursion (reserved for v0.2+).

These are the explicit gaps. Filing issues for any of them is welcome.

## License

Apache-2.0. Spec text at [TunnelMind/eat-profile](https://github.com/TunnelMind/eat-profile) is CC BY 4.0.

## Related

- [`@tunnelmindai/atap`](../atap-js) — the ATAP receipt format this verifier validates the inner submodule of
- [TunnelMind/receipt-verify](https://github.com/TunnelMind/receipt-verify) — the JSON serialization verifier for the same claim set
- Spec repo: [TunnelMind/eat-profile](https://github.com/TunnelMind/eat-profile)
