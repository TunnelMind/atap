// node:crypto (and Buffer) for atap-js in the browser, by record and replay.
//
// atap-js's verifyReceipt is synchronous and calls node:crypto; WebCrypto's
// SHA-256 and Ed25519 are async. So the shim answers from `known` when it can.
// On a miss it records the request in `pending` and returns a placeholder (a
// zero hash; `true` for a signature, so the pass runs on and finds more
// requests). The glue (main.js) reruns verification, resolving `pending` with
// WebCrypto between passes, until a pass misses nothing: that pass saw only
// real answers, so its result is the verdict. A placeholder never reaches it.

const known = new Map()
const pending = new Map()

const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')

// crypto.ts wraps raw keys in an Ed25519 SPKI DER (12-byte prefix + 32 bytes).
const SPKI_PREFIX_LEN = 12

export const nodeCrypto = {
  createHash(alg) {
    if (alg !== 'sha256') throw new Error(`unsupported hash ${alg}`)
    const parts = []
    const h = {
      update(d) {
        parts.push(d)
        return h
      },
      digest() {
        const data = new Uint8Array(parts.reduce((a, p) => a + p.length, 0))
        let off = 0
        for (const p of parts) {
          data.set(p, off)
          off += p.length
        }
        const key = `sha256:${hex(data)}`
        if (known.has(key)) return known.get(key)
        pending.set(key, async () => new Uint8Array(await crypto.subtle.digest('SHA-256', data)))
        return new Uint8Array(32)
      },
    }
    return h
  },
  createPublicKey({ key }) {
    if (key.length !== SPKI_PREFIX_LEN + 32) throw new Error('Ed25519 public key must be 32 bytes')
    return { raw: key.slice(SPKI_PREFIX_LEN) }
  },
  verify(_alg, msg, pub, sig) {
    const key = `ed25519:${hex(pub.raw)}:${hex(sig)}:${hex(msg)}`
    if (known.has(key)) return known.get(key)
    pending.set(key, async () => {
      // A key or signature WebCrypto refuses outright is a failed check, not an error.
      try {
        const k = await crypto.subtle.importKey('raw', pub.raw, { name: 'Ed25519' }, false, ['verify'])
        return await crypto.subtle.verify({ name: 'Ed25519' }, k, sig, msg)
      } catch {
        return false
      }
    })
    return true
  },
  // The viewer only verifies; signing is never reached.
  createPrivateKey() {
    throw new Error('signing is not available in the viewer')
  },
  sign() {
    throw new Error('signing is not available in the viewer')
  },
}

// crypto.ts only calls Buffer.from on bytes it then hands to node:crypto.
export const Buffer = { from: b => (b instanceof Uint8Array ? b : new Uint8Array(b)) }

export function pendingCount() {
  return pending.size
}

export async function resolvePending() {
  const reqs = [...pending]
  pending.clear()
  const results = await Promise.all(reqs.map(([, f]) => f()))
  reqs.forEach(([k], i) => known.set(k, results[i]))
}
