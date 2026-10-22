// RFC 8785 JSON Canonicalization Scheme (JCS): the bytes every ATAP signature
// and self_hash is computed over (witness.ts signs them, verify.ts and
// verify.sh's python recompute them), so the output must be the same for
// every signer and verifier. ATAP artifacts use a constrained subset of JSON
// (no NaN/Infinity, no extreme floats) so this implementation stays short and
// auditable; the frozen vectors in test/vectors/jcs.json (shared verbatim with
// receipt-verify and tollbooth) pin its bytes. A lone UTF-16 surrogate is
// refused rather than mapped to U+FFFD, so two strings can never sign to one
// byte string. Input is untrusted parsed JSON: throws on a lone surrogate, a
// non-finite number or a non-JSON type; `undefined` members are dropped.
// Never normalizes Unicode: "é" and "é" hash differently, by design.

const ESC: Record<string, string> = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
}

function encodeString(s: string): string {
  let out = '"'
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number
    // The iterator yields a valid pair as one code point > 0xFFFF, so a cp in
    // this range is a lone surrogate. TextEncoder would map it to U+FFFD and
    // two different strings would sign to the same bytes; refused, as
    // receipt-verify's jcs.ts and verify.sh's python do.
    if (cp >= 0xd800 && cp <= 0xdfff) throw new Error('JCS: lone surrogate in string')
    if (ch in ESC) {
      out += ESC[ch]
    } else if (cp < 0x20) {
      out += '\\u' + cp.toString(16).padStart(4, '0')
    } else {
      out += ch
    }
  }
  return out + '"'
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error(`JCS: non-finite number ${n} is not encodable`)
  }
  // ECMA-262 Number::toString: RFC 8785 §3.2.2.3 for integers and the
  // shortest round-trip form alike.
  return String(n)
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return encodeNumber(value)
  if (typeof value === 'string') return encodeString(value)
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']'
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj)
      .filter(k => obj[k] !== undefined)
      .sort()
    return (
      '{' +
      keys
        .map(k => encodeString(k) + ':' + canonicalize(obj[k]))
        .join(',') +
      '}'
    )
  }
  throw new Error(`JCS: unsupported type ${typeof value}`)
}

export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value))
}
