// RFC 8785 JSON Canonicalization Scheme (JCS) — subset sufficient for ATAP v0.1.
//
// JCS specifies an unambiguous serialization of JSON. v0.1 artifacts use a constrained
// subset of JSON (no NaN/Infinity, no extreme floats, no surrogate escapes) so this
// implementation is short and auditable. For artifacts that hit JCS edge cases,
// substitute a strict library.

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
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i)
    const code = s.charCodeAt(i)
    if (ch in ESC) {
      out += ESC[ch]
    } else if (code < 0x20) {
      out += '\\u' + code.toString(16).padStart(4, '0')
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
  if (Number.isInteger(n)) {
    return String(n)
  }
  // ECMA-262 / JCS shortest round-trip representation.
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
