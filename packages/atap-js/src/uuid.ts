// uuidv7 — RFC 9562 §5.7
// Format: 48-bit Unix-epoch-ms timestamp + 4-bit version (7) + 12 random bits
//       + 2-bit variant (10) + 62 random bits.

import { randomBytes } from 'node:crypto'

export function uuidv7(now: number = Date.now()): string {
  const ms = BigInt(now)
  const r = randomBytes(10)

  const b = new Uint8Array(16)

  // timestamp_high (32 bits)
  b[0] = Number((ms >> 40n) & 0xffn)
  b[1] = Number((ms >> 32n) & 0xffn)
  b[2] = Number((ms >> 24n) & 0xffn)
  b[3] = Number((ms >> 16n) & 0xffn)

  // timestamp_low (16 bits)
  b[4] = Number((ms >> 8n) & 0xffn)
  b[5] = Number(ms & 0xffn)

  // version (4 bits = 7) + rand_a (12 bits)
  b[6] = 0x70 | (r[0]! & 0x0f)
  b[7] = r[1]!

  // variant (2 bits = 10) + rand_b (62 bits)
  b[8] = 0x80 | (r[2]! & 0x3f)
  b[9] = r[3]!
  for (let i = 10; i < 16; i++) {
    b[i] = r[i - 6]!
  }

  const hex = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
  return (
    hex.slice(0, 8) +
    '-' +
    hex.slice(8, 12) +
    '-' +
    hex.slice(12, 16) +
    '-' +
    hex.slice(16, 20) +
    '-' +
    hex.slice(20)
  )
}

export const UUIDV7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function isValidUuidv7(s: string): boolean {
  return UUIDV7_RE.test(s)
}
