// A small ZIP reader for one receipt. The ZIP is hostile input: every size,
// offset and name is checked before use, and anything this reader does not
// need (ZIP64, multi-disk, encryption, methods other than stored and deflate)
// is refused with a plain error rather than guessed at.

export const MAX_ZIP_BYTES = 20 * 1024 * 1024
export const MAX_ENTRY_BYTES = 10 * 1024 * 1024
export const MAX_ENTRIES = 64

const EOCD_SIG = 0x06054b50
const CDH_SIG = 0x02014b50
const LFH_SIG = 0x04034b50

// Names that could land outside the receipt if anyone ever unpacked them:
// `..` segments, absolute paths, drive letters, backslashes, NUL.
function checkPath(name) {
  if (
    name === '' ||
    name.includes('\0') ||
    name.includes('\\') ||
    name.startsWith('/') ||
    /^[A-Za-z]:/.test(name) ||
    name.split('/').includes('..')
  ) {
    throw new Error(`refused path in ZIP: ${JSON.stringify(name)}`)
  }
}

// Inflates one entry, stopping as soon as the output passes the declared size
// or the cap: the declared size is the attacker's number, so the cap is
// enforced on the bytes actually produced.
async function inflate(name, method, data, size) {
  if (method === 0) {
    if (data.length !== size) throw new Error(`${name}: stored size ${data.length} != declared ${size}`)
    return data.slice()
  }
  if (method !== 8) throw new Error(`${name}: compression method ${method} is not supported (stored or deflate only)`)
  const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader()
  const chunks = []
  let n = 0
  for (;;) {
    let r
    try {
      r = await reader.read()
    } catch {
      throw new Error(`${name}: bad deflate data`)
    }
    if (r.done) break
    n += r.value.length
    if (n > size || n > MAX_ENTRY_BYTES) {
      reader.cancel().catch(() => {})
      throw new Error(`${name} inflates past its declared size or the ${MAX_ENTRY_BYTES}-byte cap`)
    }
    chunks.push(r.value)
  }
  if (n !== size) throw new Error(`${name} inflated to ${n} bytes, declared ${size}`)
  const out = new Uint8Array(n)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.length
  }
  return out
}

// Returns Map<path, Uint8Array> rooted at the receipt's manifest.json.
// ponytail: CRCs are not checked; manifest.files[] sha256s cover every file
// the verifier reads, and the manifest itself is checked by signature.
export async function readZip(input) {
  const buf = input instanceof Uint8Array ? input : new Uint8Array(input)
  if (buf.length > MAX_ZIP_BYTES) throw new Error(`the ZIP is over the ${MAX_ZIP_BYTES}-byte cap`)
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  const u16 = o => dv.getUint16(o, true)
  const u32 = o => dv.getUint32(o, true)

  // End of central directory: 22 bytes plus a comment of up to 65535.
  let eocd = -1
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (u32(i) === EOCD_SIG) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new Error('not a ZIP file (no end of central directory)')
  const [disk, cdDisk, onDisk, total] = [u16(eocd + 4), u16(eocd + 6), u16(eocd + 8), u16(eocd + 10)]
  const [cdSize, cdOff] = [u32(eocd + 12), u32(eocd + 16)]
  if (total === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) throw new Error('ZIP64 is not supported')
  if (disk !== 0 || cdDisk !== 0 || onDisk !== total) throw new Error('multi-disk ZIPs are not supported')
  if (total > MAX_ENTRIES) throw new Error(`the ZIP has ${total} entries; the cap is ${MAX_ENTRIES}`)
  if (cdOff + cdSize > eocd) throw new Error('central directory out of bounds')

  const files = new Map()
  let p = cdOff
  for (let i = 0; i < total; i++) {
    if (p + 46 > eocd || u32(p) !== CDH_SIG) throw new Error('bad central directory entry')
    const flags = u16(p + 8)
    const method = u16(p + 10)
    const csize = u32(p + 20)
    const usize = u32(p + 24)
    const nlen = u16(p + 28)
    const lho = u32(p + 42)
    if (p + 46 + nlen > eocd) throw new Error('bad central directory entry')
    let name
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(p + 46, p + 46 + nlen))
    } catch {
      throw new Error('a ZIP entry name is not UTF-8')
    }
    p += 46 + nlen + u16(p + 30) + u16(p + 32)
    checkPath(name)
    if (flags & 1) throw new Error(`${name} is encrypted`)
    if (csize === 0xffffffff || usize === 0xffffffff || lho === 0xffffffff) throw new Error('ZIP64 is not supported')
    if (name.endsWith('/')) continue
    if (usize > MAX_ENTRY_BYTES) throw new Error(`${name} is over the ${MAX_ENTRY_BYTES}-byte cap`)
    if (files.has(name)) throw new Error(`${name} appears twice in the ZIP`)
    if (lho + 30 > buf.length || u32(lho) !== LFH_SIG) throw new Error(`${name}: bad local header`)
    const start = lho + 30 + u16(lho + 26) + u16(lho + 28)
    if (start + csize > buf.length) throw new Error(`${name}: truncated`)
    files.set(name, await inflate(name, method, buf.subarray(start, start + csize), usize))
  }

  // `zip -r x.zip dir` puts the receipt under one top folder; the CLI's own
  // receipt.zip does not. Root the entries at the one manifest.json.
  const manifests = [...files.keys()].filter(k => /^([^/]+\/)?manifest\.json$/.test(k))
  if (manifests.length !== 1) {
    throw new Error(manifests.length ? 'more than one manifest.json in the ZIP' : 'no manifest.json in the ZIP')
  }
  const prefix = manifests[0].slice(0, -'manifest.json'.length)
  return new Map(
    [...files].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length), v]),
  )
}
