// Directory-backed WitnessStorage. Behaves like the library's InMemoryStorage,
// but every record is a line in an append-only JSONL file, one file per kind:
//
//   aits.jsonl     signed AITs
//   events.jsonl   signed Witness Events, in chain order
//   blocks.jsonl   signed Attestation Blocks, in chain order
//   cleared.jsonl  {"ait", "after"} markers written by clearPendingEvents;
//                  an AIT's pending events are the ones after its last marker
//
// Each append rewrites the file to <kind>.jsonl.tmp and renames it over the
// original, so a crash leaves readers the old or the new complete file, never
// a torn line. A bad line found on read is an error naming the file and line;
// it is never skipped or repaired, so the chain cannot change unnoticed.
//
// The storage itself does not lock. The CLI holds withLock() around a whole
// command (read last hash -> sign -> append), which is what keeps two
// processes from forking a chain.

import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import {
  GENESIS_HASH,
  type AIT,
  type AIT_ID,
  type AttestationBlock,
  type HexHash,
  type WitnessEvent,
  type WitnessStorage,
} from '@tunnelmindai/atap'

interface ClearedMarker {
  ait: AIT_ID
  after: string
}

// ponytail: every read re-parses the whole file. Fine for one run's worth of
// events; add an index (or SQLite) when a store grows past what a CLI call
// can scan in a blink.
async function readText(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8')
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return ''
    throw e
  }
}

function badLine(path: string, n: number, why: string): Error {
  return new Error(`${path}: line ${n} is not valid JSON (${why}); the chain was not changed, inspect or restore the file`)
}

async function readJsonl<T>(path: string): Promise<T[]> {
  const records: T[] = []
  const lines = (await readText(path)).split('\n')
  // Index before skipping blank lines so the reported number matches the file.
  for (const [i, line] of lines.entries()) {
    if (line === '') continue
    try {
      records.push(JSON.parse(line) as T)
    } catch (e) {
      throw badLine(path, i + 1, (e as Error).message)
    }
  }
  return records
}

/** Validators run on every write, before the append (see profile.ts coreGuards). */
export interface WriteGuards {
  ait?: (doc: unknown) => void
  event?: (doc: unknown) => void
  block?: (doc: unknown) => void
}

export class DirStorage implements WitnessStorage {
  // The library signs first and saves second, so a guard that throws here
  // leaves the store untouched: nothing is appended, the command exits non-zero.
  constructor(
    private dir: string,
    private guards: WriteGuards = {},
  ) {}

  private path(kind: string): string {
    return join(this.dir, `${kind}.jsonl`)
  }

  private async append(kind: string, record: unknown): Promise<void> {
    await mkdir(this.dir, { recursive: true })
    const path = this.path(kind)
    const text = await readText(path)
    // Never glue a record onto a torn line; leave the file for an operator.
    if (text !== '' && !text.endsWith('\n')) {
      throw badLine(path, text.split('\n').length, 'torn final line, no trailing newline')
    }
    // ponytail: rewrites the whole file per append (O(n)); switch to an
    // fsync'd append with a length check if stores grow large.
    // fsync before the rename so a power loss cannot leave the renamed file
    // empty. ponytail: the directory is not fsync'd, so the rename itself may
    // roll back to the old file after a power loss; fsync the dir if that matters.
    const fh = await open(`${path}.tmp`, 'w')
    try {
      await fh.writeFile(text + JSON.stringify(record) + '\n')
      await fh.sync()
    } finally {
      await fh.close()
    }
    await rename(`${path}.tmp`, path)
  }

  async eventsOf(aitId: AIT_ID): Promise<WitnessEvent[]> {
    return (await readJsonl<WitnessEvent>(this.path('events'))).filter(e => e.ait === aitId)
  }

  async blocksOf(aitId: AIT_ID): Promise<AttestationBlock[]> {
    return (await readJsonl<AttestationBlock>(this.path('blocks'))).filter(b => b.ait === aitId)
  }

  async saveAit(ait: AIT): Promise<void> {
    this.guards.ait?.(ait)
    await this.append('aits', ait)
  }
  async loadAit(id: AIT_ID): Promise<AIT | null> {
    return (await readJsonl<AIT>(this.path('aits'))).find(a => a.id === id) ?? null
  }
  async hasAitId(id: AIT_ID): Promise<boolean> {
    return (await this.loadAit(id)) !== null
  }
  async saveEvent(event: WitnessEvent): Promise<void> {
    this.guards.event?.(event)
    await this.append('events', event)
  }
  async lastEventHash(aitId: AIT_ID): Promise<HexHash> {
    return (await this.eventsOf(aitId)).at(-1)?.self_hash ?? GENESIS_HASH
  }
  async lastEventAt(aitId: AIT_ID): Promise<string | null> {
    return (await this.eventsOf(aitId)).at(-1)?.witnessed_at ?? null
  }
  async lastBlockHash(aitId: AIT_ID): Promise<HexHash> {
    return (await this.blocksOf(aitId)).at(-1)?.self_hash ?? GENESIS_HASH
  }
  async pendingEvents(aitId: AIT_ID): Promise<WitnessEvent[]> {
    const events = await this.eventsOf(aitId)
    const markers = (await readJsonl<ClearedMarker>(this.path('cleared'))).filter(
      m => m.ait === aitId,
    )
    const after = markers.at(-1)?.after
    if (after === undefined) return events
    return events.slice(events.findIndex(e => e.id === after) + 1)
  }
  async clearPendingEvents(aitId: AIT_ID): Promise<void> {
    const last = (await this.eventsOf(aitId)).at(-1)
    if (last) await this.append('cleared', { ait: aitId, after: last.id })
  }
  async saveBlock(block: AttestationBlock): Promise<void> {
    this.guards.block?.(block)
    await this.append('blocks', block)
  }
  async blocksInPeriod(
    aitId: AIT_ID,
    periodStart: string,
    periodEnd: string,
  ): Promise<AttestationBlock[]> {
    return (await this.blocksOf(aitId)).filter(
      b => b.period_start >= periodStart && b.period_end <= periodEnd,
    )
  }
}

const LOCK_RETRY_MS = 20
const LOCK_TIMEOUT_MS = 30_000

// Exclusive-create lock file: open(..., 'wx') fails with EEXIST while another
// process holds it. Released in finally, so a thrown command still unlocks.
// ponytail: a process killed by SIGKILL leaves the lock behind; the timeout
// error names the file so an operator can remove it. Add pid-liveness checks
// if that ever happens in practice.
export async function withLock<T>(dir: string, fn: () => Promise<T>): Promise<T> {
  await mkdir(dir, { recursive: true })
  const lockPath = join(dir, 'lock')
  const deadline = Date.now() + LOCK_TIMEOUT_MS
  for (;;) {
    try {
      const fh = await open(lockPath, 'wx')
      await fh.writeFile(String(process.pid))
      await fh.close()
      break
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for lock ${lockPath}; remove it if no witness is running`)
      }
      await new Promise(r => setTimeout(r, LOCK_RETRY_MS))
    }
  }
  try {
    return await fn()
  } finally {
    await unlink(lockPath)
  }
}
