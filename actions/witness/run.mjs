// The witness Action's one step: run the caller's test command under an
// ephemeral did:key witness, write a Receipt and verify it with both
// verifiers. All config comes from env (INPUT_*, RUNNER_TEMP, GITHUB_*), so a
// test can drive main() with a fake env.
//
// Failure policy: the Action never breaks a build. The test command always
// runs and its exit code is the step's; an error in the witnessing itself is a
// ::warning:: and verified=false, and fails the step only with fail-on-error.

import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, mkdtempSync, rmSync } from 'node:fs'
import { constants, tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const CLI = fileURLToPath(new URL('../../packages/atap-cli/dist/cli.js', import.meta.url))
const VERIFY_SH = fileURLToPath(new URL('../../verify.sh', import.meta.url))

const sha256 = s => createHash('sha256').update(s).digest('hex')

// The CLI gets PATH only: no runner secrets, and no ATAP_OFF/ATAP_WITNESS_OAI
// from the caller's env silently changing what gets written.
function cli(cwd, args, input = '') {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, input, encoding: 'utf8', env: { PATH: process.env.PATH } })
  if (r.status !== 0) {
    const reason = (() => { try { return JSON.parse(r.stderr).error } catch { return r.stderr.trim() || r.error?.message } })()
    throw new Error(`atap-witness ${args[0]} failed: ${reason}`)
  }
  return JSON.parse(r.stdout)
}

// Streams the command's output to the job log while hashing it; the hash, not
// the text, is what gets witnessed.
// ponytail: one hash over stdout+stderr in arrival order, so interleaving can
// vary between identical runs; hash each stream apart if anyone compares runs.
function runTest(command, env) {
  return new Promise(resolve => {
    const hash = createHash('sha256')
    const child = spawn('sh', ['-c', command], { env, stdio: ['inherit', 'pipe', 'pipe'] })
    child.stdout.on('data', d => { hash.update(d); process.stdout.write(d) })
    child.stderr.on('data', d => { hash.update(d); process.stderr.write(d) })
    child.on('error', () => resolve({ code: 1, outputSha: hash.digest('hex') }))
    child.on('close', (code, signal) => {
      const sig = signal && constants.signals[signal]
      resolve({ code: code ?? (sig ? 128 + sig : 1), outputSha: hash.digest('hex') })
    })
  })
}

export async function main(env = process.env) {
  const command = env.INPUT_TEST_COMMAND ?? ''
  const shortProfile = env.INPUT_PROFILE || 'code_crew'
  const profile = shortProfile.includes(':') ? shortProfile : `tunnelmind:${shortProfile}:v1`
  let error = null
  let did = ''
  let receiptPath = ''
  let verified = false
  let work, store, ait

  // Each witnessing step is skipped once one has failed; the test is not.
  const step = async fn => {
    if (error) return
    try { await fn() } catch (e) { error = e }
  }

  await step(() => {
    // Under RUNNER_TEMP, never cwd: the key and store must not land in the
    // checkout, and RUNNER_TEMP is wiped when the job ends.
    work = mkdtempSync(join(env.RUNNER_TEMP || tmpdir(), 'atap-witness-'))
    store = join(work, 'store')
    const config = cli(work, ['init', '--dir', store, '--profile', profile])
    did = config.witness_oai
    ait = config.ait
  })
  const flags = () => ['--dir', store, '--key', join(store, 'witness.pem'), '--witness-oai', did, '--ait', ait]
  // ponytail: only code_crew's event shapes; another profile fails its schema
  // check here and lands in the warning path until it gets its own events.
  await step(() => cli(work, ['event', ...flags()], JSON.stringify({
    event_type: 'code_crew:change_committed',
    payload: { timestamp: new Date().toISOString(), evidence: 'anchored', repo: env.GITHUB_REPOSITORY, commit_sha: env.GITHUB_SHA },
  })))

  const test = await runTest(command, env)

  await step(() => {
    cli(work, ['event', ...flags()], JSON.stringify({
      event_type: 'code_crew:verify_run',
      payload: {
        timestamp: new Date().toISOString(),
        evidence: 'witnessed',
        command_sha256: sha256(command),
        exit_code: test.code,
        output_sha256: test.outputSha,
      },
    }))
    // code_crew's summary counts QA verdicts, merges and tokens; a CI run has
    // none of those, so every count is 0.
    cli(work, ['block', ...flags()], JSON.stringify({ tasks_accepted: 0, tasks_rework: 0, merged_changes: 0, tokens: 0, overturns: {} }))
    const out = join(work, 'receipt')
    cli(work, ['receipt', ...flags(), '--out', out])
    // The key's job is done: drop it so nothing more can be signed as this did.
    rmSync(join(store, 'witness.pem'), { force: true })
    receiptPath = out
    const sh = spawnSync('bash', [VERIFY_SH, out], { stdio: 'ignore' }).status === 0
    const js = spawnSync(process.execPath, [CLI, 'verify', out], { stdio: 'ignore', env: { PATH: process.env.PATH } }).status === 0
    console.log(`atap-witness: verify.sh ${sh ? 'PASS' : 'FAIL'}, atap-witness verify ${js ? 'PASS' : 'FAIL'}`)
    verified = sh && js
  })

  if (error) {
    // The message only: CLI errors carry no key material or env values.
    console.log(`::warning::atap-witness: ${error.message.split('\n')[0]}`)
    verified = false
    if (store) rmSync(join(store, 'witness.pem'), { force: true })
  }
  if (env.GITHUB_OUTPUT) {
    try {
      appendFileSync(env.GITHUB_OUTPUT, `receipt-path=${receiptPath}\nverified=${verified}\ndid=${did}\n`)
    } catch (e) {
      console.log(`::warning::atap-witness: cannot write outputs: ${e.message}`)
      error ??= e
    }
  }
  if (error && env.INPUT_FAIL_ON_ERROR === 'true') return test.code || 1
  return test.code
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main()
}
