# ATAP witness Action

A composite GitHub Action that runs a CI test command under an ephemeral
`did:key` witness, writes an ATAP Receipt for the run, and verifies it with
both `verify.sh` and `atap-witness verify`. It is not published to the
Marketplace; use it from a checkout of this repo.

## Usage

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: '22'
  - uses: ./actions/witness          # or <owner>/atap/actions/witness@<ref>
    with:
      test-command: npm test
```

The Action needs Node. It runs from a checkout of the atap repo and, if
`packages/atap-cli/dist/cli.js` is missing, builds `atap-js` and `atap-cli`
there first (`npm ci && npm run build`). A failed build is a warning, not a
failed step. This repo dogfoods it in
[`.github/workflows/atap-witness.yml`](../../.github/workflows/atap-witness.yml).

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `test-command` | (required) | Shell command to run as the test (`sh -c`). |
| `profile` | `code_crew` | ATAP profile short name; `code_crew` means `tunnelmind:code_crew:v1`. |
| `fail-on-error` | `'false'` | When `true`, an error inside the Action itself fails the step. |
| `upload` | `'true'` | Upload the Receipt dir + zip as the workflow artifact `atap-receipt`. |

### Outputs

| Output | Meaning |
|---|---|
| `receipt-path` | The Receipt directory; the zip sits beside it as `<dir>.zip`. Empty if witnessing failed. |
| `verified` | `true` when both `verify.sh` and `atap-witness verify` pass. |
| `did` | The ephemeral `did:key` that witnessed the run. |

## What is witnessed, and what is not

Witnessed, signed and hash-chained:

- a `code_crew:change_committed` event: repo, commit SHA, `evidence: anchored`;
- a `code_crew:verify_run` event: sha256 of the command, its exit code, and
  sha256 of the combined stdout+stderr; `evidence: witnessed`;
- one attestation block (all counts 0: a CI run has no QA verdicts, merges or
  tokens);
- the Receipt that bundles them.

Not witnessed:

- the command text or its output (only their hashes; the output still goes to
  the job log as usual);
- which tests ran or what they covered;
- the runner or its environment (the CLI is given `PATH` only, no secrets);
- the code's content or correctness.

The Action never changes the test's pass/fail. The step's exit code is the
test's. An error in the witnessing itself is a `::warning::` with
`verified=false`, and fails the step only with `fail-on-error: true`.

Only the `code_crew` profile's event shapes are supported; another profile
fails its schema check and takes the warning path.

## How strong is the Receipt?

Not very, and on purpose. The `did:key` is generated fresh for each run and
its private key is deleted once the Receipt is written. It is self-asserted
(the ATAP-v0.2 did:key rule, `attestation_strength=self-asserted`): it proves
integrity (the Receipt was not altered after it was signed), not identity, and
not that the runner was honest. Anyone who can run the workflow can mint an
equivalent Receipt.

## Verifying a downloaded Receipt offline

Download the `atap-receipt` artifact from the run page. The Actions UI gives
you `atap-receipt.zip`; unzipped, it holds the Receipt directory `receipt/`
and the same Receipt zipped as `receipt.zip`.

```bash
unzip atap-receipt.zip -d atap-receipt/
# from a checkout of the atap repo:
bash verify.sh atap-receipt/receipt
# ==> Receipt verifies (blocks=1, attestation_strength=self-asserted)
node packages/atap-cli/dist/cli.js verify atap-receipt/receipt
```

`receipt.zip` unpacks to the same files, and the Receipt carries its own copy
of `verify.sh`. Requirements for `verify.sh`: bash, openssl, jq, python3. The
CLI needs Node and a built `packages/atap-cli/dist`.
