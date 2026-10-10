# atap (Python)

A thin Python client of [`atap-witness`](../atap-cli/): record an agent's work
in the project's `.atap/` store. Every call is one `atap-witness` subprocess
with JSON on stdin and stdout and an 8 second timeout. There is no crypto in
this package; the CLI holds the one implementation of the rules.

## Install

From a source checkout of this repo (Python 3.10+). The package is `atap`,
version 0.1.0, with no dependencies. It is not on PyPI.

```bash
pip install -e packages/atap-py
```

It needs `atap-witness`: build [`packages/atap-cli`](../atap-cli/) per its
README, then put it on your PATH or point `ATAP_WITNESS` at it. Only your
environment chooses the binary, never the project's `.atap/config.json`.

`atap.verify()` also runs [`verify.sh`](../../verify.sh): the package ships
its own copy (`src/atap/verify.sh`), and `ATAP_VERIFY_SH` overrides it. It
never runs a `verify.sh` found in the working directory, a parent directory or
the receipt itself.

## Quickstart

In a git repo with at least one commit, after `atap-witness init`:

```python
import atap
from atap import code

with atap.session():  # closes a block on a clean exit
    code.task_claimed("A101", "coder", "claude-opus-5-5")
    code.change_committed()  # HEAD of the repo at cwd="."
    code.run_tests("python3 -c 'print(42)'")  # or verify_run(command, exit_code, output)
    code.qa_verdict("A101", "accepted", 1)
    code.review_verdict("0" * 40, "pass", {"critical": 0, "high": 0, "medium": 0, "low": 0})
atap.receipt("receipt")
print(atap.verify("receipt"))  # {'ok': True, 'cli': True, 'verify_sh': True}
```

Without `session()`, call `atap.block()` yourself to close a block over the
pending events.

| Call | Returns |
|---|---|
| `atap.event(type, payload)` | The signed Witness Event, or `None` |
| `atap.block(summary=None)` | The Attestation Block, or `None` |
| `atap.receipt(out)` | The Receipt written to directory `out`, or `None` |
| `atap.verify(dir)` | `{"ok", "cli", "verify_sh"}`: the Receipt checked by both `atap-witness verify` and `verify.sh` |
| `atap.session(summary=None)` | Context manager: `block(summary)` on a clean exit; an exception propagates and closes no block |
| `atap.find_store(start=".")` | The nearest `.atap/` at or above `start`, or `None` |
| `atap.off()` | Stops recording for the rest of the process |
| `code.task_claimed(task_id, role, model)` | `role` is one of supervisor, coder, qa, reviewer, coordinator |
| `code.change_committed(cwd=".")` | Records HEAD; the repo is `owner/repo` from `origin`, else `local/<first 12 hex of the root commit>` |
| `code.verify_run(command, exit_code, output)` | Records a test/verify run |
| `code.run_tests(command, cwd=".")` | Runs `command` (a list as-is, a str under `sh -c`), streams its output, records a `verify_run` |
| `code.qa_verdict(task_id, verdict, attempt)` | `verdict` is accepted or rework; `attempt` >= 1 |
| `code.review_verdict(head_sha, verdict, findings)` | `verdict` is pass or fail; `findings` has exactly critical/high/medium/low counts |

## What is recorded, and what isn't

- The five `code.*` helpers record `tunnelmind:code_crew:v1` events and send
  only the keys the profile's schema
  ([`witness-events.schema.json`](../../profiles/profiles/tunnelmind-code-crew-v1/schemas/witness-events.schema.json))
  requires. Each checks its inputs against that schema's patterns first and
  returns `None` on a refusal, so a bad input never reaches the CLI.
- Command text and output travel only as sha256. `run_tests` records the
  command's exit code and a hash of its output, and returns the child's exit
  code unchanged (negative when killed by a signal; 127 when it can't start).
- `change_committed` is `anchored` evidence (the sha is checkable in the
  repo); the others are `asserted`.
- `block()` with no summary closes with the zero summary
  (`tasks_accepted`, `tasks_rework`, `merged_changes`, `tokens` all 0,
  `overturns` empty): this client sees no QA verdicts, merges or tokens, so it
  reports zeros rather than a guess.

## Never breaks the caller

`event`, `block`, `receipt` and the `code.*` record helpers return `None` on
any failure; `run_tests` still returns the child's exit code. A failed
`atap-witness` call appends one fixed-text line to `.atap/hook.log`; nothing
you passed is written there. The log stops growing at 1 MB. Without a `.atap/`
at or above the working directory they are silent no-ops.

### ATAP_OFF

`ATAP_OFF=1` in the environment, or `atap.off()` in the process, makes them
silent no-ops. `verify()` is the one call that reports failure, by its return
value; it never raises.
