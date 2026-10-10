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

## Framework adapters

Each adapter maps one agent framework's hooks onto `tunnelmind:agent_tools:v1`
events (built by `atap.agent_tools`). Install the framework yourself; atap
adds no dependency. Each adapter imports its framework lazily, so `import
atap` never pulls one in, and a missing framework raises `ImportError` naming
the pip package.

OpenAI Agents SDK (`pip install openai-agents`):

```python
from atap.adapters.openai_agents import AtapRunHooks
result = await Runner.run(agent, input, hooks=AtapRunHooks())
```

LangChain v1 agents, which run on LangGraph (`pip install langchain langgraph`):

```python
from atap.adapters.langgraph import AtapMiddleware
agent = create_agent(model, tools, middleware=[AtapMiddleware()])
```

CrewAI (`pip install crewai`):

```python
from atap.adapters.crewai import AtapListener
AtapListener()  # once, before kickoff: it registers on crewai_event_bus
```

### What is recorded

| Event | OpenAI Agents SDK | LangChain v1 / LangGraph | CrewAI |
|---|---|---|---|
| `session_started` | `on_agent_start` of a run's first agent | `before_agent` (agent id = `AtapMiddleware(name=...)`, default `"agent"`) | `CrewKickoffStartedEvent` (the crew's name) |
| `model_called` | `on_llm_start` + `on_llm_end` | `wrap_model_call` / `awrap_model_call` | `LLMCallStartedEvent` + `LLMCallCompletedEvent` |
| `tool_called` ok / error | `on_tool_start` + `on_tool_end` | `wrap_tool_call` / `awrap_tool_call` | `ToolUsageStartedEvent` + `ToolUsageFinishedEvent` / `ToolUsageErrorEvent`, and `MCPToolExecution*` |
| `handoff` | `on_handoff` | `record_handoff(from_agent, to_agent)` in the handoff tool | `A2ADelegationStartedEvent` |
| `human_decision` | `record_approval(state, item, approved)` in place of `state.approve()`/`state.reject()` | `record_human_decision(role, decision, subject)` where the `Command(resume=...)` value is read | `HumanFeedbackReceivedEvent` (Flows' `@human_feedback`) |

Every event is evidence `asserted`: the adapter is the agent's own code.

### What is never recorded

- Tool arguments, results, prompts, model output and feedback text: only their
  sha256, computed in the adapter's process. The raw values never reach the CLI.
- A person's name. Agent and tool ids are the framework's configured names
  mapped to the identifier pattern; a human decision is recorded by role only.
- Hooks never change what the framework passes or returns. Every hook catches
  its own exceptions and records nothing on failure.
- With [`ATAP_OFF=1` or `atap.off()`](#atap_off) the adapters record nothing.

### Verified against the real SDKs

a11 left four items "not verified". The adapter tests settle them against the
real frameworks with stub models (no network LLM, no API keys):

- **LangChain usage-metadata fields**: tokens come from the AIMessage's
  `usage_metadata["input_tokens"]` / `["output_tokens"]`. langchain 1.4.4 /
  langchain-core 1.6.9 / langgraph 1.2.14, `tests/test_adapter_langgraph.py`.
- **How a tool exception reaches OpenAI Agents hooks**: there is no
  `on_tool_error`. With the default `failure_error_function`, `on_tool_end`
  fires with the SDK's fixed message as `result`, recorded as `"error"`. With a
  custom one, `on_tool_end` gets whatever it returned, recorded as `"ok"` (a
  limit). With `failure_error_function=None`, `on_tool_end` never fires: call
  `hooks.flush()` after `Runner.run` raises to record each unfinished tool as
  `"error"`. openai-agents 0.23.1, `tests/test_adapter_openai_agents.py`.
- **CrewAI duration and token fields**: no LLM event carries a duration, so
  every duration is `end.timestamp - start.timestamp`, the pair matched by the
  end event's `started_event_id`. Tokens come from `LLMCallCompletedEvent.usage`,
  the provider's raw dict: `input_tokens`/`output_tokens` or
  `prompt_tokens`/`completion_tokens`. crewai 1.15.27,
  `tests/test_adapter_crewai.py`.
- **CrewAI in-crew delegation**: it emits no handoff event, only a
  `ToolUsageStarted`/`Finished` pair for the tool "Delegate work to coworker"
  (or "Ask question to coworker"), so it is recorded as `tool_called`, not
  `handoff`. crewai 1.15.27, `tests/test_adapter_crewai.py`.

Still open, or known limits:

- `BaseCallbackHandler`'s method list for plain (non-`create_agent`) LangGraph
  graphs: not checked. The adapter uses only `create_agent` middleware.
- CrewAI A2A, MCP and human feedback were checked with real event objects
  emitted on the bus, not with a live A2A server, MCP server or human.
- CrewAI retries a tool that raises: one `"error"` `tool_called` per attempt.
- LangGraph `session_started` carries no model (`before_agent` is not given one).
- OpenAI Agents: a `RunConfig(model=...)` override is invisible to the LLM
  hooks (the model id comes from `agent.model`); computer and shell tools expose
  no arguments to the hooks, so their `input_sha256` is `sha256("")`.

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
