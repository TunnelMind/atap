# `tunnelmind:agent_tools:v1` — ATAP application profile

| | |
|---|---|
| **Profile identifier** | `tunnelmind:agent_tools:v1` |
| **ATAP version** | 0.1 |
| **Domain** | Any agent's tool calls, model calls, handoffs and human decisions |
| **Maintainer** | TunnelMind |
| **Status** | Draft profile |
| **Standard** | <https://tunnelmind.ai/atap/standard> |

Capabilities: [`capabilities.json`](capabilities.json). Constraints:
[`schemas/constraints.schema.json`](schemas/constraints.schema.json). Event types:
[`schemas/witness-events.schema.json`](schemas/witness-events.schema.json). Period summary:
[`schemas/period-summary.schema.json`](schemas/period-summary.schema.json).

Every payload requires `timestamp` and `evidence` and sets `additionalProperties: false`.
Names are identifiers (`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$`); prompts, tool arguments,
tool results and model outputs appear only as sha256; humans appear by role only. An
event the agent's own code reports is `asserted`; `witnessed` is only for an event a
separate process observed.

## 1. Purpose

Any agent, whatever framework it runs on, calls tools, calls models, hands work
to other agents and asks humans to decide. This profile gives those five things
an ATAP vocabulary, so an agent's record of them is signed and hash-chained
instead of living in its own log. It records that a call happened and how it
ended, never what was said.

## 2. Capabilities

An AIT's `capabilities` MUST draw only from [`capabilities.json`](capabilities.json):

| Capability | Meaning |
|---|---|
| `agent_tools:call_tools` | Call tools (functions, MCP tools, APIs); inputs and outputs recorded as sha256 only. |
| `agent_tools:call_models` | Call models; token counts and duration recorded, output as sha256 only. |
| `agent_tools:handoff` | Hand work from one agent to another. |
| `agent_tools:ask_human` | Ask a human, recorded by role only, to approve, reject or edit something. |

The optional AIT `constraints` are `allowed_tools` (up to 50 tool identifiers)
and `max_tool_calls_per_session` (integer), validated by
[`schemas/constraints.schema.json`](schemas/constraints.schema.json).

## 3. Events

A Witness Event MUST validate against both the ATAP v0.1 base `witness-event`
schema and [`schemas/witness-events.schema.json`](schemas/witness-events.schema.json).
Every payload requires `timestamp` (date-time) and `evidence` (§5) and sets
`additionalProperties: false`. Agent, framework, model, tool and channel names
are identifiers matching `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$`.

### `agent_tools:session_started`

An agent began a session (one run, one conversation).
Fields: `agent`, `framework` (e.g. `langgraph`, `openai-agents`, `crewai`,
`custom`); optional `model`.

### `agent_tools:tool_called`

The agent called a tool and the call finished.
Fields: `tool`, `input_sha256` (sha256 of the arguments), `outcome`
(`ok` | `error` | `denied`), `duration_ms`; optional `output_sha256` (sha256 of
the result, absent when the call errored or was denied).

### `agent_tools:model_called`

The agent called a model and got an answer.
Fields: `model`, `duration_ms`, `output_sha256` (sha256 of the output); optional
`input_tokens`, `output_tokens`.

### `agent_tools:handoff`

One agent handed the work to another.
Fields: `from_agent`, `to_agent`.

### `agent_tools:human_decision`

A human decided on something the agent asked about.
Fields: `role` (`owner` | `operator` | `user`), `decision`
(`approve` | `reject` | `edit`), `subject_sha256` (sha256 of what was decided
on); optional `channel`.

### Period summary

An Attestation Block's `period_summary` is validated by
[`schemas/period-summary.schema.json`](schemas/period-summary.schema.json) and
holds integers only: `events` (a count per event type), `tool_outcomes`
(`tool_called` count per `ok` / `error` / `denied`) and `total_tokens` (sum of
`input_tokens` and `output_tokens` where reported).

## 4. What is never recorded

ATAP v0.1 §7.6 forbids any person-resolvable field in a payload or summary.
Under this profile these never appear, only their sha256 or nothing:

- prompts and model outputs (`output_sha256` only);
- tool arguments and tool results (`input_sha256`, `output_sha256` only);
- the subject of a human decision (`subject_sha256` only);
- the human: a decision records the role, never the person;
- free text, names and emails: no payload has a free-text key, and identifiers
  admit no spaces or `@`.

[`tests/pii-rejection.json`](tests/pii-rejection.json) is the §9.4(2) evidence:
19 events, each smuggling a name, email, phone number, sentence or raw prompt
into an otherwise valid payload; CI confirms every one is rejected.

## 5. Evidence tiers

Each event's `evidence` says how far a verifier can rely on it:

| Tier | Meaning |
|---|---|
| `asserted` | The agent says so. Every event the agent's own code reports. |
| `anchored` | Bound to something a verifier can look up. |
| `witnessed` | A separate process (a proxy, a gateway) observed it, not the agent. |

An adapter that runs inside the agent's process — a callback, a hook, a
middleware — is the agent's own code, so it can only claim `asserted`.
`witnessed` needs an observer the agent does not control.

## 6. Changelog

- **v1 (2026-10-09)** — initial draft profile.
