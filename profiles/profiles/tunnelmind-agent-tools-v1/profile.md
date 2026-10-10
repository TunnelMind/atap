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
