/**
 * Regenerates the signed example artifacts for the agent-tools profile (PROFILE
 * below). Run: `node scripts/generate-examples.mjs` from the profile dir.
 * This file is the profile's data; the keypair, clock, signing and writing live
 * in profiles/scripts/example-generator.mjs (one generator since 2026-10-20).
 */
import { generateExamples } from '../../../scripts/example-generator.mjs';

// The one place the profile name lives (it may be renamed before release).
const PROFILE = 'tunnelmind:agent_tools:v1';

await generateExamples(import.meta.url, {
  witnessOAI:  'OAI-2026-0010002', // illustrative witness OAI
  operatorOAI: 'OAI-2026-0010001', // illustrative operator OAI
  start: '2026-10-09T12:00:00Z',
  lifetimeDays: 30,
  ait: {
    agentType: 'agent-tools',
    profile: PROFILE,
    capabilities: ['agent_tools:call_tools', 'agent_tools:call_models', 'agent_tools:handoff', 'agent_tools:ask_human'],
    constraints: {
      allowed_tools: ['web_search', 'mcp:files/read'],
      max_tool_calls_per_session: 100,
    },
    attestationPolicy: {
      witness_granularity: 'per_action',
      block_interval_seconds: 3600,
      receipt_generation: 'on_demand',
    },
  },
  // One of each event type, all `asserted`: the agent's own code reports them.
  // A session starts, the agent calls a tool and a model, hands off to a
  // reviewer agent, and the operator approves the result.
  events: async ({ witness, tick, sha256 }) => [
    await witness('agent_tools:session_started', {
      timestamp: tick(), evidence: 'asserted', agent: 'research-agent', framework: 'langgraph',
      model: 'claude-sonnet-5-5',
    }),
    await witness('agent_tools:tool_called', {
      timestamp: tick(), evidence: 'asserted', tool: 'web_search',
      input_sha256: sha256('{"query":"example"}'), output_sha256: sha256('example result'),
      outcome: 'ok', duration_ms: 420,
    }),
    await witness('agent_tools:model_called', {
      timestamp: tick(), evidence: 'asserted', model: 'claude-sonnet-5-5',
      input_tokens: 1200, output_tokens: 300, duration_ms: 2100, output_sha256: sha256('example answer'),
    }),
    await witness('agent_tools:handoff', {
      timestamp: tick(), evidence: 'asserted', from_agent: 'research-agent', to_agent: 'review-agent',
    }),
    await witness('agent_tools:human_decision', {
      timestamp: tick(), evidence: 'asserted', role: 'operator', decision: 'approve',
      subject_sha256: sha256('example answer'), channel: 'cli',
    }),
  ],
  summary: {
    events: { session_started: 1, tool_called: 1, model_called: 1, handoff: 1, human_decision: 1 },
    tool_outcomes: { ok: 1, error: 0, denied: 0 },
    total_tokens: 1500,
  },
});
