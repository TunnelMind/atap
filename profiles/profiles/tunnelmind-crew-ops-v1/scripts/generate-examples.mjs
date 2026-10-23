/**
 * Regenerates the signed example artifacts for the crew-ops profile (PROFILE
 * below). Run: `node scripts/generate-examples.mjs` from the profile dir.
 * This file is the profile's data; the keypair, clock, signing and writing live
 * in profiles/scripts/example-generator.mjs (one generator since 2026-10-20).
 */
import { generateExamples } from '../../../scripts/example-generator.mjs';

// The one place the profile name lives (it may be renamed before release).
const PROFILE = 'tunnelmind:crew_ops:v1';

// One of each event type: the rails ask for a grant, the owner ratifies it by
// DKIM-verified mail (anchored), the rails allow the action, and the toolsmith
// routes a thinker idea to a workstream. Then the owner stops the toolsmith by
// DKIM-verified mail (anchored).
const INBOX_PATH = 'specs/toolsmith-inbox/example-idea.md';

await generateExamples(import.meta.url, {
  witnessOAI:  'OAI-2026-0010002', // illustrative — the crew witness operator OAI
  operatorOAI: 'OAI-2026-0010001', // illustrative — the crew's operator OAI
  start: '2026-10-09T12:00:00Z',
  lifetimeDays: 30,
  ait: {
    agentType: 'crew-ops',
    profile: PROFILE,
    capabilities: ['crew_ops:autonomy_decide', 'crew_ops:ratify', 'crew_ops:intake_decide', 'crew_ops:owner_command'],
    constraints: {
      allowed_agents: ['crew-toolsmith', 'crew-curator', 'crew-merchant', 'coordinator'],
      max_class: 2,
    },
    attestationPolicy: {
      witness_granularity: 'per_action',
      block_interval_seconds: 3600,
      receipt_generation: 'on_demand',
    },
  },
  events: async ({ witness, tick, sha256 }) => [
    await witness('crew_ops:autonomy_decision', {
      timestamp: tick(), evidence: 'asserted', agent: 'crew-toolsmith', class: 2,
      action: 'propose', decision: 'request', target_sha256: sha256(INBOX_PATH),
    }),
    await witness('crew_ops:ratification', {
      timestamp: tick(), evidence: 'anchored', role: 'owner', decision: 'approved', channel: 'mail',
      text_sha256: sha256('approve the toolsmith grant'),
      dkim_message_id_sha256: sha256('<example-message-id@example.invalid>'),
    }),
    await witness('crew_ops:autonomy_decision', {
      timestamp: tick(), evidence: 'asserted', agent: 'crew-toolsmith', class: 2,
      action: 'propose', decision: 'allow', target_sha256: sha256(INBOX_PATH),
      reason_sha256: sha256('within grant'),
    }),
    await witness('crew_ops:intake_decision', {
      timestamp: tick(), evidence: 'asserted', by: 'toolsmith', source: 'thinker',
      decision: 'act', title_sha256: sha256('example idea'), route: 'workstream',
    }),
    await witness('crew_ops:owner_command', {
      timestamp: tick(), evidence: 'anchored', role: 'owner', command: 'crew_stop',
      target_sha256: sha256('crew-toolsmith'), channel: 'mail', outcome: 'done',
      message_sha256: sha256('<example-command-id@example.invalid>'),
    }),
  ],
  summary: {
    autonomy_decisions: { allow: 1, refuse: 0, grant: 0, expired: 0, request: 1, approved: 0, rejected: 0 },
    intake_decisions: { act: 1, park: 0, drop: 0 },
    ratifications: 1,
    owner_commands: {
      crew_stop: { done: 1, refused: 0, failed: 0 },
      crew_start: { done: 0, refused: 0, failed: 0 },
      ratify_yes: { done: 0, refused: 0, failed: 0 },
      ratify_no: { done: 0, refused: 0, failed: 0 },
    },
  },
});
