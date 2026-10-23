/**
 * Regenerates the signed example artifacts for the code-crew profile (PROFILE
 * below). Run: `node scripts/generate-examples.mjs` from the profile dir.
 * This file is the profile's data; the keypair, clock, signing and writing live
 * in profiles/scripts/example-generator.mjs (one generator since 2026-10-20).
 */
import { generateExamples } from '../../../scripts/example-generator.mjs';

// The one place the profile name lives (it may be renamed before release).
const PROFILE = 'tunnelmind:code_crew:v1';

// Fake but well-formed git shas.
const COMMIT_SHA = '3f1c2a9e8b7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f';
const MERGE_SHA  = 'a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0';

await generateExamples(import.meta.url, {
  witnessOAI:  'OAI-2026-0010002', // illustrative — the crew witness operator OAI
  operatorOAI: 'OAI-2026-0010001', // illustrative — the code crew's operator OAI
  start: '2026-10-08T12:00:00Z',
  lifetimeDays: 30,
  ait: {
    agentType: 'code-crew',
    profile: PROFILE,
    capabilities: [
      'code_crew:plan', 'code_crew:code', 'code_crew:verify',
      'code_crew:qa_verdict', 'code_crew:review_verdict', 'code_crew:approve',
      'code_crew:merge', 'code_crew:deploy', 'code_crew:revert',
    ],
    constraints: {
      autonomy_class: 'gated',
      allowed_repos: ['example-org/example-repo'],
      max_iterations: 3,
      models: {
        supervisor: 'claude-opus-5-5',
        coder: 'claude-opus-5-5',
        qa: 'claude-sonnet-5-5',
        reviewer: 'claude-opus-5-5',
      },
    },
    attestationPolicy: {
      witness_granularity: 'per_action',
      block_interval_seconds: 3600,
      receipt_generation: 'on_demand',
    },
  },
  events: async ({ witness, tick, sha256 }) => [
    await witness('code_crew:task_claimed', {
      timestamp: tick(), evidence: 'asserted', task_id: 'A101', role: 'coder', model: 'claude-opus-5-5',
    }),
    await witness('code_crew:change_committed', {
      timestamp: tick(), evidence: 'anchored', repo: 'example-org/example-repo', commit_sha: COMMIT_SHA,
    }),
    await witness('code_crew:verify_run', {
      timestamp: tick(), evidence: 'witnessed',
      command_sha256: sha256('npm test'), exit_code: 0, output_sha256: sha256('example test output'),
    }),
    await witness('code_crew:qa_verdict', {
      timestamp: tick(), evidence: 'asserted', task_id: 'A101', verdict: 'accepted', attempt: 1,
    }),
    await witness('code_crew:review_verdict', {
      timestamp: tick(), evidence: 'asserted', head_sha: COMMIT_SHA, verdict: 'pass',
      findings: { critical: 0, high: 0, medium: 1, low: 2 },
    }),
    await witness('code_crew:approval', {
      timestamp: tick(), evidence: 'asserted', role: 'owner', decision: 'approve',
      channel: 'cli', approval_text_sha256: sha256('approve merge'),
    }),
    await witness('code_crew:merged', {
      timestamp: tick(), evidence: 'anchored', repo: 'example-org/example-repo',
      pr_number: 42, merge_commit_sha: MERGE_SHA,
    }),
    await witness('code_crew:deployed', {
      timestamp: tick(), evidence: 'asserted', target: 'staging', version_id: 'v-0001',
    }),
  ],
  summary: {
    tasks_accepted: 1,
    tasks_rework: 0,
    merged_changes: 1,
    tokens: 182000,
    overturns: { supervisor: 0, coder: 0, qa: 0, reviewer: 0 },
  },
});
