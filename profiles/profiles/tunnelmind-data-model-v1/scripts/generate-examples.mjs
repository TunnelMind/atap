/**
 * Regenerates the signed example artifacts for the data-model profile (PROFILE
 * below). Run: `node scripts/generate-examples.mjs` from the profile dir.
 * This file is the profile's data; the keypair, clock, signing and writing live
 * in profiles/scripts/example-generator.mjs.
 *
 * The chain is one model lineage's life story: drafted from hashed inputs, its
 * schema pinned, all four gates passed on a fixture, approved by the owner
 * (versions 1-3 of a lineage need it, profile §9), published, an agent's
 * reproducible assessment received, re-run against an independently
 * recomputed answer, confirmed (its question becomes a golden), the field
 * marked degraded, and the version retired because the re-run failed.
 * Every value is illustrative; no fixture contains real network data.
 */
import { writeFileSync } from 'node:fs';
import { canonicalizeBytes, sha256 as sha256Bytes } from '@tunnelmindai/atap';
import { generateExamples } from '../../../scripts/example-generator.mjs';

// The one place the profile name lives (it may be renamed before release).
const PROFILE = 'tunnelmind:data_model:v1';
const MODEL_ID = 'cisco-network';

// The structured query behind the assessment (schemas/query.schema.json) and
// its hash, which the assessment names as query_sha256 — so the example query
// artifact and the event agree byte-for-byte (RFC 8785 canonical bytes).
const QUERY = {
  metric: 'ise.auth_events.failure_rate',
  dimensions: ['ise.auth_events.auth_method'],
  filters: [{ field_ref: 'ise.auth_events.auth_method', op: 'eq', value: 'eap-tls' }],
  time_range: { from: '2026-10-30T00:00:00Z', to: '2026-10-31T00:00:00Z' },
};
// atap's sha256 is 0x-prefixed; profile sha256 fields are bare hex.
const QUERY_SHA256 = sha256Bytes(canonicalizeBytes(QUERY)).slice(2);

await generateExamples(import.meta.url, {
  witnessOAI:  'OAI-2026-0010012', // illustrative — the model registry witness operator OAI
  operatorOAI: 'OAI-2026-0010011', // illustrative — the build crew's operator OAI
  start: '2026-11-03T12:00:00Z',
  lifetimeDays: 365,
  ait: {
    agentType: 'data-model-crew',
    profile: PROFILE,
    // The crew only drafts; every other event is witness-derived (profile §3).
    capabilities: ['data_model:draft'],
    constraints: {
      model_id: MODEL_ID,
      allowed_sources: ['cisco-ise-3.3', 'meraki-dashboard-api-v1', 'meraki-syslog'],
      required_gates: ['compile', 'structural', 'golden', 'reconcile'],
      fixture_policy: 'fixture_then_live',
      max_live_reruns_per_day: 24,
      min_assessor_tier_for_rerun: 'software',
      models: { drafter: 'claude-opus-5-5', reviewer: 'claude-fable-5-1' },
    },
    attestationPolicy: {
      witness_granularity: 'per_action',
      block_interval_seconds: 3600,
      receipt_generation: 'on_demand',
    },
  },
  events: async ({ witness, tick, sha256 }) => {
    const v1 = sha256('cisco-network 0.3.1 (canonical JSON of the Ossie document)');
    // One pin per source the draft used; every gate run names both (profile §9).
    const fpIse = sha256('cisco-ise-3.3 schema fingerprint');
    const fpSyslog = sha256('meraki-syslog schema fingerprint');
    const fingerprints = [
      { source_id: 'cisco-ise-3.3', sha256: fpIse },
      { source_id: 'meraki-syslog', sha256: fpSyslog },
    ];
    const fixture = sha256('synthetic fixture extract 2026-11-03');
    const gate = (g, extra = {}) => witness('data_model:gate_run', {
      timestamp: tick(), evidence: 'witnessed', model_sha256: v1, gate: g,
      phase: 'pre_publish', trigger: 'build', target: 'fixture',
      schema_fingerprints: fingerprints, fixture_sha256: fixture, result: 'pass',
      checks: { total: 40, passed: 40, failed: 0, refused: 0 },
      output_sha256: sha256(`${g} gate output`), ...extra,
    });

    const out = [];
    // format_version '1.0' is illustrative: per profile §9.3 it is pinned to
    // the real Apache Ossie release at implementation.
    out.push(await witness('data_model:drafted', {
      timestamp: tick(), evidence: 'anchored', model_id: MODEL_ID, version: '0.3.1',
      model_sha256: v1, format: 'apache-ossie', format_version: '1.0',
      drafter_model: 'claude-opus-5-5', prompt_sha256: sha256('draft prompt'),
      inputs: [
        { source_id: 'cisco-ise-3.3', kind: 'vendor_api_schema', sha256: sha256('ise openapi') },
        { source_id: 'meraki-syslog', kind: 'vendor_doc', sha256: sha256('meraki syslog reference') },
      ],
    }));
    out.push(await witness('data_model:schema_pinned', {
      timestamp: tick(), evidence: 'witnessed', model_sha256: v1, source_id: 'cisco-ise-3.3',
      source_version: '3.3-patch4', schema_fingerprint_sha256: fpIse,
    }));
    out.push(await witness('data_model:schema_pinned', {
      timestamp: tick(), evidence: 'witnessed', model_sha256: v1, source_id: 'meraki-syslog',
      source_version: 'mx-18.211', schema_fingerprint_sha256: fpSyslog,
    }));
    out.push(await gate('compile'));
    out.push(await gate('structural'));
    out.push(await gate('golden', { golden_source: 'human_sql' }));
    out.push(await gate('reconcile'));
    // 0.3.1 is the lineage's first version, so the owner's approval of this
    // exact model_sha256 must precede `published` (profile §9). Only the
    // text's hash is recorded.
    out.push(await witness('data_model:approved', {
      timestamp: tick(), evidence: 'witnessed', role: 'owner', decision: 'approve',
      model_sha256: v1, approval_text_sha256: sha256('approve model 0.3.1'),
    }));
    out.push(await witness('data_model:published', {
      timestamp: tick(), evidence: 'anchored', model_id: MODEL_ID, version: '0.3.1',
      model_sha256: v1, supersedes_sha256: null,
      coverage: { observed_clean: 31, never_observed: 6, degraded: 0 },
      coverage_sha256: sha256('coverage map 0.3.1'), golden_count: 40,
    }));
    const assessment = await witness('data_model:assessment_received', {
      timestamp: tick(), evidence: 'asserted', model_sha256: v1,
      field_ref: 'ise.auth_events.failure_rate', verdict: 'inaccurate',
      assessor_kind: 'agent', assessor_tier: 'software',
      assessor_nullifier_sha256: sha256('assessor Ed25519 signature over ' + v1),
      evidence_kind: 'reproducible', query_sha256: QUERY_SHA256,
      expected: 0.031, observed: 0,
    });
    out.push(assessment);
    const rerun = await witness('data_model:gate_run', {
      timestamp: tick(), evidence: 'witnessed', model_sha256: v1, gate: 'golden',
      phase: 'post_publish', trigger: 'assessment', target: 'fixture',
      schema_fingerprints: fingerprints, fixture_sha256: fixture,
      golden_source: 'human_sql', result: 'fail',
      checks: { total: 1, passed: 0, failed: 1, refused: 0 },
      output_sha256: sha256('rerun output'),
    });
    out.push(rerun);
    out.push(await witness('data_model:assessment_resolved', {
      timestamp: tick(), evidence: 'witnessed', assessment_event: assessment.id,
      rerun_event: rerun.id, outcome: 'confirmed', golden_added: true,
    }));
    out.push(await witness('data_model:coverage_changed', {
      timestamp: tick(), evidence: 'witnessed', model_sha256: v1,
      field_ref: 'ise.auth_events.failure_rate', from: 'observed_clean', to: 'degraded',
      cause_event: rerun.id,
    }));
    out.push(await witness('data_model:retired', {
      timestamp: tick(), evidence: 'anchored', model_sha256: v1,
      reason: 'failed_rerun', cause_event: rerun.id,
    }));
    return out;
  },
  summary: {
    drafted: 1,
    published: 1,
    retired: 1,
    gate_runs: { pass: 4, fail: 1 },
    coverage_degraded: 1,
    assessments: { received: 1, confirmed: 1, not_reproduced: 0, out_of_scope: 0 },
    golden_added: 1,
  },
  extraFiles: [
    'profile_artifacts/witness_events.json',
    'profile_artifacts/models/',
    'profile_artifacts/golden_questions.json',
    'profile_artifacts/coverage/',
    'profile_artifacts/diffs/',
    'profile_artifacts/queries/',
  ],
});

// Receipt artifacts the generic generator does not write: the query and the
// golden suite (schemas/golden-questions.schema.json). The confirmed
// assessment above re-ran to 0.031, so its query is now a golden question.
const examplesDir = new URL('../examples/', import.meta.url);
const write = (name, obj) => writeFileSync(new URL(name, examplesDir), JSON.stringify(obj, null, 2) + '\n');
write('query.json', QUERY);
write('golden-questions.json', [{
  query_sha256: QUERY_SHA256, query: QUERY,
  golden_source: 'confirmed_assessment', expected: 0.031, tolerance: 0.001,
}]);
