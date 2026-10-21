/**
 * Regenerates the signed example artifacts for the sigil:media_buyer:v1
 * profile. Run: `node scripts/generate-examples.mjs` from the profile dir.
 * This file is the profile's data; the keypair, clock, signing and writing live
 * in profiles/scripts/example-generator.mjs (one generator since 2026-10-20).
 */
import { generateExamples } from '../../../scripts/example-generator.mjs';

const SIGIL_TOKEN = 'eyJhbGciOiJFZERTQSJ9.example-payload.example-signature';

const supplyPath = {
  publisher_domain: 'news.example',
  exchange_domain: 'exchange-a.example',
  seller_id: 'pub-12345',
};

await generateExamples(import.meta.url, {
  witnessOAI:  'OAI-2026-0009002', // illustrative — Sigil's witness operator OAI
  operatorOAI: 'OAI-2026-0009001', // illustrative — the media-buyer's operator OAI
  start: '2026-05-16T12:00:00Z',
  lifetimeDays: 60,
  ait: {
    agentType: 'media-buyer',
    profile: 'sigil:media_buyer:v1',
    capabilities: [
      'bid:submit', 'bid:read_response', 'supply:verify_via_sigil',
      'budget:read', 'budget:decrement', 'creative:select',
      'report:generate', 'report:export_receipt',
    ],
    constraints: {
      currency: 'USD',
      max_bid_cpm: 50,
      supply_trust_minimum: 0.7,
      budget_total_cap: 150000,
      budget_daily_cap: 10000,
      allowed_channels: ['display', 'video', 'ctv', 'audio'],
      blocked_categories: ['IAB25-3', 'IAB26'],
      geo_targeting: { allowed_countries: ['US', 'CA'] },
    },
    attestationPolicy: {
      witness_granularity: 'per_bid',
      block_interval_seconds: 300,
      receipt_generation: 'on_demand',
    },
  },
  events: async ({ witness, tick }) => [
    await witness('supply:verified', {
      timestamp: tick(), supply_path: supplyPath,
      sigil_result: 'pass', trust_score: 0.86, sigil_token: SIGIL_TOKEN,
    }),
    await witness('bid:submitted', {
      timestamp: tick(), exchange: 'exchange-a.example', publisher_domain: 'news.example',
      seller_id: 'pub-12345', bid_amount: 3.2, currency: 'USD', creative_id: 'cr-0001',
      channel: 'display', sigil_token: SIGIL_TOKEN, supply_trust_score: 0.86,
    }),
    await witness('bid:won', {
      timestamp: tick(), exchange: 'exchange-a.example',
      clearing_price: 2.8, currency: 'USD', impression_id: 'imp-77001',
    }),
    await witness('budget:decremented', {
      timestamp: tick(), amount: 2.8, currency: 'USD',
      remaining_daily: 9997.2, remaining_total: 149997.2,
    }),
    await witness('supply:rejected', {
      timestamp: tick(),
      supply_path: {
        publisher_domain: 'spoofed.example',
        exchange_domain: 'exchange-b.example',
        seller_id: 'reseller-998',
      },
      sigil_result: 'fail', rejection_reason: 'datacenter IP and ads.txt mismatch',
      trust_score: 0.31,
    }),
    await witness('bid:lost', {
      timestamp: tick(), exchange: 'exchange-a.example', reason: 'outbid',
    }),
    await witness('constraint:violated', {
      timestamp: tick(), constraint_name: 'max_bid_cpm',
      declared_value: 50, actual_value: 62,
    }),
  ],
  summary: {
    bids_submitted: 1,
    bids_won: 1,
    total_spend: 2.8,
    currency: 'USD',
    unique_publishers: 1,
    unique_exchanges: 2,
    supply_verifications: 1,
    supply_rejections: 1,
    average_trust_score: 0.585,
    constraint_violations: 1,
    channels_used: ['display'],
    geos_reached: ['US'],
  },
  extraFiles: ['profile_artifacts/sigil_tokens.json'],
});
