/**
 * Profile validation — ATAP v0.1 §9.4 acceptance checks (1) and (2).
 *
 *  (1) Every profile schema is valid JSON Schema 2020-12.
 *  (2) The schemas encode the §7.6 no-PII prohibition — proven by the
 *      tests/pii-rejection.json cases, each of which MUST fail validation.
 *
 * Also validates every committed example against both the frozen ATAP v0.1
 * base schemas and the profile schemas, and the ATAP v0.2 fixtures in
 * atap-v0.2-examples/ (did:key witnesses) against the v0.2 base schemas.
 */
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

let failures = 0;
const fail = (msg) => { console.error(`  ✗ ${msg}`); failures++; };
const pass = (msg) => console.log(`  ✓ ${msg}`);

// ── frozen ATAP v0.1 base schemas ────────────────────────────────────────────
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);

// v0.1 and v0.2 schemas carry distinct $ids, so one Ajv instance holds both.
const loadBase = (dir) => {
  const ids = {};
  for (const f of readdirSync(join(root, dir)).filter((x) => x.endsWith('.json'))) {
    const schema = readJson(join(root, dir, f));
    ajv.addSchema(schema);
    ids[f.replace('.schema.json', '')] = schema.$id;
  }
  return ids;
};
const base = loadBase('atap-v0.1-schemas');
const baseV02 = loadBase('atap-v0.2-schemas');

const errs = (v) => ajv.errorsText(v.errors, { separator: '; ' });

// ── per-profile validation ───────────────────────────────────────────────────
const profilesDir = join(root, 'profiles');
for (const profile of readdirSync(profilesDir)) {
  const pdir = join(profilesDir, profile);
  if (!existsSync(join(pdir, 'schemas'))) continue;
  console.log(`\n${profile}`);

  // (1) profile schemas compile as JSON Schema 2020-12
  const schemaDir = join(pdir, 'schemas');
  const compiled = {};
  for (const f of readdirSync(schemaDir).filter((x) => x.endsWith('.json'))) {
    try {
      compiled[f.replace('.schema.json', '')] = ajv.compile(readJson(join(schemaDir, f)));
      pass(`schema ${f} is valid JSON Schema 2020-12`);
    } catch (e) {
      fail(`schema ${f} failed to compile: ${e.message}`);
    }
  }

  const ex = join(pdir, 'examples');
  const validate = (id, doc, label) => {
    const v = ajv.getSchema(id);
    if (!v) return fail(`missing base schema ${id}`);
    v(doc) ? pass(label) : fail(`${label}: ${errs(v)}`);
  };
  const validateProfile = (name, doc, label) => {
    const v = compiled[name];
    if (!v) return fail(`missing profile schema ${name}`);
    v(doc) ? pass(label) : fail(`${label}: ${ajv.errorsText(v.errors, { separator: '; ' })}`);
  };

  // examples vs base + profile schemas
  if (existsSync(join(ex, 'ait.json'))) {
    const ait = readJson(join(ex, 'ait.json'));
    validate(base['ait'], ait, 'example AIT validates against base v0.1 ait schema');
    validateProfile('constraints', ait.constraints, 'example AIT constraints validate against profile schema');
  }
  if (existsSync(join(ex, 'witness-events.json'))) {
    const events = readJson(join(ex, 'witness-events.json'));
    events.forEach((evt, i) => {
      validate(base['witness-event'], evt, `example event[${i}] (${evt.event_type}) validates against base v0.1 schema`);
      validateProfile('witness-events', evt, `example event[${i}] (${evt.event_type}) validates against profile schema`);
    });
  }
  if (existsSync(join(ex, 'attestation-block.json'))) {
    const block = readJson(join(ex, 'attestation-block.json'));
    validate(base['attestation-block'], block, 'example block validates against base v0.1 schema');
    validateProfile('period-summary', block.period_summary, 'example block period_summary validates against profile schema');
  }
  if (existsSync(join(ex, 'receipt.json'))) {
    validate(base['receipt'], readJson(join(ex, 'receipt.json')), 'example receipt validates against base v0.1 schema');
  }
  if (existsSync(join(ex, 'public_keys.json'))) {
    validate(base['keys'], readJson(join(ex, 'public_keys.json')), 'example public_keys validates against base v0.1 schema');
  }

  // (2) PII rejection — every must_reject case fails the profile schema
  const piiPath = join(pdir, 'tests', 'pii-rejection.json');
  if (existsSync(piiPath)) {
    const v = compiled['witness-events'];
    for (const c of readJson(piiPath).must_reject) {
      v(c.event)
        ? fail(`PII case "${c.name}" was ACCEPTED — must be rejected (${c.reason})`)
        : pass(`PII case "${c.name}" correctly rejected (${c.reason})`);
    }
  }
}

// ── ATAP v0.2: did:key witnesses ─────────────────────────────────────────────
// Schema-only: the fixtures are crew-ops v0.1 examples re-labelled 0.2 with a
// did:key witness, so their signatures do not verify (chain checks live in
// @tunnelmindai/atap). The did:key encodes the crew-ops example public key.
console.log('\natap-v0.2');
const v02 = join(root, 'atap-v0.2-examples');
const checkV02 = (schemaName, file) => {
  const v = ajv.getSchema(baseV02[schemaName]);
  v(readJson(join(v02, file)))
    ? pass(`v0.2 example ${file} validates against v0.2 ${schemaName} schema`)
    : fail(`v0.2 example ${file}: ${errs(v)}`);
};
checkV02('ait', 'ait.json');
checkV02('attestation-block', 'attestation-block.json');
checkV02('receipt', 'receipt.json');
checkV02('keys', 'public_keys.json');

const ait02 = readJson(join(v02, 'ait.json'));
const receipt02 = readJson(join(v02, 'receipt.json'));
const keys02 = readJson(join(v02, 'public_keys.json'));
const dk = ait02.witness;
const withKey = (k) => ({ ...keys02, keys: [{ ...keys02.keys[0], ...k }] });
const crewOpsAit = readJson(join(profilesDir, 'tunnelmind-crew-ops-v1', 'examples', 'ait.json'));
// [name, schema $id, document, expect valid?]
const cases = [
  ['did:key receipt claiming tee-tpm', baseV02['receipt'], { ...receipt02, attestation_strength: 'tee-tpm' }, false],
  ['did:key receipt without attestation_strength', baseV02['receipt'], (({ attestation_strength, ...r }) => r)(receipt02), false],
  ['did:key key entry claiming software', baseV02['keys'], withKey({ attestation_strength: 'software' }), false],
  ['did:key with a non-Ed25519 multicodec (z6Mx…)', baseV02['ait'], { ...ait02, witness: dk.replace('z6Mk', 'z6Mx') }, false],
  ['secp256k1 did:key (zQ3s…)', baseV02['ait'], { ...ait02, witness: 'did:key:zQ3shMYdM8Kuh6LHsfSkGi2tUnnX1e4u286ZN1qzm8wcrk3zh' }, false],
  ['did:key AIT declaring ait_version 0.1 vs v0.2 schema', baseV02['ait'], { ...ait02, ait_version: '0.1' }, false],
  ['did:key AIT vs v0.1 schema', base['ait'], { ...ait02, ait_version: '0.1' }, false],
  ['did:key receipt vs v0.1 schema', base['receipt'], receipt02, false],
  ['issued-OAI AIT with ait_version 0.2', baseV02['ait'], { ...crewOpsAit, ait_version: '0.2' }, true],
];
for (const [name, id, doc, ok] of cases) {
  const v = ajv.getSchema(id);
  if (v(doc) === ok) pass(`v0.2 case "${name}" correctly ${ok ? 'accepted' : 'rejected'}`);
  else fail(`v0.2 case "${name}" was ${ok ? 'REJECTED — must be accepted' : 'ACCEPTED — must be rejected'}${ok ? `: ${errs(v)}` : ''}`);
}

console.log(failures === 0 ? '\nAll validation checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
