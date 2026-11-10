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
// a test file's case list; a missing or non-array key is a failure line, not
// a TypeError that kills the run before the other profiles are checked
const caseList = (doc, key, file) => {
  if (Array.isArray(doc?.[key])) return doc[key];
  fail(`${file}: "${key}" missing or not an array`);
  return [];
};
const pass = (msg) => console.log(`  ✓ ${msg}`);

// judge one must_accept / must_reject case → [ok, line]. A case with no input
// is a failure: v(undefined) fails every schema, so without this guard a
// must_reject case missing its doc/event would read "correctly rejected"
// having tested nothing.
const judge = (kind, c, v, input, field, mustAccept) => {
  if (input === undefined) return [false, `${kind} case "${c.name}" has no ${field}`];
  if (v(input) === mustAccept) {
    return [true, `${kind} case "${c.name}" correctly ${mustAccept ? 'accepted' : `rejected (${c.reason})`}`];
  }
  return [false, mustAccept
    ? `${kind} case "${c.name}" was REJECTED — must be accepted: ${errs(v)}`
    : `${kind} case "${c.name}" was ACCEPTED — must be rejected (${c.reason})`];
};
const report = ([ok, line]) => (ok ? pass(line) : fail(line));

// approval-chain rule (data-model profile §9): for every data_model:published
// event, the LAST data_model:approved event before it with the same
// model_sha256 must say `approve`. ponytail: every published event is treated
// as one of the lineage's first three versions — the cases only publish first
// versions.
const approvedOk = (events) => events.every((e, i) => e.event_type !== 'data_model:published'
  || events.slice(0, i).filter((a) => a.event_type === 'data_model:approved'
    && a.payload.model_sha256 === e.payload.model_sha256).at(-1)?.payload.decision === 'approve');
// judge one approval-chain case → [ok, line]. A case with no events array is a
// failure line (not a TypeError), and a must_pass chain with no published
// event is a failure: `every` over nothing to check would pass having tested
// nothing. (A must_fail chain with no published event already fails: it
// passes the rule vacuously, so it reads "PASSED — must fail".)
const judgeChain = (c, v, want) => {
  if (!Array.isArray(c.events)) return [false, `approval chain "${c.name}" has no events array`];
  if (want && !c.events.some((e) => e?.event_type === 'data_model:published')) {
    return [false, `approval chain "${c.name}": must_pass chain has no data_model:published event`];
  }
  const bad = c.events.findIndex((e) => !v(e));
  if (bad >= 0) return [false, `approval chain "${c.name}" event[${bad}] fails the profile schema: ${errs(v)}`];
  return approvedOk(c.events) === want
    ? [true, `approval chain "${c.name}" correctly ${want ? 'passes' : `fails (${c.reason})`}`]
    : [false, `approval chain "${c.name}" ${want ? 'FAILED — must pass' : `PASSED — must fail (${c.reason})`}`];
};

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

// resolve one added profile schema → [ok, line, validator]. A schema with no
// $id is added under no key, so getSchema(undefined) returns undefined; without
// this guard the loop printed "valid" and stored an undefined validator.
const resolveSchema = (f, id) => {
  const v = id === undefined ? undefined : ajv.getSchema(id);
  return v ? [true, `schema ${f} is valid JSON Schema 2020-12`, v]
    : [false, `schema ${f} has no $id / could not be resolved`];
};
// self-test: a schema with no $id is a reported failure, not "valid"
resolveSchema('self-test.schema.json', undefined)[0]
  ? fail('self-test: a schema with no $id was reported as valid')
  : pass('self-test: a schema with no $id is a reported failure');

// self-test: a malformed must_reject case (no doc, no event) against a schema
// that rejects everything must come back as a failure, not "correctly rejected"
{
  const [ok] = judge('self-test', { name: 'no input', reason: 'malformed' }, () => false, undefined, 'doc or event', false);
  ok ? fail('self-test: a case with no doc/event was reported as passing')
    : pass('self-test: a case with no doc/event is a reported failure');
}
// self-test: malformed approval chains (no events array; a must_pass chain
// with no published event) are reported failures, never a throw or a pass
{
  const accept = () => true;
  const okNoArray = judgeChain({ name: 'no events' }, accept, true)[0];
  const okNoPub = judgeChain({ name: 'no published', events: [{ event_type: 'data_model:approved', payload: {} }] }, accept, true)[0];
  okNoArray || okNoPub
    ? fail('self-test: a malformed approval chain was reported as passing')
    : pass('self-test: a malformed approval chain is a reported failure');
}

// ── per-profile validation ───────────────────────────────────────────────────
const profilesDir = join(root, 'profiles');
for (const profile of readdirSync(profilesDir)) {
  const pdir = join(profilesDir, profile);
  if (!existsSync(join(pdir, 'schemas'))) continue;
  console.log(`\n${profile}`);

  // (1) profile schemas compile as JSON Schema 2020-12
  const schemaDir = join(pdir, 'schemas');
  // Two passes: register every schema first so one may $ref a sibling by
  // relative $id (golden-questions → query) regardless of file order.
  const compiled = {};
  const files = readdirSync(schemaDir).filter((x) => x.endsWith('.json'));
  const added = [];
  for (const f of files) {
    try {
      const schema = readJson(join(schemaDir, f));
      ajv.addSchema(schema);
      added.push([f, schema.$id]);
    } catch (e) {
      fail(`schema ${f} failed to compile: ${e.message}`);
    }
  }
  for (const [f, id] of added) {
    try {
      const [ok, line, v] = resolveSchema(f, id);
      if (ok) compiled[f.replace('.schema.json', '')] = v;
      report([ok, line]);
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
  // receipt artifacts with their own profile schema (data-model: query and
  // golden suite); the example file is named after the schema
  for (const name of ['query', 'golden-questions']) {
    if (compiled[name] && existsSync(join(ex, `${name}.json`))) {
      validateProfile(name, readJson(join(ex, `${name}.json`)), `example ${name}.json validates against profile schema`);
    }
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
    // a case names its schema (default witness-events) and carries `doc`
    // instead of `event` when it is not a Witness Event
    for (const c of caseList(readJson(piiPath), 'must_reject', piiPath)) {
      const v = compiled[c.schema || 'witness-events'];
      if (!v) { fail(`PII case "${c.name}" names missing schema ${c.schema}`); continue; }
      report(judge('PII', c, v, c.doc ?? c.event, 'doc or event', false));
    }
    // optional must_accept: ordinary values a PII heuristic must leave alone
    // (data-model: the query filter-value address/key pattern)
    const pii = readJson(piiPath);
    for (const c of pii.must_accept ? caseList(pii, 'must_accept', piiPath) : []) {
      const v = compiled[c.schema || 'witness-events'];
      if (!v) { fail(`PII case "${c.name}" names missing schema ${c.schema}`); continue; }
      report(judge('PII', c, v, c.doc ?? c.event, 'doc or event', true));
    }
  }

  // approval chains (data-model profile §9): multi-event cases for the
  // latest-event rule, which no single-event schema can express; the rule is
  // approvedOk / judgeChain above.
  const chainsPath = join(pdir, 'tests', 'approval-chains.json');
  if (existsSync(chainsPath)) {
    const v = compiled['witness-events'];
    const chains = readJson(chainsPath);
    for (const [key, want] of [['must_pass', true], ['must_fail', false]]) {
      for (const c of caseList(chains, key, chainsPath)) {
        report(judgeChain(c, v, want));
      }
    }
  }

  // payload-shape cases (e.g. code_crew:merged PR vs local, data_model gate
  // rules): every tests/*-shapes.json file — must_accept validates,
  // must_reject fails the profile schema
  const testsDir = join(pdir, 'tests');
  const shapeFiles = existsSync(testsDir)
    ? readdirSync(testsDir).filter((f) => f.endsWith('-shapes.json')).sort()
    : [];
  for (const shapeFile of shapeFiles) {
    const v = compiled['witness-events'];
    const shapes = readJson(join(testsDir, shapeFile));
    for (const c of caseList(shapes, 'must_accept', shapeFile)) {
      report(judge('shape', c, v, c.event, 'event', true));
    }
    for (const c of caseList(shapes, 'must_reject', shapeFile)) {
      report(judge('shape', c, v, c.event, 'event', false));
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
