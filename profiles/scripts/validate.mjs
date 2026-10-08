/**
 * Profile validation — ATAP v0.1 §9.4 acceptance checks (1) and (2).
 *
 *  (1) Every profile schema is valid JSON Schema 2020-12.
 *  (2) The schemas encode the §7.6 no-PII prohibition — proven by the
 *      tests/pii-rejection.json cases, each of which MUST fail validation.
 *
 * Also validates every committed example against both the frozen ATAP v0.1
 * base schemas and the profile schemas.
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

const baseDir = join(root, 'atap-v0.1-schemas');
const base = {};
for (const f of readdirSync(baseDir).filter((x) => x.endsWith('.json'))) {
  const schema = readJson(join(baseDir, f));
  ajv.addSchema(schema);
  base[f.replace('.schema.json', '')] = schema.$id;
}

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
    validate(base['ait'], ait, 'example AIT validates against base ait schema');
    validateProfile('constraints', ait.constraints, 'example AIT constraints validate against profile schema');
  }
  if (existsSync(join(ex, 'witness-events.json'))) {
    const events = readJson(join(ex, 'witness-events.json'));
    events.forEach((evt, i) => {
      validate(base['witness-event'], evt, `example event[${i}] (${evt.event_type}) validates against base schema`);
      validateProfile('witness-events', evt, `example event[${i}] (${evt.event_type}) validates against profile schema`);
    });
  }
  if (existsSync(join(ex, 'attestation-block.json'))) {
    const block = readJson(join(ex, 'attestation-block.json'));
    validate(base['attestation-block'], block, 'example block validates against base schema');
    validateProfile('period-summary', block.period_summary, 'example block period_summary validates against profile schema');
  }
  if (existsSync(join(ex, 'receipt.json'))) {
    validate(base['receipt'], readJson(join(ex, 'receipt.json')), 'example receipt validates against base schema');
  }
  if (existsSync(join(ex, 'public_keys.json'))) {
    validate(base['keys'], readJson(join(ex, 'public_keys.json')), 'example public_keys validates against base schema');
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

console.log(failures === 0 ? '\nAll validation checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
