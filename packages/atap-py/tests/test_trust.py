"""Which verify.sh runs and which store records: only the package's own
verify.sh (or ATAP_VERIFY_SH), and the store of the repo change_committed was
pointed at. Run from packages/atap-py: python3 -m unittest discover -s tests"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import test_core

import atap  # noqa: E402  (test_core puts src/ on sys.path)
import atap.code  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGED = Path(atap.__file__).with_name("verify.sh")
ATAP_JS = REPO_ROOT / "packages/atap-js/dist/index.js"
CLI = REPO_ROOT / "packages/atap-cli/dist/cli.js"

# An OAI receipt dir, as atap-witness receipt lays it out, whose one key is
# argv[3] ('active' or 'compromised', disclosed an hour after the AIT's
# issued_at, so every signer-written time is before the disclosure).
RECEIPT_JS = """
import { WitnessService, InMemoryStorage, toHex, sha256 } from '%s'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const [dir, verifySh, status] = process.argv.slice(1)
const { privateKey } = generateKeyPairSync('ed25519')
const svc = new WitnessService({ witnessOAI: 'OAI-2026-0010002', privateKey, storage: new InMemoryStorage() })
const ait = await svc.declareAit({ agentType: 'crew-ops', profile: 'tunnelmind:crew_ops:v1', operator: 'OAI-2026-0010002',
  capabilities: ['crew_ops:ratify'], expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString(),
  attestationPolicy: { witness_granularity: 'per_action', block_interval_seconds: 3600, receipt_generation: 'on_demand' } })
await svc.witness(ait.id, 'crew_ops:ratify', { n: 1 })
const block = await svc.rollUp(ait.id, { ratifications: 1 })
const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
const disclosed_at = new Date(Date.parse(ait.issued_at) + 3600_000).toISOString()
const key = { witness: ait.witness, key_id: 'k1', algorithm: 'ed25519', public_key: '0x' + toHex(new Uint8Array(der.subarray(der.length - 32))),
  valid_from: '2000-01-01T00:00:00Z', valid_until: '2100-01-01T00:00:00Z', status, attestation_strength: 'self-asserted', rotated_to: null,
  compromise_notice: status === 'compromised' ? { disclosed_at, detected_at: disclosed_at } : null }
const bodies = { 'ait.json': JSON.stringify(ait), 'attestation_chain.json': JSON.stringify([block]),
  'public_keys.json': JSON.stringify({ keys: [key], updated_at: new Date().toISOString() }), 'verify.sh': readFileSync(verifySh) }
for (const [f, b] of Object.entries(bodies)) writeFileSync(join(dir, f), b)
const files = [{ path: 'manifest.json', sha256: null }, ...Object.entries(bodies).map(([path, b]) => ({ path, sha256: sha256(Buffer.from(b)) }))]
writeFileSync(join(dir, 'manifest.json'), JSON.stringify(await svc.generateReceipt(ait.id, block.period_start, block.period_end, 'full', files)))
""" % ATAP_JS.as_uri()


class TrustTest(unittest.TestCase):
    # test_core's fixture: a store at self.root, the stub on ATAP_WITNESS,
    # cwd self.root/a/b, environment restored on tearDown.
    setUp = test_core.CoreTest.setUp
    tearDown = test_core.CoreTest.tearDown
    recorded = test_core.CoreTest.recorded

    def test_packaged_verify_sh_is_the_repo_copy(self):
        self.assertEqual(PACKAGED.read_bytes(), (REPO_ROOT / "verify.sh").read_bytes())
        os.environ.pop("ATAP_VERIFY_SH", None)
        self.assertEqual(atap._verify_sh(), str(PACKAGED))

    def test_hostile_verify_sh_never_runs(self):
        os.environ.pop("ATAP_VERIFY_SH", None)
        receipt = Path.cwd() / "r"
        receipt.mkdir()
        # cwd, its parents (also the receipt dir's parents) and the receipt dir.
        dirs = [Path.cwd(), self.root / "a", self.root, receipt]
        for i, d in enumerate(dirs):
            (d / "verify.sh").write_text(f"#!/bin/sh\ntouch {self.root / f'MARK{i}'}\nexit 0\n")
            (d / "verify.sh").chmod(0o755)
        result = atap.verify(receipt)
        self.assertTrue(result["cli"])
        for i in range(len(dirs)):
            self.assertFalse((self.root / f"MARK{i}").exists(), dirs[i])

    def test_change_committed_records_to_its_own_repos_store(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t).resolve()
            env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
            for name in ("A", "B", "C"):
                (t / name).mkdir()
                for args in (["git", "init", "-q"],
                             ["git", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "root"]):
                    subprocess.run(args, cwd=t / name, env=env, check=True, capture_output=True)
            for name in ("A", "B"):  # C has no store
                (t / name / ".atap").mkdir()
                (t / name / ".atap" / "config.json").write_text("{}")
            os.chdir(t / "A")
            self.assertEqual(atap.code.change_committed(cwd=t / "B"), {"ok": True})
            [c] = self.recorded()
            self.assertEqual(c["cwd"], str(t / "B"))
            self.assertEqual(json.loads(c["stdin"])["event_type"], "code_crew:change_committed")
            self.assertIsNone(atap.code.change_committed(cwd=t / "C"))
            self.assertEqual(len(self.recorded()), 1)


    def test_run_tests_records_to_the_store_of_its_cwd(self):
        # coordinator 2026-10-09 (review low): the same rule as change_committed
        with tempfile.TemporaryDirectory() as t:
            t = Path(t).resolve()
            for name in ("A", "B"):
                (t / name / ".atap").mkdir(parents=True)
                (t / name / ".atap" / "config.json").write_text("{}")
            os.chdir(t / "A")
            self.assertEqual(atap.code.run_tests(["true"], cwd=t / "B"), 0)
            [c] = self.recorded()
            self.assertEqual(c["cwd"], str(t / "B"))
            self.assertEqual(json.loads(c["stdin"])["event_type"], "code_crew:verify_run")

    def test_run_tests_survives_no_stdout(self):
        # a daemonized agent has sys.stdout None; run_tests must still run and record
        import sys
        saved = sys.stdout
        try:
            sys.stdout = None
            self.assertEqual(atap.code.run_tests(["sh", "-c", "echo hi; exit 3"]), 3)
        finally:
            sys.stdout = saved
        self.assertEqual(len(self.recorded()), 1)
    @unittest.skipUnless(ATAP_JS.is_file() and CLI.is_file() and all(shutil.which(b) for b in ("node", "bash", "jq")),
                         "needs packages/atap-js and packages/atap-cli built, node, bash and jq")
    def test_verify_refuses_a_compromised_key(self):
        # ATAP-v0.1 §8.1 (A-1): refused for any signer-written time, whatever
        # disclosed_at says; the same receipt with the key active verifies.
        os.environ.pop("ATAP_VERIFY_SH", None)  # the packaged copy
        wrapper = self.root / "atap-witness-real"
        wrapper.write_text(f'#!/bin/sh\nexec node "{CLI}" "$@"\n')
        wrapper.chmod(0o755)
        os.environ["ATAP_WITNESS"] = str(wrapper)
        for status, ok in (("active", True), ("compromised", False)):
            d = self.root / status
            d.mkdir()
            subprocess.run(["node", "--input-type=module", "-e", RECEIPT_JS, str(d), str(PACKAGED), status], check=True)
            self.assertEqual(atap.verify(d), {"ok": ok, "cli": ok, "verify_sh": ok}, status)


if __name__ == "__main__":
    unittest.main()
