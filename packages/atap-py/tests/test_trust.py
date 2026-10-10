"""Which verify.sh runs and which store records: only the package's own
verify.sh (or ATAP_VERIFY_SH), and the store of the repo change_committed was
pointed at. Run from packages/atap-py: python3 -m unittest discover -s tests"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import test_core

import atap  # noqa: E402  (test_core puts src/ on sys.path)
import atap.code  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGED = Path(atap.__file__).with_name("verify.sh")


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


if __name__ == "__main__":
    unittest.main()
