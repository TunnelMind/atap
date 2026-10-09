"""Smoke tests for the atap core against a fake atap-witness (a python stub on
ATAP_WITNESS that records its argv, cwd and stdin). Run from packages/atap-py:
python3 -m unittest discover -s tests"""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

# No install needed: import the package straight from src/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import atap  # noqa: E402

STUB = """#!{python}
import json, os, sys
with open({calls!r}, "a") as f:
    f.write(json.dumps({{"argv": sys.argv[1:], "cwd": os.getcwd(), "stdin": sys.stdin.read()}}) + "\\n")
print(json.dumps({{"ok": True}}))
"""


class CoreTest(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)
        self.cwd = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / ".atap").mkdir()
        (self.root / ".atap" / "config.json").write_text(json.dumps({"ait": "ait:x", "cli": "./evil.sh"}))
        # A config `cli` must never run: if it did, this marker would appear.
        evil = self.root / "evil.sh"
        evil.write_text(f"#!/bin/sh\ntouch {self.root / 'EVIL'}\n")
        evil.chmod(0o755)
        self.calls = self.root / "calls.jsonl"
        stub = self.root / "stub.py"
        stub.write_text(STUB.format(python=sys.executable, calls=str(self.calls)))
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        os.environ["ATAP_WITNESS"] = str(stub)
        os.environ.pop("ATAP_OFF", None)
        sub = self.root / "a" / "b"
        sub.mkdir(parents=True)
        os.chdir(sub)

    def tearDown(self):
        os.chdir(self.cwd)
        os.environ.clear()
        os.environ.update(self.env)
        atap._off = False
        self.tmp.cleanup()

    def recorded(self):
        if not self.calls.exists():
            return []
        return [json.loads(l) for l in self.calls.read_text().splitlines()]

    def test_find_store_walks_up(self):
        self.assertEqual(atap.find_store(), self.root / ".atap")
        self.assertIsNone(atap.find_store("/"))

    def test_event_sends_stdin_from_project_root(self):
        self.assertEqual(atap.event("code_crew:verify_run", {"exit_code": 0}), {"ok": True})
        [c] = self.recorded()
        self.assertEqual(c["argv"], ["event"])
        self.assertEqual(c["cwd"], str(self.root))
        self.assertEqual(json.loads(c["stdin"]), {"event_type": "code_crew:verify_run", "payload": {"exit_code": 0}})

    def test_receipt_passes_out(self):
        self.assertEqual(atap.receipt("r"), {"ok": True})
        [c] = self.recorded()
        self.assertEqual(c["argv"], ["receipt", "--out", os.path.abspath("r")])

    def test_session_blocks_on_clean_exit_only(self):
        with atap.session():
            pass
        [c] = self.recorded()
        self.assertEqual(c["argv"], ["block"])
        self.assertEqual(json.loads(c["stdin"]), atap.ZERO_SUMMARY)
        with self.assertRaises(KeyError):
            with atap.session():
                raise KeyError("boom")
        self.assertEqual(len(self.recorded()), 1)

    def test_atap_off_env_and_off(self):
        os.environ["ATAP_OFF"] = "1"
        self.assertIsNone(atap.event("t", {}))
        self.assertIsNone(atap.block())
        del os.environ["ATAP_OFF"]
        atap.off()
        self.assertIsNone(atap.event("t", {}))
        self.assertIsNone(atap.receipt("r"))
        self.assertEqual(self.recorded(), [])
        self.assertFalse((self.root / ".atap" / "hook.log").exists())

    def test_missing_binary_returns_none_and_logs_one_line(self):
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.assertIsNone(atap.event("t", {}))
        [line] = (self.root / ".atap" / "hook.log").read_text().splitlines()
        self.assertRegex(line, r"^\d{4}-\d\d-\d\dT\S+Z event atap-witness not found$")

    def test_config_cli_never_executed(self):
        os.environ.pop("ATAP_WITNESS")
        os.environ["PATH"] = str(self.root / "empty")  # no atap-witness on PATH either
        self.assertIsNone(atap.event("t", {}))
        self.assertIsNone(atap.block())
        self.assertFalse((self.root / "EVIL").exists())

    def test_verify_reports_both(self):
        # The stub exits 0 for the CLI; a verify.sh that fails makes ok False.
        bad = self.root / "verify.sh"
        bad.write_text("exit 1\n")
        os.environ["ATAP_VERIFY_SH"] = str(bad)
        self.assertEqual(atap.verify("r"), {"ok": False, "cli": True, "verify_sh": False})
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.assertEqual(atap.verify("r"), {"ok": False, "cli": False, "verify_sh": False})


if __name__ == "__main__":
    unittest.main()
