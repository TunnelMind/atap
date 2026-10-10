"""The helpers against the real atap-witness (packages/atap-cli/dist): init,
one event per helper, block, receipt, then both verifiers. Skipped when the CLI
is not built or node/bash/jq are missing. Run from packages/atap-py:
python3 -m unittest discover -s tests"""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import test_core  # noqa: F401  (puts src/ on sys.path)

import atap  # noqa: E402
import atap.code  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "packages/atap-cli/dist/cli.js"


@unittest.skipUnless(
    CLI.is_file() and all(shutil.which(b) for b in ("node", "bash", "jq", "git")),
    "needs packages/atap-cli built, node, bash, jq and git",
)
class IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)
        self.cwd = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        # atap-witness may not be on PATH: a wrapper around the built CLI.
        wrapper = self.root / "atap-witness"
        wrapper.write_text(f'#!/bin/sh\nexec node "{CLI}" "$@"\n')
        wrapper.chmod(0o755)
        os.environ.pop("ATAP_OFF", None)
        os.environ.update({
            "ATAP_WITNESS": str(wrapper),
            "ATAP_VERIFY_SH": str(REPO_ROOT / "verify.sh"),
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        })
        self.project = self.root / "project"
        self.project.mkdir()
        for args in (["git", "init", "-q"], ["git", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "root"],
                     [str(wrapper), "init"]):
            subprocess.run(args, cwd=self.project, check=True, capture_output=True)
        os.chdir(self.project)

    def tearDown(self):
        os.chdir(self.cwd)
        os.environ.clear()
        os.environ.update(self.env)
        atap._off = False
        self.tmp.cleanup()

    def test_init_helpers_block_receipt_verify(self):
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        results = {
            "task_claimed": atap.code.task_claimed("Y1004", "coder", "claude-opus-5-5"),
            "change_committed": atap.code.change_committed(),
            "verify_run": atap.code.verify_run("python3 -m unittest", 0, "OK\n"),
            "qa_verdict": atap.code.qa_verdict("Y1004", "accepted", 1),
            "review_verdict": atap.code.review_verdict(head, "pass", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
        }
        for name, r in results.items():
            self.assertIsNotNone(r, f"{name}: {self.hook_log()}")
        # run_tests records a sixth event through the same path.
        real, sys.stdout = sys.stdout, io.TextIOWrapper(io.BytesIO())
        try:
            self.assertEqual(atap.code.run_tests("true"), 0)
        finally:
            sys.stdout = real
        self.assertIsNotNone(atap.block(), self.hook_log())
        out = self.root / "out"
        self.assertIsNotNone(atap.receipt(out), self.hook_log())
        self.assertEqual(atap.verify(out), {"ok": True, "cli": True, "verify_sh": True})
        self.assertEqual(self.hook_log(), "")

    def test_agent_tools_profile(self):
        # setUp's store has no events yet, so init --force may re-declare it
        # under another registered profile.
        subprocess.run([os.environ["ATAP_WITNESS"], "init", "--force", "--profile", "tunnelmind:agent_tools:v1"],
                       check=True, capture_output=True)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(), "evidence": "asserted", "tool": "web.search",
            "input_sha256": "a" * 64, "output_sha256": "b" * 64, "outcome": "ok", "duration_ms": 12,
        }
        ev = atap.event("agent_tools:tool_called", payload)
        self.assertIsNotNone(ev, self.hook_log())
        self.assertEqual(ev["event_type"], "agent_tools:tool_called")
        # A PII payload is refused: None, and one fixed-text line in hook.log
        # that never quotes the payload.
        self.assertIsNone(atap.event("agent_tools:tool_called", {**payload, "tool": "jane@example.com"}))
        self.assertEqual(self.hook_log().split(" ", 1)[1], "event atap-witness event failed: exit 1\n")
        summary = {
            "events": {"session_started": 0, "tool_called": 1, "model_called": 0, "handoff": 0, "human_decision": 0},
            "tool_outcomes": {"ok": 1, "error": 0, "denied": 0}, "total_tokens": 0,
        }
        block = atap.block(summary)
        self.assertIsNotNone(block, self.hook_log())
        self.assertEqual(block["event_count"], 1)
        out = self.root / "out"
        self.assertIsNotNone(atap.receipt(out), self.hook_log())
        self.assertEqual(atap.verify(out), {"ok": True, "cli": True, "verify_sh": True})

    def hook_log(self):
        f = self.project / ".atap" / "hook.log"
        return f.read_text() if f.exists() else ""


if __name__ == "__main__":
    unittest.main()
