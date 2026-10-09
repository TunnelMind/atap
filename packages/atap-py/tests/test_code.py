"""atap.code helpers against the fake atap-witness of test_core: payloads are
schema-shaped, bad input never reaches the CLI, and nothing ever raises. Run
from packages/atap-py: python3 -m unittest discover -s tests"""

import io
import json
import os
import re
import subprocess
import sys
import unittest
from datetime import datetime
from pathlib import Path

import test_core

import atap  # noqa: E402  (test_core puts src/ on sys.path)
import atap.code  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((REPO_ROOT / "profiles/profiles/tunnelmind-code-crew-v1/schemas/witness-events.schema.json").read_text())
DEFS = SCHEMA["$defs"]
SECRET = "SECRET-TOKEN-123"
SHA = "0123456789abcdef0123456789abcdef01234567"
FINDINGS = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# One good call per helper, for the shape, off and missing-CLI tests.
GOOD = {
    "task_claimed": lambda: atap.code.task_claimed("Y1004", "coder", "claude-opus-5-5"),
    "verify_run": lambda: atap.code.verify_run("make test", 0, "ok"),
    "qa_verdict": lambda: atap.code.qa_verdict("Y1004", "accepted", 1),
    "review_verdict": lambda: atap.code.review_verdict(SHA, "pass", FINDINGS),
}


def resolve(spec):
    # ponytail: one level of $ref is all this schema uses.
    if "$ref" in spec:
        return {**DEFS[spec["$ref"].split("/")[-1]], **{k: v for k, v in spec.items() if k != "$ref"}}
    return spec


def check(test, name, payload):
    """payload against $defs[name]: exactly the required keys, and each value
    within its pattern/enum/const/range. No jsonschema: stdlib only."""
    schema = DEFS[name]
    test.assertEqual(set(payload), set(schema["required"]))
    test.assertEqual(set(payload), set(schema["properties"]))
    for key, value in payload.items():
        spec = resolve(schema["properties"][key])
        if "pattern" in spec:
            test.assertRegex(value, spec["pattern"])
        if "enum" in spec:
            test.assertIn(value, spec["enum"])
        if "const" in spec:
            test.assertEqual(value, spec["const"])
        if spec.get("type") == "integer":
            test.assertIs(type(value), int)
            test.assertGreaterEqual(value, spec.get("minimum", value))
            test.assertLessEqual(value, spec.get("maximum", value))
        if spec.get("format") == "date-time":
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        if spec.get("type") == "object":
            test.assertEqual(set(value), set(spec["required"]))
            for v in value.values():
                test.assertIs(type(v), int)
                test.assertGreaterEqual(v, 0)
        if isinstance(value, str):
            test.assertNotRegex(value, r"[@\s]")
            test.assertFalse(value.startswith(("/", "~", ".")), value)


class CodeTest(unittest.TestCase):
    setUp = test_core.CoreTest.setUp
    tearDown = test_core.CoreTest.tearDown
    recorded = test_core.CoreTest.recorded

    def sent(self):
        return [json.loads(c["stdin"]) for c in self.recorded()]

    def log(self):
        f = self.root / ".atap" / "hook.log"
        return f.read_text().splitlines() if f.exists() else []

    def test_payloads_match_schema(self):
        for name, call in GOOD.items():
            with self.subTest(name):
                self.assertEqual(call(), {"ok": True})
                p = self.sent()[-1]
                self.assertEqual(p["event_type"], f"code_crew:{name}")
                check(self, name, p["payload"])

    def git(self, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=self.root, env=env,
                              check=True, capture_output=True, text=True).stdout.strip()

    def test_change_committed_names_local_repo_by_root_commit(self):
        self.git("init", "-q")
        self.git("commit", "-q", "--allow-empty", "-m", "root")
        root = self.git("rev-parse", "HEAD")
        self.git("commit", "-q", "--allow-empty", "-m", "two")
        self.assertEqual(atap.code.change_committed(self.root), {"ok": True})
        p = self.sent()[-1]
        self.assertEqual(p["event_type"], "code_crew:change_committed")
        check(self, "change_committed", p["payload"])
        self.assertEqual(p["payload"]["repo"], f"local/{root[:12]}")
        self.assertRegex(p["payload"]["repo"], r"^local/[0-9a-f]{12}$")
        self.assertEqual(p["payload"]["commit_sha"], self.git("rev-parse", "HEAD"))
        self.assertNotIn(str(self.root), self.recorded()[-1]["stdin"])

    def test_change_committed_outside_a_repo_is_none(self):
        self.assertIsNone(atap.code.change_committed(self.root))
        self.assertEqual(self.recorded(), [])

    def test_bad_inputs_never_reach_the_cli(self):
        bad = {
            "bad role": lambda: atap.code.task_claimed("Y1", "boss", "m"),
            "email task id": lambda: atap.code.task_claimed("a@b.c", "coder", "m"),
            "spaced model": lambda: atap.code.task_claimed("Y1", "coder", "my model"),
            "bool attempt": lambda: atap.code.qa_verdict("Y1", "accepted", True),
            "zero attempt": lambda: atap.code.qa_verdict("Y1", "accepted", 0),
            "bad verdict": lambda: atap.code.qa_verdict("Y1", "maybe", 1),
            "missing finding": lambda: atap.code.review_verdict(SHA, "pass", {"critical": 0, "high": 0, "medium": 0}),
            "extra finding": lambda: atap.code.review_verdict(SHA, "pass", {**FINDINGS, "who": 1}),
            "bool finding": lambda: atap.code.review_verdict(SHA, "pass", {**FINDINGS, "low": False}),
            "39-char sha": lambda: atap.code.review_verdict(SHA[:39], "pass", FINDINGS),
            "str exit code": lambda: atap.code.verify_run("c", "0", "o"),
            "bool exit code": lambda: atap.code.verify_run("c", False, "o"),
            "none output": lambda: atap.code.verify_run("c", 0, None),
        }
        for name, call in bad.items():
            with self.subTest(name):
                self.assertIsNone(call())
        self.assertEqual(self.recorded(), [])

    def test_no_command_or_output_text_is_sent(self):
        atap.code.verify_run(f"pytest --token={SECRET}", 1, f"leaked {SECRET}\n")
        real, sys.stdout = sys.stdout, io.TextIOWrapper(io.BytesIO())
        try:
            self.assertEqual(atap.code.run_tests(f"echo {SECRET}; exit 2"), 2)
        finally:
            sys.stdout = real
        calls = self.recorded()
        self.assertEqual(len(calls), 2)
        for c in calls:
            self.assertNotIn(SECRET, c["stdin"])
            self.assertNotIn("TOKEN", c["stdin"])
            p = json.loads(c["stdin"])["payload"]
            check(self, "verify_run", p)
            # Every free-form string is a sha256; the rest are fixed tokens.
            self.assertRegex(p["command_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(p["output_sha256"], r"^[0-9a-f]{64}$")

    def test_off_env_and_off(self):
        os.environ["ATAP_OFF"] = "1"
        for call in GOOD.values():
            self.assertIsNone(call())
        del os.environ["ATAP_OFF"]
        atap.off()
        for call in GOOD.values():
            self.assertIsNone(call())
        self.assertEqual(self.recorded(), [])
        self.assertEqual(self.log(), [])

    def test_missing_cli_returns_none_and_logs_one_fixed_line(self):
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.assertIsNone(atap.code.task_claimed("Y1004-PRIVATE", "coder", "model-PRIVATE"))
        [line] = self.log()
        self.assertIn("atap-witness not found", line)
        self.assertNotIn("PRIVATE", line)

    def stub(self, body):
        s = self.root / "bad.py"
        s.write_text(f"#!{sys.executable}\nimport sys, time\nsys.stdin.read()\n{body}\n")
        s.chmod(0o755)
        os.environ["ATAP_WITNESS"] = str(s)

    def test_failing_cli_never_raises(self):
        cases = [
            ("print('Y1004-PRIVATE'); sys.exit(1)", "failed: exit 1"),
            ("print('not json Y1004-PRIVATE')", "failed: bad JSON on stdout"),
            ("time.sleep(5)", "failed: killed"),
        ]
        old = atap.TIMEOUT
        atap.TIMEOUT = 1
        try:
            for body, tail in cases:
                with self.subTest(tail):
                    self.stub(body)
                    self.assertIsNone(atap.code.task_claimed("Y1004-PRIVATE", "coder", "m"))
                    self.assertIsNone(atap.code.qa_verdict("Y1004-PRIVATE", "rework", 2))
                    for line in self.log()[-2:]:
                        self.assertRegex(line, rf"^\S+Z event atap-witness event {tail}$")
        finally:
            atap.TIMEOUT = old
        self.assertEqual(len(self.log()), 6)

    def test_config_cli_never_executed_by_helpers(self):
        os.environ.pop("ATAP_WITNESS")
        os.environ["PATH"] = str(self.root / "empty")
        for call in GOOD.values():
            self.assertIsNone(call())
        self.assertIsNone(atap.event("code_crew:task_claimed", {}))
        self.assertIsNone(atap.block())
        self.assertFalse((self.root / "EVIL").exists())


if __name__ == "__main__":
    unittest.main()
