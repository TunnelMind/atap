"""atap.code.run_tests against the fake atap-witness of test_core. Run from
packages/atap-py: python3 -m unittest discover -s tests"""

import io
import json
import os
import sys
import unittest

import test_core

import atap.code  # noqa: E402  (test_core puts src/ on sys.path)


class RunTestsTest(unittest.TestCase):
    setUp = test_core.CoreTest.setUp
    tearDown = test_core.CoreTest.tearDown
    recorded = test_core.CoreTest.recorded

    def run_captured(self, command):
        # The child's output is copied through sys.stdout.buffer; catch it there.
        real, sys.stdout = sys.stdout, io.TextIOWrapper(io.BytesIO())
        try:
            code = atap.code.run_tests(command)
            return code, sys.stdout.buffer.getvalue()
        finally:
            sys.stdout = real

    def payloads(self):
        return [json.loads(c["stdin"]) for c in self.recorded()]

    def test_str_exit_code(self):
        self.assertEqual(self.run_captured("exit 3")[0], 3)
        [p] = self.payloads()
        self.assertEqual(p["event_type"], "code_crew:verify_run")
        self.assertEqual(p["payload"]["exit_code"], 3)

    def test_list_streams_and_sends_only_hashes(self):
        code, out = self.run_captured([sys.executable, "-c", 'print("hi")'])
        self.assertEqual((code, out), (0, b"hi\n"))
        [c] = self.recorded()
        self.assertNotIn("hi", c["stdin"])
        self.assertNotIn("print", c["stdin"])
        p = json.loads(c["stdin"])["payload"]
        self.assertEqual(set(p), {"timestamp", "evidence", "command_sha256", "exit_code", "output_sha256"})
        self.assertEqual(p["evidence"], "asserted")

    def test_signal_and_missing_program(self):
        self.assertEqual(self.run_captured("kill -9 $$")[0], -9)
        self.assertEqual(self.run_captured(["/nonexistent/prog"]), (127, b""))
        self.assertEqual([p["payload"]["exit_code"] for p in self.payloads()], [-9, 127])

    def test_exit_code_survives_off_and_missing_cli(self):
        os.environ["ATAP_OFF"] = "1"
        self.assertEqual(self.run_captured("exit 5")[0], 5)
        self.assertEqual(self.recorded(), [])
        del os.environ["ATAP_OFF"]
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.assertEqual(self.run_captured("exit 4")[0], 4)


if __name__ == "__main__":
    unittest.main()
