"""atap.adapters.openai_agents: unit tests on fake SDK objects (no SDK needed,
against the fake atap-witness of test_core), then the real OpenAI Agents SDK in
a temp venv with its ScriptedModel (no network LLM, no API key) through
block → receipt → both verifiers. The real-SDK test skips, printing why, when
pip, the network or the built CLI is missing. Run from packages/atap-py:
python3 -m unittest discover -s tests"""

import asyncio
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime
from pathlib import Path

import test_core
import test_integration

import atap  # noqa: E402  (test_core puts src/ on sys.path)
from atap import agent_tools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = Path(__file__).resolve().parents[1] / "src"
SCHEMA = json.loads((REPO_ROOT / "profiles/profiles/tunnelmind-agent-tools-v1/schemas/witness-events.schema.json").read_text())
DEFS = SCHEMA["$defs"]
SECRET = "SECRET-TOKEN-123"
DEFAULT_ERROR = "An error occurred while running the tool. Please try again."


def load_adapter():
    """Import the adapter against a fake `agents` package, then take the fake
    out of sys.modules again so no other test sees it."""
    fake = types.ModuleType("agents")
    fake.__path__ = []
    fake.RunHooks = type("RunHooks", (), {})
    tool = types.ModuleType("agents.tool")
    tool.default_tool_error_function = lambda ctx, err: DEFAULT_ERROR
    models = types.ModuleType("agents.models")
    models.get_default_model = lambda: "gpt-default"
    mods = {"agents": fake, "agents.tool": tool, "agents.models": models}
    sys.modules.pop("atap.adapters.openai_agents", None)
    sys.modules.update(mods)
    try:
        return importlib.import_module("atap.adapters.openai_agents")
    finally:
        for name in mods:
            sys.modules.pop(name, None)
        sys.modules.pop("atap.adapters.openai_agents", None)


def check(test, payload):
    """payload against the agent_tools $defs for its event_type: every required
    key, no other key (additionalProperties:false), each value in its
    pattern/enum/range. Stdlib only: no jsonschema."""
    schema = DEFS[payload["event_type"].split(":", 1)[1]]
    p = payload["payload"]
    test.assertLessEqual(set(schema["required"]), set(p))
    test.assertLessEqual(set(p), set(schema["properties"]))
    test.assertEqual(p["evidence"], "asserted")
    datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00"))
    for key, value in p.items():
        spec = schema["properties"][key]
        spec = {**DEFS[spec["$ref"].split("/")[-1]], **spec} if "$ref" in spec else spec
        if "pattern" in spec:
            test.assertRegex(value, spec["pattern"])
        if "enum" in spec:
            test.assertIn(value, spec["enum"])
        if spec.get("type") == "integer":
            test.assertIs(type(value), int)
            test.assertGreaterEqual(value, 0)


def ns(**kw):
    return types.SimpleNamespace(**kw)


class Boom:
    """Any attribute access raises: a hook input the SDK might hand over broken."""

    def __getattr__(self, name):
        raise RuntimeError(SECRET)


class FakeState:
    def __init__(self):
        self.calls = []

    def approve(self, item):
        self.calls.append(("approve", item))

    def reject(self, item):
        self.calls.append(("reject", item))


class HelpersTest(unittest.TestCase):
    def test_ident(self):
        self.assertEqual(agent_tools.ident("Research agent@x.com"), "Research-agent-x.com")
        self.assertEqual(agent_tools.ident("../tools/web search"), "tools/web-search")
        self.assertEqual(len(agent_tools.ident("a" * 100)), 64)
        for bad in ("", "  ", "é", "--", None, 3):
            self.assertIsNone(agent_tools.ident(bad), bad)

    def test_sha(self):
        self.assertEqual(agent_tools.sha(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(agent_tools.sha("x"), agent_tools.sha(b"x"))
        self.assertEqual(agent_tools.sha({"b": 1, "a": 2}), agent_tools.sha({"a": 2, "b": 1}))
        self.assertRegex(agent_tools.sha(object()), r"^[0-9a-f]{64}$")

    def test_import_atap_pulls_in_no_framework(self):
        code = 'import atap, atap.agent_tools, atap.adapters, sys; assert not any(m in sys.modules for m in ("agents","langchain","crewai"))'
        subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONPATH": str(SRC)}, check=True)

    def test_missing_sdk_names_the_pip_package(self):
        r = subprocess.run([sys.executable, "-c", "import atap.adapters.openai_agents"], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(SRC)})
        if r.returncode == 0:
            self.skipTest("the OpenAI Agents SDK is installed here")
        self.assertIn("pip install openai-agents", r.stderr)


class AdapterTest(unittest.TestCase):
    setUp = test_core.CoreTest.setUp
    tearDown = test_core.CoreTest.tearDown
    recorded = test_core.CoreTest.recorded

    def sent(self):
        return [json.loads(c["stdin"]) for c in self.recorded()]

    def run_fake(self):
        """One fake run through every hook; returns the hooks object."""
        oa = load_adapter()
        h = oa.AtapRunHooks()
        main = ns(name="main agent", model="gpt-x")
        helper = ns(name="helper", model=None)
        ctx = ns()
        run = asyncio.run
        self.assertIsNone(run(h.on_agent_start(ctx, main)))
        self.assertIsNone(run(h.on_llm_start(ctx, main, SECRET, [SECRET])))
        response = ns(output=[f"say {SECRET}"], usage=ns(input_tokens=7, output_tokens=3))
        self.assertIsNone(run(h.on_llm_end(ctx, main, response)))
        tool = ns(name="web search")
        for call_id, result in (("c1", f"result {SECRET}"), ("c2", DEFAULT_ERROR)):
            tctx = ns(tool_call_id=call_id, tool_arguments=json.dumps({"q": SECRET}))
            self.assertIsNone(run(h.on_tool_start(tctx, main, tool)))
            self.assertIsNone(run(h.on_tool_end(tctx, main, tool, result)))
        self.assertIsNone(run(h.on_handoff(ctx, main, helper)))
        self.assertIsNone(run(h.on_agent_start(ctx, helper)))  # a handoff target: no second session
        run(h.on_tool_start(ns(tool_call_id="c3", tool_arguments="{}"), helper, ns(name="crash")))
        self.assertIsNone(h.flush())
        state = FakeState()
        item = ns(name="deploy", arguments=json.dumps({"to": SECRET}))
        self.assertIsNone(oa.record_approval(state, item, False))
        self.assertEqual(state.calls, [("reject", item)])
        return h

    def test_hooks_record_schema_shaped_payloads(self):
        self.run_fake()
        sent = self.sent()
        self.assertEqual([s["event_type"].split(":")[1] for s in sent],
                         ["session_started", "model_called", "tool_called", "tool_called", "handoff", "tool_called", "human_decision"])
        for s in sent:
            check(self, s)
        p = [s["payload"] for s in sent]
        self.assertEqual((p[0]["agent"], p[0]["framework"], p[0]["model"]), ("main-agent", "openai-agents", "gpt-x"))
        self.assertEqual((p[1]["model"], p[1]["input_tokens"], p[1]["output_tokens"]), ("gpt-x", 7, 3))
        self.assertEqual((p[2]["tool"], p[2]["outcome"]), ("web-search", "ok"))
        self.assertEqual(p[2]["output_sha256"], agent_tools.sha(f"result {SECRET}"))
        self.assertEqual(p[2]["input_sha256"], agent_tools.sha(json.dumps({"q": SECRET})))
        self.assertEqual(p[3]["outcome"], "error")
        self.assertNotIn("output_sha256", p[3])
        self.assertEqual((p[4]["from_agent"], p[4]["to_agent"]), ("main-agent", "helper"))
        self.assertEqual((p[5]["tool"], p[5]["outcome"]), ("crash", "error"))
        self.assertEqual((p[6]["role"], p[6]["decision"], p[6]["channel"]), ("user", "reject", "openai-agents"))

    def test_raw_values_never_sent(self):
        self.run_fake()
        for c in self.recorded():
            self.assertNotIn(SECRET, c["stdin"])
            self.assertNotIn("TOKEN", c["stdin"])

    def test_atap_off_records_nothing(self):
        os.environ["ATAP_OFF"] = "1"
        self.run_fake()
        self.assertEqual(self.recorded(), [])

    def test_broken_inputs_never_raise(self):
        oa = load_adapter()
        h = oa.AtapRunHooks()
        run = asyncio.run
        self.assertIsNone(run(h.on_agent_start(Boom(), Boom())))
        self.assertIsNone(run(h.on_llm_start(Boom(), Boom(), None, None)))
        self.assertIsNone(run(h.on_llm_end(Boom(), Boom(), Boom())))
        self.assertIsNone(run(h.on_tool_start(Boom(), Boom(), Boom())))
        self.assertIsNone(run(h.on_tool_end(Boom(), Boom(), Boom(), Boom())))
        self.assertIsNone(run(h.on_handoff(Boom(), Boom(), Boom())))
        self.assertIsNone(oa.record_approval(None, Boom(), True))
        self.assertEqual(self.recorded(), [])
        # The witness itself failing is no different: None, the run goes on.
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.run_fake()


# The real SDK, driven by a ScriptedModel: one tool call, one tool that raises
# (default formatter), one handoff; then a tool under failure_error_function=None
# (flush), then an approval round trip. Prints what the hooks saw as JSON.
SCRIPT = r'''
import asyncio, json, sys
import atap.agent_tools as at
from agents import Agent, Runner, function_tool
from agents.testing import ScriptedModel, assistant_message, function_call
from atap.adapters.openai_agents import AtapRunHooks, record_approval

SECRET = sys.argv[1]
sent = []
real = at.event
def spy(type, payload, cwd="."):
    sent.append({"event_type": type, "payload": payload, "signed": real(type, payload, cwd) is not None})
    return sent[-1]["signed"]
at.event = spy

@function_tool
def lookup(q: str) -> str:
    return "result " + SECRET

@function_tool
def boom(q: str) -> str:
    raise ValueError(SECRET)

@function_tool(failure_error_function=None)
def crash(q: str) -> str:
    raise ValueError(SECRET)

@function_tool(needs_approval=True)
def deploy(q: str) -> str:
    return "deployed"

async def main():
    out = {}
    m = ScriptedModel([
        [function_call("lookup", {"q": SECRET}, call_id="c1"), function_call("boom", {"q": SECRET}, call_id="c2")],
        [function_call("transfer_to_helper", {}, call_id="c3")],
        [assistant_message("done " + SECRET)],
    ])
    helper = Agent(name="helper", model=m)
    r = await Runner.run(Agent(name="main agent", model=m, tools=[lookup, boom], handoffs=[helper]), SECRET, hooks=AtapRunHooks())
    out["final"] = r.final_output
    out["after_run1"] = len(sent)

    hooks = AtapRunHooks()
    try:
        await Runner.run(Agent(name="crasher", model=ScriptedModel([[function_call("crash", {"q": SECRET}, call_id="c4")]]), tools=[crash]),
                         SECRET, hooks=hooks)
        out["raised"] = None
    except Exception as e:
        out["raised"] = type(e).__name__
    out["before_flush"] = len(sent)
    hooks.flush()

    a = Agent(name="deployer", model=ScriptedModel([[function_call("deploy", {"q": SECRET}, call_id="c5")], [assistant_message("ok")]]), tools=[deploy])
    r = await Runner.run(a, SECRET, hooks=AtapRunHooks())
    state = r.to_state()
    record_approval(state, r.interruptions[0], True)
    r = await Runner.run(a, state, hooks=AtapRunHooks())
    out["approved_final"] = r.final_output
    out["sent"] = sent
    print(json.dumps(out))

asyncio.run(main())
'''


@unittest.skipUnless(
    test_integration.CLI.is_file() and all(shutil.which(b) for b in ("node", "bash", "jq", "git")),
    "needs packages/atap-cli built, node, bash, jq and git (as test_integration)",
)
class RealSdkTest(unittest.TestCase):
    setUp = test_integration.IntegrationTest.setUp
    tearDown = test_integration.IntegrationTest.tearDown
    hook_log = test_integration.IntegrationTest.hook_log

    def venv_python(self):
        venv = self.root / "venv"
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True, timeout=120)
            py = str(venv / "bin" / "python")
            r = subprocess.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "openai-agents"],
                               capture_output=True, text=True, timeout=600)
        except (subprocess.SubprocessError, OSError) as e:
            reason = f"cannot create a venv with openai-agents: {type(e).__name__}"
            print(f"\nRealSdkTest skipped: {reason}", file=sys.stderr)
            self.skipTest(reason)
        if r.returncode != 0:
            reason = f"pip install openai-agents failed (exit {r.returncode}): {r.stderr.strip()[-300:]}"
            print(f"\nRealSdkTest skipped: {reason}", file=sys.stderr)
            self.skipTest(reason)
        return py

    def test_real_sdk_run_block_receipt_verify(self):
        py = self.venv_python()
        subprocess.run([os.environ["ATAP_WITNESS"], "init", "--force", "--profile", "tunnelmind:agent_tools:v1"],
                       check=True, capture_output=True)
        script = self.root / "run_agents.py"
        script.write_text(SCRIPT)
        env = {**os.environ, "PYTHONPATH": str(SRC), "OPENAI_AGENTS_DISABLE_TRACING": "1"}
        env.pop("OPENAI_API_KEY", None)
        r = subprocess.run([py, str(script), SECRET], capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        sent = out["sent"]
        names = [s["event_type"].split(":")[1] for s in sent]

        # Run 1: one session (the handoff target is not a new one), two model
        # calls before the handoff and one after, lookup ok, boom error.
        self.assertEqual(out["final"], f"done {SECRET}")
        run1 = sent[:out["after_run1"]]
        tools = {s["payload"]["tool"]: s["payload"] for s in run1 if s["event_type"].endswith("tool_called")}
        self.assertEqual(tools["lookup"]["outcome"], "ok")
        self.assertEqual(tools["lookup"]["output_sha256"], agent_tools.sha(f"result {SECRET}"))
        self.assertEqual(tools["lookup"]["input_sha256"], agent_tools.sha(json.dumps({"q": SECRET}, separators=(",", ":"))))
        # The finding: a raising tool under the default formatter still ends in
        # on_tool_end, with the SDK's fixed message as its result.
        self.assertEqual(tools["boom"]["outcome"], "error")
        self.assertEqual([s["event_type"].split(":")[1] for s in run1].count("session_started"), 1)
        [h] = [s["payload"] for s in run1 if s["event_type"].endswith("handoff")]
        self.assertEqual((h["from_agent"], h["to_agent"]), ("main-agent", "helper"))
        self.assertEqual(names[:out["after_run1"]].count("model_called"), 3)

        # Run 2: failure_error_function=None ends the run and on_tool_end never
        # fires; only flush() records the tool, as error.
        self.assertIsNotNone(out["raised"])
        self.assertNotIn("crash", [s["payload"].get("tool") for s in sent[:out["before_flush"]]])
        crash = sent[out["before_flush"]]["payload"]
        self.assertEqual((crash["tool"], crash["outcome"]), ("crash", "error"))

        # Run 3: the approval is recorded and the run resumes with it.
        self.assertEqual(out["approved_final"], "ok")
        [d] = [s["payload"] for s in sent if s["event_type"].endswith("human_decision")]
        self.assertEqual((d["role"], d["decision"], d["channel"]), ("user", "approve", "openai-agents"))

        for s in sent:
            self.assertTrue(s["signed"], f"{s['event_type']}: {self.hook_log()}")
            check(self, s)
            self.assertNotIn(SECRET, json.dumps(s))

        # Every event signed by the CLI under the profile → block → receipt → both verifiers.
        outcomes = [s["payload"]["outcome"] for s in sent if s["event_type"].endswith("tool_called")]
        summary = {
            "events": {k: names.count(k) for k in ("session_started", "tool_called", "model_called", "handoff", "human_decision")},
            "tool_outcomes": {k: outcomes.count(k) for k in ("ok", "error", "denied")},
            "total_tokens": sum(s["payload"].get("input_tokens", 0) + s["payload"].get("output_tokens", 0) for s in sent),
        }
        block = atap.block(summary)
        self.assertIsNotNone(block, self.hook_log())
        self.assertEqual(block["event_count"], len(sent))
        receipt = self.root / "out"
        self.assertIsNotNone(atap.receipt(receipt), self.hook_log())
        self.assertEqual(atap.verify(receipt), {"ok": True, "cli": True, "verify_sh": True})
        self.assertEqual(self.hook_log(), "")


if __name__ == "__main__":
    unittest.main()
