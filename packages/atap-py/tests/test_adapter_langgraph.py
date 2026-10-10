"""atap.adapters.langgraph: unit tests on fake langchain objects (no framework
needed, against the fake atap-witness of test_core), then the real LangChain v1
+ LangGraph in a temp venv with a GenericFakeChatModel (no network LLM, no API
key) through block → receipt → both verifiers. The real-framework test skips,
printing why, when pip, the network or the built CLI is missing. Run from
packages/atap-py: python3 -m unittest discover -s tests"""

import asyncio
import importlib
import json
import os
import shutil
import subprocess
import sys
import types
import unittest

import test_core
import test_integration
from test_adapter_openai_agents import SECRET, SRC, Boom, check, ns

import atap  # noqa: E402  (test_core puts src/ on sys.path)
from atap import agent_tools  # noqa: E402


class GraphBubbleUp(Exception):
    pass


def load_adapter():
    """Import the adapter against fake langchain/langgraph packages, then take
    the fakes out of sys.modules again so no other test sees them."""
    mods = {n: types.ModuleType(n) for n in ("langchain", "langchain.agents", "langchain.agents.middleware",
                                             "langgraph", "langgraph.errors")}
    mods["langchain.agents.middleware"].AgentMiddleware = type("AgentMiddleware", (), {})
    mods["langgraph.errors"].GraphBubbleUp = GraphBubbleUp
    sys.modules.pop("atap.adapters.langgraph", None)
    sys.modules.update(mods)
    try:
        return importlib.import_module("atap.adapters.langgraph")
    finally:
        for name in mods:
            sys.modules.pop(name, None)
        sys.modules.pop("atap.adapters.langgraph", None)


def tool_request(name, args):
    return ns(tool_call={"name": name, "args": args, "id": "c1"})


class ImportTest(unittest.TestCase):
    def test_missing_framework_names_the_pip_packages(self):
        r = subprocess.run([sys.executable, "-c", "import atap.adapters.langgraph"], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(SRC)})
        if r.returncode == 0:
            self.skipTest("langchain is installed here")
        self.assertIn("pip install langchain langgraph", r.stderr)


class AdapterTest(unittest.TestCase):
    setUp = test_core.CoreTest.setUp
    tearDown = test_core.CoreTest.tearDown
    recorded = test_core.CoreTest.recorded

    def sent(self):
        return [json.loads(c["stdin"]) for c in self.recorded()]

    def run_fake(self):
        """One fake run through every hook and helper, sync then async."""
        lg = load_adapter()
        m = lg.AtapMiddleware(name="main agent")
        self.assertIsNone(m.before_agent({"messages": [SECRET]}, ns()))

        usage = {"input_tokens": 7, "output_tokens": 3, "total_tokens": 10}
        response = ns(result=[ns(content=f"say {SECRET}", usage_metadata=usage)])
        request = ns(model=ns(model_name="gpt-x"), messages=[SECRET])
        self.assertIs(m.wrap_model_call(request, lambda r: response), response)
        bare = ns(content=SECRET, usage_metadata=None)  # a bare AIMessage, no usage
        self.assertIs(asyncio.run(m.awrap_model_call(ns(model=object()), self.coro(bare))), bare)

        ok = ns(content=f"result {SECRET}", status="success")
        self.assertIs(m.wrap_tool_call(tool_request("web search", {"q": SECRET}), lambda r: ok), ok)
        bad = ns(content=f"Error {SECRET}", status="error")
        self.assertIs(asyncio.run(m.awrap_tool_call(tool_request("web search", {"q": 1}), self.coro(bad))), bad)

        self.assertIsNone(lg.record_handoff("main agent", "helper"))
        self.assertIsNone(lg.record_human_decision("user", "approve", {"tool": "deploy", "to": SECRET}))
        return lg, m

    @staticmethod
    def coro(value):
        async def handler(request):
            return value
        return handler

    def test_hooks_record_schema_shaped_payloads(self):
        self.run_fake()
        sent = self.sent()
        self.assertEqual([s["event_type"].split(":")[1] for s in sent],
                         ["session_started", "model_called", "model_called", "tool_called", "tool_called", "handoff", "human_decision"])
        for s in sent:
            check(self, s)
        p = [s["payload"] for s in sent]
        self.assertEqual((p[0]["agent"], p[0]["framework"]), ("main-agent", "langgraph"))
        self.assertNotIn("model", p[0])
        self.assertEqual((p[1]["model"], p[1]["input_tokens"], p[1]["output_tokens"]), ("gpt-x", 7, 3))
        self.assertEqual(p[2]["model"], "object")
        self.assertNotIn("input_tokens", p[2])
        self.assertEqual((p[3]["tool"], p[3]["outcome"]), ("web-search", "ok"))
        self.assertEqual(p[3]["input_sha256"], agent_tools.sha({"q": SECRET}))
        self.assertEqual(p[3]["output_sha256"], agent_tools.sha(f"result {SECRET}"))
        self.assertEqual(p[4]["outcome"], "error")
        self.assertNotIn("output_sha256", p[4])
        self.assertEqual((p[5]["from_agent"], p[5]["to_agent"]), ("main-agent", "helper"))
        self.assertEqual((p[6]["role"], p[6]["decision"], p[6]["channel"]), ("user", "approve", "langgraph"))
        self.assertEqual(p[6]["subject_sha256"], agent_tools.sha({"tool": "deploy", "to": SECRET}))

    def test_raw_values_never_sent(self):
        self.run_fake()
        for c in self.recorded():
            self.assertNotIn(SECRET, c["stdin"])
            self.assertNotIn("TOKEN", c["stdin"])

    def test_atap_off_records_nothing(self):
        os.environ["ATAP_OFF"] = "1"
        self.run_fake()
        self.assertEqual(self.recorded(), [])

    def test_handler_exceptions_reach_the_app_unchanged(self):
        lg = load_adapter()
        m = lg.AtapMiddleware()
        err = ValueError(SECRET)

        def raise_(request):
            raise err

        async def araise(request):
            raise err

        for call in (lambda: m.wrap_tool_call(tool_request("boom", {"q": SECRET}), raise_),
                     lambda: asyncio.run(m.awrap_tool_call(tool_request("boom", {"q": SECRET}), araise)),
                     lambda: m.wrap_model_call(ns(model=object()), raise_),
                     lambda: asyncio.run(m.awrap_model_call(ns(model=object()), araise))):
            with self.assertRaises(ValueError) as cm:
                call()
            self.assertIs(cm.exception, err)
        # Each raising tool is an error, the raising model calls record nothing.
        sent = self.sent()
        self.assertEqual([(s["event_type"], s["payload"]["outcome"]) for s in sent],
                         [("agent_tools:tool_called", "error")] * 2)
        for s in sent:
            check(self, s)
            self.assertNotIn(SECRET, json.dumps(s))

        # interrupt()/Command.PARENT bubble up through the handler: control flow, not an error.
        bubble = GraphBubbleUp()
        with self.assertRaises(GraphBubbleUp) as cm:
            m.wrap_tool_call(tool_request("ask", {}), lambda r: (_ for _ in ()).throw(bubble))
        self.assertIs(cm.exception, bubble)
        self.assertEqual(len(self.recorded()), 2)

    def test_broken_inputs_never_change_the_result(self):
        lg = load_adapter()
        m = lg.AtapMiddleware(name=Boom())
        self.assertIsNone(m.before_agent(Boom(), Boom()))
        out = object()
        self.assertIs(m.wrap_model_call(Boom(), lambda r: out), out)
        self.assertIs(m.wrap_model_call(ns(model=object()), lambda r: Boom()).__class__, Boom)
        self.assertIs(m.wrap_tool_call(Boom(), lambda r: out), out)
        self.assertIs(m.wrap_tool_call(ns(tool_call={"name": "t", "args": Boom()}), lambda r: Boom()).__class__, Boom)
        self.assertIs(asyncio.run(m.awrap_tool_call(Boom(), self.coro(out))), out)
        self.assertIsNone(lg.record_handoff(Boom(), "x"))
        self.assertIsNone(lg.record_human_decision(Boom(), "approve", "x"))
        self.assertEqual(self.recorded(), [])
        # The witness itself failing is no different: the run goes on.
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.run_fake()

    def test_invalid_human_decision_records_nothing(self):
        lg = load_adapter()
        self.assertIsNone(lg.record_human_decision("Josh", "approve", "x"))
        self.assertIsNone(lg.record_human_decision("user", "maybe", "x"))
        self.assertIsNone(lg.record_handoff("", "helper"))
        self.assertEqual(self.recorded(), [])


# The real framework, driven by a GenericFakeChatModel: a sync invoke with one
# tool call (and a usage_metadata on the model's message), then an async
# ainvoke whose tool raises, then the two helpers. Prints what was sent as JSON.
SCRIPT = r'''
import asyncio, json, sys
import atap.agent_tools as at
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from atap.adapters.langgraph import AtapMiddleware, record_handoff, record_human_decision

SECRET = sys.argv[1]
sent = []
real = at.event
def spy(type, payload, cwd="."):
    sent.append({"event_type": type, "payload": payload, "signed": real(type, payload, cwd) is not None})
    return sent[-1]["signed"]
at.event = spy

class Fake(GenericFakeChatModel):
    def bind_tools(self, tools, **kw):  # the fake ignores tools; create_agent needs the method
        return self

@tool
def lookup(q: str) -> str:
    """Look something up."""
    return "result " + SECRET

@tool
def boom(q: str) -> str:
    """Fail."""
    raise ValueError(SECRET)

out = {}
usage = {"input_tokens": 11, "output_tokens": 4, "total_tokens": 15}
m = Fake(messages=iter([AIMessage("", tool_calls=[{"name": "lookup", "args": {"q": SECRET}, "id": "c1"}], usage_metadata=usage),
                        AIMessage("done " + SECRET)]))
r = create_agent(m, [lookup], middleware=[AtapMiddleware(name="main agent")]).invoke({"messages": [("user", SECRET)]})
out["final"] = r["messages"][-1].content
out["after_run1"] = len(sent)

m = Fake(messages=iter([AIMessage("", tool_calls=[{"name": "boom", "args": {"q": SECRET}, "id": "c2"}])]))
agent = create_agent(m, [boom], middleware=[AtapMiddleware(name="crasher")])
try:
    asyncio.run(agent.ainvoke({"messages": [("user", SECRET)]}))
    out["raised"] = None
except Exception as e:
    out["raised"] = [type(e).__name__, str(e) == SECRET]

record_handoff("main agent", "helper")
record_human_decision("operator", "edit", {"q": SECRET})
out["sent"] = sent
print(json.dumps(out))
'''


@unittest.skipUnless(
    test_integration.CLI.is_file() and all(shutil.which(b) for b in ("node", "bash", "jq", "git")),
    "needs packages/atap-cli built, node, bash, jq and git (as test_integration)",
)
class RealFrameworkTest(unittest.TestCase):
    setUp = test_integration.IntegrationTest.setUp
    tearDown = test_integration.IntegrationTest.tearDown
    hook_log = test_integration.IntegrationTest.hook_log

    def venv_python(self):
        venv = self.root / "venv"
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True, timeout=120)
            py = str(venv / "bin" / "python")
            r = subprocess.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "langchain", "langgraph"],
                               capture_output=True, text=True, timeout=600)
        except (subprocess.SubprocessError, OSError) as e:
            reason = f"cannot create a venv with langchain + langgraph: {type(e).__name__}"
            print(f"\nRealFrameworkTest skipped: {reason}", file=sys.stderr)
            self.skipTest(reason)
        if r.returncode != 0:
            reason = f"pip install langchain langgraph failed (exit {r.returncode}): {r.stderr.strip()[-300:]}"
            print(f"\nRealFrameworkTest skipped: {reason}", file=sys.stderr)
            self.skipTest(reason)
        return py

    def test_real_framework_run_block_receipt_verify(self):
        py = self.venv_python()
        versions = subprocess.run([py, "-c", "from importlib.metadata import version as v; "
                                   "print(*(f'{p} {v(p)}' for p in ('langchain','langchain-core','langgraph')), sep=', ')"],
                                  capture_output=True, text=True).stdout.strip()
        print(f"\nRealFrameworkTest: {versions}", file=sys.stderr)
        subprocess.run([os.environ["ATAP_WITNESS"], "init", "--force", "--profile", "tunnelmind:agent_tools:v1"],
                       check=True, capture_output=True)
        script = self.root / "run_langgraph.py"
        script.write_text(SCRIPT)
        env = {**os.environ, "PYTHONPATH": str(SRC), "LANGSMITH_TRACING": "false"}
        r = subprocess.run([py, str(script), SECRET], capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        sent = out["sent"]
        names = [s["event_type"].split(":")[1] for s in sent]

        # Run 1 (sync): one session, model → tool → model, tokens from usage_metadata.
        self.assertEqual(out["final"], f"done {SECRET}")
        self.assertEqual(names[:out["after_run1"]], ["session_started", "model_called", "tool_called", "model_called"])
        p = [s["payload"] for s in sent]
        self.assertEqual((p[0]["agent"], p[0]["framework"]), ("main-agent", "langgraph"))
        self.assertEqual((p[1]["model"], p[1]["input_tokens"], p[1]["output_tokens"]), ("Fake", 11, 4))
        self.assertEqual((p[2]["tool"], p[2]["outcome"]), ("lookup", "ok"))
        self.assertEqual(p[2]["input_sha256"], agent_tools.sha({"q": SECRET}))
        self.assertEqual(p[2]["output_sha256"], agent_tools.sha(f"result {SECRET}"))

        # Run 2 (async): the tool's own exception ends ainvoke, unchanged; recorded as error.
        self.assertEqual(out["raised"], ["ValueError", True])
        self.assertEqual(names[out["after_run1"]:], ["session_started", "model_called", "tool_called", "handoff", "human_decision"])
        self.assertEqual((p[-3]["tool"], p[-3]["outcome"]), ("boom", "error"))
        self.assertEqual((p[-1]["role"], p[-1]["decision"]), ("operator", "edit"))

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
