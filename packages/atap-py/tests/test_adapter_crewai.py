"""atap.adapters.crewai: unit tests on a fake crewai event bus (no framework
needed, against the fake atap-witness of test_core), then the real CrewAI in a
temp venv with a scripted BaseLLM (no network LLM, no API key) through
block → receipt → both verifiers. The real-framework test skips, printing why,
when pip, the network or the built CLI is missing. Run from packages/atap-py:
python3 -m unittest discover -s tests"""

import importlib
import json
import os
import shutil
import subprocess
import sys
import types
import unittest
import uuid
from datetime import datetime, timedelta, timezone

import test_core
import test_integration
from test_adapter_openai_agents import SECRET, SRC, Boom, check

import atap  # noqa: E402  (test_core puts src/ on sys.path)
from atap import agent_tools  # noqa: E402

EVENTS = ("CrewKickoffStartedEvent", "HumanFeedbackReceivedEvent", "LLMCallCompletedEvent", "LLMCallFailedEvent",
          "LLMCallStartedEvent", "MCPToolExecutionCompletedEvent", "MCPToolExecutionFailedEvent",
          "MCPToolExecutionStartedEvent", "ToolUsageErrorEvent", "ToolUsageFinishedEvent", "ToolUsageStartedEvent")
T0 = datetime(2026, 10, 9, tzinfo=timezone.utc)


class FakeEvent:
    def __init__(self, **kw):
        self.event_id = str(uuid.uuid4())
        self.started_event_id = None
        self.timestamp = T0
        self.__dict__.update(kw)


class FakeBus:
    """Calls handlers inline and, unlike the real bus, lets their exceptions
    through: a test fails if a handler does not swallow its own."""

    def __init__(self):
        self.handlers = {}

    def on(self, cls):
        def register(handler):
            self.handlers.setdefault(cls, []).append(handler)
            return handler
        return register

    def emit(self, event):
        for handler in self.handlers.get(type(event), []):
            handler(None, event)
        return event


def load_adapter():
    """Import the adapter against fake crewai packages, then take the fakes out
    of sys.modules again so no other test sees them. Returns (module, bus, E)."""
    bus = FakeBus()
    E = types.SimpleNamespace(**{n: type(n, (FakeEvent,), {}) for n in EVENTS + ("A2ADelegationStartedEvent",)})
    events = types.ModuleType("crewai.events")
    for n in EVENTS:
        setattr(events, n, getattr(E, n))

    class BaseEventListener:
        def __init__(self):
            self.setup_listeners(bus)

    events.BaseEventListener = BaseEventListener
    a2a = types.ModuleType("crewai.events.types.a2a_events")
    a2a.A2ADelegationStartedEvent = E.A2ADelegationStartedEvent
    mods = {"crewai": types.ModuleType("crewai"), "crewai.events": events,
            "crewai.events.types": types.ModuleType("crewai.events.types"), "crewai.events.types.a2a_events": a2a}
    sys.modules.pop("atap.adapters.crewai", None)
    sys.modules.update(mods)
    try:
        return importlib.import_module("atap.adapters.crewai"), bus, E
    finally:
        for name in mods:
            sys.modules.pop(name, None)
        sys.modules.pop("atap.adapters.crewai", None)


def ended(cls, start, ms=0, **kw):
    """The end event of `start`, as the real bus links it: started_event_id."""
    return cls(started_event_id=start.event_id, timestamp=start.timestamp + timedelta(milliseconds=ms), **kw)


class ImportTest(unittest.TestCase):
    def test_missing_framework_names_the_pip_package(self):
        r = subprocess.run([sys.executable, "-c", "import atap.adapters.crewai"], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(SRC)})
        if r.returncode == 0:
            self.skipTest("crewai is installed here")
        self.assertIn("pip install crewai", r.stderr)


class AdapterTest(unittest.TestCase):
    setUp = test_core.CoreTest.setUp
    tearDown = test_core.CoreTest.tearDown
    recorded = test_core.CoreTest.recorded

    def sent(self):
        return [json.loads(c["stdin"]) for c in self.recorded()]

    def run_fake(self):
        """One fake crew run through every handler."""
        cr, bus, E = load_adapter()
        cr.AtapListener(role="operator", decisions={"approved": "approve"})
        emit = bus.emit
        emit(E.CrewKickoffStartedEvent(crew_name="main crew", inputs={"q": SECRET}))

        llm = emit(E.LLMCallStartedEvent(model="gpt-x", messages=[SECRET], call_id="c1"))
        emit(ended(E.LLMCallCompletedEvent, llm, 25, model="gpt-x", response=f"say {SECRET}",
                   usage={"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}))
        # The bus runs handlers on a thread pool: an end may be handled before its start.
        llm = E.LLMCallStartedEvent(model="claude-x", messages=[SECRET], call_id="c2")
        emit(ended(E.LLMCallCompletedEvent, llm, 4, model="claude-x", response=SECRET,
                   usage={"input_tokens": 2, "output_tokens": 1}))
        emit(llm)
        llm = emit(E.LLMCallStartedEvent(model="gpt-x", messages=[SECRET], call_id="c3"))
        emit(ended(E.LLMCallFailedEvent, llm, 5, model="gpt-x", error=SECRET))

        tool = emit(E.ToolUsageStartedEvent(tool_name="web search", tool_args={"q": SECRET}))
        emit(ended(E.ToolUsageFinishedEvent, tool, 12, tool_name="web search", tool_args={"q": SECRET},
                   output=f"result {SECRET}"))
        tool = emit(E.ToolUsageStartedEvent(tool_name="web search", tool_args={"q": SECRET}))
        emit(ended(E.ToolUsageErrorEvent, tool, 3, tool_name="web search", tool_args={"q": SECRET}, error=SECRET))
        mcp = emit(E.MCPToolExecutionStartedEvent(tool_name="read file", tool_args={"path": SECRET}))
        emit(ended(E.MCPToolExecutionCompletedEvent, mcp, 2, tool_name="read file", result=SECRET))
        mcp = emit(E.MCPToolExecutionStartedEvent(tool_name="read file", tool_args={"path": SECRET}))
        emit(ended(E.MCPToolExecutionFailedEvent, mcp, 1, tool_name="read file", error=SECRET))

        emit(E.A2ADelegationStartedEvent(agent_role="manager", a2a_agent_name="remote agent", task_description=SECRET))
        emit(E.HumanFeedbackReceivedEvent(flow_name="review", method_name="check", feedback=SECRET, outcome="approved"))
        return cr, bus, E

    def test_handlers_record_schema_shaped_payloads(self):
        self.run_fake()
        sent = self.sent()
        self.assertEqual([s["event_type"].split(":")[1] for s in sent],
                         ["session_started", "model_called", "model_called", "tool_called", "tool_called",
                          "tool_called", "tool_called", "handoff", "human_decision"])
        for s in sent:
            check(self, s)
        p = [s["payload"] for s in sent]
        self.assertEqual((p[0]["agent"], p[0]["framework"]), ("main-crew", "crewai"))
        self.assertEqual((p[1]["model"], p[1]["duration_ms"], p[1]["input_tokens"], p[1]["output_tokens"]),
                         ("gpt-x", 25, 7, 3))
        self.assertEqual(p[1]["output_sha256"], agent_tools.sha(f"say {SECRET}"))
        self.assertEqual((p[2]["model"], p[2]["duration_ms"], p[2]["input_tokens"]), ("claude-x", 4, 2))
        self.assertEqual((p[3]["tool"], p[3]["outcome"], p[3]["duration_ms"]), ("web-search", "ok", 12))
        self.assertEqual(p[3]["input_sha256"], agent_tools.sha({"q": SECRET}))
        self.assertEqual(p[3]["output_sha256"], agent_tools.sha(f"result {SECRET}"))
        self.assertEqual((p[4]["outcome"], p[4]["duration_ms"]), ("error", 3))
        self.assertNotIn("output_sha256", p[4])
        self.assertEqual((p[5]["tool"], p[5]["outcome"]), ("read-file", "ok"))
        self.assertEqual(p[5]["output_sha256"], agent_tools.sha(SECRET))
        self.assertEqual((p[6]["tool"], p[6]["outcome"]), ("read-file", "error"))
        self.assertEqual((p[7]["from_agent"], p[7]["to_agent"]), ("manager", "remote-agent"))
        self.assertEqual((p[8]["role"], p[8]["decision"], p[8]["channel"]), ("operator", "approve", "crewai"))
        self.assertEqual(p[8]["subject_sha256"], agent_tools.sha({"flow": "review", "method": "check", "feedback": SECRET}))

    def test_raw_values_never_sent(self):
        self.run_fake()
        self.assertTrue(self.recorded())
        for c in self.recorded():
            self.assertNotIn(SECRET, c["stdin"])
            self.assertNotIn("TOKEN", c["stdin"])

    def test_atap_off_records_nothing(self):
        os.environ["ATAP_OFF"] = "1"
        self.run_fake()
        self.assertEqual(self.recorded(), [])

    def test_unpaired_and_broken_events_never_raise(self):
        cr, bus, E = load_adapter()
        listener = cr.AtapListener()
        # An end whose start was never seen (the listener created mid-call), and
        # a start that never ends: held, nothing recorded, nothing raised.
        bus.emit(E.ToolUsageErrorEvent(started_event_id="gone", timestamp=T0, tool_name="t", error=SECRET))
        bus.emit(E.LLMCallStartedEvent(model="m", call_id="c"))
        # Boom raises on every attribute: each handler must swallow it.
        for cls in [getattr(E, n) for n in EVENTS] + [E.A2ADelegationStartedEvent]:
            bus.handlers[cls][0](None, Boom())
        # A pair missing fields: the recording raises inside, the bus goes on.
        start = bus.emit(E.ToolUsageStartedEvent(tool_name="t"))
        bus.emit(ended(E.ToolUsageFinishedEvent, start))
        self.assertEqual(self.recorded(), [])
        self.assertEqual(len(listener._pending), 2)
        # The witness itself failing is no different: the run goes on.
        os.environ["ATAP_WITNESS"] = "/nonexistent"
        self.run_fake()

    def test_invalid_human_decision_records_nothing(self):
        cr, bus, E = load_adapter()
        cr.AtapListener(role="Josh")
        bus.emit(E.HumanFeedbackReceivedEvent(flow_name="f", method_name="m", feedback="x", outcome="approve"))
        cr, bus, E = load_adapter()
        cr.AtapListener()
        for outcome in ("maybe", None):
            bus.emit(E.HumanFeedbackReceivedEvent(flow_name="f", method_name="m", feedback="x", outcome=outcome))
        bus.emit(E.A2ADelegationStartedEvent(agent_role="manager", a2a_agent_name=None))
        self.assertEqual(self.recorded(), [])


# The real framework: a two-agent Crew on a scripted BaseLLM (each call()
# emits the LLM call events as CrewAI's providers do). The manager calls a
# tool, a raising tool, then delegates to the worker. Then real event objects
# emitted on the real bus for what needs a server or a human: MCP, a failed
# LLM call, A2A, human feedback. Prints what was sent as JSON.
SCRIPT = r'''
import json, sys
import atap.agent_tools as at
from crewai import Agent, Crew, Task
from crewai.events import (crewai_event_bus, HumanFeedbackReceivedEvent, LLMCallStartedEvent, LLMCallFailedEvent,
                           MCPToolExecutionStartedEvent, MCPToolExecutionCompletedEvent, MCPToolExecutionFailedEvent)
from crewai.events.types.a2a_events import A2ADelegationStartedEvent
from crewai.events.types.llm_events import LLMCallType
from crewai.llms.base_llm import BaseLLM, llm_call_context
from crewai.tools import tool
from atap.adapters.crewai import AtapListener

SECRET = sys.argv[1]
sent = []
real = at.event
def spy(type, payload, cwd="."):
    sent.append({"event_type": type, "payload": payload, "signed": real(type, payload, cwd) is not None})
    return sent[-1]["signed"]
at.event = spy
AtapListener(role="operator", decisions={"approved": "approve"})

class Scripted(BaseLLM):
    def __init__(self, replies):
        super().__init__(model="scripted-llm")
        self._replies = iter(replies)
    def supports_function_calling(self):
        return False
    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None, from_agent=None, response_model=None):
        with llm_call_context():
            self._emit_call_started_event(messages=messages, from_task=from_task, from_agent=from_agent)
            reply = next(self._replies)
            self._emit_call_completed_event(reply, LLMCallType.LLM_CALL, from_task, from_agent, messages,
                                            usage={"prompt_tokens": 5, "completion_tokens": 2})
            return reply

@tool("lookup")
def lookup(q: str) -> str:
    """Look something up."""
    return "result " + q

@tool("boom")
def boom(q: str) -> str:
    """Fail."""
    raise ValueError(SECRET)

worker = Agent(role="worker", goal="help", backstory="b", llm=Scripted(["Thought: x\nFinal Answer: worker " + SECRET]))
manager = Agent(role="manager", goal="lead", backstory="b", allow_delegation=True, tools=[lookup, boom], max_iter=6, llm=Scripted([
    'Thought: look\nAction: lookup\nAction Input: {"q": "%s"}' % SECRET,
    'Thought: fail\nAction: boom\nAction Input: {"q": "%s"}' % SECRET,
    'Thought: delegate\nAction: Delegate work to coworker\nAction Input: {"task": "%s", "context": "c", "coworker": "worker"}' % SECRET,
    'Thought: done\nFinal Answer: done ' + SECRET]))
crew = Crew(name="main crew", agents=[manager, worker], tasks=[Task(description=SECRET, expected_output="x", agent=manager)])
out = {"final": str(crew.kickoff())}
crewai_event_bus.flush()
out["after_crew"] = len(sent)

def emit(event):
    crewai_event_bus.emit(None, event)
mcp = dict(server_name="files", server_url="stdio", transport_type="stdio", tool_name="read file", tool_args={"path": SECRET})
emit(MCPToolExecutionStartedEvent(**mcp))
emit(MCPToolExecutionCompletedEvent(**mcp, result=SECRET, execution_duration_ms=3))
emit(MCPToolExecutionStartedEvent(**mcp))
emit(MCPToolExecutionFailedEvent(**mcp, error=SECRET))
with llm_call_context():
    emit(LLMCallStartedEvent(model="scripted-llm", messages=SECRET, call_id="x"))
    emit(LLMCallFailedEvent(model="scripted-llm", error=SECRET, call_id="x"))
emit(A2ADelegationStartedEvent(endpoint="https://peer.example", task_description=SECRET, agent_id="remote-id",
                               a2a_agent_name="remote agent", from_agent=manager))
emit(HumanFeedbackReceivedEvent(flow_name="review flow", method_name="review", feedback=SECRET, outcome="approved"))
crewai_event_bus.flush()
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
            r = subprocess.run([py, "-m", "pip", "install", "-q", "--disable-pip-version-check", "crewai"],
                               capture_output=True, text=True, timeout=900)
        except (subprocess.SubprocessError, OSError) as e:
            reason = f"cannot create a venv with crewai: {type(e).__name__}"
            print(f"\nRealFrameworkTest skipped: {reason}", file=sys.stderr)
            self.skipTest(reason)
        if r.returncode != 0:
            reason = f"pip install crewai failed (exit {r.returncode}): {r.stderr.strip()[-300:]}"
            print(f"\nRealFrameworkTest skipped: {reason}", file=sys.stderr)
            self.skipTest(reason)
        return py

    def test_real_framework_run_block_receipt_verify(self):
        py = self.venv_python()
        versions = subprocess.run([py, "-c", "from importlib.metadata import version as v; print('crewai', v('crewai'))"],
                                  capture_output=True, text=True).stdout.strip()
        print(f"\nRealFrameworkTest: {versions}", file=sys.stderr)
        subprocess.run([os.environ["ATAP_WITNESS"], "init", "--force", "--profile", "tunnelmind:agent_tools:v1"],
                       check=True, capture_output=True)
        script = self.root / "run_crewai.py"
        script.write_text(SCRIPT)
        env = {**os.environ, "PYTHONPATH": str(SRC), "CREWAI_DISABLE_TELEMETRY": "true", "OTEL_SDK_DISABLED": "true",
               "CREWAI_TRACING_ENABLED": "false"}
        env.pop("OPENAI_API_KEY", None)
        r = subprocess.run([py, str(script), SECRET], capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        sent = out["sent"]
        names = [s["event_type"].split(":")[1] for s in sent]
        p = [s["payload"] for s in sent]

        # The crew: one session for the whole kickoff, the worker's run included.
        self.assertEqual(out["final"], f"done {SECRET}")
        crew = p[:out["after_crew"]]
        self.assertEqual(names[:out["after_crew"]].count("session_started"), 1)
        self.assertEqual((p[0]["agent"], p[0]["framework"]), ("main-crew", "crewai"))
        models = [m for m, n in zip(crew, names) if n == "model_called"]
        self.assertEqual(len(models), 5)  # four manager replies, one worker reply
        self.assertEqual({(m["model"], m["input_tokens"], m["output_tokens"]) for m in models}, {("scripted-llm", 5, 2)})
        tools = [t for t, n in zip(crew, names) if n == "tool_called"]
        [lookup] = [t for t in tools if t["tool"] == "lookup"]
        self.assertEqual(lookup["outcome"], "ok")
        self.assertEqual(lookup["output_sha256"], agent_tools.sha(f"result {SECRET}"))
        # The findings: CrewAI retries a raising tool (one error per attempt),
        # and in-crew delegation is a tool usage, no handoff.
        booms = [t for t in tools if t["tool"] == "boom"]
        self.assertGreaterEqual(len(booms), 1)
        self.assertEqual({t["outcome"] for t in booms}, {"error"})
        [delegate] = [t for t in tools if t["tool"] == "Delegate-work-to-coworker"]
        self.assertEqual(delegate["outcome"], "ok")
        self.assertNotIn("handoff", names[:out["after_crew"]])

        # The emitted events (handled on the bus's thread pool, in any order):
        # MCP ok + error, the failed LLM call records nothing.
        rest = {}
        for s in sent[out["after_crew"]:]:
            rest.setdefault(s["event_type"].split(":")[1], []).append(s["payload"])
        self.assertEqual(sorted(rest), ["handoff", "human_decision", "tool_called"])
        self.assertEqual(sorted((t["tool"], t["outcome"]) for t in rest["tool_called"]), [("read-file", "error"), ("read-file", "ok")])
        [h] = rest["handoff"]
        self.assertEqual((h["from_agent"], h["to_agent"]), ("manager", "remote-agent"))
        [d] = rest["human_decision"]
        self.assertEqual((d["role"], d["decision"]), ("operator", "approve"))

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
