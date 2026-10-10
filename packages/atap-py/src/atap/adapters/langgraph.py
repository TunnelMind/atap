"""ATAP for LangChain v1 agents, which run on LangGraph (pip install langchain langgraph).

    from atap.adapters.langgraph import AtapMiddleware
    agent = create_agent(model, tools, middleware=[AtapMiddleware()])

Maps create_agent middleware onto tunnelmind:agent_tools:v1 events:
session_started ← before_agent (once per invoke/ainvoke; the agent id is the
`name` given to AtapMiddleware, default "agent": middleware cannot see
create_agent's own name); model_called ← wrap_model_call / awrap_model_call
(times the handler, hashes response.result, tokens from the AIMessage's
usage_metadata["input_tokens"/"output_tokens"]); tool_called ← wrap_tool_call /
awrap_tool_call; handoff ← record_handoff(), called inside the handoff tool;
human_decision ← record_human_decision(), called where the value passed back
with Command(resume=...) is read.

Every recording catches its own exceptions and records nothing on failure.
Each wrapper returns the handler's result unchanged and lets the handler's
exception reach the app unchanged. Tool arguments, results and model output
are only hashed, in this process.

Tool outcomes (verified against langchain 1.4.4 / langchain-core 1.6.9 /
langgraph 1.2.14 in tests/test_adapter_langgraph.py, sync and async):
- A tool that raises: the default handle_tool_errors re-raises it through the
  handler, so it is recorded as "error" and re-raised, ending the run.
- Arguments that fail the tool's schema: the handler returns a ToolMessage
  with status "error" (the run goes on); recorded as "error".
- A langgraph GraphBubbleUp (interrupt(), Command.PARENT) is control flow,
  not a failure: nothing is recorded and the tool runs again on resume.

Limits: session_started carries no model (before_agent is not given one); the
model id is the chat model's model_name/model, else its class name.
"""

import time

try:
    from langchain.agents.middleware import AgentMiddleware
    from langgraph.errors import GraphBubbleUp
except ImportError:
    raise ImportError("atap.adapters.langgraph needs LangChain v1: pip install langchain langgraph") from None

from .. import agent_tools as at

FRAMEWORK = "langgraph"


def _ms(t0):
    return max(0, int((time.monotonic() - t0) * 1000))


def _model(model):
    # ChatOpenAI and most providers carry model_name; ChatAnthropic and others `model`.
    for attr in ("model_name", "model"):
        name = getattr(model, attr, None)
        if isinstance(name, str):
            return name
    return type(model).__name__


def _record_model(request, response, t0):
    try:
        # The handler gives a ModelResponse (.result: list of messages); a
        # middleware further in may hand back a bare AIMessage.
        messages = getattr(response, "result", None)
        if messages is None:
            messages = [response]
        usage = next((m.usage_metadata for m in reversed(messages) if getattr(m, "usage_metadata", None)), {})
        at.model_called(_model(request.model), _ms(t0), at.sha(messages),
                        usage.get("input_tokens"), usage.get("output_tokens"))
    except Exception:
        pass


def _record_tool(call, input_sha, t0, result=None, raised=False):
    try:
        if raised or getattr(result, "status", None) == "error":
            at.tool_called(call["name"], input_sha, "error", _ms(t0))
        else:
            # A ToolMessage's content, or the Command a handoff tool returns.
            at.tool_called(call["name"], input_sha, "ok", _ms(t0), at.sha(getattr(result, "content", result)))
    except Exception:
        pass


def _start_tool(request):
    try:
        call = request.tool_call
        return call, at.sha(call["args"])
    except Exception:
        return None, None


class AtapMiddleware(AgentMiddleware):
    """create_agent middleware that records the agent's runs with ATAP."""

    def __init__(self, name="agent"):
        super().__init__()
        # Not self.name: AgentMiddleware.name names this middleware's graph nodes.
        self.agent_name = name

    def before_agent(self, state, runtime):
        try:
            at.session_started(self.agent_name, FRAMEWORK)
        except Exception:
            pass
        return None

    def wrap_model_call(self, request, handler):
        t0 = time.monotonic()
        response = handler(request)  # a raise here reaches the app untouched, nothing recorded
        _record_model(request, response, t0)
        return response

    async def awrap_model_call(self, request, handler):
        t0 = time.monotonic()
        response = await handler(request)
        _record_model(request, response, t0)
        return response

    def wrap_tool_call(self, request, handler):
        call, input_sha = _start_tool(request)
        t0 = time.monotonic()
        try:
            result = handler(request)
        except GraphBubbleUp:
            raise
        except Exception:
            if call is not None:
                _record_tool(call, input_sha, t0, raised=True)
            raise
        if call is not None:
            _record_tool(call, input_sha, t0, result)
        return result

    async def awrap_tool_call(self, request, handler):
        call, input_sha = _start_tool(request)
        t0 = time.monotonic()
        try:
            result = await handler(request)
        except GraphBubbleUp:
            raise
        except Exception:
            if call is not None:
                _record_tool(call, input_sha, t0, raised=True)
            raise
        if call is not None:
            _record_tool(call, input_sha, t0, result)
        return result


def record_handoff(from_agent, to_agent):
    """Record a handoff; call it in the handoff tool that returns
    Command(goto=to_agent, graph=Command.PARENT). Never raises."""
    try:
        at.handoff(from_agent, to_agent)
    except Exception:
        pass
    return None


def record_human_decision(role, decision, subject):
    """Record a human's decision on an interrupt(...) once its resume value is
    read: role owner|operator|user, decision approve|reject|edit, `subject`
    any object (what was decided on), hashed here. The person is never
    recorded. Invalid role/decision record nothing. Never raises."""
    try:
        at.human_decision(role, decision, at.sha(subject), FRAMEWORK)
    except Exception:
        pass
    return None
