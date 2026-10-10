"""ATAP for the OpenAI Agents SDK (pip install openai-agents).

    from atap.adapters.openai_agents import AtapRunHooks
    result = await Runner.run(agent, input, hooks=AtapRunHooks())

Maps the SDK's RunHooks onto tunnelmind:agent_tools:v1 events:
session_started ← on_agent_start of a run's first agent (not a handoff target);
model_called ← on_llm_start + on_llm_end; tool_called ← on_tool_start +
on_tool_end; handoff ← on_handoff; human_decision ← record_approval(), which
the app calls in place of state.approve()/state.reject().

Every hook catches its own exceptions, records nothing on failure, returns
None and never touches what the SDK passes it: tool arguments, results and
model output are only hashed, in this process.

How a tool exception reaches the hooks (verified against openai-agents 0.23.1
in tests/test_adapter_openai_agents.py; there is no on_tool_error hook):
- Default failure_error_function: the SDK catches the exception and
  on_tool_end fires with its fixed message ("An error occurred while running
  the tool. Please try again.") as `result`. No flag on the hook's context
  says it failed, so this adapter records outcome "error" when `result` is
  exactly that message.
- A custom failure_error_function: on_tool_end fires with whatever it
  returned. Indistinguishable from a result from hooks alone, so it is
  recorded as "ok" (limit; a formatter that returns a fixed string can be
  told apart by whoever reads the output hash).
- failure_error_function=None: the exception ends the run and on_tool_end
  never fires. Call hooks.flush() after Runner.run raises to record each
  started-but-unfinished tool as "error".

Other limits: input_sha256 hashes ToolContext.tool_arguments; tools whose
hooks get a plain RunContextWrapper (computer, shell) expose no arguments
there, so their input_sha256 is sha256(""). A RunConfig(model=...) override
is not visible to the LLM hooks; the model id comes from agent.model.
"""

import time

try:
    from agents import RunHooks
    from agents.tool import default_tool_error_function
except ImportError:
    raise ImportError("atap.adapters.openai_agents needs the OpenAI Agents SDK: pip install openai-agents") from None

from .. import agent_tools as at

FRAMEWORK = "openai-agents"
# The fixed text the SDK's default failure_error_function hands to the model.
DEFAULT_TOOL_ERROR = default_tool_error_function(None, None)


def _ms(t0):
    return max(0, int((time.monotonic() - t0) * 1000))


def _model(agent):
    # agent.model is a str, a Model object or None (the SDK default).
    m = agent.model
    if m is None:
        from agents.models import get_default_model
        return get_default_model()
    if isinstance(m, str):
        return m
    name = getattr(m, "model", None)
    return name if isinstance(name, str) else type(m).__name__


class AtapRunHooks(RunHooks):
    """RunHooks that record the run with ATAP. One instance per Runner.run
    call (it holds the run's in-flight timers)."""

    def __init__(self):
        super().__init__()
        self._llm_t0 = None
        self._tools = {}  # call id → (tool name, input sha256, start time)
        self._handoff_to = None

    async def on_agent_start(self, context, agent):
        try:
            # on_agent_start also fires for a handoff's target: that is the
            # same session, already recorded by on_handoff.
            if self._handoff_to is not None and agent is self._handoff_to:
                self._handoff_to = None
                return None
            at.session_started(agent.name, FRAMEWORK, _model(agent))
        except Exception:
            pass
        return None

    async def on_llm_start(self, context, agent, system_prompt, input_items):
        try:
            self._llm_t0 = time.monotonic()
        except Exception:
            pass
        return None

    async def on_llm_end(self, context, agent, response):
        try:
            if self._llm_t0 is not None:
                usage = getattr(response, "usage", None)
                at.model_called(_model(agent), _ms(self._llm_t0), at.sha(response.output),
                                getattr(usage, "input_tokens", None), getattr(usage, "output_tokens", None))
            self._llm_t0 = None
        except Exception:
            pass
        return None

    async def on_tool_start(self, context, agent, tool):
        try:
            args = getattr(context, "tool_arguments", None)
            key = getattr(context, "tool_call_id", None) or id(context)
            self._tools[key] = (tool.name, at.sha(args if isinstance(args, str) else ""), time.monotonic())
        except Exception:
            pass
        return None

    async def on_tool_end(self, context, agent, tool, result):
        try:
            started = self._tools.pop(getattr(context, "tool_call_id", None) or id(context), None)
            if started is not None:
                name, input_sha, t0 = started
                if isinstance(result, str) and result == DEFAULT_TOOL_ERROR:
                    at.tool_called(name, input_sha, "error", _ms(t0))
                else:
                    at.tool_called(name, input_sha, "ok", _ms(t0), at.sha(result))
        except Exception:
            pass
        return None

    async def on_handoff(self, context, from_agent, to_agent):
        try:
            self._handoff_to = to_agent
            at.handoff(from_agent.name, to_agent.name)
        except Exception:
            pass
        return None

    def flush(self):
        """Record every tool that started but never ended as "error": what a
        tool raising under failure_error_function=None leaves behind. Call it
        after Runner.run raises. duration_ms then runs to this call."""
        try:
            for name, input_sha, t0 in self._tools.values():
                at.tool_called(name, input_sha, "error", _ms(t0))
            self._tools.clear()
        except Exception:
            pass
        return None


def record_approval(state, item, approved):
    """Approve or reject an interruption (a tool declared with needs_approval)
    and record the human's decision, by role "user": the person is never
    recorded. `state` is result.to_state(), `item` one of result.interruptions.

    state.approve()/state.reject() run first and outside the guard, so an SDK
    error there reaches the app exactly as without ATAP; with state=None only
    the record is made. The record itself never raises."""
    if state is not None:
        (state.approve if approved else state.reject)(item)
    try:
        subject = at.sha({"tool": getattr(item, "name", None), "arguments": getattr(item, "arguments", None)})
        at.human_decision("user", "approve" if approved else "reject", subject, FRAMEWORK)
    except Exception:
        pass
    return None
