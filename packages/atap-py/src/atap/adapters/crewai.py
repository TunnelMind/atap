"""ATAP for CrewAI (pip install crewai).

    from atap.adapters.crewai import AtapListener
    AtapListener()  # once, before kickoff: it registers on crewai_event_bus

Maps CrewAI's event bus onto tunnelmind:agent_tools:v1 events:
session_started ← CrewKickoffStartedEvent (agent = the crew's name);
model_called ← LLMCallStartedEvent + LLMCallCompletedEvent (hashes response,
tokens from usage; LLMCallFailedEvent records nothing, the schema has no model
outcome); tool_called ← ToolUsageStartedEvent + ToolUsageFinishedEvent ("ok")
or ToolUsageErrorEvent ("error"), and the same for MCPToolExecutionStarted /
Completed / Failed; handoff ← A2ADelegationStartedEvent (from the delegating
agent's role to the remote agent card's name); human_decision ← HumanFeedbackReceivedEvent
(Flows' @human_feedback): its `outcome` mapped through `decisions` (default:
taken as is) must be approve|reject|edit, the role is the listener's `role`
(default "user"), the subject the hash of flow, method and feedback.

Every handler catches its own exceptions and records nothing on failure.
Tool arguments, results, LLM responses and feedback are only hashed, in this
process.

Verified against crewai 1.15.27 in tests/test_adapter_crewai.py (a real Crew
on a scripted BaseLLM, no network LLM):
- Durations: no LLM event carries one. ToolUsageFinishedEvent has
  started_at/finished_at and MCPToolExecutionCompletedEvent
  execution_duration_ms, but ToolUsageErrorEvent has neither. So every
  duration here is end.timestamp - start.timestamp, the pair matched by the
  end event's started_event_id (the bus sets it to the start's event_id for
  all six pairs). The bus runs sync handlers on a 10-thread pool, so an end
  can be handled before its start: whichever comes second records.
- Tokens: LLMCallCompletedEvent.usage is the provider's raw dict, so
  input_tokens/output_tokens or prompt_tokens/completion_tokens.
- In-crew delegation (allow_delegation=True) emits no delegation or handoff
  event: it is a ToolUsageStarted/Finished pair for the tool "Delegate work to
  coworker" (or "Ask question to coworker") around the coworker's own run, so
  it is recorded as a tool_called, not a handoff.
- A tool that raises is retried by CrewAI: one ToolUsageErrorEvent, so one
  "error" tool_called, per attempt (three for one call in the test).
- A2ADelegationStartedEvent: its validator moves from_agent into agent_role
  and overwrites the remote agent_id with the local agent's id, so the remote
  agent is named by a2a_agent_name (its agent card's name); no name, no event.
Limits: A2A, MCP and human feedback were checked with real event objects
emitted on the bus, not from a live A2A server, MCP server or human.
"""

import threading

try:
    from crewai.events import (
        BaseEventListener,
        CrewKickoffStartedEvent,
        HumanFeedbackReceivedEvent,
        LLMCallCompletedEvent,
        LLMCallFailedEvent,
        LLMCallStartedEvent,
        MCPToolExecutionCompletedEvent,
        MCPToolExecutionFailedEvent,
        MCPToolExecutionStartedEvent,
        ToolUsageErrorEvent,
        ToolUsageFinishedEvent,
        ToolUsageStartedEvent,
    )
    from crewai.events.types.a2a_events import A2ADelegationStartedEvent
except ImportError:
    raise ImportError("atap.adapters.crewai needs CrewAI: pip install crewai") from None

from .. import agent_tools as at

FRAMEWORK = "crewai"


def _ms(start, end):
    return max(0, int((end.timestamp - start.timestamp).total_seconds() * 1000))


def _tokens(usage, *keys):
    return next((usage[k] for k in keys if k in usage), None)


def _record_model(start, end):
    if isinstance(end, LLMCallFailedEvent):
        return
    usage = end.usage or {}
    at.model_called(end.model or start.model, _ms(start, end), at.sha(end.response),
                    _tokens(usage, "input_tokens", "prompt_tokens"),
                    _tokens(usage, "output_tokens", "completion_tokens"))


def _record_tool(start, end):
    if isinstance(end, (ToolUsageErrorEvent, MCPToolExecutionFailedEvent)):
        at.tool_called(start.tool_name, at.sha(start.tool_args), "error", _ms(start, end))
    else:
        output = end.output if isinstance(end, ToolUsageFinishedEvent) else end.result
        at.tool_called(start.tool_name, at.sha(start.tool_args), "ok", _ms(start, end), at.sha(output))


class AtapListener(BaseEventListener):
    """Records every crew run on crewai_event_bus with ATAP. Create it once."""

    def __init__(self, role="user", decisions=None):
        self.role = role
        self.decisions = decisions or {}
        self._pending = {}
        self._lock = threading.Lock()
        super().__init__()  # calls setup_listeners(crewai_event_bus)

    def _meet(self, event, is_start, record):
        """Hold one side of a start/end pair until the other arrives, then record."""
        try:
            key = event.event_id if is_start else event.started_event_id
            if key is None:
                return
            with self._lock:
                other = self._pending.pop(key, None)
                if other is None:
                    self._pending[key] = event
                    return
            if is_start:
                record(event, other)
            else:
                record(other, event)
        except Exception:
            pass

    def _pair_handlers(self, record):
        # Built here, not as loop-default lambdas: the bus passes a third
        # (state) argument to any handler that takes three parameters.
        def on_start(source, event):
            self._meet(event, True, record)

        def on_end(source, event):
            self._meet(event, False, record)

        return on_start, on_end

    def setup_listeners(self, crewai_event_bus):
        bus = crewai_event_bus

        @bus.on(CrewKickoffStartedEvent)
        def on_kickoff(source, event):
            try:
                at.session_started(event.crew_name, FRAMEWORK)
            except Exception:
                pass

        for start_cls, end_classes, record in (
                (LLMCallStartedEvent, (LLMCallCompletedEvent, LLMCallFailedEvent), _record_model),
                (ToolUsageStartedEvent, (ToolUsageFinishedEvent, ToolUsageErrorEvent), _record_tool),
                (MCPToolExecutionStartedEvent, (MCPToolExecutionCompletedEvent, MCPToolExecutionFailedEvent), _record_tool)):
            on_start, on_end = self._pair_handlers(record)
            bus.on(start_cls)(on_start)
            for end_cls in end_classes:
                bus.on(end_cls)(on_end)

        @bus.on(A2ADelegationStartedEvent)
        def on_a2a(source, event):
            try:
                # Not event.agent_id: given from_agent, the event overwrites it
                # with the local agent's id (see the module docstring).
                at.handoff(event.agent_role, event.a2a_agent_name)
            except Exception:
                pass

        @bus.on(HumanFeedbackReceivedEvent)
        def on_feedback(source, event):
            try:
                decision = self.decisions.get(event.outcome, event.outcome)
                subject = {"flow": event.flow_name, "method": event.method_name, "feedback": event.feedback}
                at.human_decision(self.role, decision, at.sha(subject), FRAMEWORK)
            except Exception:
                pass
