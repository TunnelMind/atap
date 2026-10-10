"""agent_tools helpers: build tunnelmind:agent_tools:v1 payloads and record them.

The framework adapters (atap.adapters.*) map their hooks onto these. Each
builder shapes its inputs to the profile's schema
(profiles/profiles/tunnelmind-agent-tools-v1/schemas/witness-events.schema.json)
before it calls atap.event: names go through ident(), raw arguments, results,
prompts and outputs only ever through sha(), in this process. Every event is
evidence "asserted": an adapter is the agent's own code (profile.md §5).

As the rest of the package, these never raise: a refusal, or any unexpected
error, returns None. ATAP_OFF=1 is honored by atap.event itself.
"""

import hashlib
import json
import re

from . import event
from .code import _int, _now

IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def ident(name):
    """A framework's configured name mapped onto the identifier pattern:
    other chars → `-`, leading non-alphanumerics dropped, trimmed to 64.
    None when nothing is left (or `name` is not a str)."""
    if not isinstance(name, str):
        return None
    s = re.sub(r"^[^A-Za-z0-9]+", "", re.sub(r"[^A-Za-z0-9._:/-]", "-", name))[:64]
    return s if IDENT.fullmatch(s) else None


def sha(value):
    """sha256 hex of a str/bytes, else of its sorted-key JSON (str() for the
    rest). The value itself never leaves this process."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    elif not isinstance(value, (bytes, bytearray)):
        value = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _sha(v):
    return isinstance(v, str) and SHA256.fullmatch(v) is not None


def _count(v):
    return _int(v) and v >= 0


def _record(name, fields):
    return event(f"agent_tools:{name}", {"timestamp": _now(), "evidence": "asserted", **fields})


def session_started(agent, framework, model=None):
    try:
        fields = {"agent": ident(agent), "framework": ident(framework)}
        if None in fields.values():
            return None
        if ident(model):
            fields["model"] = ident(model)
        return _record("session_started", fields)
    except Exception:
        return None


def tool_called(tool, input_sha256, outcome, duration_ms, output_sha256=None):
    try:
        tool = ident(tool)
        if not (tool and _sha(input_sha256) and outcome in ("ok", "error", "denied") and _count(duration_ms)):
            return None
        fields = {"tool": tool, "input_sha256": input_sha256, "outcome": outcome, "duration_ms": duration_ms}
        # The schema: output_sha256 is absent when the call errored or was denied.
        if outcome == "ok" and _sha(output_sha256):
            fields["output_sha256"] = output_sha256
        return _record("tool_called", fields)
    except Exception:
        return None


def model_called(model, duration_ms, output_sha256, input_tokens=None, output_tokens=None):
    try:
        model = ident(model)
        if not (model and _count(duration_ms) and _sha(output_sha256)):
            return None
        fields = {"model": model, "duration_ms": duration_ms, "output_sha256": output_sha256}
        # Token counts only where the framework reported them.
        for k, v in (("input_tokens", input_tokens), ("output_tokens", output_tokens)):
            if _count(v):
                fields[k] = v
        return _record("model_called", fields)
    except Exception:
        return None


def handoff(from_agent, to_agent):
    try:
        fields = {"from_agent": ident(from_agent), "to_agent": ident(to_agent)}
        if None in fields.values():
            return None
        return _record("handoff", fields)
    except Exception:
        return None


def human_decision(role, decision, subject_sha256, channel=None):
    """A human's decision, by role only: never the person (ATAP §7.6)."""
    try:
        if not (role in ("owner", "operator", "user") and decision in ("approve", "reject", "edit") and _sha(subject_sha256)):
            return None
        fields = {"role": role, "decision": decision, "subject_sha256": subject_sha256}
        if ident(channel):
            fields["channel"] = ident(channel)
        return _record("human_decision", fields)
    except Exception:
        return None
