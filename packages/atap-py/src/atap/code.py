"""code_crew helpers: build tunnelmind:code_crew:v1 payloads and record them.

Each helper checks its inputs against the profile's schema
(profiles/profiles/tunnelmind-code-crew-v1/schemas/witness-events.schema.json)
before it calls atap.event, so a bad input never reaches the CLI. The schema
is the no-PII rule: every payload is additionalProperties:false, identifiers
admit no `@` or whitespace, and command text and output travel only as sha256.

As the rest of the package, these never raise: a refusal, or any unexpected
error, returns None. Nothing the caller passed is ever written to a log.
"""

import hashlib
import re
import subprocess
import sys
from datetime import datetime, timezone

from . import event

# Patterns from the schema's $defs. Always re.fullmatch: Python's `$` also
# matches before a trailing newline.
OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
ROLES = ("supervisor", "coder", "qa", "reviewer", "coordinator")
FINDINGS = ("critical", "high", "medium", "low")

# owner/repo from an https, ssh:// or scp-style (git@host:owner/repo) remote,
# the plugin hook's ownerRepo (plugins/claude-code/scripts/atap-hook.mjs).
REMOTE = re.compile(r"(?:[a-z][a-z0-9+.-]*://[^/]+/|[^@/\s]+@[^:/\s]+:)(.+?)(?:\.git)?/?", re.I)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _int(v):
    # bool is an int subclass; True must not pass as attempt 1 or a count.
    return isinstance(v, int) and not isinstance(v, bool)


def _id(v, pattern=OPAQUE_ID):
    return isinstance(v, str) and pattern.fullmatch(v) is not None


def _sha256(v):
    return hashlib.sha256(v.encode("utf-8") if isinstance(v, str) else bytes(v)).hexdigest()


def _owner_repo(url):
    url = url.strip()
    # file:// is a local path however it is spelled (file://localhost/a/b would
    # otherwise parse): the repo field is never a path.
    if url.lower().startswith("file:"):
        return None
    m = REMOTE.fullmatch(url)
    return m.group(1) if m and REPO.fullmatch(m.group(1)) else None


def _git(cwd, *args):
    # Trimmed stdout, or "" on any failure (no git, not a repo, no commit).
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def task_claimed(task_id, role, model):
    """An agent took a task. evidence asserted."""
    try:
        if not (_id(task_id) and role in ROLES and _id(model, MODEL)):
            return None
        return event("code_crew:task_claimed", {
            "timestamp": _now(), "evidence": "asserted", "task_id": task_id, "role": role, "model": model,
        })
    except Exception:
        return None


def change_committed(cwd="."):
    """HEAD of the repo at `cwd` was committed. evidence anchored: the sha is
    checkable in repo."""
    try:
        sha = _git(cwd, "rev-parse", "HEAD")
        if not GIT_SHA.fullmatch(sha):
            return None
        # A repo with no usable origin is named by its root commit instead:
        # local/<12 hex>, stable for the repo's life, no path or name in it.
        repo = _owner_repo(_git(cwd, "remote", "get-url", "origin"))
        if repo is None:
            root = _git(cwd, "rev-list", "--max-parents=0", "HEAD").split("\n")[-1]
            if not GIT_SHA.fullmatch(root):
                return None
            repo = f"local/{root[:12]}"
        return event("code_crew:change_committed", {
            "timestamp": _now(), "evidence": "anchored", "repo": repo, "commit_sha": sha,
        })
    except Exception:
        return None


def verify_run(command, exit_code, output):
    """A test/verify command ran. Only hashes of the command and its output are
    sent, never the text. evidence asserted."""
    try:
        if not (isinstance(command, (str, bytes)) and isinstance(output, (str, bytes)) and _int(exit_code)):
            return None
        return event("code_crew:verify_run", {
            "timestamp": _now(),
            "evidence": "asserted",
            "command_sha256": _sha256(command),
            "exit_code": max(-255, min(255, exit_code)),
            "output_sha256": _sha256(output),
        })
    except Exception:
        return None


def run_tests(command, cwd="."):
    """Run a test command, streaming its output through live, then record a
    verify_run of it. A list runs as-is (shell=False); a str runs under sh -c.
    Returns the child's exit code unchanged (negative when killed by a signal)."""
    argv = list(command) if isinstance(command, (list, tuple)) else ["sh", "-c", command]
    # A list command is hashed as its argv joined by single spaces.
    text = command if isinstance(command, str) else " ".join(map(str, command))
    out = getattr(sys.stdout, "buffer", None)
    chunks = []
    sys.stdout.flush()
    try:
        p = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError:
        # The program can't start: the shell's "command not found" code.
        code = 127
    else:
        with p.stdout:
            for chunk in iter(lambda: p.stdout.read1(65536), b""):
                chunks.append(chunk)
                if out is not None:
                    out.write(chunk)
                    out.flush()
                else:
                    sys.stdout.write(chunk.decode("utf-8", "replace"))
                    sys.stdout.flush()
        code = p.wait()
    try:
        verify_run(text, code, b"".join(chunks))
    except Exception:
        pass
    return code


def qa_verdict(task_id, verdict, attempt):
    """QA's verdict on a task attempt. evidence asserted."""
    try:
        if not (_id(task_id) and verdict in ("accepted", "rework") and _int(attempt) and attempt >= 1):
            return None
        return event("code_crew:qa_verdict", {
            "timestamp": _now(), "evidence": "asserted", "task_id": task_id, "verdict": verdict, "attempt": attempt,
        })
    except Exception:
        return None


def review_verdict(head_sha, verdict, findings):
    """A branch review at `head_sha`. findings is a dict of exactly
    critical/high/medium/low counts. evidence asserted."""
    try:
        if not (_id(head_sha, GIT_SHA) and verdict in ("pass", "fail") and isinstance(findings, dict)):
            return None
        if set(findings) != set(FINDINGS) or not all(_int(findings[k]) and findings[k] >= 0 for k in FINDINGS):
            return None
        return event("code_crew:review_verdict", {
            "timestamp": _now(),
            "evidence": "asserted",
            "head_sha": head_sha,
            "verdict": verdict,
            "findings": {k: findings[k] for k in FINDINGS},
        })
    except Exception:
        return None
