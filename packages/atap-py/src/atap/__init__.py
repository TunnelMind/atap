"""Record an agent's work in the project's .atap/ store.

A thin client of `atap-witness`, modeled on the Claude Code plugin's hook
(plugins/claude-code/scripts/atap-hook.mjs): every call is one subprocess with
JSON on stdin and stdout and a timeout. The CLI holds the one implementation
of the rules; there is no crypto here.

The rule above all: never break the caller. event/block/receipt return None on
any failure and append one fixed-text line to .atap/hook.log. ATAP_OFF=1, or
atap.off(), makes them silent no-ops; so does a project without .atap/.
verify() is the one call that reports failure, by return value.

Stdlib only: the package ships with no dependencies.
"""

import contextlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

__all__ = ["find_store", "event", "block", "receipt", "verify", "session", "off"]

LOG_CAP = 1024 * 1024  # hook.log stops growing at 1 MB
TIMEOUT = 8  # seconds per atap-witness call, as the plugin's hook
VERIFY_TIMEOUT = 120  # verify.sh shells out to jq/openssl/python3 per signature

# The same zero summary the plugin's session-end sends: this client sees no QA
# verdicts, merges or tokens, so it reports zeros rather than a guess.
ZERO_SUMMARY = {"tasks_accepted": 0, "tasks_rework": 0, "merged_changes": 0, "tokens": 0, "overturns": {}}

_off = False


def find_store(start="."):
    """The nearest .atap/ at or above `start` whose config.json parses to a
    JSON object (the same walk as atap-cli's findAtap), as a Path, else None."""
    try:
        d = Path(start).resolve()
        for p in (d, *d.parents):
            try:
                config = json.loads((p / ".atap" / "config.json").read_text("utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(config, dict):
                return p / ".atap"
    except Exception:
        pass
    return None


def _log(store, event, msg):
    # One line to hook.log. Never raises: logging is the last resort.
    try:
        f = store / "hook.log"
        # ponytail: past the cap new lines are dropped, not rotated (as the plugin).
        if f.exists() and f.stat().st_size >= LOG_CAP:
            return
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with f.open("a", encoding="utf-8") as fh:
            fh.write(f"{ts} {event} {str(msg)[:300]}\n")
    except Exception:
        pass


def _witness(args, input=None):
    """One `atap-witness <args>` run from the store's project; parsed stdout or None."""
    if _off or os.environ.get("ATAP_OFF") == "1":
        return None
    store = find_store()
    if store is None:
        return None
    # Never a path from the project: .atap/config.json can be committed, so a
    # cloned repo could name a script inside itself (the a8 security finding).
    # Only the user's own environment chooses the binary.
    bin = os.environ.get("ATAP_WITNESS") or "atap-witness"
    try:
        r = subprocess.run(
            [bin, *args],
            cwd=store.parent,
            input=json.dumps(input) if input is not None else "",
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
    except FileNotFoundError:
        _log(store, args[0], "atap-witness not found")
        return None
    except subprocess.TimeoutExpired:
        _log(store, args[0], f"atap-witness {args[0]} failed: killed")
        return None
    except Exception as e:
        _log(store, args[0], f"atap-witness {args[0]} failed: {type(e).__name__}")
        return None
    # Fixed text only: the CLI's own output may quote payload fields.
    if r.returncode != 0:
        _log(store, args[0], f"atap-witness {args[0]} failed: exit {r.returncode}")
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        _log(store, args[0], f"atap-witness {args[0]} failed: bad JSON on stdout")
        return None


def event(type, payload):
    """Witness one event under the store's AIT; the signed event, or None."""
    return _witness(["event"], {"event_type": type, "payload": payload})


def block(summary=None):
    """Close a block over the pending events; the block, or None."""
    return _witness(["block"], ZERO_SUMMARY if summary is None else summary)


def receipt(out):
    """Write a Receipt to directory `out`; the receipt, or None."""
    return _witness(["receipt", "--out", os.path.abspath(out)])


def _verify_sh():
    # The repo's verify.sh: ATAP_VERIFY_SH if set, else the first verify.sh at
    # or above this file (a repo checkout or editable install). An installed
    # wheel finds none, and verify() then reports verify_sh False, never a skip.
    env = os.environ.get("ATAP_VERIFY_SH")
    if env:
        return env
    for p in Path(__file__).resolve().parents:
        if (p / "verify.sh").is_file():
            return str(p / "verify.sh")
    return None


def _ok(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout).returncode == 0
    except Exception:
        return False


def verify(dir):
    """Check the Receipt in `dir` with BOTH verifiers, the CLI and verify.sh.
    Returns {"ok", "cli", "verify_sh"}; never raises."""
    dir = os.path.abspath(dir)
    cli = _ok([os.environ.get("ATAP_WITNESS") or "atap-witness", "verify", dir], VERIFY_TIMEOUT)
    sh = _verify_sh()
    # bash explicitly: a copied verify.sh may have lost its exec bit.
    vsh = sh is not None and _ok(["bash", sh, dir], VERIFY_TIMEOUT)
    return {"ok": cli and vsh, "cli": cli, "verify_sh": vsh}


@contextlib.contextmanager
def session(summary=None):
    """`with atap.session(): ...` closes a block on a clean exit. An exception
    inside propagates untouched and closes no block: a failed run is not a period."""
    yield
    block(summary)


def off():
    """Stop recording for the rest of the process, as ATAP_OFF=1."""
    global _off
    _off = True
