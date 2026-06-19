"""A real pause. Lets an agent actually wait — e.g. for a target to come back
after a reset/reboot — instead of immediately re-sending a request in a tight
loop. Optionally polls a host:port and returns the moment it is reachable, so the
agent doesn't burn the full duration when the service recovers early.

Meta-tool: handled by the orchestrator (no engagement state needed), available in
every active phase. Capped so it can never hang the engagement.
"""
import socket
import time

_MAX_WAIT = 180        # hard cap (s) — a single wait can never exceed this
_POLL_EVERY = 3        # seconds between reachability probes


def _reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def wait(seconds: int = 10, host: str | None = None, port: int | None = None) -> dict:
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        seconds = 10
    seconds = max(1, min(seconds, _MAX_WAIT))

    # Plain sleep when there's nothing to poll.
    if not (host and port):
        time.sleep(seconds)
        return {"waited_s": seconds, "note": f"Waited {seconds}s."}

    # Poll the host:port and return as soon as it's back (or on timeout).
    start = time.monotonic()
    deadline = start + seconds
    attempts = 0
    while True:
        attempts += 1
        if _reachable(host, int(port)):
            waited = round(time.monotonic() - start, 1)
            return {"reachable": True, "host": host, "port": int(port),
                    "waited_s": waited, "attempts": attempts,
                    "note": f"{host}:{port} reachable after {waited}s."}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            waited = round(time.monotonic() - start, 1)
            return {"reachable": False, "host": host, "port": int(port),
                    "waited_s": waited, "attempts": attempts,
                    "note": f"{host}:{port} still not reachable after {waited}s — "
                            "it may need longer, or the host/port is wrong."}
        time.sleep(min(_POLL_EVERY, remaining))


TOOL_DEFINITION = {
    "name": "wait",
    "description": (
        "Actually pause for a number of seconds — use this to WAIT instead of immediately "
        "re-sending a request when something needs time (a target rebooting or resetting, a "
        "service restarting, a scheduled job, rate-limit backoff). Re-sending in a tight loop "
        "does not give the target time to recover; this does. Optionally pass host + port and it "
        "polls that endpoint, returning the instant it becomes reachable (so you don't wait the "
        f"full time if it comes back early). Capped at {_MAX_WAIT}s per call — for longer waits, "
        "call it again. Default 10s."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "seconds": {
                "type": "integer",
                "description": f"How long to wait, in seconds (1–{_MAX_WAIT}). Default 10.",
            },
            "host": {
                "type": "string",
                "description": "Optional host/IP to poll for reachability — returns as soon as it's up.",
            },
            "port": {
                "type": "integer",
                "description": "Port to poll on `host` (required if host is given).",
            },
        },
    },
}
