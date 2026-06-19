"""Killable subprocess runner + an engagement-scoped process registry.

Tools that shell out route through `proc.run(...)` instead of `subprocess.run(...)`.
Each live process is registered in a `ProcessRegistry` tagged with the job it
belongs to (or `None` for a synchronous/foreground tool call), so the operator
can terminate it on demand:

  * `/job kill <id>`  → `registry.kill_job(<id>)`     (one background job)
  * `/abort`          → `registry.kill_all()`         (everything in flight)

`proc.run` is a drop-in for the `subprocess.run(cmd, capture_output=True,
text=True, timeout=N, ...)` shape the tools use, and re-raises
`subprocess.TimeoutExpired` exactly like `subprocess.run` so existing handlers
keep working. The current binding (which registry / which job) is carried on a
`contextvars.ContextVar` set by the orchestrator (foreground) or the JobManager
(background) on the thread that runs the tool.
"""
from __future__ import annotations

import contextlib
import contextvars
import os
import signal
import subprocess
import threading
import uuid
from core.timeutil import now_local
from typing import Optional


class ProcessRegistry:
    """Thread-safe registry of live child processes, tagged by job id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: dict[str, dict] = {}   # handle id -> entry

    def register(self, popen: subprocess.Popen, job_id: Optional[str],
                 label: str, cmd) -> str:
        hid = uuid.uuid4().hex[:8]
        with self._lock:
            self._procs[hid] = {
                "popen":   popen,
                "job_id":  job_id,
                "label":   label,
                "cmd":     cmd,
                "started": now_local(),
            }
        return hid

    def deregister(self, hid: str) -> None:
        with self._lock:
            self._procs.pop(hid, None)

    def kill_job(self, job_id: str) -> int:
        """Terminate every live process tagged with job_id. Returns the count."""
        with self._lock:
            targets = [e for e in self._procs.values() if e["job_id"] == job_id]
        for e in targets:
            _kill(e["popen"])
        return len(targets)

    def kill_all(self, exempt=None) -> dict:
        """Terminate every live process, foreground and background, except those
        whose tool label is in `exempt` (left running). Returns
        {"killed": n, "skipped": [labels]}."""
        exempt = set(exempt or ())
        with self._lock:
            entries = list(self._procs.values())
        targets = [e for e in entries if e["label"] not in exempt]
        skipped = sorted({e["label"] for e in entries if e["label"] in exempt})
        for e in targets:
            _kill(e["popen"])
        return {"killed": len(targets), "skipped": skipped}

    def snapshot(self) -> list[dict]:
        now = now_local()
        with self._lock:
            return [{
                "job_id":    e["job_id"],
                "label":     e["label"],
                "runtime_s": round((now - e["started"]).total_seconds(), 1),
            } for e in self._procs.values()]


# ── current binding (set per-thread by orchestrator / JobManager) ─────────────
# value is (registry, job_id, label) or None.
_current: contextvars.ContextVar[Optional[tuple]] = contextvars.ContextVar(
    "proc_binding", default=None)


@contextlib.contextmanager
def bind(registry: Optional[ProcessRegistry], job_id: Optional[str], label: str):
    """Bind the calling thread's proc.run calls to a registry + job tag."""
    token = _current.set((registry, job_id, label) if registry is not None else None)
    try:
        yield
    finally:
        _current.reset(token)


def _kill(popen: subprocess.Popen, grace: float = 2.0) -> None:
    """Best-effort terminate of a process and its group: SIGTERM, then SIGKILL
    after a short grace if it is still alive. The escalation matters — tools like
    hashcat trap SIGTERM to checkpoint (and some scanners double-fork), so a single
    SIGTERM does not reliably kill them. SIGKILL cannot be caught or ignored."""
    if popen.poll() is not None:
        return                                  # already exited

    def _send(sig) -> None:
        if os.name == "posix":
            # Child was started in its own session (start_new_session=True), so
            # signal the whole group to catch children it spawned.
            try:
                os.killpg(os.getpgid(popen.pid), sig)
                return
            except (ProcessLookupError, PermissionError):
                pass
        # Non-POSIX, or the group signal failed: act on the process directly.
        with contextlib.suppress(Exception):
            popen.kill() if sig == getattr(signal, "SIGKILL", None) else popen.terminate()

    with contextlib.suppress(Exception):
        _send(signal.SIGTERM)
    try:
        popen.wait(timeout=grace)
        return                                  # exited on SIGTERM
    except Exception:                            # noqa: BLE001 — still alive, escalate
        pass
    with contextlib.suppress(Exception):
        _send(getattr(signal, "SIGKILL", signal.SIGTERM))


def run(cmd, *, capture_output: bool = False, text: bool = False,
        timeout: Optional[float] = None, env=None, input=None, cwd=None,
        stdout=None, stderr=None, stdin=None, check: bool = False,
        encoding=None, errors=None) -> subprocess.CompletedProcess:
    """Killable stand-in for subprocess.run for the kwargs the tools use.

    Registers the spawned process in the bound registry (if any) so it can be
    terminated mid-flight, then deregisters on completion. Re-raises
    subprocess.TimeoutExpired like subprocess.run does.
    """
    popen_kwargs: dict = {"text": text}
    if capture_output:
        popen_kwargs["stdout"] = subprocess.PIPE
        popen_kwargs["stderr"] = subprocess.PIPE
    else:
        if stdout is not None:
            popen_kwargs["stdout"] = stdout
        if stderr is not None:
            popen_kwargs["stderr"] = stderr
    if input is not None:
        popen_kwargs["stdin"] = subprocess.PIPE
    elif stdin is not None:
        popen_kwargs["stdin"] = stdin
    if env is not None:
        popen_kwargs["env"] = env
    if cwd is not None:
        popen_kwargs["cwd"] = cwd
    if encoding is not None:
        popen_kwargs["encoding"] = encoding
    if errors is not None:
        popen_kwargs["errors"] = errors
    if os.name == "posix":
        # Own session/process-group so a kill takes the whole tree, not just the
        # launcher (matters for tools that fork children, e.g. shells, wrappers).
        popen_kwargs["start_new_session"] = True

    popen = subprocess.Popen(cmd, **popen_kwargs)

    binding = _current.get()
    hid = None
    registry = None
    if binding is not None:
        registry, job_id, label = binding
        hid = registry.register(popen, job_id, label, cmd)

    try:
        out, err = popen.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(popen)
        out, err = popen.communicate()
        raise
    finally:
        if hid is not None and registry is not None:
            registry.deregister(hid)

    completed = subprocess.CompletedProcess(cmd, popen.returncode, out, err)
    if check and popen.returncode:
        raise subprocess.CalledProcessError(popen.returncode, cmd, out, err)
    return completed
