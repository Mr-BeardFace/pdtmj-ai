"""Background job runner for long-running tools (hashcat, big fuzzing).

A heavy tool is started as a Job — its function runs on a daemon thread while the
engagement keeps working. Job *completion handling* (state ingest, caching,
events) is done by the orchestrator on its own thread when it drains completed
jobs at a turn boundary, so engagement state is never mutated from a job thread.

Engagement-scoped: one JobManager per Orchestrator, so a job started by one agent
(e.g. exploitation kicking off hashcat) is still tracked when a later agent runs.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime
from core.timeutil import now_local
from typing import Callable, Optional

from core import proc


class Job:
    def __init__(self, label: str, inputs: dict):
        self.id: str = uuid.uuid4().hex[:8]
        self.label: str = label                 # tool name
        self.inputs: dict = inputs               # for cache keying on completion
        self.status: str = "running"            # running | done | failed | killed
        self.result: Optional[dict] = None
        self.error: Optional[str] = None
        self.command_str: Optional[str] = None
        self.started: datetime = now_local()
        self.finished: Optional[datetime] = None
        self._collected: bool = False            # orchestrator has ingested it
        self._thread: Optional[threading.Thread] = None
        self._killed: bool = False               # operator killed it via /job kill

    @property
    def runtime_s(self) -> float:
        end = self.finished or now_local()
        return (end - self.started).total_seconds()


class JobManager:
    def __init__(self, proc_registry: "Optional[proc.ProcessRegistry]" = None):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        # Registry the job's processes register into, so /job kill can reach them.
        self._procs = proc_registry

    def start(self, label: str, inputs: dict, fn: Callable[[], dict]) -> Job:
        """Run fn() on a daemon thread. Returns the Job immediately."""
        job = Job(label, inputs)
        with self._lock:
            self._jobs[job.id] = job

        def _run() -> None:
            try:
                # Bind this thread's proc.run calls to the job so the process it
                # spawns is registered under job.id and can be killed on demand.
                with proc.bind(self._procs, job.id, label):
                    res = fn()
            except Exception as e:  # noqa: BLE001 — surface tool crashes as job failure
                with self._lock:
                    job.error = str(e)
                    job.status = "killed" if job._killed else "failed"
                    job.finished = now_local()
                return
            with self._lock:
                if job._killed:
                    # Operator terminated the process; whatever came back is partial.
                    job.result = res if isinstance(res, dict) else {"result": res}
                    job.error = job.error or "killed by operator"
                    job.status = "killed"
                elif isinstance(res, dict):
                    job.result = res
                    job.command_str = res.get("_command")
                    if res.get("error"):
                        job.error = res["error"]
                        job.status = "failed"
                    else:
                        job.status = "done"
                else:
                    job.result = {"result": res}
                    job.status = "done"
                job.finished = now_local()

        t = threading.Thread(target=_run, name=f"job-{label}-{job.id}", daemon=True)
        job._thread = t
        t.start()
        return job

    def kill(self, job_id: str) -> dict:
        """Operator-requested kill of one running job. Terminates its process(es)
        and marks it killed. Returns a small result dict for the UI."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return {"ok": False, "error": f"no job with id {job_id}"}
        if job.status != "running":
            return {"ok": False, "error": f"job {job_id} is not running (status: {job.status})"}
        job._killed = True
        killed = self._procs.kill_job(job_id) if self._procs else 0
        return {"ok": True, "job_id": job_id, "label": job.label, "processes": killed}

    def kill_all(self) -> dict:
        """Kill EVERY running job and its process(es) — for `/job kill all` and
        engagement teardown. Targets only job-owned processes (via each job's id),
        so a foreground tool call the agent is mid-way through is left alone."""
        with self._lock:
            running = [j for j in self._jobs.values() if j.status == "running"]
        procs = 0
        for job in running:
            job._killed = True
            if self._procs:
                procs += self._procs.kill_job(job.id)
        return {"ok": True, "jobs": len(running), "processes": procs}

    def poll_completed(self) -> list[Job]:
        """Return jobs that finished and haven't been collected yet (marks them collected)."""
        with self._lock:
            done = [j for j in self._jobs.values()
                    if j.status in ("done", "failed") and not j._collected]
            for j in done:
                j._collected = True
            return done

    def running(self) -> list[Job]:
        with self._lock:
            return [j for j in self._jobs.values() if j.status == "running"]

    def all_jobs(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    def has_pending(self) -> bool:
        return bool(self.running())

    def wait_all(self, timeout: Optional[float] = None) -> None:
        """Join all job threads (no timeout = wait indefinitely)."""
        for job in self.all_jobs():
            t = job._thread
            if t is not None:
                t.join(timeout)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [{
                "id": j.id, "label": j.label, "status": j.status,
                "runtime_s": round(j.runtime_s, 1),
                "error": j.error,
            } for j in self._jobs.values()]

    def list_active(self, finished_tail: int = 3) -> list[dict]:
        """For the /job view: all RUNNING jobs plus the last `finished_tail`
        finished ones (done/failed/killed), newest finished first — not the full
        history. Each entry carries a compact `info` derived from its inputs."""
        with self._lock:
            jobs = list(self._jobs.values())
        running = [j for j in jobs if j.status == "running"]
        finished = [j for j in jobs if j.status != "running"]
        finished.sort(key=lambda j: j.finished or j.started, reverse=True)
        chosen = running + finished[:max(0, finished_tail)]
        return [{
            "id": j.id, "label": j.label, "status": j.status,
            "runtime_s": round(j.runtime_s, 1),
            "error": j.error,
            "info": _job_info(j.inputs),
        } for j in chosen]


def _job_info(inputs: dict) -> str:
    """Compact one-line summary of a job's inputs for the log/list view."""
    if not isinstance(inputs, dict):
        return ""
    parts = []
    for k, v in inputs.items():
        if k == "background" or v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = ",".join(str(x) for x in v)
        s = str(v)
        if len(s) > 40:
            s = s[:37] + "…"
        parts.append(f"{k}={s}")
        if len(parts) >= 4:
            break
    return " ".join(parts)
