"""Concurrency primitives for the parallel hypothesis/surface search (2.0).

The serial 1.0 engagement spends time as a SUM over every surface and every
attack path tried. This module is the machinery that converts that into a MAX:
independent work runs on threads, and the first worker to reach the objective can
cancel the rest.

Two pieces:

  * AgentGate — one global ceiling on concurrent LLM agent loops, acquired by the
    *leaf* agent run (never held across a nested fan-out), so the two parallel
    layers (surfaces × hypotheses) share a single budget instead of multiplying.
    A leaf agent acquires, runs, releases; threads waiting on the gate hold no
    slot, so nesting cannot deadlock.

  * fan_out — run a set of jobs on daemon threads, collect results in completion
    order, and (optionally) signal first-success cancellation through a shared
    Event the jobs cooperatively check.

LLM agent loops are I/O-bound (they block on the API), so OS threads parallelize
them well despite the GIL.
"""
from __future__ import annotations

import threading
import queue
from dataclasses import dataclass
from typing import Any, Callable, Optional


class AgentGate:
    """Bounds how many agent loops run at once, across every parallel layer.

    Acquire it around a single leaf agent run only — NOT around a whole surface
    cycle that itself fans out — so a surface waiting in the exploit phase never
    holds a slot another worker needs. A limit <= 0 is treated as 1.
    """

    def __init__(self, limit: int):
        self.limit = max(1, int(limit or 1))
        self._sem = threading.BoundedSemaphore(self.limit)

    def __enter__(self) -> "AgentGate":
        self._sem.acquire()
        return self

    def __exit__(self, *exc) -> bool:
        self._sem.release()
        return False


@dataclass
class FanResult:
    """Outcome of a fan_out: every job's result in completion order, plus the one
    result (if any) that tripped the solve predicate and cancelled the rest."""
    results: list
    solved: Optional[Any] = None
    errors: list = None  # (index, Exception) for jobs that raised

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


# A unique sentinel so a job that legitimately returns None is not mistaken for a
# crashed one.
class _Crashed:
    __slots__ = ("exc", "index")

    def __init__(self, exc: Exception, index: int):
        self.exc = exc
        self.index = index


def fan_out(
    jobs: list[Callable[[threading.Event], Any]],
    *,
    is_solve: Optional[Callable[[Any], bool]] = None,
    join_timeout: float = 10.0,
) -> FanResult:
    """Run `jobs` concurrently, each on its own daemon thread.

    Each job is a callable taking one argument — a `cancel` threading.Event it
    should poll between expensive steps and bail out of when set. Jobs that don't
    cooperate simply run to completion (the Event is advisory, like 1.0's /abort
    which kills processes out from under a still-looping agent).

    If `is_solve` is given, the first returned result for which it is True sets
    the shared cancel Event so the remaining jobs can stop early; that result is
    reported as `solved`. A job that raises is captured in `errors` and does not
    take down the others.

    Returns when every thread has produced a result (or its join times out).
    """
    if not jobs:
        return FanResult(results=[])

    cancel = threading.Event()
    q: "queue.Queue[Any]" = queue.Queue()
    threads: list[threading.Thread] = []

    def _runner(job: Callable, index: int) -> None:
        try:
            q.put(job(cancel))
        except Exception as exc:  # one crash must not hang the collector
            q.put(_Crashed(exc, index))

    for i, job in enumerate(jobs):
        t = threading.Thread(target=_runner, args=(job, i), daemon=True,
                             name=f"fanout-{i}")
        threads.append(t)
        t.start()

    results: list = []
    errors: list = []
    solved = None
    for _ in jobs:
        item = q.get()
        if isinstance(item, _Crashed):
            errors.append((item.index, item.exc))
            continue
        results.append(item)
        if solved is None and is_solve is not None:
            try:
                if is_solve(item):
                    solved = item
                    cancel.set()
            except Exception:
                pass

    for t in threads:
        t.join(timeout=join_timeout)

    return FanResult(results=results, solved=solved, errors=errors)
