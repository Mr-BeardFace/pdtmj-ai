"""Process registry + killable runner, and JobManager kill / list_active."""
import sys
import threading
import time

from core.proc import ProcessRegistry, bind, run
from core.jobs import JobManager

_SLEEP = [sys.executable, "-c", "import time; time.sleep(30)"]


def _wait_registered(reg, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if reg.snapshot():
            return True
        time.sleep(0.02)
    return False


def test_run_registers_then_deregisters_on_completion():
    reg = ProcessRegistry()
    with bind(reg, None, "py"):
        cp = run([sys.executable, "-c", "print('hi')"], capture_output=True, text=True)
    assert cp.returncode == 0
    assert "hi" in cp.stdout
    assert reg.snapshot() == []          # cleaned up after the call returns


def test_run_without_binding_is_a_noop_registry():
    # No bind() context → nothing to register against, must still run fine.
    cp = run([sys.executable, "-c", "print(2+2)"], capture_output=True, text=True)
    assert cp.stdout.strip() == "4"


def test_kill_all_terminates_in_flight_process():
    reg = ProcessRegistry()
    box = {}

    def worker():
        with bind(reg, "j1", "sleeper"):
            box["cp"] = run(_SLEEP, capture_output=True, text=True)

    t = threading.Thread(target=worker)
    t.start()
    assert _wait_registered(reg), "process should have registered"
    assert reg.kill_all() == {"killed": 1, "skipped": []}
    t.join(timeout=10)
    assert not t.is_alive()
    assert box["cp"].returncode != 0      # did not exit cleanly — it was killed


def test_kill_all_skips_exempt_tools():
    reg = ProcessRegistry()
    boxes = {}

    def worker(label):
        with bind(reg, label, label):
            boxes[label] = run(_SLEEP, capture_output=True, text=True)

    tp = threading.Thread(target=worker, args=("apt_install",))
    ts = threading.Thread(target=worker, args=("nmap_scan",))
    tp.start(); ts.start()
    end = time.time() + 5
    while time.time() < end and len(reg.snapshot()) < 2:
        time.sleep(0.02)
    assert len(reg.snapshot()) == 2

    res = reg.kill_all(exempt=["apt_install"])
    assert res == {"killed": 1, "skipped": ["apt_install"]}
    ts.join(timeout=10)
    assert not ts.is_alive()
    # apt_install left running
    assert any(e["label"] == "apt_install" for e in reg.snapshot())
    reg.kill_all()                        # cleanup
    tp.join(timeout=10)


def test_kill_job_only_targets_that_job():
    reg = ProcessRegistry()
    boxes = {}

    def worker(tag):
        with bind(reg, tag, tag):
            boxes[tag] = run(_SLEEP, capture_output=True, text=True)

    ta = threading.Thread(target=worker, args=("A",))
    tb = threading.Thread(target=worker, args=("B",))
    ta.start(); tb.start()
    end = time.time() + 5
    while time.time() < end and len(reg.snapshot()) < 2:
        time.sleep(0.02)
    assert len(reg.snapshot()) == 2

    assert reg.kill_job("A") == 1
    ta.join(timeout=10)
    assert not ta.is_alive()
    # B is still running
    assert any(e["job_id"] == "B" for e in reg.snapshot())
    reg.kill_all()
    tb.join(timeout=10)


def test_jobmanager_kill_marks_killed_and_stops_process():
    reg = ProcessRegistry()
    jm = JobManager(reg)

    def fn():
        cp = run(_SLEEP, capture_output=True, text=True)
        return {"rc": cp.returncode}

    job = jm.start("sleeper", {"target": "10.0.0.1"}, fn)
    assert _wait_registered(reg), "job process should have registered"
    res = jm.kill(job.id)
    assert res["ok"] is True
    assert res["processes"] == 1
    job._thread.join(timeout=10)
    assert job.status == "killed"


def test_jobmanager_kill_all_stops_every_running_job():
    reg = ProcessRegistry()
    jm = JobManager(reg)

    def fn():
        cp = run(_SLEEP, capture_output=True, text=True)
        return {"rc": cp.returncode}

    j1 = jm.start("sleeper-a", {}, fn)
    j2 = jm.start("sleeper-b", {}, fn)
    # wait for both processes to register
    end = time.time() + 5
    while time.time() < end and len(reg.snapshot()) < 2:
        time.sleep(0.02)

    res = jm.kill_all()
    assert res["ok"] is True
    assert res["jobs"] == 2
    assert res["processes"] == 2
    for j in (j1, j2):
        j._thread.join(timeout=10)
        assert j.status == "killed"


def test_jobmanager_kill_unknown_and_finished():
    jm = JobManager(ProcessRegistry())
    assert jm.kill("deadbeef")["ok"] is False

    done = jm.start("echo", {}, lambda: {"ok": True})
    done._thread.join(timeout=5)
    assert jm.kill(done.id)["ok"] is False      # not running anymore


def test_list_active_runs_first_and_caps_finished_tail():
    jm = JobManager(ProcessRegistry())
    for i in range(6):
        j = jm.start("quick", {"n": i}, lambda i=i: {"i": i})
        j._thread.join(timeout=5)
    active = jm.list_active(finished_tail=3)
    assert len(active) == 3                      # only the last 3 finished, not all 6
    assert all(a["status"] == "done" for a in active)
    assert "info" in active[0]
