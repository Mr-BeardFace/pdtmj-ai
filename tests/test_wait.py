import socket
import threading
import time

import tools.wait as wait_mod
from tools.wait import wait, _MAX_WAIT


def test_plain_wait_sleeps_capped(monkeypatch):
    slept = []
    monkeypatch.setattr(wait_mod.time, "sleep", lambda s: slept.append(s))
    out = wait(seconds=5)
    assert out["waited_s"] == 5
    assert slept == [5]


def test_wait_caps_at_max(monkeypatch):
    monkeypatch.setattr(wait_mod.time, "sleep", lambda s: None)
    assert wait(seconds=10_000)["waited_s"] == _MAX_WAIT
    assert wait(seconds=0)["waited_s"] == 1          # floor


def test_wait_bad_input_defaults(monkeypatch):
    monkeypatch.setattr(wait_mod.time, "sleep", lambda s: None)
    assert wait(seconds="oops")["waited_s"] == 10


def test_wait_returns_when_port_reachable():
    # Stand up a listener, then wait on it — should return reachable fast.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        out = wait(seconds=5, host="127.0.0.1", port=port)
        assert out["reachable"] is True
        assert out["waited_s"] < 5
    finally:
        srv.close()


def test_wait_reports_unreachable_after_timeout():
    # Closed port on localhost → connection refused fast → loops to the deadline.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                         # now nothing is listening
    start = time.monotonic()
    out = wait(seconds=1, host="127.0.0.1", port=port)
    assert out["reachable"] is False
    assert time.monotonic() - start < 6              # bounded, didn't hang
