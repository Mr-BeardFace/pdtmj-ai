"""port_forward — SSH pivot/tunnel to internal services. ssh spawn + port probe
are mocked so no real ssh runs."""
import tools.port_forward as pf


class _FakePopen:
    def __init__(self, *a, **k):
        self.pid = 4242
        self._alive = True
    def poll(self):
        return None if self._alive else 0


def _reset():
    pf._TUNNELS.clear()


def _mock_up(monkeypatch):
    """ssh present; local port free then listening; Popen faked."""
    monkeypatch.setattr(pf.shutil, "which", lambda n: f"/usr/bin/{n}")
    seq = iter([False, True])                      # not-in-use check, then came-up check
    monkeypatch.setattr(pf, "_port_listening", lambda *a, **k: next(seq, True))
    monkeypatch.setattr(pf.subprocess, "Popen", lambda *a, **k: _FakePopen())


def test_start_requires_pivot(monkeypatch):
    _reset()
    monkeypatch.setattr(pf.shutil, "which", lambda n: "/usr/bin/ssh")
    assert "error" in pf.port_forward("start")


def test_local_mode_requires_remote(monkeypatch):
    _reset()
    monkeypatch.setattr(pf.shutil, "which", lambda n: "/usr/bin/ssh")
    out = pf.port_forward("start", pivot="ben@10.0.0.1", mode="local")
    assert "error" in out and "remote" in out["error"]


def test_local_port_in_use(monkeypatch):
    _reset()
    monkeypatch.setattr(pf.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(pf, "_port_listening", lambda *a, **k: True)     # already in use
    out = pf.port_forward("start", pivot="ben@x", remote_host="127.0.0.1",
                          remote_port=3001, local_port=3001, key_file="/k")
    assert "error" in out and "in use" in out["error"]


def test_start_local_brings_up_and_lists(monkeypatch):
    _reset()
    _mock_up(monkeypatch)
    out = pf.port_forward("start", pivot="ben@10.0.0.1", remote_host="127.0.0.1",
                          remote_port=3001, local_port=3001, key_file="/k")
    assert out["action"] == "start"
    assert out["local"] == "127.0.0.1:3001"
    assert out["socks"] is False
    listed = pf.port_forward("list")
    assert listed["count"] == 1 and listed["tunnels"][0]["id"] == out["id"]


def test_dynamic_is_socks(monkeypatch):
    _reset()
    _mock_up(monkeypatch)
    out = pf.port_forward("start", pivot="ben@x", mode="dynamic",
                          local_port=1080, key_file="/k")
    assert out["socks"] is True


def test_stop_unknown_id():
    _reset()
    assert "error" in pf.port_forward("stop", tunnel_id="nope")


def test_stop_all_kills_and_clears(monkeypatch):
    _reset()
    _mock_up(monkeypatch)
    killed = []
    monkeypatch.setattr(pf._proc, "_kill", lambda p, **k: killed.append(p))
    pf.port_forward("start", pivot="ben@x", remote_host="127.0.0.1",
                    remote_port=22, local_port=2222, key_file="/k")
    res = pf.stop_all()
    assert res["stopped"] == 1 and len(killed) == 1
    assert pf.port_forward("list")["count"] == 0


def test_registered_and_in_post_ex_scope():
    from core.registry import build_registry, load_all_agents
    reg = build_registry()
    names = {t.name for t in reg.get_by_scope(load_all_agents()["pentest/post-exploitation"].scope)}
    assert "port_forward" in names
