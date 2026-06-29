"""local_exec refuses never-returning daemons (they hang it) and points them at
run_daemon; also refuses bare `&` backgrounding (captured output blocks forever)."""
from tools.local_exec import local_exec


def test_refuses_responder_and_points_to_run_daemon():
    r = local_exec("responder -I tun0 -wrf")
    assert "error" in r and "run_daemon" in r["error"]


def test_refuses_responder_with_sudo_and_path():
    r = local_exec("sudo /usr/bin/responder.py -I eth0")
    assert "error" in r and "daemon" in r["error"]


def test_refuses_mitm6_and_ntlmrelay():
    assert "error" in local_exec("mitm6 -d lab.local")
    assert "error" in local_exec("impacket-ntlmrelayx -t smb://10.0.0.5")


def test_refuses_trailing_ampersand():
    r = local_exec("strings big.bin > out.txt &")
    assert "error" in r and "&" in r["error"]


def test_allows_normal_inspection():
    # a real returning command still runs
    r = local_exec("echo responder-mentioned-in-text")
    assert r.get("exit_code") == 0
    assert "responder-mentioned-in-text" in r["stdout"]
