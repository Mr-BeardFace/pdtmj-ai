"""netexec command construction. The logged `_command` must shell-quote each argument
and mask credentials — an unquoted multi-statement `-x` payload once read as "split"
and made an agent abandon a working call (proc.run execs the argv list, no shell, so
the command actually ran fine)."""
from tools.netexec import _redact_command


def test_multistatement_exec_is_quoted_as_one_token():
    cmd = ["nxc", "winrm", "10.0.0.1", "-u", "MSA_HEALTH$", "-H", "aabbcc",
           "-d", "logging.htb", "-x", "Get-Content a.txt; Get-Content b.txt"]
    out = _redact_command(cmd)
    # the whole -x payload is one quoted token — the ; is inside the quotes, not split
    assert "-x 'Get-Content a.txt; Get-Content b.txt'" in out


def test_pipe_in_exec_is_quoted():
    cmd = ["nxc", "winrm", "10.0.0.1", "-x", "Get-ChildItem | Select-Object Name"]
    assert "-x 'Get-ChildItem | Select-Object Name'" in _redact_command(cmd)


def test_credentials_masked_not_quoted():
    cmd = ["nxc", "smb", "10.0.0.1", "-u", "admin", "-H", "deadbeef", "-p", "s3cr3t"]
    out = _redact_command(cmd)
    assert "deadbeef" not in out and "s3cr3t" not in out
    assert "-H ***" in out and "-p ***" in out


def test_plain_args_unchanged():
    # simple tokens don't get spurious quotes
    assert _redact_command(["nxc", "smb", "10.0.0.1", "--shares"]) == "nxc smb 10.0.0.1 --shares"
