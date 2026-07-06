"""Passwords in reconstructed CLI strings must not reach the report's tool log. The
flag-based redactor missed ldapsearch -w, impacket user:password, and -computer-pass
(they leaked in cleartext). It must mask those while leaving ports, wordlists, SPNs,
and hostnames intact."""
from core.utils import redact_command as rc


def test_ldapsearch_w_password_masked():
    out = rc("ldapsearch -x -H ldap://dc -b DC=support,DC=htb -LLL -D ldap@support.htb "
             "-w nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz")
    assert "nvEfEK16" not in out and "-w ***" in out


def test_impacket_user_password_masked():
    out = rc("impacket-addcomputer support.htb/support:'Ironside47pleasure40Watchful' "
             "-computer-name 'RBCD_EVIL$'")
    assert "Ironside47pleasure40Watchful" not in out
    assert "support.htb/support:***" in out


def test_impacket_getst_colon_password_masked():
    out = rc("impacket-getST -spn 'cifs/dc.support.htb' -impersonate Administrator "
             "support.htb/'RBCD_EVIL$':'RbcdEvil123!'")
    assert "RbcdEvil123!" not in out
    assert "'cifs/dc.support.htb'" in out          # the SPN is NOT a credential — kept


def test_computer_pass_flag_masked():
    out = rc("impacket-addcomputer support.htb/support:x -computer-pass 'RbcdEvil123!'")
    assert "RbcdEvil123!" not in out and "-computer-pass ***" in out


def test_netexec_p_still_masked():
    out = rc("nxc winrm 10.129.230.181 -u support -p Ironside47pleasure40Watchful")
    assert "Ironside47pleasure40Watchful" not in out and "-p ***" in out


# ── must NOT over-mask ─────────────────────────────────────────────────────────
def test_ffuf_wordlist_w_kept():
    out = rc("ffuf -u http://x/FUZZ -w /usr/share/seclists/Discovery/DNS/subs.txt")
    assert "/usr/share/seclists/Discovery/DNS/subs.txt" in out   # -w is a wordlist here


def test_nmap_port_spec_kept():
    out = rc("nmap -p 1-65535 -sV 10.10.10.5")
    assert "-p 1-65535" in out


def test_url_and_path_kept():
    assert "http://dc.support.htb:8080/app" in rc("curl http://dc.support.htb:8080/app")
    out = rc("cd /home/x/Desktop/bh_data && ls -la a.json")
    assert out == "cd /home/x/Desktop/bh_data && ls -la a.json"   # nothing masked
