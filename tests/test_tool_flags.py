import inspect

import pytest

from tools.nmap_scan import _validate_nmap_flags
from tools.netexec import _validate_nxc_flags
import tools.ffuf as ffuf_mod
import tools.gobuster_dir as gobuster_mod
import tools.nuclei_scan as nuclei_mod
import tools.dalfox as dalfox_mod


# ── nmap: minimal guard, broad passthrough ────────────────────────────────────

def test_nmap_allows_common_flags():
    assert _validate_nmap_flags("-Pn -T4 --script vuln -oN out.txt") == \
        ["-Pn", "-T4", "--script", "vuln", "-oN", "out.txt"]


@pytest.mark.parametrize("flag", ["--resume", "-iL", "-iR", "-oX"])
def test_nmap_blocks_only_contract_breakers(flag):
    with pytest.raises(ValueError):
        _validate_nmap_flags(f"{flag} something")


def test_nmap_target_normalization():
    from tools.nmap_scan import _normalize_target
    assert _normalize_target("http://example.com:8080/admin") == "example.com"
    assert _normalize_target("https://10.0.0.5/app?x=1") == "10.0.0.5"
    assert _normalize_target("10.0.0.0/24") == "10.0.0.0/24"   # CIDR preserved
    assert _normalize_target("10.0.0.5") == "10.0.0.5"
    assert _normalize_target("example.com") == "example.com"


# ── netexec: full passthrough, including command exec ─────────────────────────

def test_netexec_allows_exec_and_modules():
    # -x (command exec) used to be blocked; now permitted for exploitation
    assert _validate_nxc_flags("-x whoami -M spider_plus") == \
        ["-x", "whoami", "-M", "spider_plus"]


# ── scanners now expose extra_args (param + schema) ───────────────────────────

@pytest.mark.parametrize("mod,fn", [
    (ffuf_mod, "ffuf"), (gobuster_mod, "gobuster_dir"), (nuclei_mod, "nuclei_scan"),
    (dalfox_mod, "dalfox"),
])
def test_scanner_has_extra_args(mod, fn):
    sig = inspect.signature(getattr(mod, fn))
    assert "extra_args" in sig.parameters
    props = mod.TOOL_DEFINITION["input_schema"]["properties"]
    assert "extra_args" in props
