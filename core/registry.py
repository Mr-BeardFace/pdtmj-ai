"""Tool registry construction and agent/pipeline helpers.

Previously private helpers in main.py — moved here so ui/app.py and the CLI
can both import them without coupling UI code to the entry-point script.
"""
from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.agent_loader import AgentDefinition

from core.paths import AGENTS_DIR
from core.tool_registry import ToolRegistry, Tool

# (module_path, function_name) — function name must match TOOL_DEFINITION["name"]
_TOOL_MODULES: list[tuple[str, str]] = [
    # Web / HTTP
    ("tools.nmap_scan",        "nmap_scan"),
    ("tools.masscan",          "masscan"),
    ("tools.tls_inspect",      "tls_inspect"),
    ("tools.gobuster_dir",     "gobuster_dir"),
    ("tools.ffuf",             "ffuf"),
    ("tools.nuclei_scan",      "nuclei_scan"),
    ("tools.http_request",     "http_request"),
    ("tools.hosts_entry",      "hosts_entry"),
    ("tools.captcha_solve",    "captcha_solve"),
    ("tools.port_forward",     "port_forward"),
    ("tools.web_search",       "web_search"),
    ("tools.fetch_url",        "fetch_url"),
    ("tools.sqlmap_scan",      "sqlmap_scan"),
    ("tools.dalfox",           "dalfox"),
    ("tools.oob_listener",     "oob_listener"),
    # Network / Infrastructure
    ("tools.netexec",          "netexec"),
    ("tools.hydra",            "hydra"),
    ("tools.enum4linux_ng",    "enum4linux_ng"),
    ("tools.searchsploit",     "searchsploit"),
    ("tools.ysoserial",        "ysoserial"),
    # Active Directory / Kerberos / Coercion
    ("tools.ldapsearch_query",    "ldapsearch_query"),
    ("tools.kerbrute",            "kerbrute"),
    ("tools.impacket_kerberos",   "impacket_kerberos"),
    ("tools.hashcat_crack",       "hashcat_crack"),
    ("tools.john",                "john"),
    ("tools.hash_extract",        "hash_extract"),
    ("tools.bloodhound_python",   "bloodhound_python"),
    ("tools.certipy_ad",          "certipy_ad"),
    ("tools.impacket_ntlmrelay",  "impacket_ntlmrelay"),
    ("tools.petitpotam",          "petitpotam"),
    ("tools.coercer",             "coercer"),
    ("tools.rpcclient",           "rpcclient"),
    ("tools.smbclient",           "smbclient"),
    ("tools.snmp_enum",           "snmp_enum"),
    # Databases
    ("tools.impacket_mssql",   "impacket_mssql"),
    ("tools.mongosh_query",    "mongosh_query"),
    ("tools.redis_query",      "redis_query"),
    # IIS / web extensions
    ("tools.iis_shortname",    "iis_shortname"),
    # Cloud
    ("tools.awscli",           "awscli"),
    ("tools.gcloud",           "gcloud"),
    # VCS
    ("tools.git_ops",          "git_ops"),
    # Code analysis
    ("tools.semgrep",          "semgrep"),
    ("tools.bandit",           "bandit"),
    ("tools.trufflehog",       "trufflehog"),
    ("tools.gitleaks",         "gitleaks"),
    ("tools.trivy",            "trivy"),
    ("tools.safety_check",     "safety_check"),
    # Reverse engineering / binary
    ("tools.file_identify",    "file_identify"),
    ("tools.strings_extract",  "strings_extract"),
    ("tools.readelf_analyze",  "readelf_analyze"),
    ("tools.binwalk_scan",     "binwalk_scan"),
    ("tools.yara_scan",        "yara_scan"),
    ("tools.strace_run",       "strace_run"),
    ("tools.ltrace_run",       "ltrace_run"),
    # Post-exploitation / interactive clients
    ("tools.ssh_exec",         "ssh_exec"),
    ("tools.ftp_client",       "ftp"),
    ("tools.nc",               "nc"),
    ("tools.telnet_client",    "telnet"),
    # Foothold / blind-RCE
    ("tools.ssh_keygen",       "ssh_keygen"),
    ("tools.web_exec",         "web_exec"),
    # Ad-hoc scripting (custom exploits / tools at runtime)
    ("tools.run_script",       "run_script"),
    # Local shell for inspecting downloaded/local files (strings/cat/grep/unzip)
    ("tools.local_exec",       "local_exec"),
    # Long-lived offensive daemons (responder / ntlmrelayx / mitm6) with read/stop
    ("tools.run_daemon",       "run_daemon"),
    # Self-provisioning missing tooling
    ("tools.pip_install",      "pip_install"),
    ("tools.apt_install",      "apt_install"),
]


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for module_path, func_name in _TOOL_MODULES:
        mod = importlib.import_module(module_path)
        registry.register(Tool(
            name=mod.TOOL_DEFINITION["name"],
            description=mod.TOOL_DEFINITION["description"],
            input_schema=mod.TOOL_DEFINITION["input_schema"],
            func=getattr(mod, func_name),
        ))
    return registry


def load_all_agents() -> dict[str, "AgentDefinition"]:
    """Load every agent from the agents directory tree. Returns {name: AgentDefinition}."""
    from core.agent_loader import discover_agents
    return discover_agents(AGENTS_DIR)


