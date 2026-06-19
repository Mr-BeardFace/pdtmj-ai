import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET

from core import proc as runner

# Minimal guard: only flags that would break the wrapper's own contract are
# rejected — those that change which targets get scanned or replace the stdout
# XML the wrapper parses. Everything else (timing, scripts, output-to-file,
# evasion, etc.) is passed through so the agent can use nmap to its full extent.
_NMAP_FLAG_DENY = re.compile(
    r'^(--resume|-iL|-iR|-oX)$',
    re.IGNORECASE,
)


def _validate_nmap_flags(flags: str) -> list[str]:
    parts = shlex.split(flags)
    for p in parts:
        if _NMAP_FLAG_DENY.match(p):
            raise ValueError(
                f"{p!r} conflicts with how this wrapper runs nmap (it parses XML from "
                f"stdout via -oX - and scans the given target). Use the 'ports'/'target' "
                f"params or other flags instead."
            )
    return parts


def _normalize_target(target: str) -> str:
    """Reduce a URL to a bare host nmap can scan (CIDR/host:port left intact)."""
    t = (target or "").strip()
    if "://" in t:
        from urllib.parse import urlparse
        return urlparse(t).hostname or t
    return t


def nmap_scan(
    target: str,
    ports: str | None = None,
    flags: str | None = None,
    fast: bool = False,
    timeout: int = 300,
) -> dict:
    if not shutil.which("nmap"):
        return {"error": "nmap not found in PATH"}

    scan_target = _normalize_target(target)

    # Parse operator flags up front so we can reason about what they select.
    extra: list[str] = []
    if flags:
        try:
            extra = _validate_nmap_flags(flags)
        except ValueError as e:
            return {"error": str(e), "target": target}

    # Has the caller already chosen which ports to scan? If so, don't layer our
    # own default port selection on top (avoids -p / --top-ports conflicts).
    has_port_selection = bool(ports) or any(
        f.startswith(("-p", "--top-ports")) for f in extra
    )

    # Assemble flags in reading order (scan/timing/selection, then port spec,
    # then operator extras), with the target and `-oX -` last so the rendered
    # command reads the way a human would type it.
    #
    # -Pn: treat hosts as online. Pentest targets routinely filter ICMP/probe
    # pings; without this nmap reports them "down" and returns zero hosts, which
    # is the usual reason the host table comes back empty.
    if fast:
        # Quick discovery sweep: aggressive timing and NO -sV/-sC so it returns
        # in seconds. Default breadth is the top 1000 ports; widen by passing a
        # larger `--top-ports N` (or an explicit `ports` range) on later passes.
        scan_flags = ["-Pn", "-T4", "--open"]
        if not has_port_selection:
            scan_flags += ["--top-ports", "1000"]
    else:
        scan_flags = ["-sV", "-sC", "-Pn", "--open"]

    cmd = ["nmap", *scan_flags]
    if ports:
        cmd += ["-p", ports]
    cmd += extra
    cmd += [scan_target, "-oX", "-"]

    try:
        proc = runner.run(cmd, capture_output=True, text=True,
                          timeout=max(30, int(timeout or 300)))
    except subprocess.TimeoutExpired:
        return {"error": "nmap timed out", "target": target}

    if not proc.stdout.strip():
        return {"error": proc.stderr.strip() or "no output from nmap", "target": target}

    result = _parse_xml(proc.stdout, target)
    result["_command"] = " ".join(cmd)
    return result


def _parse_xml(xml_str: str, target: str) -> dict:
    xml_str = re.sub(r"<!DOCTYPE[^>]+>", "", xml_str)
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        return {"error": f"XML parse error: {e}", "target": target}

    hosts = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        # NB: do NOT use `a or b` here — an empty ElementTree element is falsy, so
        # `find(ipv4) or find(ipv6)` discards a real ipv4 match and the IP comes back
        # empty (which then breaks the host table, surfaces, and recon).
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            addr_el = host_el.find("address")          # any address as a last resort
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        # Fallback: scan was for a single literal IP/host — use it if nmap's XML
        # somehow carried no address element.
        if not ip and target and "/" not in target:
            ip = target

        hostnames = [h.get("name", "") for h in host_el.findall(".//hostname") if h.get("name")]

        open_ports = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc = port_el.find("service")
            scripts = {
                s.get("id", ""): s.get("output", "")[:500]
                for s in port_el.findall("script")
            }

            open_ports.append({
                "port":       int(port_el.get("portid", 0)),
                "protocol":   port_el.get("protocol", "tcp"),
                "service":    svc.get("name", "")        if svc is not None else "",
                "product":    svc.get("product", "")     if svc is not None else "",
                "version":    svc.get("version", "")     if svc is not None else "",
                "extra_info": svc.get("extrainfo", "")   if svc is not None else "",
                "scripts":    scripts,
            })

        os_matches = [
            {"name": m.get("name", ""), "accuracy": m.get("accuracy", "")}
            for m in host_el.findall(".//osmatch")[:3]
        ]

        hosts.append({
            "ip":         ip,
            "hostnames":  hostnames,
            "open_ports": open_ports,
            "os_matches": os_matches,
        })

    return {"target": target, "hosts": hosts, "host_count": len(hosts)}


TOOL_DEFINITION = {
    "name": "nmap_scan",
    "description": (
        "Run nmap against a target. By default does service/version detection (-sV) and default scripts (-sC), "
        "returning open ports, service banners, version info, and NSE script output. "
        "Set fast=true for a quick top-1000-port sweep (--top-ports 1000 -T4, no version/script detection) that "
        "returns in seconds — use it as the FIRST pass to find open ports fast, then re-scan the found ports "
        "with fast=false for full version/script detail. Widen a fast pass by passing a larger '--top-ports N' "
        "in flags. "
        "Optionally accepts a port range (e.g. '80,443,8000-9000') and extra nmap flags (e.g. '-Pn -T4')."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Hostname, IP, or CIDR range to scan",
            },
            "ports": {
                "type": "string",
                "description": "Port specification e.g. '80,443' or '1-65535'. Omit for nmap default top-1000.",
            },
            "flags": {
                "type": "string",
                "description": "Additional nmap flags as a single string e.g. '-Pn -T4 --script vuln'",
            },
            "fast": {
                "type": "boolean",
                "description": "Quick top-1000-port sweep (--top-ports 1000 -T4, no -sV/-sC). Returns in seconds; "
                               "ideal for the first discovery pass before a deeper version scan. Widen with a "
                               "larger '--top-ports N' in flags. Default false.",
            },
            "timeout": {
                "type": "integer",
                "description": "Max seconds to allow the scan to run before it is killed (default 300). Raise it "
                               "for wide port ranges or UDP scans; pair with `background: true` so it doesn't block.",
            },
        },
        "required": ["target"],
    },
}
