"""Deep sweep now runs a service scan on every discovered port: deep TCP + UDP
discovery (no version) feeds a -sV -sC pass on the union, so even ports beyond the
top-1000 (and UDP) come back version-identified, not bare."""
from core.frontier_driver import _open_ports, _merge_nmap_results, _deep_scan_and_service_id


def _host(ip, ports):
    return {"ip": ip, "hostnames": [], "open_ports": ports, "os_matches": []}


def _p(port, proto="tcp", product="", version=""):
    return {"port": port, "protocol": proto, "service": "", "product": product,
            "version": version, "extra_info": "", "scripts": {}}


def test_open_ports_filters_by_protocol():
    res = {"hosts": [_host("10.0.0.5", [_p(22), _p(8080), _p(161, "udp")])]}
    assert _open_ports(res, "tcp") == {22, 8080}
    assert _open_ports(res, "udp") == {161}


def test_merge_prefers_versioned_entry():
    bare = {"target": "x", "hosts": [_host("10.0.0.5", [_p(8080)])]}
    sv = {"target": "x", "hosts": [_host("10.0.0.5", [_p(8080, product="nginx", version="1.26")])]}
    merged = _merge_nmap_results([bare, sv])
    ports = merged["hosts"][0]["open_ports"]
    assert len(ports) == 1 and ports[0]["product"] == "nginx"


class _FakeNmap:
    def __init__(self):
        self.calls = []

    def execute(self, **kw):
        self.calls.append(kw)
        flags = kw.get("flags") or ""
        ports = kw.get("ports")
        if "--top-ports 45000" in flags:                     # deep TCP discovery (bare)
            return {"target": "t", "hosts": [_host("10.0.0.5", [_p(22), _p(8080)])]}
        if "-sU --top-ports 250" in flags:                   # UDP discovery (bare)
            return {"target": "t", "hosts": [_host("10.0.0.5", [_p(161, "udp")])]}
        if ports and "-sU" in flags:                         # UDP service scan
            return {"target": "t", "hosts": [_host("10.0.0.5",
                    [_p(161, "udp", product="net-snmp", version="5.9")])]}
        if ports:                                            # TCP service scan
            return {"target": "t", "hosts": [_host("10.0.0.5",
                    [_p(22, product="OpenSSH", version="9.2"),
                     _p(8080, product="nginx", version="1.26")])]}
        return {"target": "t", "hosts": []}


def test_deep_scan_versions_every_discovered_port():
    nmap = _FakeNmap()
    merged = _deep_scan_and_service_id("10.0.0.5", nmap)
    ports = {p["port"]: p for p in merged["hosts"][0]["open_ports"]}
    assert ports[8080]["product"] == "nginx"        # deep TCP port got versioned
    assert ports[161]["product"] == "net-snmp"      # UDP port got versioned
    # a -sV pass was issued over the discovered TCP ports
    sv = [c for c in nmap.calls if c.get("ports") == "22,8080" and "-sU" not in (c.get("flags") or "")]
    assert sv, "expected a TCP service scan over the discovered ports"
