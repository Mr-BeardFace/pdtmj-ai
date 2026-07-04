# record_service is a meta-tool handled directly by the orchestrator.
# It lets the agent write what it has determined about a host/service into the
# target tracker in clean, structured fields — instead of leaving the raw scanner
# banner (e.g. "OpenSSH 9.9p1 Ubuntu 3ubuntu3.2") as an uninterpreted blob.

TOOL_DEFINITION = {
    "name": "record_service",
    "description": (
        "Record what a service actually is, in clean structured fields, once you've identified or "
        "refined it. This populates the operator's target tracker. A port scan fills a raw baseline "
        "(e.g. a banner like 'OpenSSH 9.9p1 Ubuntu 3ubuntu3.2'); call this to interpret that into "
        "proper fields — the app is 'OpenSSH', the version '9.9p1', the OS 'Ubuntu' — and to add "
        "application-layer detail a port scan cannot see (e.g. the CMS 'Camaleon CMS' running behind "
        "an nginx server, or frameworks/libraries in use). Call it whenever you identify or sharpen "
        "your understanding of a service; later calls upgrade the same host:port row. Only fill the "
        "fields you are confident about — omit the rest."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The target's IP address — the IP shown for this row in the tracker.",
            },
            "port": {
                "type": "integer",
                "description": "Port number. Omit for a host-level update (e.g. setting just the OS).",
            },
            "service": {
                "type": "string",
                "description": "Protocol/service name, e.g. ssh, http, https, smb, ftp, mysql.",
            },
            "app": {
                "type": "string",
                "description": "The product/application/server/CMS, e.g. OpenSSH, nginx, MinIO, Camaleon CMS.",
            },
            "version": {
                "type": "string",
                "description": "Version of the app, e.g. 9.9p1, 1.26.3.",
            },
            "tech": {
                "type": "string",
                "description": "Application-layer technologies/frameworks/libraries, comma-separated, e.g. 'Ruby on Rails, jQuery, Bootstrap'.",
            },
            "os": {
                "type": "string",
                "description": "Operating system of the host (host-level), e.g. Ubuntu, Windows Server 2019.",
            },
            "hostname": {
                "type": "string",
                "description": "The MACHINE's own DNS/LDAP identity — its resolved/PTR name or LDAP dNSHostName (e.g. 'DC01.corp.htb'). One per host; shown in the Hostname column. NOT a website name — use vhost for that.",
            },
            "vhost": {
                "type": "string",
                "description": "A WEBSITE (HTTP Host header) served on this IP:port, e.g. 'store.target.htb' found via vhost fuzzing, a redirect, a TLS cert SAN, or page content. Each vhost is tracked as its own service row (it may be a different app), and is added to scope. Set service='http'/'https' and the port when you record one.",
            },
            "bind": {
                "type": "string",
                "description": "Network reachability. Omit for a normally reachable service. Use 'loopback' for a service bound to the host's 127.0.0.1 — reachable only via a pivot/port_forward. NEVER set host to 127.0.0.1/localhost: record the FOOTHOLD's real IP and mark bind='loopback' (the service runs on that host, just bound to loopback). port_forward records these automatically.",
            },
        },
        "required": ["host"],
    },
}
