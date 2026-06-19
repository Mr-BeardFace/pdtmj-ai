import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

_WEAK_PROTOCOLS    = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_WEAK_CIPHER_KWDS  = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}

_OID_LABELS = {
    NameOID.COMMON_NAME:               "commonName",
    NameOID.ORGANIZATION_NAME:         "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME:  "organizationalUnitName",
    NameOID.COUNTRY_NAME:              "countryName",
    NameOID.STATE_OR_PROVINCE_NAME:    "stateOrProvinceName",
    NameOID.LOCALITY_NAME:             "localityName",
}


def _parse_name(name: x509.Name) -> dict:
    return {
        _OID_LABELS.get(attr.oid, attr.oid.dotted_string): attr.value
        for attr in name
    }


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def tls_inspect(target: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    protocol_version = ""
    cipher_name      = ""
    der_cert: Optional[bytes] = None

    try:
        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                der_cert         = ssock.getpeercert(binary_form=True)
                protocol_version = ssock.version() or ""
                cipher_info      = ssock.cipher()
                cipher_name      = cipher_info[0] if cipher_info else ""
    except ConnectionRefusedError:
        return {"error": "connection refused",   "target": target, "port": port}
    except socket.timeout:
        return {"error": "connection timed out", "target": target, "port": port}
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}",      "target": target, "port": port}
    except Exception as e:
        return {"error": str(e),                 "target": target, "port": port}

    if not der_cert:
        return {"error": "no certificate received", "target": target, "port": port}

    cert = x509.load_der_x509_certificate(der_cert)

    subject = _parse_name(cert.subject)
    issuer  = _parse_name(cert.issuer)

    # Subject Alternative Names
    dns_names: list = []
    ip_names:  list = []
    sans:      list = []
    try:
        san_ext   = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = list(san_ext.value.get_values_for_type(x509.DNSName))
        ip_names  = [str(n) for n in san_ext.value.get_values_for_type(x509.IPAddress)]
        sans      = (
            [{"type": "DNS",  "value": v} for v in dns_names] +
            [{"type": "IP",   "value": v} for v in ip_names]
        )
    except x509.ExtensionNotFound:
        cn = subject.get("commonName", "")
        if cn:
            dns_names = [cn]
            sans      = [{"type": "DNS", "value": cn}]

    # Validity
    not_before = _utc(cert.not_valid_before_utc
                      if hasattr(cert, "not_valid_before_utc")
                      else cert.not_valid_before)  # type: ignore[attr-defined]
    not_after  = _utc(cert.not_valid_after_utc
                      if hasattr(cert, "not_valid_after_utc")
                      else cert.not_valid_after)   # type: ignore[attr-defined]
    now            = datetime.now(timezone.utc)
    expired        = not_after < now
    days_remaining = (not_after - now).days

    # Self-signed: subject and issuer are identical
    self_signed = cert.subject == cert.issuer

    # Flag weak protocol / cipher
    weak_protocol = protocol_version in _WEAK_PROTOCOLS
    weak_cipher   = any(kw.lower() in cipher_name.lower() for kw in _WEAK_CIPHER_KWDS)

    issues = []
    if expired:
        issues.append("certificate is expired")
    if self_signed:
        issues.append("certificate is self-signed")
    if weak_protocol:
        issues.append(f"weak TLS protocol: {protocol_version}")
    if weak_cipher:
        issues.append(f"weak cipher suite: {cipher_name}")
    if 0 < days_remaining < 30:
        issues.append(f"certificate expires in {days_remaining} days")

    return {
        "target":           target,
        "port":             port,
        "protocol_version": protocol_version,
        "cipher":           cipher_name,
        "subject":          subject,
        "issuer":           issuer,
        "sans":             sans,
        "dns_names":        dns_names,
        "ip_names":         ip_names,
        "not_before":       not_before.isoformat(),
        "not_after":        not_after.isoformat(),
        "expired":          expired,
        "self_signed":      self_signed,
        "days_remaining":   days_remaining,
        "issues":           issues,
    }


TOOL_DEFINITION = {
    "name": "tls_inspect",
    "description": (
        "Inspect the TLS certificate on a target host/port. "
        "Extracts Subject Alternative Names (SANs) — often reveals every domain and vhost "
        "the server handles. Also checks for expired certs, self-signed certs, weak protocols "
        "(TLS 1.0/1.1, SSLv2/3), and weak cipher suites. "
        "Run against every HTTPS port discovered. No external tool dependencies."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Hostname or IP address",
            },
            "port": {
                "type": "integer",
                "description": "HTTPS port to inspect (default: 443)",
            },
        },
        "required": ["target"],
    },
}
