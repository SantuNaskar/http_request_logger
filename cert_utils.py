import ssl, socket
from datetime import datetime, timezone
from typing import Dict, Any, List

def _parse_name_seq(seq):
    # seq is like ((('commonName','example.com'),), (('organizationName','Org'),))
    return {k: v for inner in seq for (k, v) in inner}

def fetch_certificate(host: str, port: int = 443) -> Dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    # Convert times
    not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    issuer = _parse_name_seq(cert.get('issuer', ()))
    subject = _parse_name_seq(cert.get('subject', ()))
    san = [v for (k, v) in cert.get('subjectAltName', ()) if k.lower() in ('dns', 'ip')]
    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "subject_cn": subject.get("commonName"),
        "san": san,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "raw": cert
    }

def analyze_certificate(host: str, port: int = 443) -> Dict[str, Any]:
    data = fetch_certificate(host, port)
    # Compute days to expiry
    na = datetime.fromisoformat(data["not_after"])
    now = datetime.now(timezone.utc)
    days_to_expiry = int((na - now).total_seconds() // 86400)
    warnings: List[str] = []

    # CN/SAN mismatch
    if host not in data["san"]:
        warnings.append("Host not present in SAN (possible CN/SAN mismatch)")

    # Self-signed heuristic
    issuer_cn = data.get("issuer") or ""
    subject_cn = data.get("subject_cn") or ""
    if issuer_cn and subject_cn and issuer_cn == subject_cn:
        warnings.append("Certificate appears self-signed (issuer == subject CN)")

    # Expiry status
    if days_to_expiry < 0:
        status = "CRITICAL"
        warnings.append("Certificate expired")
    elif days_to_expiry <= 7:
        status = "WARNING"
        warnings.append("Certificate expiring within 7 days")
    elif days_to_expiry <= 30:
        status = "WARNING"
        warnings.append("Certificate expiring within 30 days")
    else:
        status = "OK"

    return {
        "host": host,
        "port": port,
        "issuer": data["issuer"],
        "subject_cn": data["subject_cn"],
        "san": data["san"],
        "not_before": data["not_before"],
        "not_after": data["not_after"],
        "days_to_expiry": days_to_expiry,
        "status": status,
        "warnings": warnings
    }
