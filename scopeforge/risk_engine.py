from __future__ import annotations

from scopeforge.models import HostResult, PortService

HIGH_PORTS = {
    23: ("Telnet exposes clear-text remote administration.", "Disable Telnet; use SSH with key-based authentication and network restrictions."),
    3389: ("RDP is a remote administration service and should not be broadly exposed.", "Place RDP behind VPN, enforce MFA/NLA, restrict by IP allowlist, and monitor login attempts."),
    445: ("SMB exposure can increase file-sharing and lateral-movement risk.", "Restrict SMB to trusted internal networks, disable unused shares, patch systems, and monitor access."),
    139: ("NetBIOS/SMB exposure can disclose internal file-sharing services.", "Restrict NetBIOS/SMB exposure and disable legacy protocols where possible."),
    5900: ("VNC is a remote-control service and may expose interactive desktop access.", "Restrict VNC with VPN/IP allowlists and strong authentication; disable if unused."),
    3306: ("MySQL appears reachable on the scanned interface.", "Restrict database access to application hosts, enforce strong authentication, and avoid public exposure."),
    5432: ("PostgreSQL appears reachable on the scanned interface.", "Restrict database access to trusted hosts, require TLS where appropriate, and monitor logins."),
    6379: ("Redis exposure can be high-risk if unauthenticated or misconfigured.", "Bind Redis to trusted interfaces, require authentication, and block external access."),
    27017: ("MongoDB exposure can be high-risk if access controls are weak.", "Restrict MongoDB to trusted networks, enforce authentication, and review bind configuration."),
    9200: ("Elasticsearch exposure may leak data or allow unauthorized access if misconfigured.", "Restrict access, enable authentication/TLS, and avoid internet exposure."),
    11211: ("Memcached exposure can leak cached data or enable abuse.", "Bind Memcached to localhost/private networks and block external access."),
}

MEDIUM_HIGH_PORTS = {
    21: ("FTP may expose clear-text credentials or unauthenticated file transfer.", "Use SFTP/FTPS where needed, disable anonymous access, and restrict network access."),
    25: ("SMTP exposure should be reviewed for relay and mail-server hardening.", "Confirm relay restrictions, TLS, patch level, and authentication controls."),
}

HTTP_PORTS = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}


def classify_port(service: PortService, host: HostResult | None = None) -> PortService:
    if service.state != "open":
        service.risk = "Info"
        service.reason = "Port is not open."
        service.recommendation = "No action required unless this state is unexpected."
        return service

    if service.port in HIGH_PORTS:
        service.risk = "High"
        service.reason, service.recommendation = HIGH_PORTS[service.port]
        return service

    if service.port in MEDIUM_HIGH_PORTS:
        service.risk = "Medium"
        service.reason, service.recommendation = MEDIUM_HIGH_PORTS[service.port]
        return service

    service_name = (service.service or "").lower()
    if service_name in {"telnet", "ms-wbt-server", "microsoft-rdp", "rdp", "smb", "netbios-ssn", "vnc"}:
        service.risk = "High"
        service.reason = f"Service '{service.service}' is commonly associated with remote access or file-sharing exposure."
        service.recommendation = "Confirm business need, restrict access, patch the service, and monitor usage."
        return service

    if service.port in HTTP_PORTS or service_name in {"http", "http-proxy"}:
        has_https = False
        if host:
            has_https = any(p.state == "open" and p.port in HTTPS_PORTS for p in host.ports)
        service.risk = "Medium" if not has_https else "Low"
        service.reason = "HTTP service should be reviewed for TLS, headers, and exposed admin panels."
        service.recommendation = "Prefer HTTPS, review security headers, restrict admin paths, and patch the web stack."
        return service

    if service.port in HTTPS_PORTS or service_name in {"https", "ssl/http"}:
        service.risk = "Low"
        service.reason = "Encrypted web service detected; review TLS and exposed application surface."
        service.recommendation = "Check TLS configuration, security headers, authentication, and patch level."
        return service

    if service.service in {"", "unknown"}:
        service.risk = "Medium"
        service.reason = "Unknown open service requires manual verification."
        service.recommendation = "Identify the service owner, confirm business purpose, and restrict if unnecessary."
        return service

    service.risk = "Low"
    service.reason = "Open service found; no high-risk rule matched."
    service.recommendation = "Confirm business need, patch level, exposure, and access controls."
    return service


def enrich_host_risks(host: HostResult) -> None:
    for port in host.ports:
        classify_port(port, host=host)

    open_ports = [p for p in host.ports if p.state == "open"]
    if len(open_ports) >= 10:
        for p in open_ports:
            if p.risk in {"Low", "Info"}:
                p.risk = "Medium"
                p.reason = "Host exposes many open ports; service minimization review recommended."
                p.recommendation = "Reduce unnecessary services and validate firewall segmentation."
