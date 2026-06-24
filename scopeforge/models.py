from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class PortService:
    host: str
    hostname: str
    port: int
    protocol: str
    state: str
    service: str = "unknown"
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: list[dict[str, str]] = field(default_factory=list)
    risk: str = "Info"
    recommendation: str = "Review service exposure and confirm business need."
    reason: str = "No rule matched."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostResult:
    address: str
    status: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[PortService] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "status": self.status,
            "hostnames": self.hostnames,
            "ports": [p.to_dict() for p in self.ports],
            "os_matches": self.os_matches,
        }


@dataclass
class ScanResult:
    scanner: str = "nmap"
    nmap_version: str = ""
    command: str = ""
    start_time: str = ""
    end_time: str = ""
    elapsed: str = ""
    summary: str = ""
    target_label: str = ""
    project: str = "default"
    scan_name: str = ""
    scan_dir: str = ""
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def all_ports(self) -> list[PortService]:
        return [p for h in self.hosts for p in h.ports]

    @property
    def live_hosts(self) -> list[HostResult]:
        return [h for h in self.hosts if h.status == "up"]

    def stats(self) -> dict[str, Any]:
        open_ports = [p for p in self.all_ports if p.state == "open"]
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for p in open_ports:
            risk_counts[p.risk] = risk_counts.get(p.risk, 0) + 1
        top_ports: dict[str, int] = {}
        top_services: dict[str, int] = {}
        for p in open_ports:
            top_ports[str(p.port)] = top_ports.get(str(p.port), 0) + 1
            top_services[p.service] = top_services.get(p.service, 0) + 1
        return {
            "hosts_scanned": len(self.hosts),
            "live_hosts": len(self.live_hosts),
            "open_ports": len(open_ports),
            "high_risk_services": risk_counts.get("High", 0) + risk_counts.get("Critical", 0),
            "risk_counts": risk_counts,
            "top_ports": sorted(top_ports.items(), key=lambda x: x[1], reverse=True)[:10],
            "top_services": sorted(top_services.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "nmap_version": self.nmap_version,
            "command": self.command,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "elapsed": self.elapsed,
            "summary": self.summary,
            "target_label": self.target_label,
            "project": self.project,
            "scan_name": self.scan_name,
            "scan_dir": self.scan_dir,
            "stats": self.stats(),
            "hosts": [h.to_dict() for h in self.hosts],
        }


@dataclass
class ScanPaths:
    root: Path
    raw: Path
    exports: Path
    evidence: Path
    screenshots: Path
    base: Path

    @classmethod
    def create(cls, root: Path) -> "ScanPaths":
        raw = root / "raw"
        exports = root / "exports"
        evidence = root / "evidence"
        screenshots = root / "screenshots"
        for path in (raw, exports, evidence, screenshots):
            path.mkdir(parents=True, exist_ok=True)
        return cls(root=root, raw=raw, exports=exports, evidence=evidence, screenshots=screenshots, base=raw / "scan")
