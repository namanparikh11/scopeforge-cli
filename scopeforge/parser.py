from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from scopeforge.models import HostResult, PortService, ScanResult
from scopeforge.risk_engine import enrich_host_risks


class NmapParseError(ValueError):
    pass


def parse_nmap_xml(xml_path: Path, project: str = "default", scan_name: str = "", scan_dir: str = "") -> ScanResult:
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid XML: {exc}") from exc
    except FileNotFoundError as exc:
        raise NmapParseError(f"File not found: {xml_path}") from exc

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise NmapParseError("This does not look like Nmap XML. Expected root tag <nmaprun>.")

    result = ScanResult(
        scanner=root.attrib.get("scanner", "nmap"),
        nmap_version=root.attrib.get("version", ""),
        command=root.attrib.get("args", ""),
        start_time=root.attrib.get("startstr", root.attrib.get("start", "")),
        target_label=" ".join([t.attrib.get("specification", "") for t in root.findall("target")]).strip(),
        project=project,
        scan_name=scan_name,
        scan_dir=scan_dir,
    )

    finished = root.find("runstats/finished")
    if finished is not None:
        result.end_time = finished.attrib.get("timestr", finished.attrib.get("time", ""))
        result.elapsed = finished.attrib.get("elapsed", "")
        result.summary = finished.attrib.get("summary", "")

    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"

        address = "unknown"
        for address_node in host_node.findall("address"):
            if address_node.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                address = address_node.attrib.get("addr", "unknown")
                break
        if address == "unknown":
            first_addr = host_node.find("address")
            if first_addr is not None:
                address = first_addr.attrib.get("addr", "unknown")

        hostnames = [
            hn.attrib.get("name", "")
            for hn in host_node.findall("hostnames/hostname")
            if hn.attrib.get("name")
        ]
        hostname_label = ", ".join(hostnames)
        host = HostResult(address=address, status=status, hostnames=hostnames)

        for osmatch in host_node.findall("os/osmatch"):
            name = osmatch.attrib.get("name")
            accuracy = osmatch.attrib.get("accuracy")
            if name:
                host.os_matches.append(f"{name} ({accuracy}% accuracy)" if accuracy else name)

        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
            service = PortService(
                host=address,
                hostname=hostname_label,
                port=int(port_node.attrib.get("portid", "0")),
                protocol=port_node.attrib.get("protocol", "tcp"),
                state=state,
                service=service_node.attrib.get("name", "unknown") if service_node is not None else "unknown",
                product=service_node.attrib.get("product", "") if service_node is not None else "",
                version=service_node.attrib.get("version", "") if service_node is not None else "",
                extrainfo=service_node.attrib.get("extrainfo", "") if service_node is not None else "",
            )
            for script_node in port_node.findall("script"):
                service.scripts.append(
                    {"id": script_node.attrib.get("id", ""), "output": script_node.attrib.get("output", "")}
                )
            host.ports.append(service)

        enrich_host_risks(host)
        result.hosts.append(host)

    return result
