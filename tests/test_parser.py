from pathlib import Path

from scopeforge.parser import parse_nmap_xml


def test_parse_sample_nmap_xml():
    result = parse_nmap_xml(Path("samples/sample-nmap.xml"), project="demo", scan_name="sample")
    assert result.nmap_version == "7.95"
    assert len(result.hosts) == 1
    assert result.stats()["open_ports"] == 4
    risks = {p.port: p.risk for p in result.all_ports}
    assert risks[445] == "High"
    assert risks[3389] == "High"
