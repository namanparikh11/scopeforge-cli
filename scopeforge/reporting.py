from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from scopeforge.models import ScanResult
from scopeforge.utils import read_text_safe


def _env() -> Environment:
    return Environment(
        loader=PackageLoader("scopeforge", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_all_reports(result: ScanResult, scan_root: Path, raw_nmap_path: Path | None = None, make_pdf: bool = False) -> dict[str, Path]:
    exports = scan_root / "exports"
    exports.mkdir(parents=True, exist_ok=True)

    raw_output = read_text_safe(raw_nmap_path) if raw_nmap_path else ""
    context: dict[str, Any] = {"scan": result, "stats": result.stats(), "raw_output": raw_output}

    env = _env()
    outputs: dict[str, Path] = {}

    html = env.get_template("report.html").render(**context)
    html_path = exports / "report.html"
    html_path.write_text(html, encoding="utf-8")
    outputs["html"] = html_path

    markdown = env.get_template("report.md").render(**context)
    md_path = exports / "report.md"
    md_path.write_text(markdown, encoding="utf-8")
    outputs["markdown"] = md_path

    json_path = exports / "parsed-results.json"
    json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    outputs["json"] = json_path

    csv_path = exports / "services.csv"
    write_services_csv(result, csv_path)
    outputs["csv"] = csv_path

    if make_pdf:
        pdf_path = exports / "report.pdf"
        if generate_pdf(html_path, pdf_path):
            outputs["pdf"] = pdf_path

    return outputs


def write_services_csv(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "host",
                "hostname",
                "port",
                "protocol",
                "state",
                "service",
                "product",
                "version",
                "risk",
                "reason",
                "recommendation",
            ],
        )
        writer.writeheader()
        for port in result.all_ports:
            row = port.to_dict()
            writer.writerow({key: row.get(key, "") for key in writer.fieldnames})


def generate_pdf(html_path: Path, pdf_path: Path) -> bool:
    try:
        from weasyprint import HTML  # type: ignore

        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return True
    except Exception:
        return False
