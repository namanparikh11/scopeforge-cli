from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scopeforge import __version__
from scopeforge.models import ScanPaths
from scopeforge.nmap_runner import (
    NmapNotFoundError,
    NmapOutputFlagError,
    build_nmap_command,
    get_nmap_help,
    run_nmap,
)
from scopeforge.parser import NmapParseError, parse_nmap_xml
from scopeforge.reporting import generate_all_reports
from scopeforge.utils import build_scan_folder, find_latest_report, slugify

console = Console()


def open_report_silently(report_path: Path) -> None:
    """Open a report without letting GUI app warnings pollute the terminal."""
    path = report_path.resolve()
    try:
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:
        console.print(f"[yellow]Could not auto-open report:[/yellow] {exc}")
        console.print(f"[cyan]Open manually:[/cyan] {path}")

BANNER = r"""
  ____                        ______
 / ___|  ___ ___  _ __   ___ |  ___|__  _ __ __ _  ___
 \___ \ / __/ _ \| '_ \ / _ \| |_ / _ \| '__/ _` |/ _ \
  ___) | (_| (_) | |_) |  __/|  _| (_) | | | (_| |  __/
 |____/ \___\___/| .__/ \___||_|  \___/|_|  \__, |\___|
                 |_|                         |___/
"""

WRAPPER_OPTIONS = {
    "--sf-project": True,
    "--sf-name": True,
    "--sf-dir": True,
    "--sf-pdf": False,
    "--sf-no-report": False,
    "--sf-open": False,
    "--sf-dry-run": False,
    "--sf-allow-output-flags": False,
    "--sf-no-banner": False,
}

HELP_TEXT = """
ScopeForge CLI / sfmap

Usage:
  sfmap [normal nmap options] TARGET [--sf-project PROJECT] [--sf-name SCAN_NAME]
  sfmap import scan.xml [--sf-project PROJECT] [--sf-name SCAN_NAME]
  sfmap reports [--sf-dir DIRECTORY]
  sfmap open latest|PATH [--sf-dir DIRECTORY]
  sfmap nmap-help

Examples:
  sfmap -sV 192.168.1.1
  sfmap -sV --top-ports 100 192.168.1.10 --sf-project home-lab --sf-name router-check
  sfmap -p 80,443,8080,8443 -sV example.com --sf-project web-lab --sf-name web-ports
  sfmap import samples/sample-nmap.xml --sf-project demo --sf-name imported-scan
  sfmap reports
  sfmap open latest

ScopeForge options:
  --sf-project NAME       Project/workspace folder under reports/  [default: default]
  --sf-name NAME          Human-readable scan name added after timestamp
  --sf-dir DIRECTORY      Base output directory  [default: ./reports]
  --sf-pdf                Try to generate report.pdf using optional WeasyPrint
  --sf-no-report          Save raw outputs but skip report generation
  --sf-open               Open generated HTML report after completion
  --sf-dry-run            Show the Nmap command and output folder without running it
  --sf-allow-output-flags Allow user-supplied Nmap -o* flags (not recommended)
  --sf-no-banner          Hide the ScopeForge banner

Important:
  ScopeForge controls Nmap output by adding -oA automatically.
  Do not use -oA, -oX, -oN, or -oG unless you also pass --sf-allow-output-flags.
  Use this only on systems you own or have written permission to assess.
"""

class WrapperConfig(NamedTuple):
    project: str
    scan_name: str
    base_dir: Path
    make_pdf: bool
    no_report: bool
    open_report: bool
    dry_run: bool
    allow_output_flags: bool
    no_banner: bool
    remainder: list[str]


def print_banner(no_banner: bool = False) -> None:
    if no_banner:
        return
    title = Text("ScopeForge CLI", style="bold cyan")
    subtitle = Text("Smart Nmap wrapper • timestamped evidence • professional reports", style="white")
    console.print(Panel.fit(f"[cyan]{BANNER}[/cyan]\n[bold]ScopeForge CLI[/bold]\n{subtitle}", border_style="cyan", title=title))


def split_wrapper_options(argv: list[str]) -> WrapperConfig:
    project = "default"
    scan_name = ""
    base_dir = Path("reports")
    make_pdf = False
    no_report = False
    open_report = False
    dry_run = False
    allow_output_flags = False
    no_banner = False
    remainder: list[str] = []

    i = 0
    while i < len(argv):
        token = argv[i]
        if token in WRAPPER_OPTIONS:
            needs_value = WRAPPER_OPTIONS[token]
            if needs_value:
                if i + 1 >= len(argv):
                    raise SystemExit(f"Missing value for {token}")
                value = argv[i + 1]
                if token == "--sf-project":
                    project = value
                elif token == "--sf-name":
                    scan_name = value
                elif token == "--sf-dir":
                    base_dir = Path(value)
                i += 2
            else:
                if token == "--sf-pdf":
                    make_pdf = True
                elif token == "--sf-no-report":
                    no_report = True
                elif token == "--sf-open":
                    open_report = True
                elif token == "--sf-dry-run":
                    dry_run = True
                elif token == "--sf-allow-output-flags":
                    allow_output_flags = True
                elif token == "--sf-no-banner":
                    no_banner = True
                i += 1
        else:
            remainder.append(token)
            i += 1

    return WrapperConfig(
        project=slugify(project, "default"),
        scan_name=slugify(scan_name, "") if scan_name else "",
        base_dir=base_dir,
        make_pdf=make_pdf,
        no_report=no_report,
        open_report=open_report,
        dry_run=dry_run,
        allow_output_flags=allow_output_flags,
        no_banner=no_banner,
        remainder=remainder,
    )


def print_summary(result, outputs: dict[str, Path], scan_root: Path) -> None:
    stats = result.stats()
    table = Table(title="ScopeForge Scan Summary", show_lines=False)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="bold white")
    table.add_row("Scan folder", str(scan_root))
    table.add_row("Hosts scanned", str(stats["hosts_scanned"]))
    table.add_row("Live hosts", str(stats["live_hosts"]))
    table.add_row("Open ports", str(stats["open_ports"]))
    table.add_row("High-risk services", str(stats["high_risk_services"]))
    console.print(table)

    out_table = Table(title="Generated Files")
    out_table.add_column("Type", style="green")
    out_table.add_column("Path")
    for key, path in outputs.items():
        out_table.add_row(key, str(path))
    console.print(out_table)


def cmd_scan(argv: list[str]) -> int:
    config = split_wrapper_options(argv)
    print_banner(config.no_banner)

    scan_root = build_scan_folder(config.base_dir, config.project, config.scan_name)
    paths = ScanPaths.create(scan_root)
    (paths.evidence / "notes.md").write_text("# Analyst Notes\n\n", encoding="utf-8")

    try:
        command = build_nmap_command(
            config.remainder,
            paths.base,
            allow_output_flags=config.allow_output_flags,
        )
    except (NmapNotFoundError, NmapOutputFlagError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    console.print(Panel.fit("[bold]Nmap command to execute[/bold]\n" + " ".join(command), border_style="yellow"))
    console.print(f"[cyan]Output folder:[/cyan] {scan_root}")

    if config.dry_run:
        console.print("[yellow]Dry run only. No scan executed.[/yellow]")
        return 0

    with console.status("Running Nmap scan...", spinner="dots"):
        completed = run_nmap(command)

    if completed.stdout:
        console.print(Panel(completed.stdout[-4000:], title="Nmap stdout", border_style="blue"))
    if completed.stderr:
        console.print(Panel(completed.stderr[-4000:], title="Nmap stderr", border_style="red"))

    if completed.returncode != 0:
        console.print(f"[bold red]Nmap exited with code {completed.returncode}.[/bold red]")
        console.print("Raw files may be incomplete. Check the raw/ directory.")
        return completed.returncode

    xml_path = paths.raw / "scan.xml"
    normal_path = paths.raw / "scan.nmap"

    if config.no_report:
        console.print("[yellow]Report generation skipped by --sf-no-report.[/yellow]")
        return 0

    try:
        result = parse_nmap_xml(xml_path, project=config.project, scan_name=config.scan_name, scan_dir=str(scan_root))
    except NmapParseError as exc:
        console.print(f"[bold red]Could not parse Nmap XML:[/bold red] {exc}")
        return 3

    with console.status("Generating HTML/Markdown/CSV/JSON reports...", spinner="dots"):
        outputs = generate_all_reports(result, scan_root, raw_nmap_path=normal_path, make_pdf=config.make_pdf)

    print_summary(result, outputs, scan_root)
    if config.make_pdf and "pdf" not in outputs:
        console.print('[yellow]PDF was requested but could not be generated. For pipx installs run: pipx inject scopeforge-cli "weasyprint>=62.0"[/yellow]')
    if config.open_report and "html" in outputs:
        open_report_silently(outputs["html"])
    return 0


def cmd_import(argv: list[str]) -> int:
    if not argv:
        console.print("[red]Usage: sfmap import scan.xml [--sf-project PROJECT] [--sf-name NAME][/red]")
        return 2
    xml_file = Path(argv[0]).expanduser().resolve()
    config = split_wrapper_options(argv[1:])
    print_banner(config.no_banner)

    scan_root = build_scan_folder(config.base_dir, config.project, config.scan_name or xml_file.stem)
    paths = ScanPaths.create(scan_root)
    imported_xml = paths.raw / "scan.xml"
    shutil.copy2(xml_file, imported_xml)
    (paths.raw / "scan.nmap").write_text("Imported XML only. Raw normal output was not provided.\n", encoding="utf-8")
    (paths.evidence / "notes.md").write_text("# Analyst Notes\n\nImported existing Nmap XML.\n", encoding="utf-8")

    try:
        result = parse_nmap_xml(imported_xml, project=config.project, scan_name=config.scan_name or xml_file.stem, scan_dir=str(scan_root))
    except NmapParseError as exc:
        console.print(f"[bold red]Could not parse Nmap XML:[/bold red] {exc}")
        return 3

    outputs = generate_all_reports(result, scan_root, raw_nmap_path=paths.raw / "scan.nmap", make_pdf=config.make_pdf)
    print_summary(result, outputs, scan_root)
    if config.open_report and "html" in outputs:
        open_report_silently(outputs["html"])
    return 0


def cmd_reports(argv: list[str]) -> int:
    config = split_wrapper_options(argv)
    base = config.base_dir.expanduser().resolve()
    table = Table(title=f"ScopeForge Reports in {base}")
    table.add_column("Modified", style="cyan")
    table.add_column("Project", style="green")
    table.add_column("Scan Folder")
    table.add_column("HTML Report")

    reports = sorted(base.glob("*/*/exports/report.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        console.print("[yellow]No reports found.[/yellow]")
        return 0
    for path in reports[:50]:
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        project = path.parents[2].name
        scan_folder = path.parents[1].name
        table.add_row(modified, project, scan_folder, str(path))
    console.print(table)
    return 0


def cmd_open(argv: list[str]) -> int:
    config = split_wrapper_options(argv[1:] if argv else [])
    target = argv[0] if argv else "latest"
    if target == "latest":
        report = find_latest_report(config.base_dir)
        if not report:
            console.print("[yellow]No latest report found.[/yellow]")
            return 1
    else:
        report = Path(target).expanduser().resolve()
        if report.is_dir():
            report = report / "exports" / "report.html"
    if not report.exists():
        console.print(f"[red]Report not found:[/red] {report}")
        return 1
    console.print(f"[green]Opening:[/green] {report}")
    open_report_silently(report)
    return 0


def cmd_nmap_help() -> int:
    try:
        help_text = get_nmap_help()
    except NmapNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        help_text = EMBEDDED_NMAP_REFERENCE
    transformed = help_text.replace("nmap ", "sfmap ").replace("Nmap", "Nmap / sfmap")
    console.print(Panel(Text(transformed), title="Nmap-compatible options shown as sfmap", border_style="blue"))
    console.print(Panel(Text(HELP_TEXT), title="ScopeForge-only options", border_style="cyan"))
    return 0


EMBEDDED_NMAP_REFERENCE = """
Common Nmap options shown as sfmap examples:
  sfmap -sV TARGET                    Service/version detection
  sfmap -sn TARGET                    Host discovery without port scan
  sfmap -p 80,443 TARGET              Scan specific ports
  sfmap --top-ports 100 TARGET        Scan top 100 ports
  sfmap -O TARGET                     OS detection where permitted/available
  sfmap -A TARGET                     Aggressive detection bundle; use only with authorization
  sfmap -iL targets.txt               Read targets from file
  sfmap -v TARGET                     Increase verbosity
  sfmap --reason TARGET               Show reason a port is in a state

ScopeForge controls output with -oA automatically.
"""


def main() -> int:
    argv = sys.argv[1:]
    if not argv or argv[0] in {"help", "--help", "-h"}:
        print_banner("--sf-no-banner" in argv)
        console.print(HELP_TEXT, markup=False)
        return 0

    if argv[0] == "import":
        return cmd_import(argv[1:])
    if argv[0] == "reports":
        return cmd_reports(argv[1:])
    if argv[0] == "open":
        return cmd_open(argv[1:])
    if argv[0] in {"nmap-help", "commands"}:
        return cmd_nmap_help()
    if argv[0] == "version":
        console.print(f"ScopeForge CLI {__version__}")
        return 0

    return cmd_scan(argv)


if __name__ == "__main__":
    raise SystemExit(main())
