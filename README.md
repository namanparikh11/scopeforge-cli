# ScopeForge CLI

**Smart Nmap wrapper + timestamped evidence + professional reports.**

ScopeForge provides the `sfmap` command. You run mostly normal Nmap options, but ScopeForge automatically saves raw Nmap outputs, parses XML, classifies exposed services, and generates meeting-ready reports in timestamped project folders.

> ScopeForge does **not** replace Nmap. It adds an evidence and reporting workflow on top of Nmap.

## Why this exists

Nmap is excellent for network discovery and security auditing. Its XML output is designed for programmatic parsing, and `-oA` is useful for saving multiple output formats with a single base filename. ScopeForge uses that workflow and adds project folders, CSV/JSON exports, Markdown/HTML reports, and risk triage.

## Features

- `sfmap` command that accepts normal Nmap options
- Automatic timestamped folder creation
- Nmap raw output saved as `.nmap`, `.xml`, and `.gnmap`
- Mature HTML report suitable for meetings or proof-of-scan documentation
- Markdown report for GitHub, notes, and consulting workflows
- CSV services inventory
- JSON parsed results
- Risk labels for common exposed services such as RDP, SMB, Telnet, FTP, databases, HTTP
- `sfmap import` for existing Nmap XML files
- `sfmap nmap-help` to show Nmap options as `sfmap` examples plus ScopeForge options
- Optional PDF export using WeasyPrint
- Local-only: no telemetry, no cloud upload, no account

## Install

Nmap must be installed separately.

```bash
sudo apt update
sudo apt install nmap
```

Then install ScopeForge from the repo:

```bash
git clone https://github.com/namanparikh11/scopeforge-cli.git
cd scopeforge-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional PDF support:

```bash
pip install -e '.[pdf]'
```

## Basic usage

Run a service scan and auto-generate reports:

```bash
sfmap -sV 192.168.1.1
```

Run top 100 ports and store it under a project with a scan name:

```bash
sfmap -sV --top-ports 100 192.168.1.10 --sf-project home-lab --sf-name router-check
```

Web ports example:

```bash
sfmap -p 80,443,8080,8443 -sV example.com --sf-project web-lab --sf-name web-ports
```

Import existing Nmap XML:

```bash
sfmap import samples/sample-nmap.xml --sf-project demo --sf-name imported-scan --sf-open
```

List reports:

```bash
sfmap reports
```

Open latest report:

```bash
sfmap open latest
```

Show command reference:

```bash
sfmap nmap-help
```

## Output structure

Every scan gets a folder like this:

```text
reports/
  home-lab/
    2026-06-24_23-55-20_router-check/
      raw/
        scan.nmap
        scan.xml
        scan.gnmap
      exports/
        report.html
        report.md
        services.csv
        parsed-results.json
        report.pdf      # optional, when --sf-pdf works
      evidence/
        notes.md
      screenshots/
```

## ScopeForge-only options

Use these options in addition to normal Nmap options:

```text
--sf-project NAME       Project/workspace folder under reports/  [default: default]
--sf-name NAME          Human-readable scan name added after timestamp
--sf-dir DIRECTORY      Base output directory  [default: ./reports]
--sf-pdf                Try to generate report.pdf using optional WeasyPrint
--sf-no-report          Save raw outputs but skip report generation
--sf-open               Open generated HTML report after completion
--sf-dry-run            Show the Nmap command and output folder without running it
--sf-allow-output-flags Allow user-supplied Nmap -o* flags (not recommended)
--sf-no-banner          Hide the ScopeForge banner
```

## Nmap output handling

ScopeForge automatically adds:

```bash
-oA reports/<project>/<timestamp_name>/raw/scan
```

So do not manually use:

```text
-oA, -oX, -oN, -oG, -oS
```

unless you pass `--sf-allow-output-flags`. In normal use, let ScopeForge manage output so reports stay organized.

## Example generated report

The HTML report includes:

1. Cover page
2. Executive summary
3. Scan proof and metadata
4. Dashboard metrics
5. Risk distribution
6. Host summary
7. Services inventory
8. Priority findings
9. Raw evidence appendix
10. Limitations and disclaimer


## Nmap licensing note

ScopeForge does **not** bundle, redistribute, modify, or include Nmap, Npcap, Nmap source code, or Nmap data files. It calls the user's separately installed `nmap` binary and parses the XML output generated on the user's own machine.

For normal personal/internal use, users should install Nmap from their OS package manager or the official Nmap website and follow Nmap's license. If someone wants to redistribute Nmap inside a proprietary product, appliance, VM, container, or commercial installer, they should review the Nmap Public Source License and Nmap OEM licensing requirements.

## Safety and ethics

Use ScopeForge only on systems you own or have explicit written permission to assess.

ScopeForge itself does not include exploit code, brute force, malware, stealth scanning, or IDS evasion logic. It passes Nmap options to the user's installed Nmap binary and adds local reporting. The user is responsible for lawful and authorized use.

## Privacy

ScopeForge is local-only:

- no telemetry
- no cloud upload
- no third-party API upload
- no login/account
- reports stay on your machine

Nmap reports can contain IP addresses, hostnames, service banners, and internal system information. Treat generated reports as sensitive.

## Roadmap

- PDF styling improvements
- Report hash/signature for proof-of-scan integrity
- Scope file validation
- Diff mode between two scans
- Plugin-based risk rules
- Optional local web viewer: `sfmap serve`
- More report themes

## Disclaimer

This is a portfolio/security workflow tool. It does not confirm vulnerabilities unless manually validated. Findings are service-exposure review items based on Nmap output and transparent risk rules.
