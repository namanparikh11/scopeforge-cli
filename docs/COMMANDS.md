# ScopeForge Command Reference

`sfmap` is a smart wrapper around Nmap. Use normal Nmap options, then add ScopeForge-only options beginning with `--sf-`.

## Version and help

```bash
sfmap --version
sfmap version
sfmap -V
sfmap --help
sfmap nmap-help
```

Use `sfmap --version`, `sfmap version`, or `sfmap -V` for the ScopeForge version. Use `sfmap nmap-help` when you want Nmap option help.

## Normal Nmap-style examples through sfmap

```bash
sfmap -sV 192.168.1.1
```
Service/version detection.

```bash
sfmap -sn 192.168.1.0/24
```
Host discovery without a port scan.

```bash
sfmap -p 80,443 192.168.1.10
```
Scan selected ports.

```bash
sfmap --top-ports 100 -sV 192.168.1.10
```
Scan top ports with service detection.

```bash
sfmap -iL targets.txt -sV
```
Read targets from a file.

```bash
sfmap --reason -sV 192.168.1.10
```
Show Nmap reasons for port states.

## ScopeForge project/reporting examples

```bash
sfmap -sV 192.168.1.1 --sf-name router-check
```
Save with scan name.

```bash
sfmap -sV 192.168.1.0/24 --sf-project home-lab --sf-name internal-scan
```
Save inside project folder.

```bash
sfmap -sV 192.168.1.10 --sf-dir ~/pentest-reports --sf-project client-a --sf-name first-pass
```
Save in a custom base directory.

```bash
sfmap -sV 192.168.1.10 --sf-pdf
```
Try PDF generation.

```bash
sfmap import scan.xml --sf-project home-lab --sf-name imported-scan
```
Generate reports from existing Nmap XML.

```bash
sfmap reports
```
List generated reports.

```bash
sfmap open latest
```
Open latest HTML report.

## ScopeForge-only flags

| Flag | Meaning |
|---|---|
| `--sf-project NAME` | Project folder under reports |
| `--sf-name NAME` | Custom scan name after timestamp |
| `--sf-dir DIRECTORY` | Base reports directory |
| `--sf-pdf` | Try high-quality PDF export |
| `--sf-no-report` | Save raw files but skip reports |
| `--sf-open` | Open generated HTML report |
| `--sf-dry-run` | Show command without running |
| `--sf-no-banner` | Hide banner |

## Output flags

ScopeForge manages output automatically with Nmap `-oA`, so avoid passing Nmap output flags manually.
