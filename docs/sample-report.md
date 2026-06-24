# ScopeForge Security Scan Report

**Project:** demo  
**Scan Name:** sample  
**Nmap Version:** 7.95  
**Scan Folder:** `/mnt/data/scopeforge-cli/reports/demo/2026-06-24_20-05-34_sample`

## Executive Summary

This report identified **1** live host(s) and **4** open service(s). **2** service(s) were flagged as high-priority review items based on transparent exposure rules.

No exploitation is performed by ScopeForge. Findings are based on Nmap discovery/service output and should be treated as review priorities unless further validation confirms a vulnerability.

## Scan Proof & Metadata

**Command executed:**

```bash
nmap -sV --top-ports 100 -oA raw/scan 192.168.56.10
```

- **Start:** Wed Jun 24 20:30:00 2026
- **End:** Wed Jun 24 20:30:16 2026
- **Elapsed:** 16.23

Generated evidence files:

- `raw/scan.nmap`
- `raw/scan.xml`
- `raw/scan.gnmap`
- `exports/report.html`
- `exports/report.md`
- `exports/services.csv`
- `exports/parsed-results.json`

## Dashboard Summary

| Metric | Value |
|---|---:|
| Hosts scanned | 1 |
| Live hosts | 1 |
| Open ports | 4 |
| High-risk services | 2 |

## Risk Distribution

| Risk | Count |
|---|---:|
| Critical | 0 |
| High | 2 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |

## Host Summary

| Host | Hostnames | Status | Open Ports | OS Guesses |
|---|---|---|---:|---|
| `192.168.56.10` | lab-server.local | up | 4 | Linux 5.x (94% accuracy) |

## Services Inventory

| Host | Port | Service | Product / Version | Risk | Recommendation |
|---|---:|---|---|---|---|
| `192.168.56.10` | 22/tcp | ssh | OpenSSH 8.9p1 Ubuntu Linux | Low | Confirm business need, patch level, exposure, and access controls. |
| `192.168.56.10` | 80/tcp | http | Apache httpd 2.4.52 | Medium | Prefer HTTPS, review security headers, restrict admin paths, and patch the web stack. |
| `192.168.56.10` | 445/tcp | microsoft-ds | Samba smbd 4.15 | High | Restrict SMB to trusted internal networks, disable unused shares, patch systems, and monitor access. |
| `192.168.56.10` | 3389/tcp | ms-wbt-server | Microsoft Terminal Services | High | Place RDP behind VPN, enforce MFA/NLA, restrict by IP allowlist, and monitor login attempts. |

## Priority Findings

### HTTP exposure on 192.168.56.10:80

- **Severity:** Medium
- **Evidence:** `80/tcp open http Apache httpd 2.4.52`
- **Impact:** HTTP service should be reviewed for TLS, headers, and exposed admin panels.
- **Recommendation:** Prefer HTTPS, review security headers, restrict admin paths, and patch the web stack.

### MICROSOFT-DS exposure on 192.168.56.10:445

- **Severity:** High
- **Evidence:** `445/tcp open microsoft-ds Samba smbd 4.15`
- **Impact:** SMB exposure can increase file-sharing and lateral-movement risk.
- **Recommendation:** Restrict SMB to trusted internal networks, disable unused shares, patch systems, and monitor access.

### MS-WBT-SERVER exposure on 192.168.56.10:3389

- **Severity:** High
- **Evidence:** `3389/tcp open ms-wbt-server Microsoft Terminal Services `
- **Impact:** RDP is a remote administration service and should not be broadly exposed.
- **Recommendation:** Place RDP behind VPN, enforce MFA/NLA, restrict by IP allowlist, and monitor login attempts.


## Limitations & Disclaimer

This report is based on Nmap discovery/service output and ScopeForge risk rules. It does not confirm vulnerabilities unless they are manually validated. No exploitation, brute force, malware, stealth scanning, or intrusive testing is performed by ScopeForge itself.

Use only on systems you own or have explicit written permission to assess. The user is responsible for lawful and authorized use.