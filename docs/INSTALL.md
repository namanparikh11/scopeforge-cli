# Installation Guide

ScopeForge is meant to be installed like a normal Linux CLI tool. Normal users do **not** need to create or activate a Python virtual environment.

## Recommended install: pipx

This installs the `sfmap` command globally for your user while keeping Python dependencies isolated automatically.

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y nmap pipx
pipx ensurepath
pipx install git+https://github.com/namanparikh11/scopeforge-cli.git
sfmap --help
```

If `sfmap` is not found immediately, open a new terminal or run:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Optional PDF support

HTML, Markdown, CSV, and JSON reports work by default. PDF export requires WeasyPrint:

```bash
pipx inject scopeforge-cli "weasyprint>=62.0"
```

If your Linux system needs PDF rendering libraries:

```bash
sudo apt install -y libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 shared-mime-info
```

Then run a scan with PDF export:

```bash
sfmap -sV --top-ports 100 127.0.0.1 --sf-project local-test --sf-name localhost --sf-pdf --sf-open
```

## Developer install

Use this only if you want to modify the code locally:

```bash
git clone https://github.com/namanparikh11/scopeforge-cli.git
cd scopeforge-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Why pipx instead of venv for normal users?

A virtual environment is good for development, but it requires `source .venv/bin/activate` every time. `pipx` is better for CLI tools because it makes `sfmap` available from anywhere while still isolating dependencies safely.
