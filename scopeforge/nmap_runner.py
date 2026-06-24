from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

OUTPUT_FLAGS = {
    "-oA",
    "-oN",
    "-oX",
    "-oG",
    "-oS",
    "--append-output",
    "--resume",
    "--stylesheet",
    "--webxml",
}

DANGEROUS_EXAMPLE_FLAGS = {
    # These are not blocked by default because sfmap is a wrapper, but the README intentionally
    # avoids examples for stealth/evasion. This set is reserved for future strict mode.
}


class NmapNotFoundError(RuntimeError):
    pass


class NmapOutputFlagError(ValueError):
    pass


def ensure_nmap_exists() -> str:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise NmapNotFoundError(
            "Nmap was not found in PATH. Install it first, e.g. sudo apt install nmap"
        )
    return nmap_path


def has_blocked_output_flags(args: list[str]) -> list[str]:
    blocked: list[str] = []
    for arg in args:
        if arg in OUTPUT_FLAGS:
            blocked.append(arg)
        elif arg.startswith("-o") and len(arg) >= 3 and arg[:3] in {"-oA", "-oN", "-oX", "-oG", "-oS"}:
            blocked.append(arg)
    return blocked


def build_nmap_command(nmap_args: list[str], output_base: Path, allow_output_flags: bool = False) -> list[str]:
    if not nmap_args:
        raise ValueError("No Nmap arguments/target provided. Example: sfmap -sV 192.168.1.1")

    blocked = has_blocked_output_flags(nmap_args)
    if blocked and not allow_output_flags:
        raise NmapOutputFlagError(
            "ScopeForge manages Nmap output automatically. Remove these flags: "
            + ", ".join(blocked)
            + ". Use --sf-dir, --sf-project, and --sf-name instead."
        )

    command = [ensure_nmap_exists(), *nmap_args]
    if not blocked:
        command.extend(["-oA", str(output_base)])
    return command


def run_nmap(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def get_nmap_help() -> str:
    nmap = ensure_nmap_exists()
    result = subprocess.run([nmap, "--help"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.stdout
