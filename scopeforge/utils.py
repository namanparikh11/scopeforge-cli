from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path


SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def slugify(value: str, default: str = "default") -> str:
    value = value.strip().replace(" ", "-")
    value = SAFE_NAME_PATTERN.sub("-", value)
    value = value.strip(".-_")
    return value or default


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def build_scan_folder(base_dir: Path, project: str, scan_name: str | None) -> Path:
    project_slug = slugify(project or "default")
    ts = timestamp()
    if scan_name:
        folder_name = f"{ts}_{slugify(scan_name, 'scan')}"
    else:
        folder_name = ts
    return base_dir.expanduser().resolve() / project_slug / folder_name


def read_text_safe(path: Path, max_chars: int = 120_000) -> str:
    try:
        data = path.read_text(errors="replace")
        return data[:max_chars]
    except FileNotFoundError:
        return ""


def find_latest_report(base_dir: Path) -> Path | None:
    base = base_dir.expanduser().resolve()
    if not base.exists():
        return None
    candidates = sorted(
        [p for p in base.glob("*/*/exports/report.html") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None
