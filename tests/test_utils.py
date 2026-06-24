from pathlib import Path

from scopeforge.utils import slugify, build_scan_folder


def test_slugify():
    assert slugify("Home Lab!") == "Home-Lab"
    assert slugify("///", "default") == "default"


def test_build_scan_folder_has_project_and_name():
    path = build_scan_folder(Path("reports"), "home lab", "router check")
    assert "home-lab" in str(path)
    assert "router-check" in str(path)
