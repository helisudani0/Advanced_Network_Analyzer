from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
PUBLIC_DOWNLOADS = ROOT / "apps" / "marketing" / "public" / "downloads"
WINDOWS_ASSET = "Ravynel-Windows-Launcher.zip"
LINUX_ASSET = "ravynel-sensor-linux-install.sh"
K8S_ASSET = "ravynel-kubernetes-control-plane.yaml"
CHECKSUMS = "checksums.txt"

INCLUDE_FILES = [
    "app.py",
    "requirements.txt",
    "README.md",
]

INCLUDE_DIRS = [
    "analyzer",
    "feeds",
    "profiles",
    "brand/ravynel",
]

EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pyd", ".db", ".sqlite", ".log"}
EXCLUDED_NAMES = {"__pycache__", ".pytest_cache", ".next", "out", "node_modules", "target", "logs", "reports", "dist"}

README_FIRST = """Ravynel NDR - Windows Sensor Control Center

Quick start
1. Install Python 3.12 or newer from https://www.python.org/downloads/windows/.
2. Install Npcap from https://npcap.com/ for live packet capture.
3. Open PowerShell in this folder and run:
   python -m pip install -r requirements.txt
4. Double-click Ravynel-Launch.pyw.
5. Press Start in the desktop GUI. Ravynel detects this laptop's LAN IP and opens the console URL.

If packet capture does not start, run the launcher as Administrator. Full LAN visibility requires a gateway sensor, SPAN/TAP mirror, or distributed sensor. A normal laptop adapter only sees traffic visible to that adapter.

Security note
This community build is packaged as scripts. Enterprise distribution should code-sign packaged executables/MSI installers and verify release checksums before deployment.
"""

DEFAULT_APP_SETTINGS = """{
  "api_host": "0.0.0.0",
  "api_port": 8080,
  "database_path": "analyzer.db",
  "geoip_db": "",
  "ioc_sources": ["feeds/threat_iocs.csv"],
  "interfaces": [],
  "bpf_filter": "",
  "quick_filter": "all",
  "packet_parser": "scapy",
  "storage_backend": "auto",
  "report_dir": "reports",
  "session_dir": "reports/sessions",
  "artifact_dir": "reports/artifacts",
  "ml_enabled": true,
  "sequence_model_enabled": true,
  "lstm_enabled": false,
  "worker_count": 2,
  "dashboard_refresh_seconds": 5
}
"""
LINUX_INSTALL = """#!/usr/bin/env bash
set -euo pipefail

echo "Ravynel Linux sensor bootstrap"
echo "Install Python 3.12+, libpcap/tcpdump permissions, then deploy the Ravynel package or containerized sensor."
echo "For production, run the Rust/Go sensor stack under systemd with least privilege capture capabilities."
"""


def clean_dist() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)


def should_skip(path: Path) -> bool:
    if any(part in EXCLUDED_NAMES for part in path.parts):
        return True
    return path.suffix.lower() in EXCLUDED_SUFFIXES


def copy_tree(src: Path, dst: Path) -> None:
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        if should_skip(rel):
            continue
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def stage_windows_package() -> Path:
    stage = DIST / "Ravynel-Security"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    for file_name in INCLUDE_FILES:
        src = ROOT / file_name
        if src.exists() and src.is_file():
            shutil.copy2(src, stage / src.name)

    for dir_name in INCLUDE_DIRS:
        src = ROOT / dir_name
        if src.exists() and src.is_dir():
            copy_tree(src, stage / dir_name)

    for launcher_name in ["Ravynel-Launch.pyw", "Ravynel-Start.cmd", "Ravynel-Operator-Setup.ps1"]:
        src = ROOT / "installers" / "windows" / launcher_name
        if src.exists():
            shutil.copy2(src, stage / launcher_name)

    (stage / "README-FIRST.txt").write_text(README_FIRST, encoding="utf-8")
    (stage / "app_settings.json").write_text(DEFAULT_APP_SETTINGS, encoding="utf-8")
    (stage / "reports").mkdir(exist_ok=True)
    (stage / "logs").mkdir(exist_ok=True)
    return stage


def zip_dir(source: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for item in source.rglob("*"):
            if item.is_file():
                archive.write(item, item.relative_to(source.parent))


def write_support_assets() -> list[Path]:
    linux = DIST / LINUX_ASSET
    linux.write_text(LINUX_INSTALL, encoding="utf-8", newline="\n")
    linux.chmod(linux.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    k8s_src = ROOT / "infra" / "kubernetes" / "control-plane.yaml"
    k8s = DIST / K8S_ASSET
    if k8s_src.exists():
        shutil.copy2(k8s_src, k8s)
    else:
        k8s.write_text("# Ravynel Kubernetes control plane manifest placeholder\n", encoding="utf-8")
    return [linux, k8s]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(paths: list[Path]) -> Path:
    checksum_path = DIST / CHECKSUMS
    lines = [f"{sha256(path)}  {path.name}" for path in paths]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checksum_path


def copy_to_public(paths: list[Path]) -> None:
    PUBLIC_DOWNLOADS.mkdir(parents=True, exist_ok=True)
    for path in paths:
        shutil.copy2(path, PUBLIC_DOWNLOADS / path.name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Ravynel release assets.")
    parser.add_argument("--no-public-copy", action="store_true", help="Do not copy assets into the marketing public/downloads folder.")
    args = parser.parse_args()

    clean_dist()
    stage = stage_windows_package()
    windows_zip = DIST / WINDOWS_ASSET
    zip_dir(stage, windows_zip)
    support_assets = write_support_assets()
    assets = [windows_zip, *support_assets]
    checksums = write_checksums(assets)
    assets.append(checksums)

    if not args.no_public_copy:
        copy_to_public(assets)

    print("Built release assets:")
    for path in assets:
        print(f" - {path.relative_to(ROOT)} ({path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


