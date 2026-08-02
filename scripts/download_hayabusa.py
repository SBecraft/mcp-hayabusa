#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/"""

import json
import platform
import shutil
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
DEST_DIR = Path(__file__).resolve().parent.parent / "hayabusa"


def detect_asset_suffix() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    is_arm = machine in ("arm64", "aarch64")

    if system == "Linux":
        return "lin-aarch64-gnu" if is_arm else "lin-x64-gnu"
    if system == "Darwin":
        return "mac-aarch64" if is_arm else "mac-x64"
    if system == "Windows":
        if is_arm:
            return "win-aarch64"
        return "win-x86" if machine in ("x86", "i386", "i686") else "win-x64"

    raise RuntimeError(f"Unsupported platform: {system} {machine}")


def get_latest_release() -> dict:
    url = f"https://api.github.com/repos/{REPO}/releases/latest"
    with urllib.request.urlopen(url) as resp:
        return json.load(resp)


def find_asset(release: dict, suffix: str) -> dict:
    for asset in release["assets"]:
        name = asset["name"]
        if name.endswith(f"{suffix}.zip") and "live-response" not in name:
            return asset
    raise RuntimeError(f"No release asset found for suffix '{suffix}'")


def download(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def extract(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)


def normalize_binary_name(dest_dir: Path) -> Path:
    """Rename the extracted, version-suffixed binary to a fixed name so callers
    can always find it at hayabusa/hayabusa (or hayabusa/hayabusa.exe on Windows)."""
    is_windows = platform.system() == "Windows"
    fixed_name = "hayabusa.exe" if is_windows else "hayabusa"

    for path in dest_dir.iterdir():
        if not path.is_file() or not path.name.lower().startswith("hayabusa"):
            continue
        if is_windows and path.suffix.lower() != ".exe":
            continue

        renamed = path.with_name(fixed_name)
        path.rename(renamed)
        renamed.chmod(renamed.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return renamed

    raise RuntimeError(f"Could not find extracted Hayabusa binary in {dest_dir}")


def main() -> None:
    suffix = detect_asset_suffix()
    print(f"Detected platform suffix: {suffix}")

    release = get_latest_release()
    tag = release["tag_name"]
    print(f"Latest release: {tag}")

    asset = find_asset(release, suffix)
    print(f"Downloading {asset['name']} ({asset['size'] / 1_000_000:.1f} MB)...")

    tmp_zip = DEST_DIR.parent / asset["name"]
    download(asset["browser_download_url"], tmp_zip)

    print(f"Extracting to {DEST_DIR}...")
    if DEST_DIR.exists():
        shutil.rmtree(DEST_DIR)
    extract(tmp_zip, DEST_DIR)
    tmp_zip.unlink()

    binary_path = normalize_binary_name(DEST_DIR)
    print(f"Done. Hayabusa {tag} is available at {binary_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
