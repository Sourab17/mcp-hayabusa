#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform into ./hayabusa/."""

import json
import platform
import shutil
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
LATEST_RELEASE_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
TARGET_DIR = Path(__file__).resolve().parent.parent / "hayabusa"


def platform_tag() -> str:
    """Map the current OS/architecture to a Hayabusa release asset tag."""
    system = sys.platform
    machine = platform.machine().lower()

    if system == "win32":
        if machine in ("amd64", "x86_64"):
            return "win-x64"
        if machine in ("arm64", "aarch64"):
            return "win-aarch64"
        if machine in ("x86", "i386", "i686"):
            return "win-x86"
    elif system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "mac-aarch64"
        if machine in ("x86_64", "amd64"):
            return "mac-x64"
    elif system.startswith("linux"):
        if machine in ("aarch64", "arm64"):
            return "lin-aarch64-gnu"
        if machine in ("x86_64", "amd64"):
            return "lin-x64-gnu"

    raise RuntimeError(f"Unsupported platform: sys.platform={system!r}, machine={machine!r}")


def fetch_latest_release() -> dict:
    request = urllib.request.Request(
        LATEST_RELEASE_URL,
        headers={"User-Agent": "mcp-hayabusa-downloader", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def find_asset(release: dict, tag: str) -> dict:
    version = release["tag_name"].lstrip("v")
    expected_name = f"hayabusa-{version}-{tag}.zip"
    for asset in release["assets"]:
        if asset["name"] == expected_name:
            return asset
    available = ", ".join(a["name"] for a in release["assets"])
    raise RuntimeError(
        f"No asset named {expected_name!r} in release {release['tag_name']}. "
        f"Available assets: {available}"
    )


def download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "mcp-hayabusa-downloader"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as f:
        shutil.copyfileobj(response, f)


def extract(zip_path: Path, target_dir: Path) -> None:
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(target_dir)


def promote_binary(target_dir: Path, tag: str) -> Path:
    """Rename the versioned Hayabusa binary to a stable name (hayabusa[.exe])."""
    is_windows = tag.startswith("win-")
    suffix = ".exe" if is_windows else ""
    candidates = [
        p
        for p in target_dir.iterdir()
        if p.is_file() and p.name.startswith("hayabusa-") and p.suffix == suffix
    ]
    if len(candidates) != 1:
        raise RuntimeError(
            f"Expected exactly one Hayabusa binary in {target_dir}, found: {candidates}"
        )

    stable_path = target_dir / f"hayabusa{suffix}"
    candidates[0].rename(stable_path)
    if not is_windows:
        stable_path.chmod(stable_path.stat().st_mode | 0o111)
    return stable_path


def main() -> int:
    try:
        tag = platform_tag()
        print(f"Detected platform tag: {tag}")

        print(f"Fetching latest release info from {LATEST_RELEASE_URL} ...")
        release = fetch_latest_release()
        print(f"Latest release: {release['tag_name']}")

        asset = find_asset(release, tag)
        print(f"Found asset: {asset['name']} ({asset['size']:,} bytes)")

        zip_path = TARGET_DIR.parent / asset["name"]
        print(f"Downloading to {zip_path} ...")
        download(asset["browser_download_url"], zip_path)

        print(f"Extracting to {TARGET_DIR} ...")
        extract(zip_path, TARGET_DIR)
        zip_path.unlink()

        binary_path = promote_binary(TARGET_DIR, tag)
        print(f"Hayabusa {release['tag_name']} ready at {binary_path}")
        return 0
    except (urllib.error.URLError, RuntimeError, OSError, KeyError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
