#!/usr/bin/env python3
"""
Tor Browser Hasher for fapolicyd

Downloads Tor Browser archives, hashes all ELF binaries, and generates
a deduplicated fapolicyd deny-rules manifest.

Usage:
    python3 hasher.py update   [--data-dir /data]   # Process new versions only
    python3 hasher.py backfill [--data-dir /data]   # Process ALL historical versions
    python3 hasher.py test     --archive FILE --version VER [--data-dir /data]
"""

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ARCHIVE_BASE = "https://archive.torproject.org/tor-package-archive/torbrowser"
USER_AGENT = "tor-hasher/1.0"
ELF_MAGIC = b"\x7fELF"

# Filename patterns for Linux x86_64 archives, tried in order
ARCHIVE_PATTERNS = [
    "tor-browser-linux-x86_64-{version}.tar.xz",
    "tor-browser-linux64-{version}_ALL.tar.xz",
    "tor-browser-linux64-{version}_en-US.tar.xz",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("tor-hasher")


# ---------------------------------------------------------------------------
# HTML directory listing parser
# ---------------------------------------------------------------------------
class DirListingParser(HTMLParser):
    """Extract href links from an Apache/nginx directory listing."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value and not value.startswith(("?", "/")):
                    self.links.append(value.rstrip("/"))


def fetch_listing(url: str) -> list[str]:
    """Fetch a directory listing page and return the link names."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError) as exc:
        log.error("Failed to fetch %s: %s", url, exc)
        return []
    parser = DirListingParser()
    parser.feed(html)
    return parser.links


# ---------------------------------------------------------------------------
# Version discovery
# ---------------------------------------------------------------------------
def discover_versions() -> list[dict]:
    """Scrape the Tor archive and return a list of version info dicts."""
    log.info("Fetching version listing from %s", ARCHIVE_BASE)
    links = fetch_listing(f"{ARCHIVE_BASE}/")
    if not links:
        log.error("No versions found in archive listing")
        return []

    versions = []
    # Version directories look like "14.0.1", "16.0a4", etc.
    version_re = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:a\d+)?$")
    for link in links:
        if version_re.match(link):
            channel = "alpha" if "a" in link else "stable"
            versions.append({"version": link, "channel": channel})

    log.info("Found %d versions (%d stable, %d alpha)",
             len(versions),
             sum(1 for v in versions if v["channel"] == "stable"),
             sum(1 for v in versions if v["channel"] == "alpha"))
    return versions


def find_archive_url(version: str) -> str | None:
    """Find the download URL for a given version's Linux x86_64 archive."""
    version_url = f"{ARCHIVE_BASE}/{version}/"
    files = fetch_listing(version_url)

    # Try each known filename pattern
    for pattern in ARCHIVE_PATTERNS:
        expected = pattern.format(version=version)
        if expected in files:
            return f"{version_url}{expected}"

    # Fallback: look for any linux x86_64 tar.xz in the listing
    for f in files:
        if ("linux" in f.lower() and "x86_64" in f.lower()
                and f.endswith(".tar.xz") and not f.endswith(".asc")):
            return f"{version_url}{f}"
        # Older naming used "linux64"
        if ("linux64" in f.lower() and f.endswith(".tar.xz")
                and not f.endswith(".asc") and "debug" not in f.lower()
                and "mar" not in f.lower()):
            return f"{version_url}{f}"

    return None


# ---------------------------------------------------------------------------
# Download and extract
# ---------------------------------------------------------------------------
def download_file(url: str, dest: Path) -> bool:
    """Download a file with progress logging."""
    log.info("Downloading %s", url)
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=300) as resp:
            total = resp.headers.get("Content-Length")
            total = int(total) if total else None
            downloaded = 0
            with open(dest, "wb") as fp:
                while True:
                    chunk = resp.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    fp.write(chunk)
                    downloaded += len(chunk)
            if total:
                log.info("Downloaded %.1f MB", downloaded / (1024 * 1024))
            else:
                log.info("Downloaded %.1f MB (size unknown)", downloaded / (1024 * 1024))
        return True
    except (HTTPError, URLError, OSError) as exc:
        log.error("Download failed: %s", exc)
        return False


def extract_archive(archive_path: Path, dest_dir: Path) -> bool:
    """Extract a .tar.xz archive."""
    log.info("Extracting %s", archive_path.name)
    try:
        with tarfile.open(archive_path, "r:xz") as tar:
            tar.extractall(path=dest_dir)
        return True
    except (tarfile.TarError, OSError) as exc:
        log.error("Extraction failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# ELF detection and hashing
# ---------------------------------------------------------------------------
def is_elf(filepath: Path) -> bool:
    """Check if a file is an ELF binary by reading its magic bytes."""
    try:
        with open(filepath, "rb") as fp:
            return fp.read(4) == ELF_MAGIC
    except OSError:
        return False


def sha256_file(filepath: Path) -> str:
    """Compute the SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_elf_files(extract_dir: Path) -> dict[str, str]:
    """Walk the extracted directory and hash all ELF files.

    Returns a dict of {relative_path: sha256_hash}.
    """
    hashes = {}
    for root, _dirs, files in os.walk(extract_dir):
        for name in files:
            filepath = Path(root) / name
            if filepath.is_symlink():
                continue
            if is_elf(filepath):
                rel = filepath.relative_to(extract_dir)
                digest = sha256_file(filepath)
                hashes[str(rel)] = digest
                log.debug("  %s -> %s", rel, digest[:16])
    log.info("Hashed %d ELF files", len(hashes))
    return hashes


# ---------------------------------------------------------------------------
# Data store (versions.json)
# ---------------------------------------------------------------------------
def load_versions(data_dir: Path) -> dict:
    """Load the versions tracking file."""
    path = data_dir / "versions.json"
    if path.exists():
        with open(path) as fp:
            return json.load(fp)
    return {}


def save_versions(data_dir: Path, versions: dict):
    """Save the versions tracking file atomically."""
    path = data_dir / "versions.json"
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as fp:
        json.dump(versions, fp, indent=2, sort_keys=True)
    tmp.rename(path)


def record_version(data_dir: Path, versions: dict, version: str,
                   channel: str, hashes: dict[str, str]):
    """Record a processed version into the tracking data."""
    versions[version] = {
        "channel": channel,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": hashes,
    }
    save_versions(data_dir, versions)


# ---------------------------------------------------------------------------
# Manifest generation
# ---------------------------------------------------------------------------
def generate_manifest(data_dir: Path, versions: dict):
    """Generate the deduplicated fapolicyd deny-rules manifest."""
    unique_hashes: set[str] = set()
    for vdata in versions.values():
        for h in vdata.get("hashes", {}).values():
            unique_hashes.add(h)

    manifest_path = data_dir / "manifest.rules"
    tmp = manifest_path.with_suffix(".tmp")

    sorted_hashes = sorted(unique_hashes)
    with open(tmp, "w") as fp:
        fp.write(f"# Tor Browser fapolicyd deny rules\n")
        fp.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        fp.write(f"# Versions tracked: {len(versions)}\n")
        fp.write(f"# Unique hashes: {len(sorted_hashes)}\n")
        fp.write(f"#\n")
        for h in sorted_hashes:
            fp.write(f"deny perm=execute all : sha256hash={h}\n")
    tmp.rename(manifest_path)

    log.info("Manifest written: %d unique hashes from %d versions",
             len(sorted_hashes), len(versions))


# ---------------------------------------------------------------------------
# Processing logic
# ---------------------------------------------------------------------------
def process_version(version: str, channel: str, data_dir: Path,
                    versions: dict, archive_path: Path | None = None) -> bool:
    """Process a single Tor Browser version.

    If archive_path is provided, use it directly (test mode).
    Otherwise, discover and download the archive.
    """
    if version in versions:
        log.info("Skipping %s (already processed)", version)
        return False

    with tempfile.TemporaryDirectory(prefix=f"tor-{version}-") as tmpdir:
        tmpdir = Path(tmpdir)

        if archive_path is None:
            # Discover the download URL
            url = find_archive_url(version)
            if url is None:
                log.warning("No Linux x86_64 archive found for %s, skipping", version)
                return False

            # Download
            archive_path = tmpdir / "archive.tar.xz"
            if not download_file(url, archive_path):
                return False

        # Extract
        extract_dir = tmpdir / "extracted"
        extract_dir.mkdir()
        if not extract_archive(archive_path, extract_dir):
            return False

        # Hash all ELF files
        hashes = hash_elf_files(extract_dir)
        if not hashes:
            log.warning("No ELF files found in %s", version)
            return False

        # Record
        record_version(data_dir, versions, version, channel, hashes)
        log.info("Processed %s: %d ELF files hashed", version, len(hashes))
        return True


def cmd_update(data_dir: Path):
    """Check for new versions and process them."""
    versions = load_versions(data_dir)
    all_versions = discover_versions()
    if not all_versions:
        log.error("Could not discover any versions")
        sys.exit(1)

    new_versions = [v for v in all_versions if v["version"] not in versions]
    if not new_versions:
        log.info("All %d versions already processed, nothing to do", len(all_versions))
        generate_manifest(data_dir, versions)
        return

    log.info("%d new version(s) to process", len(new_versions))
    processed = 0
    for vinfo in new_versions:
        if process_version(vinfo["version"], vinfo["channel"], data_dir, versions):
            processed += 1

    log.info("Processed %d new version(s)", processed)
    # Reload in case versions were updated during processing
    versions = load_versions(data_dir)
    generate_manifest(data_dir, versions)


def cmd_backfill(data_dir: Path):
    """Process ALL historical versions from the archive."""
    versions = load_versions(data_dir)
    all_versions = discover_versions()
    if not all_versions:
        log.error("Could not discover any versions")
        sys.exit(1)

    pending = [v for v in all_versions if v["version"] not in versions]
    log.info("%d version(s) to backfill out of %d total",
             len(pending), len(all_versions))

    processed = 0
    failed = 0
    for i, vinfo in enumerate(pending, 1):
        log.info("--- Backfill %d/%d: %s ---", i, len(pending), vinfo["version"])
        if process_version(vinfo["version"], vinfo["channel"], data_dir, versions):
            processed += 1
        else:
            failed += 1

    log.info("Backfill complete: %d processed, %d failed, %d skipped",
             processed, failed, len(all_versions) - len(pending))
    versions = load_versions(data_dir)
    generate_manifest(data_dir, versions)


def cmd_test(archive: str, version: str, data_dir: Path):
    """Process a local archive file for testing."""
    archive_path = Path(archive)
    if not archive_path.exists():
        log.error("Archive not found: %s", archive)
        sys.exit(1)

    versions = load_versions(data_dir)
    # Remove existing entry if present so we can re-test
    versions.pop(version, None)

    channel = "alpha" if "a" in version else "stable"
    process_version(version, channel, data_dir, versions, archive_path=archive_path)
    versions = load_versions(data_dir)
    generate_manifest(data_dir, versions)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Tor Browser Hasher for fapolicyd"
    )
    parser.add_argument("--data-dir", default="/data",
                        help="Directory for versions.json and manifest.rules")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("update", help="Process new versions only")
    sub.add_parser("backfill", help="Process all historical versions")

    test_parser = sub.add_parser("test", help="Process a local archive")
    test_parser.add_argument("--archive", required=True,
                             help="Path to a .tar.xz archive")
    test_parser.add_argument("--version", required=True,
                             help="Version string (e.g. 16.0a4)")

    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    if args.command == "update":
        cmd_update(data_dir)
    elif args.command == "backfill":
        cmd_backfill(data_dir)
    elif args.command == "test":
        cmd_test(args.archive, args.version, data_dir)


if __name__ == "__main__":
    main()
