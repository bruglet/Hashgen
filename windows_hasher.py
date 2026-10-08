"""Opt-in Windows Tor inventory and AppLocker policy generation.

This module never writes the legacy Linux state or manifest. Packages are
extracted as data; no downloaded executable is launched.
"""

import hashlib
import json
import logging
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen

from hasher import ARCHIVE_BASE, USER_AGENT, DirListingParser, download_file, sha256_file, version_sort_key

log = logging.getLogger("tor-hasher.windows")
SCHEMA_VERSION = 1
RULE_NAMESPACE = uuid.UUID("305850de-b10a-4c6b-9a2b-e1f140996650")
POLICY_FILES = {
    "applocker-exe.xml": ("Exe",),
    "applocker-dll.xml": ("Dll",),
    "applocker-exe-dll.xml": ("Exe", "Dll"),
}


class WindowsError(Exception):
    """A failed operation that must not be recorded as complete."""


def now():
    return datetime.now(timezone.utc).isoformat()


def listing(url):
    # Unlike the legacy helper, failures must not look like an empty directory.
    with urlopen(Request(url, headers={"User-Agent": USER_AGENT}), timeout=30) as response:
        html = response.read().decode("utf-8", errors="replace")
    parser = DirListingParser()
    parser.feed(html)
    return parser.links


def identify_package(name):
    """Recognize current and historical official full Windows distributions."""
    if "/" in name or "\\" in name or ":" in name:
        return None
    lower = name.lower()
    if any(token in lower for token in ("debug", "unsigned", "incremental")):
        return None
    if lower.endswith((".asc", ".mar")):
        return None
    if lower.startswith(("tor-expert-bundle-windows-", "tor-win32-", "tor-win64-")) and lower.endswith((".tar.gz", ".zip", ".exe")):
        bundle = "expert"
    elif (lower.startswith(("tor-browser-windows-", "torbrowser-install-", "torbrowser-"))
          and ("windows" in lower or "install" in lower or "win32" in lower or "win64" in lower)
          and lower.endswith((".exe", ".zip"))):
        bundle = "browser"
    else:
        return None
    if any(token in lower for token in ("x86_64", "win64", "install-win64")):
        architecture = "x86_64"
    elif any(token in lower for token in ("i686", "win32", "windows-x86-")) or lower.startswith("torbrowser-install-"):
        # Historical torbrowser-install-VERSION_LOCALE.exe packages were x86.
        architecture = "i686"
    else:
        return None
    return {"bundle": bundle, "architecture": architecture}


def discover_artifacts():
    versions = [v for v in listing(ARCHIVE_BASE + "/")
                if re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:a\d+)?", v)]
    if not versions:
        raise WindowsError("No Tor versions discovered")
    for version in sorted(set(versions), key=version_sort_key, reverse=True):
        try:
            names = listing(f"{ARCHIVE_BASE}/{version}/")
        except Exception as exc:
            # Continue the remaining history, but surface incomplete discovery.
            yield {"discovery_error": f"{version}: {exc}"}
            continue
        for name in sorted(set(names)):
            kind = identify_package(name)
            if kind:
                yield {"id": f"{version}/{name}", "filename": name,
                       "url": f"{ARCHIVE_BASE}/{version}/{name}",
                       "version": version, "channel": "alpha" if "a" in version else "stable",
                       **kind}


def safe_member(name):
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or ":" in normalized or "\x00" in normalized:
        raise WindowsError(f"Unsafe archive path: {name!r}")
    return path


def extract_package(archive, destination):
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as source:
            for member in source.getmembers():
                safe_member(member.name)
                if not (member.isfile() or member.isdir()):
                    raise WindowsError(f"Unsupported archive member: {member.name}")
            source.extractall(destination, filter="data")
    elif zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as source:
            for member in source.infolist():
                safe_member(member.filename)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not
                                        (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                    raise WindowsError(f"Unsupported archive member: {member.filename}")
            source.extractall(destination)
    else:
        executable = shutil.which("7zz") or shutil.which("7z")
        if not executable:
            raise WindowsError("7-Zip is required to extract Windows executable packages")
        result = subprocess.run([executable, "l", "-slt", "--", str(archive)],
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise WindowsError(f"7-Zip listing failed: {result.stderr.strip()}")
        # -slt separates the archive's own properties from member properties.
        if "----------" not in result.stdout:
            raise WindowsError("Unrecognized 7-Zip listing")
        members = result.stdout.split("----------", 1)[1]
        for block in re.split(r"\r?\n\s*\r?\n", members.strip()):
            properties = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
            if "Path" in properties:
                safe_member(properties["Path"])
            if (any(key in properties for key in ("Symbolic Link", "Hard Link"))
                    or "l" in properties.get("Mode", "")[:1]
                    or "L" in properties.get("Attributes", "")):
                raise WindowsError("Archive links are not supported")
        result = subprocess.run([executable, "x", "-y", f"-o{destination}", "--", str(archive)],
                                capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise WindowsError(f"7-Zip extraction failed: {result.stderr.strip()}")
    for path in destination.rglob("*"):
        if path.is_symlink() or not path.resolve().is_relative_to(destination.resolve()):
            raise WindowsError(f"Unsafe extracted member: {path}")


def pe_kind(path):
    """Classify PE executables and DLLs by headers; ignore drivers/non-PE data."""
    with path.open("rb") as source:
        header = source.read(64)
        if header[:2] != b"MZ":
            return None
        if len(header) < 64:
            raise WindowsError(f"Truncated DOS header: {path.name}")
        offset = struct.unpack_from("<I", header, 60)[0]
        if offset < 64 or offset + 24 > path.stat().st_size:
            raise WindowsError(f"Invalid PE header offset: {path.name}")
        source.seek(offset)
        header = source.read(24)
        if header[:4] != b"PE\0\0":
            raise WindowsError(f"Unsupported MZ image: {path.name}")
        optional_size, characteristics = struct.unpack_from("<HH", header, 20)
        optional = source.read(optional_size)
        if len(optional) < 70 or len(optional) != optional_size:
            raise WindowsError(f"Truncated PE optional header: {path.name}")
        if struct.unpack_from("<H", optional)[0] not in (0x10B, 0x20B):
            raise WindowsError(f"Unsupported PE optional header: {path.name}")
        if path.suffix.lower() == ".sys" or struct.unpack_from("<H", optional, 68)[0] == 1:
            return None
        if not characteristics & 0x0002:
            return None
        return "Dll" if characteristics & 0x2000 else "Exe"


@lru_cache(maxsize=1)
def authenticode_classes():
    try:
        # oscrypto's automatic discovery requires tools absent from Alpine.
        # Select the image's installed OpenSSL libraries before Signify imports it.
        if Path("/etc/alpine-release").exists():
            import oscrypto
            oscrypto.use_openssl("/usr/lib/libcrypto.so.3", "/usr/lib/libssl.so.3")
        from signify.authenticode.signed_file.pe import SignedPEFile, SignedPEFingerprinter
    except ImportError as exc:
        raise WindowsError("Install requirements-windows.txt to hash Windows binaries") from exc
    return SignedPEFile, SignedPEFingerprinter


def hash_pe(path, relative_path):
    collection = pe_kind(path)
    if collection is None:
        return None
    SignedPEFile, SignedPEFingerprinter = authenticode_classes()
    with path.open("rb") as source:
        if SignedPEFile(source).get_authenticode_omit_sections() is None:
            raise WindowsError(f"Cannot compute Authenticode hash: {relative_path}")
        source.seek(0)
        fingerprinter = SignedPEFingerprinter(source)
        fingerprinter.add_signed_pe_hashers(hashlib.sha256)
        digest = fingerprinter.hash()["sha256"].hex()
    if len(digest) != 64:
        raise WindowsError(f"Invalid Authenticode digest: {relative_path}")
    return {"path": relative_path, "collection": collection, "size": path.stat().st_size,
            "sha256": sha256_file(path), "applocker_sha256": digest}


def process_artifact(artifact, local_archive=None):
    with tempfile.TemporaryDirectory(prefix="tor-windows-") as temporary:
        root = Path(temporary)
        archive = local_archive or root / artifact["filename"]
        if local_archive is None and not download_file(artifact["url"], archive):
            raise WindowsError(f"Download failed: {artifact['id']}")
        extracted = root / "extracted"
        extracted.mkdir()
        extract_package(archive, extracted)
        files = []
        extracted_executables = 0
        if archive.suffix.lower() == ".exe":
            record = hash_pe(archive, "@package/" + artifact["filename"])
            if record:
                files.append(record)
        for path in sorted(extracted.rglob("*")):
            if path.is_file():
                record = hash_pe(path, path.relative_to(extracted).as_posix())
                if record:
                    files.append(record)
                    extracted_executables += record["collection"] == "Exe"
        if not extracted_executables:
            raise WindowsError(f"No PE executables extracted from {artifact['id']}")
        return {**artifact, "processed_at": now(), "package_sha256": sha256_file(archive), "files": files}


def validate_state(state):
    if state.get("schema_version") != SCHEMA_VERSION or not isinstance(state.get("artifacts"), dict):
        raise WindowsError("Unsupported Windows state schema")
    for identity, artifact in state["artifacts"].items():
        if artifact.get("id") != identity or not isinstance(artifact.get("files"), list) or not artifact["files"]:
            raise WindowsError(f"Invalid Windows artifact record: {identity}")
        for record in artifact["files"]:
            if (record.get("collection") not in ("Exe", "Dll")
                    or not isinstance(record.get("size"), int) or record["size"] < 0
                    or not isinstance(record.get("path"), str)
                    or any(not re.fullmatch(r"[0-9a-f]{64}", record.get(field, ""))
                           for field in ("sha256", "applocker_sha256"))):
                raise WindowsError(f"Invalid Windows file record: {identity}")


def atomic_write(path, content):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        # NamedTemporaryFile defaults to 0600; published manifests must be
        # readable by a separate static-file server, like manifest.rules.
        temporary.chmod(0o644)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def json_text(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def inventory(state):
    unique = {}
    for identity, artifact in sorted(state["artifacts"].items()):
        for record in artifact["files"]:
            key = (record["collection"], record["applocker_sha256"])
            entry = unique.setdefault(key, {"collection": key[0], "applocker_sha256": key[1], "sources": []})
            entry["sources"].append({"artifact": identity, "version": artifact["version"],
                                     "architecture": artifact["architecture"], "bundle": artifact["bundle"],
                                     "path": record["path"], "size": record["size"], "sha256": record["sha256"]})
    return [unique[key] for key in sorted(unique)]


def policy_xml(entries, collections):
    root = ET.Element("AppLockerPolicy", Version="1")
    for collection in collections:
        rules = ET.SubElement(root, "RuleCollection", Type=collection, EnforcementMode="Enabled")
        allow = ET.SubElement(rules, "FilePathRule", Id=str(uuid.uuid5(RULE_NAMESPACE, collection + ":allow-all")),
                              Name="Hashgen: allow other files", Description="Standalone blocklist baseline",
                              UserOrGroupSid="S-1-1-0", Action="Allow")
        ET.SubElement(ET.SubElement(allow, "Conditions"), "FilePathCondition", Path="*")
        for entry in entries:
            if entry["collection"] != collection:
                continue
            digest = entry["applocker_sha256"]
            source = entry["sources"][0]
            rule = ET.SubElement(rules, "FileHashRule", Id=str(uuid.uuid5(RULE_NAMESPACE, collection + ":" + digest)),
                                 Name=f"Hashgen: {PurePosixPath(source['path']).name} [{digest[:12]}]",
                                 Description=f"Tor {source['bundle']} {source['version']}; {len(entry['sources'])} source(s)",
                                 UserOrGroupSid="S-1-1-0", Action="Deny")
            condition = ET.SubElement(ET.SubElement(rule, "Conditions"), "FileHashCondition")
            ET.SubElement(condition, "FileHash", Type="SHA256", Data="0x" + digest.upper(),
                          SourceFileName=PurePosixPath(source["path"]).name, SourceFileLength=str(source["size"]))
    ET.indent(root)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def publish(directory, state, errors, attempted, limit_reached):
    validate_state(state)
    entries = inventory(state)
    if not entries:
        raise WindowsError("No completed Windows inventory; previous policies retained")
    generated = now()
    outputs = {"manifest.json": json_text({"schema_version": SCHEMA_VERSION,
                                           "generated_at": generated, "files": entries})}
    for filename, collections in POLICY_FILES.items():
        outputs[filename] = policy_xml(entries, collections)
        ET.fromstring(outputs[filename])
    status = {"schema_version": SCHEMA_VERSION, "generated_at": generated,
              "artifacts_completed": len(state["artifacts"]), "artifacts_attempted": attempted,
              "unique_executables": sum(e["collection"] == "Exe" for e in entries),
              "unique_dlls": sum(e["collection"] == "Dll" for e in entries),
              "errors": errors, "limit_reached": limit_reached,
              "outputs": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in outputs.items()}}
    # Construct/validate all documents before replacement. Status is the final
    # commit marker; its checksums let readers detect a mixed generation.
    for filename, body in outputs.items():
        atomic_write(directory / filename, body)
    atomic_write(directory / "status.json", json_text(status))


def run_windows(data_dir, command, limit=None, archive=None, version=None, bundle="browser"):
    directory = data_dir / "windows"
    directory.mkdir(parents=True, exist_ok=True)
    errors = []
    attempted = 0
    limit_reached = False
    try:
        state_path = directory / "versions.json"
        state = json.loads(state_path.read_text()) if state_path.exists() else {"schema_version": SCHEMA_VERSION, "artifacts": {}}
        validate_state(state)
        if command == "test":
            if archive is None or not archive.is_file():
                raise WindowsError(f"Local archive not found: {archive}")
            archive = archive.resolve()
            artifacts = [{"id": f"local/{version}/{bundle}/{archive.name}", "filename": archive.name,
                          "url": None, "version": version, "channel": "alpha" if "a" in version else "stable",
                          "bundle": bundle, "architecture": "local"}]
        else:
            artifacts = discover_artifacts()
        for artifact in artifacts:
            if "discovery_error" in artifact:
                errors.append(artifact["discovery_error"])
                log.error("Discovery failed: %s", artifact["discovery_error"])
                continue
            if command != "test" and artifact["id"] in state["artifacts"]:
                continue
            if limit is not None and attempted >= limit:
                limit_reached = True
                break
            attempted += 1
            try:
                record = process_artifact(artifact, archive)
                # Validate before replacing state; an unsuccessful test rerun
                # also leaves the previous completed record intact.
                candidate = {"schema_version": SCHEMA_VERSION,
                             "artifacts": {**state["artifacts"], artifact["id"]: record}}
                validate_state(candidate)
                atomic_write(state_path, json_text(candidate))
                state = candidate
                log.info("Processed Windows %s: %d PE files", artifact["id"], len(record["files"]))
            except Exception as exc:
                errors.append(f"{artifact['id']}: {exc}")
                log.error("Windows artifact failed: %s", errors[-1])
        publish(directory, state, errors, attempted, limit_reached)
        log.info("Windows outputs generated from %d packages", len(state["artifacts"]))
    except Exception as exc:
        log.error("Windows processing failed: %s", exc)
        return False
    return not errors
