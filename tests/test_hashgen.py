"""Offline regression tests; run with python -m unittest discover -s tests."""

import hashlib
import io
import json
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest.mock import patch

import hasher
import windows_hasher as windows

ROOT = Path(__file__).resolve().parents[1]


def pe_bytes(dll=False, bits=32, certificate=False):
    """Small PE fixture with checksum and certificate-table fields populated."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    optional_size = 224 if bits == 32 else 240
    struct.pack_into("<HHIIIHH", data, 132, 0x14C if bits == 32 else 0x8664,
                     1, 0, 0, 0, optional_size, 0x0002 | (0x2000 if dll else 0))
    optional = 152
    struct.pack_into("<H", data, optional, 0x10B if bits == 32 else 0x20B)
    struct.pack_into("<II", data, optional + 32, 4096, 512)
    struct.pack_into("<II", data, optional + 56, 8192, 512)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + (92 if bits == 32 else 108), 16)
    section = optional + optional_size
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 512, 4096, 512, 512)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[512:524] = b"Hashgen-test"
    if certificate:
        struct.pack_into("<II", data, optional + (128 if bits == 32 else 144), len(data), 16)
        data.extend(struct.pack("<IHH", 16, 0x0200, 2) + b"certtest")
    return bytes(data)


def make_tar(path, files, mode="w:gz"):
    with tarfile.open(path, mode) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class HashgenTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()

    def artifact(self, identity="16.0a4/tor-expert-bundle-windows-x86_64-16.0a4.tar.gz"):
        return {"id": identity, "filename": identity.split("/")[-1], "url": "https://example.invalid/" + identity,
                "version": "16.0a4", "channel": "alpha", "architecture": "x86_64", "bundle": "expert"}

    def record(self, collection="Exe", digest="a" * 64):
        return {"path": "tor/test.exe" if collection == "Exe" else "tor/test.dll",
                "collection": collection, "size": 1024, "sha256": "b" * 64, "applocker_sha256": digest}

    def completed(self, identity="one", files=None):
        return {**self.artifact(identity), "files": files or [self.record()], "processed_at": "test"}

    def test_linux_cli_is_unchanged_without_windows_dependencies(self):
        archive = self.root / "linux.tar.xz"
        elf = b"\x7fELF" + b"linux regression fixture"
        make_tar(archive, {"bundle/tor": elf, "bundle/readme": b"ignore"}, "w:xz")
        result = subprocess.run([sys.executable, "-S", str(ROOT / "hasher.py"), "test", "--archive", str(archive),
                                 "--version", "16.0a4", "--data-dir", str(self.data)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = hashlib.sha256(elf).hexdigest()
        state = json.loads((self.data / "versions.json").read_text())
        self.assertEqual(set(state["16.0a4"]), {"channel", "processed_at", "hashes"})
        self.assertEqual(state["16.0a4"]["hashes"], {"bundle/tor": digest})
        self.assertEqual((self.data / "manifest.rules").read_text().splitlines()[-1],
                         f"deny perm=execute all : sha256hash={digest}")
        self.assertFalse((self.data / "windows").exists())

    def test_existing_linux_state_not_reprocessed(self):
        state = {"15.0": {"channel": "stable", "processed_at": "original", "hashes": {"tor": "a" * 64}}}
        hasher.save_versions(self.data, state)
        with patch.object(hasher, "discover_versions", return_value=[{"version": "15.0", "channel": "stable"}]), \
                patch.object(hasher, "process_version") as process:
            hasher.cmd_update(self.data)
        process.assert_not_called()
        self.assertEqual(json.loads((self.data / "versions.json").read_text()), state)

    def test_package_discovery_current_and_historical(self):
        packages = {"tor-browser-windows-x86_64-portable-15.0.exe": ("browser", "x86_64"),
                    "tor-browser-windows-i686-portable-15.0.exe": ("browser", "i686"),
                    "torbrowser-install-win64-9.0_en-US.exe": ("browser", "x86_64"),
                    "torbrowser-install-6.0_en-US.exe": ("browser", "i686"),
                    "tor-expert-bundle-windows-x86_64-15.0.tar.gz": ("expert", "x86_64"),
                    "tor-win32-0.2.7.6.zip": ("expert", "i686"),
                    "tor-win64-0.4.1.6.zip": ("expert", "x86_64")}
        for name, (bundle, arch) in packages.items():
            with self.subTest(name=name):
                self.assertEqual(windows.identify_package(name), {"bundle": bundle, "architecture": arch})
        for name in ("tor-browser-linux-x86_64-15.0.tar.xz", "tor-browser-windows-x86_64-15.0.exe.asc",
                     "tor-browser-debug-symbols-windows-x86_64.zip", "tor-browser-windows-x86_64-15.0.mar"):
            self.assertIsNone(windows.identify_package(name))

    def test_pe_headers_and_authenticode_hashes(self):
        for bits in (32, 64):
            for dll in (False, True):
                with self.subTest(bits=bits, dll=dll):
                    path = self.root / "renamed.data"
                    content = pe_bytes(dll=dll, bits=bits)
                    path.write_bytes(content)
                    record = windows.hash_pe(path, path.name)
                    self.assertEqual(record["collection"], "Dll" if dll else "Exe")
                    # Independent fixture calculation: omit checksum and security directory.
                    security = 152 + (128 if bits == 32 else 144)
                    expected = hashlib.sha256(content[:216] + content[220:security] + content[security + 8:]).hexdigest()
                    self.assertEqual(record["applocker_sha256"], expected)
                    modified = bytearray(content)
                    struct.pack_into("<I", modified, 216, 12345)
                    path.write_bytes(modified)
                    changed = windows.hash_pe(path, path.name)
                    self.assertEqual(record["applocker_sha256"], changed["applocker_sha256"])
                    self.assertNotEqual(record["sha256"], changed["sha256"])
                    path.write_bytes(pe_bytes(dll=dll, bits=bits, certificate=True))
                    signed = windows.hash_pe(path, path.name)
                    self.assertEqual(record["applocker_sha256"], signed["applocker_sha256"])

    def test_bad_pe_and_drivers(self):
        path = self.root / "file.exe"
        path.write_bytes(b"MZbad")
        with self.assertRaises(windows.WindowsError):
            windows.pe_kind(path)
        path.write_bytes(b"ordinary data")
        self.assertIsNone(windows.pe_kind(path))
        driver = self.root / "driver.sys"
        driver.write_bytes(pe_bytes())
        self.assertIsNone(windows.pe_kind(driver))

    def test_installer_alone_is_not_complete_package_coverage(self):
        archive = self.root / "installer.exe"
        archive.write_bytes(pe_bytes())
        with patch.object(windows, "extract_package"):
            with self.assertRaisesRegex(windows.WindowsError, "No PE executables extracted"):
                windows.process_artifact(self.artifact("15.0/installer.exe"), archive)

    def test_extraction_rejects_traversal_and_links(self):
        for name in ("../escaped.exe", "/escaped.exe", "C:\\escaped.exe", "..\\escaped.exe"):
            with self.subTest(name=name):
                archive = self.root / "bad.tar.gz"
                make_tar(archive, {name: pe_bytes()})
                with self.assertRaises(windows.WindowsError):
                    windows.extract_package(archive, self.root / "unpack")
        archive = self.root / "bad.zip"
        with zipfile.ZipFile(archive, "w") as source:
            source.writestr("../escaped.exe", pe_bytes())
        with self.assertRaises(windows.WindowsError):
            windows.extract_package(archive, self.root / "unpack")
        archive = self.root / "link.tar.gz"
        with tarfile.open(archive, "w:gz") as source:
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../escaped"
            source.addfile(link)
        with self.assertRaises(windows.WindowsError):
            windows.extract_package(archive, self.root / "unpack")

    def test_windows_local_pipeline_and_policy_separation(self):
        for name in ("versions.json", "manifest.rules"):
            (self.data / name).write_bytes(b"legacy sentinel")
        archive = self.root / "expert.tar.gz"
        make_tar(archive, {"tor/tor.exe": pe_bytes(), "tor/copy.exe": pe_bytes(),
                           "tor/runtime.dll": pe_bytes(dll=True), "tor/transport.data": pe_bytes(bits=64)})
        self.assertTrue(windows.run_windows(self.data, "test", archive=archive, version="16.0a4", bundle="expert"))
        directory = self.data / "windows"
        status = json.loads((directory / "status.json").read_text())
        self.assertEqual(status["unique_executables"], 2)
        self.assertEqual(status["unique_dlls"], 1)
        for name, collections in windows.POLICY_FILES.items():
            root = ET.parse(directory / name).getroot()
            self.assertEqual(tuple(c.get("Type") for c in root), collections)
            for collection in root:
                self.assertEqual(collection.find("FilePathRule/Conditions/FilePathCondition").get("Path"), "*")
                self.assertTrue(all(r.get("Action") == "Deny" for r in collection.findall("FileHashRule")))
        previous = (directory / "applocker-exe-dll.xml").read_bytes()
        if sys.platform != "win32":
            self.assertEqual((directory / "applocker-exe.xml").stat().st_mode & 0o777, 0o644)
        self.assertTrue(windows.run_windows(self.data, "test", archive=archive, version="16.0a4", bundle="expert"))
        self.assertEqual(previous, (directory / "applocker-exe-dll.xml").read_bytes())
        for name in ("versions.json", "manifest.rules"):
            self.assertEqual((self.data / name).read_bytes(), b"legacy sentinel")
        for filename in status["outputs"]:
            # status from first generation has a timestamp-dependent manifest;
            # validate current checksums after the second generation instead.
            current = json.loads((directory / "status.json").read_text())
            self.assertEqual(hashlib.sha256((directory / filename).read_bytes()).hexdigest(), current["outputs"][filename])

    def test_limit_resume_independent_packages_and_retry(self):
        artifacts = [self.artifact("a/browser.exe"), self.artifact("a/expert.tar.gz")]
        def process(artifact, archive):
            return {**artifact, "files": [self.record()], "processed_at": "test"}
        with patch.object(windows, "discover_artifacts", side_effect=lambda: iter(artifacts)), \
                patch.object(windows, "process_artifact", side_effect=process) as processing:
            self.assertTrue(windows.run_windows(self.data, "update", limit=1))
            self.assertTrue(json.loads((self.data / "windows/status.json").read_text())["limit_reached"])
            self.assertTrue(windows.run_windows(self.data, "backfill", limit=1))
            self.assertEqual(processing.call_count, 2)
            self.assertTrue(windows.run_windows(self.data, "update"))
            self.assertEqual(processing.call_count, 2)
        failed = self.artifact("a/new.exe")
        with patch.object(windows, "discover_artifacts", return_value=iter([failed])), \
                patch.object(windows, "process_artifact", side_effect=windows.WindowsError("download failed")):
            self.assertFalse(windows.run_windows(self.data, "update"))
        state = json.loads((self.data / "windows/versions.json").read_text())
        self.assertNotIn(failed["id"], state["artifacts"])
        with patch.object(windows, "discover_artifacts", return_value=iter([failed])), \
                patch.object(windows, "process_artifact", side_effect=process):
            self.assertTrue(windows.run_windows(self.data, "update"))

    def test_publication_failure_keeps_previous_outputs(self):
        directory = self.data / "windows"
        directory.mkdir()
        state = {"schema_version": 1, "artifacts": {"one": self.completed()}}
        windows.publish(directory, state, [], 1, False)
        previous = {p.name: p.read_bytes() for p in directory.iterdir()}
        with patch.object(windows, "policy_xml", return_value="broken xml"):
            with self.assertRaises(ET.ParseError):
                windows.publish(directory, state, [], 0, False)
        self.assertEqual(previous, {p.name: p.read_bytes() for p in directory.iterdir()})

    def test_failed_local_rerun_preserves_completed_state(self):
        archive = self.root / "expert.tar.gz"
        make_tar(archive, {"tor.exe": pe_bytes()})
        self.assertTrue(windows.run_windows(self.data, "test", archive=archive, version="15.0"))
        state_path = self.data / "windows/versions.json"
        previous = state_path.read_bytes()
        make_tar(archive, {"tor.exe": b"MZbroken"})
        self.assertFalse(windows.run_windows(self.data, "test", archive=archive, version="15.0"))
        self.assertEqual(previous, state_path.read_bytes())

    def test_directory_listing_failure_does_not_hide_other_packages(self):
        def listing(url):
            if url == windows.ARCHIVE_BASE + "/":
                return ["15.0", "14.0"]
            if url.endswith("15.0/"):
                raise OSError("temporary failure")
            return ["torbrowser-install-14.0_en-US.exe"]
        with patch.object(windows, "listing", side_effect=listing):
            artifacts = list(windows.discover_artifacts())
        self.assertIn("discovery_error", artifacts[0])
        self.assertEqual(artifacts[1]["id"], "14.0/torbrowser-install-14.0_en-US.exe")

    def test_bad_state_and_empty_inventory_do_not_replace_outputs(self):
        directory = self.data / "windows"
        directory.mkdir()
        (directory / "versions.json").write_text('{"schema_version": 999, "artifacts": {}}')
        policy = directory / "applocker-exe.xml"
        policy.write_text("previous policy")
        self.assertFalse(windows.run_windows(self.data, "update"))
        self.assertEqual(policy.read_text(), "previous policy")
        with self.assertRaises(windows.WindowsError):
            windows.publish(directory, {"schema_version": 1, "artifacts": {}}, [], 0, False)
        self.assertEqual(policy.read_text(), "previous policy")

    def test_all_finishes_linux_before_windows_failure(self):
        arguments = ["hasher.py", "update", "--platform", "all", "--data-dir", str(self.data)]
        with patch.object(sys, "argv", arguments), patch.object(hasher, "cmd_update") as linux, \
                patch.object(windows, "run_windows", side_effect=lambda *args, **kwargs: linux.called and False):
            with self.assertRaises(SystemExit) as result:
                hasher.main()
        self.assertEqual(result.exception.code, 1)
        linux.assert_called_once_with(self.data)


if __name__ == "__main__":
    unittest.main()
