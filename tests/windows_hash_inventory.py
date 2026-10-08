"""Produce policies for native Windows comparison, without applying any policy."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from windows_hasher import extract_package, hash_pe, publish

directory = Path(sys.argv[1])
output = directory / "generated"
output.mkdir(exist_ok=True)
for archive in sorted(directory.glob("tor-*")):
    if archive.is_file() and (archive.suffix.lower() == ".exe" or archive.name.endswith(".tar.gz")):
        extracted = directory / "packages" / archive.name
        extracted.mkdir(parents=True, exist_ok=True)
        extract_package(archive, extracted)
files = [hash_pe(path, path.relative_to(directory).as_posix()) for path in sorted(directory.rglob("*"))
         if path.is_file() and path.suffix.lower() in (".exe", ".dll")]
state = {"schema_version": 1, "artifacts": {"native-fixtures": {
    "id": "native-fixtures", "version": "test", "architecture": "mixed",
    "bundle": "browser", "files": files,
}}}
publish(output, state, [], 1, False)
(output / "hashes.json").write_text(json.dumps(files), encoding="utf-8")
