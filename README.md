# Hashgen

A container that downloads every version of [Tor Browser](https://www.torproject.org/) for Linux x86_64, hashes all ELF binaries, and generates a deduplicated [fapolicyd](https://github.com/linux-application-whitelisting/fapolicyd) deny-rules manifest.

Designed to run as a daily scheduled task. The generated manifest can be served by any static file server and consumed by client machines to block Tor Browser execution at the kernel level.

- *Disclaimer: Generated with AI. This is a relatively simple project, but still, keep best security practices in mind and audit before using.*

## How It Works

1. Scrapes the [Tor archive](https://archive.torproject.org/tor-package-archive/torbrowser/) for all versions (stable + alpha)
2. Skips versions already processed (tracked in `versions.json`)
3. Downloads the Linux x86_64 `.tar.xz` archive for each new version
4. Extracts and identifies all ELF binaries by magic bytes (`\x7fELF`)
5. Computes SHA-256 hashes for each binary (~30 per version)
6. Records results in `versions.json` and regenerates a deduplicated `manifest.rules`

Versions with no Linux archive are marked as skipped so they aren't rechecked.

## Output Files

Both files are written to the data directory (default `/data`):

| File | Purpose |
|---|---|
| `versions.json` | Tracks every processed version, its channel, timestamp, and file→hash mappings |
| `manifest.rules` | Deduplicated fapolicyd deny rules — one line per unique hash |

Example `manifest.rules`:
```
# Tor Browser fapolicyd deny rules
# Generated: 2026-03-31T04:00:00+00:00
# Versions tracked: 437
# Unique hashes: 7736
#
deny perm=execute all : sha256hash=039e223a4e75f33bd4184f940ad8c812c3a97766bc0d03c32afc61d459dcf5fb
deny perm=execute all : sha256hash=14a2b8e615be06268fba8e3e9f51252c53ed98cf9eef2e3cf0f8572f47e19760
...
```

## Usage

### Container (recommended)

```bash
# Daily update — process only new versions
podman run --rm -v hashgen-data:/data ghcr.io/bruglet/hashgen:latest update

# Backfill — process ALL historical versions (first run)
podman run --rm -v hashgen-data:/data ghcr.io/bruglet/hashgen:latest backfill
```

### Standalone

```bash
python3 hasher.py update --data-dir ./data
python3 hasher.py backfill --data-dir ./data
```

### Test mode

Process a local archive without network access:

```bash
python3 hasher.py test --archive tor-browser-linux-x86_64-16.0a4.tar.xz --version 16.0a4 --data-dir ./data
```

## Building

```bash
podman build -t hashgen .
```

Or push to main and GitHub Actions will build and push to GHCR automatically.

## What Gets Hashed

All ELF binaries in the Tor Browser bundle, detected dynamically. For a typical version this includes:

- `firefox.real` — the browser binary
- `tor` — the Tor daemon
- `lyrebird`, `conjure-client` — pluggable transports
- `libxul.so` — core rendering engine
- ~20 shared libraries (NSS, NSPR, OpenSSL, codec libs, etc.)
- Utility binaries (`updater`, `abicheck`, `glxtest`, `vaapitest`)

These are Tor Browser's **bundled copies** — they have different hashes from system-installed libraries with the same name, so blocking them does not affect other applications.

## Windows AppLocker output (opt-in)

The existing commands still default to Linux. Upgrading the image does not
change `versions.json`, the format or location of `manifest.rules`, or the
Linux client's configuration. Existing Linux state requires no migration.

Windows processing runs in the same Linux container and never executes the
downloaded Windows programs. It inventories official Windows Tor Browser and
Tor Expert Bundles, including historical `tor-win32`/`tor-win64` ZIP packages,
stable and alpha releases, and both x86 and x86_64 distributions. All available
language variants recognized in the archive are included. Full packages are
processed; source, debug, signature, and incremental update files are excluded.

```bash
# Windows only; attempt up to 10 unprocessed packages per invocation
podman run --rm -v hashgen-data:/data ghcr.io/bruglet/hashgen:latest \
  update --platform windows --max-windows-artifacts 10

# Publish the usual Linux manifest first, then process Windows
podman run --rm -v hashgen-data:/data ghcr.io/bruglet/hashgen:latest \
  update --platform all --max-windows-artifacts 10

# Historical Windows backfill (resumable)
podman run --rm -v hashgen-data:/data ghcr.io/bruglet/hashgen:latest \
  backfill --platform windows --max-windows-artifacts 50
```

As with Linux, `update` processes all discovered packages absent from its state,
including history on the first run. `backfill` has the same incremental behavior.
Use the limit to bound **package attempts**, including failed downloads. Omit it
to process all pending packages. Historical language variants can make a full
backfill large. Completed packages are skipped on subsequent runs; failures are
retried. Directory listings are revisited so a package published later can be
discovered. Windows does not share Linux's version-completion flags.

### Output files

All new files live under `/data/windows/`:

| File | Purpose |
|---|---|
| `versions.json` | Schema-versioned package state and per-file inventory |
| `manifest.json` | Unique AppLocker hashes grouped by EXE/DLL, retaining all source paths and raw hashes |
| `applocker-exe.xml` | Standalone executable blocklist, with no DLL collection |
| `applocker-dll.xml` | Standalone DLL blocklist, with no executable collection |
| `applocker-exe-dll.xml` | Combined executable and DLL blocklist |
| `status.json` | Completed-package and unique-file counts, errors, batch-limit status, and output checksums |

The server **always hashes EXEs and DLLs** for Windows. The future client can
choose executable-only enforcement without repeating downloads or hashing to
enable DLL enforcement later. PE headers identify executable images and DLLs,
including renamed files and DLL-form OCX components. Drivers are excluded.
Inventory includes the executable package itself and supported PE files in the
extracted bundle: the browser, `tor.exe`, transports such as Lyrebird and
Conjure, historical transport programs, helpers, and bundled libraries.

Each file has a raw `sha256` and a separate `applocker_sha256`. AppLocker uses
the **Authenticode** digest; the raw hash must not be substituted into its rules.
The Windows state schema is version 1, with `schema_version` and an `artifacts`
map keyed by relative archive URL. Each artifact records its URL, version,
channel, architecture, bundle type, processing timestamp, package hash, and
`files` list. Each file records `path`, `collection` (`Exe`/`Dll`), `size`,
`sha256`, and `applocker_sha256`. Manifest entries deduplicate by collection and
Authenticode digest, with a `sources` list preserving package/file provenance.

### Policy semantics and publication

Each included collection has an `Allow *` rule and explicit hash deny rules for
Everyone (`S-1-1-0`). Rule GUIDs remain stable across runs. **These are standalone
blocklist policies, not deny-only fragments.** Do not blindly merge their broad
allow rules into an existing restrictive policy. A future policy-composing
client can consume the deny records in `manifest.json` instead.

DLL enforcement is activated only if a client applies a policy containing the
DLL collection. Generating the files does not activate any client enforcement.
DLL checking can incur performance and compatibility costs. Exact copies of
libraries or helpers may also occur in unrelated applications; these hashes
block the same binary wherever it occurs, not only inside a Tor directory.

State and each output are replaced atomically. All documents are constructed
and validated before publication. `status.json` is written last, with SHA-256
checksums of the manifest and XML files, so future consumers can detect mixed
generations if a run is interrupted between file replacements. Run one writer
per data directory, as with the existing Linux deployment.

Successfully processed packages remain available even if other packages fail.
Windows processing returns a nonzero exit code for discovery, processing, or
publication failures; reaching a requested batch limit is not a failure.
Top-level failures retain previous outputs. Partial processing publishes the
accumulated successful inventory and reports errors in `status.json`. In `all`
mode, the Linux pipeline finishes and publishes first; Windows failures do not
roll back its manifest. The overall combined command then reports failure.

The server image generates files only. A separate downloadable
[Windows client script](client/windows/README.md) installs scheduled updates and
applies local AppLocker rules; it is excluded from the build context and image.
Serve these additional files using your existing static-file server. The blocklist
covers known official distributions, not modified builds or arbitrary VPNs and
third-party proxy software.

### Standalone use and local package testing

Linux standalone use still needs only the Python standard library. Windows
processing additionally needs Python 3.12+, the pinned dependencies, and 7-Zip
(`7zz` or `7z`) for self-extracting executable packages:

```bash
python3 -m pip install -r requirements-windows.txt
python3 hasher.py update --platform windows --data-dir ./data --max-windows-artifacts 10

python3 hasher.py test --platform windows \
  --archive tor-expert-bundle-windows-x86_64-15.0.24.tar.gz \
  --version 15.0.24 --bundle expert --data-dir ./test-data
```

Local tests use independent `local/` artifact IDs and label package architecture
as `local`. A failed local rerun preserves its previous completed record.
`test --platform all` is rejected because one archive belongs to one platform.

### Validation

```bash
python3 -m pip install -r requirements-windows.txt
python3 -m unittest discover -s tests -v
```

The offline tests cover legacy Linux commands/state, Windows inventory and
hashing, separate XML collections, stable rules, batching/retries, extraction
path safety, and publication failures. The CI Windows job runs
`tests/verify_applocker.ps1` in Windows PowerShell: it compares generated hashes
against native AppLocker for signed/unsigned x86/x64 EXEs and DLLs, and evaluates
the policies with `Test-AppLockerPolicy`. It also downloads fixed-version
official Browser and Expert Bundles to validate their files. It does **not**
install a policy. Pass `-TorVersion ''` to run native fixture checks without
downloading Tor packages. Image publishing waits for both CI jobs to pass.
Native comparison is required before treating Windows output as deployment
validated; Linux/container tests alone do not establish AppLocker compatibility.
