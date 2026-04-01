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