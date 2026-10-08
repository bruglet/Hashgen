# Windows client

[Download HashgenClient.ps1](HashgenClient.ps1) using GitHub's **Raw / Download raw
file** action. The single script includes installation, updates, status, and
uninstallation. It is excluded from the server build context by `.dockerignore`
and is not copied into the server container. There is no automatic script update:
install a reviewed new copy to upgrade the client.

Use an elevated **Windows PowerShell 5.1** console (64-bit on 64-bit Windows).
The machine must support AppLocker enforcement: updated Windows 10 2004+ or
Windows 11, with the AppLocker PowerShell module available. Validate actual
blocking under a standard account on your Windows version before deploying.
The repository's native Windows hash/policy CI checks must also pass.

## Install

Configure the server to publish Windows files with `--platform windows` or
`--platform all`. Serve `/data/windows/` through HTTPS. The URL below is the
directory containing `status.json` and `manifest.json`, not a GitHub download
URL for the script. Files must be served directly with HTTP 200; redirects,
interactive authentication, and URL credentials are not supported.

```powershell
# After reviewing the downloaded file, remove its downloaded-file restriction.
Unblock-File .\HashgenClient.ps1

# Executable blocking, immediate first update, then startup/every six hours.
.\HashgenClient.ps1 -Action Install -ServerUrl 'https://hashes.example/windows/'

# Optional: include DLLs, or start with audit-only logging.
.\HashgenClient.ps1 -Action Install -ServerUrl 'https://hashes.example/windows/' -EnableDll -AuditOnly

# Choose a different update interval (1–168 hours).
.\HashgenClient.ps1 -Action Install -ServerUrl 'https://hashes.example/windows/' -IntervalHours 12
```

Installation stores a protected copy and configuration in
`C:\Program Files\Hashgen`, configures Application Identity for automatic startup,
and registers **Hashgen blocklist update** as a SYSTEM scheduled task. Only
SYSTEM and Administrators can change installation files or the task. Each action
uses an exclusive file lock. The initial download and policy update must succeed
before normal task registration completes. Re-run installation to change the
URL, DLL setting, audit mode, interval, or installed script; supply all intended
options again because omitted switches return to their defaults.

DLLs default **off**. Changing to DLL enforcement adds checks at library load
time and can block unrelated software using identical bundled libraries. The
script checks currently loaded updater DLLs before applying a DLL policy, but
that does not cover every library an application may load later. Audit first on
representative devices. `-AuditOnly` logs decisions; it does not block execution.

## Update, inspect, or uninstall

Run these commands in an elevated Windows PowerShell console:

```powershell
$client = "$env:ProgramFiles\Hashgen\HashgenClient.ps1"
& $client -Action Update
& $client -Action Status
& $client -Action Uninstall
```

Uninstallation removes the task and recognized Hashgen rules while preserving
other AppLocker rules. It retains the protected script, configuration, backups,
and logs, and leaves Application Identity running for other policies. Status
reports configuration, last successful policy application, service, and task
state. Read `client.log` for unchanged updates and errors; Task Scheduler records
the process's nonzero exit status on failure. Unchanged updates leave the
last-success timestamp as the last actual application time.

The script preserves `previous-policy.xml` before applying changes and restores
it if policy application or read-back verification fails. An administrator can
also restore it manually with `Set-AppLockerPolicy -XmlPolicy` after reviewing
its contents. Do not edit local AppLocker policy concurrently with an update.

## Policy handling

The client consumes the JSON inventory rather than blindly importing the
server's standalone XML. It generates only hash deny rules for Everyone,
using the same UUIDv5 namespace as the server. It replaces recognized Hashgen
rules instead of accumulating duplicates. It also recognizes rules from the
server's standalone policies if they were previously imported manually.

For an empty executable/DLL collection, it adds an `Allow *` baseline. For a
collection with unrelated rules, it preserves those rules and adds **no broad
allow rule**. Its requested enforcement mode must already match that collection's
mode; it will not silently activate somebody else's audit-only rules. If
Application Identity is stopped with unrelated rules present, configure that
service yourself before installing. Existing Script/MSI/Store policy remains
intact. The candidate must allow the SYSTEM updater script and PowerShell host.

Removing DLL enforcement or uninstalling removes only recognized Hashgen rules;
if unrelated rules were added later, they remain. Independently modified
Hashgen deny-rule IDs with changed scope or conditions cause a conflict rather than
being overwritten. If you need different target groups, adapt the client and
its ownership scheme deliberately.

This client is for **locally managed** policies. It detects rules/settings
contributed by Group Policy and refuses to replace local policy in that case.
`Get-AppLockerPolicy -Effective` does not expose every MDM CSP policy, so do not
use this script on an MDM-managed AppLocker device; integrate through its existing
management system instead.

## Download and offline behavior

The client validates schema version, selected EXE/DLL hashes, source metadata,
and publication consistency by downloading status both before and after the
manifest and checking its SHA-256. It retries mixed generations three times.
Empty selected collections and malformed feeds are rejected. Each response is
limited to 256 MiB. Partial server coverage is logged and its validated
accumulated inventory can still be used.

HTTPS and the machine's certificate trust authenticate the server; checksums
detect inconsistent files but are **not publisher signatures**. The current
server does not issue signed release manifests. Protect the server and use a
trusted HTTPS endpoint. No downloaded content is executed. The scheduled task
uses SYSTEM's network/proxy context, which may differ from the interactive user.

Failed downloads/validation leave existing AppLocker rules in place, including
while offline. The policy also remains active across network changes. Existing
Tor processes are not terminated by this script: test blocking with fresh
process launches, and close existing sessions during rollout. The client covers
the known binaries in the server feed, not modified builds or arbitrary tunnels.

## Tests

`tests/test_windows_client.ps1` parses the script and tests pure policy
composition, UUID/hash agreement, preserved restrictive rules, DLL selection,
uninstall, validation, atomic file writes, and mocked update failures and rollback.
These tests do not configure a
device. The Windows CI job runs them in Windows PowerShell 5.1. Native service,
scheduled-task registration, ACLs, actual execution blocking, and installation
rollback still require a Windows integration test before deployment.
