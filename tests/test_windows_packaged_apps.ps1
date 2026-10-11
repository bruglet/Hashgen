# Native validation of packaged-app and updater decisions. Never installs policy.
param([string]$WorkDir = (Join-Path $env:TEMP 'hashgen-packaged-app-tests'))
$ErrorActionPreference = 'Stop'
Import-Module AppLocker
Import-Module Appx
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'client/windows/HashgenClient.ps1')
[void](New-Item -ItemType Directory -Path $WorkDir -Force)
$policyPath = Join-Path $WorkDir 'candidate.xml'
$cmd = Join-Path $env:WINDIR 'System32/cmd.exe'
[xml]$nativeHash = Get-AppLockerFileInformation -Path $cmd | New-AppLockerPolicy -RuleType Hash -User Everyone -Xml
$digest = $nativeHash.SelectSingleNode('//FileHash').GetAttribute('Data').Substring(2).ToLowerInvariant()
$manifest = @{schema_version=1; files=@(@{collection='Exe'; applocker_sha256=$digest; sources=@(@{path='cmd.exe'; size=(Get-Item $cmd).Length})})}
$candidate = Merge-ClientPolicy (Read-PolicyXml '<AppLockerPolicy Version="1" />') (New-DesiredPolicy $manifest $false 'Enabled')
[IO.File]::WriteAllText($policyPath, $candidate.OuterXml)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$packages = @(Get-AppxPackage)
if (-not $packages.Count) { throw 'No installed packages available for native packaged-app validation.' }
$decisions = @(Test-AppLockerPolicy -XmlPolicy $policyPath -Packages $packages -User $sid)
if (-not $decisions.Count) { throw 'Native test returned no packaged-app decisions.' }
foreach ($decision in $decisions) {
    if ($decision.PolicyDecision.ToString() -notmatch '^Allowed') { throw "Packaged app would be blocked: $($decision.FilePath) ($($decision.PolicyDecision))" }
}
$deny = Test-AppLockerPolicy -XmlPolicy $policyPath -Path $cmd -User $sid
if ($deny.PolicyDecision.ToString() -ne 'Denied') { throw 'Packaged-app baseline accidentally bypassed executable hash deny.' }
$hostPath = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
$allow = Test-AppLockerPolicy -XmlPolicy $policyPath -Path $hostPath -User 'S-1-5-18'
if ($allow.PolicyDecision.ToString() -notmatch '^Allowed') { throw 'Candidate blocks the SYSTEM updater host.' }
$critical = @($packages | Where-Object { $_.Name -match 'SecHealthUI|ChatGPT|Codex' })
foreach ($package in $critical) {
    $criticalDecisions = @(Test-AppLockerPolicy -XmlPolicy $policyPath -Packages $package -User $sid)
    if (-not $criticalDecisions.Count -or @($criticalDecisions | Where-Object { $_.PolicyDecision.ToString() -notmatch '^Allowed' }).Count) {
        throw "Critical packaged app was not verified allowed: $($package.Name)"
    }
}
# Windows omits some framework/resource-only packages from decision output.
$names = @($critical | ForEach-Object { [string]$_.Name })
Write-Output "Native policy test passed: $($decisions.Count) packaged-app decisions, including $($names -join ', '). EXE deny and SYSTEM updater allow also passed. No policy installed."
