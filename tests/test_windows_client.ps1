# Pure client policy tests. No tasks, services, or device policies are changed.
$ErrorActionPreference = 'Stop'
$client = Join-Path (Split-Path $PSScriptRoot -Parent) 'client/windows/HashgenClient.ps1'
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($client, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
. $client

function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Operation, [string]$Message) {
    $thrown = $false
    try { & $Operation | Out-Null } catch { $thrown = $true }
    Assert $thrown $Message
}

Assert ((Get-RuleId 'Exe:allow-all') -eq 'b1e58bba-8bfc-5ecc-8325-a1e511ddb0d7') 'UUID namespace differs from server.'
Assert ((Get-RuleId ('Exe:' + ('a' * 64))) -eq 'b1d3a9b0-5d2a-59be-86e4-a810284d0061') 'UUIDv5 hash differs from server.'
Assert ((Get-RuleId ('Dll:' + ('b' * 64))) -eq '18cc1a5b-875d-5a00-b3c8-2a9fff552637') 'DLL UUID differs from server.'
$manifest = @{ schema_version = 1; files = @(
    @{ collection = 'Exe'; applocker_sha256 = ('a' * 64); sources = @(@{path = 'Browser/tor.exe'; size = 1024}) },
    @{ collection = 'Dll'; applocker_sha256 = ('b' * 64); sources = @(@{path = 'Browser/runtime.dll'; size = 2048}) }
) }
$empty = Read-PolicyXml '<AppLockerPolicy Version="1" />'
$exe = New-DesiredPolicy $manifest $false 'Enabled'
$combined = New-DesiredPolicy $manifest $true 'Enabled'
$standalone = Merge-ClientPolicy $empty $exe
Assert ($standalone.SelectNodes('//RuleCollection').Count -eq 1) 'Executable-only policy has extra collections.'
Assert ($standalone.SelectNodes('//FileHashRule').Count -eq 1) 'Executable hash rule missing.'
Assert ($standalone.SelectSingleNode('//FilePathCondition').GetAttribute('Path') -eq '*') 'Fresh policy needs allow baseline.'
Assert (Test-OwnedRule $standalone.SelectSingleNode('//FileHashRule') 'Exe') 'Generated deny was not recognized as owned.'
Assert (Test-OwnedRule $standalone.SelectSingleNode('//FilePathRule') 'Exe') 'Generated baseline was not recognized as owned.'
Assert-DesiredPolicy $standalone $exe
Assert-LocalPolicy $standalone $standalone
$repeated = Merge-ClientPolicy $standalone $exe
Assert ($repeated.OuterXml -eq $standalone.OuterXml) 'Repeated composition creates duplicates or changes policy.'

$foreignId = '11111111-1111-4111-8111-111111111111'
$restricted = Read-PolicyXml @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="$foreignId" Name="Existing rule" Description="Preserve" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="C:\Windows\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="22222222-2222-4222-8222-222222222222" Name="Script rule" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="C:\scripts\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
$merged = Merge-ClientPolicy $restricted $combined
Assert ($merged.SelectNodes('//FilePathCondition[@Path="*"]').Count -eq 1) 'Existing EXE policy was broadened by allow-all.'
Assert ($merged.SelectSingleNode("//*[@Id='$foreignId']").OuterXml -eq $restricted.SelectSingleNode("//*[@Id='$foreignId']").OuterXml) 'Existing rule changed.'
Assert ($merged.SelectSingleNode('//RuleCollection[@Type="Script"]').OuterXml -eq $restricted.SelectSingleNode('//RuleCollection[@Type="Script"]').OuterXml) 'Unrelated script policy changed.'
$disabled = Merge-ClientPolicy $merged $exe
Assert (-not $disabled.SelectSingleNode('//RuleCollection[@Type="Dll"]')) 'Disabling DLLs left an owned DLL collection.'
$uninstalled = Merge-ClientPolicy $merged $empty
Assert ($uninstalled.OuterXml -eq $restricted.OuterXml) 'Uninstall did not restore unrelated policy.'
Assert ((Merge-ClientPolicy $standalone $empty).DocumentElement.ChildNodes.Count -eq 0) 'Standalone uninstall left rules.'

$audit = Read-PolicyXml ($restricted.OuterXml.Replace('Type="Exe" EnforcementMode="Enabled"', 'Type="Exe" EnforcementMode="AuditOnly"'))
Assert-Throws { Merge-ClientPolicy $audit $exe } 'Changing existing rule enforcement must be refused.'
Assert-Throws { Assert-LocalPolicy $empty $restricted } 'Group Policy rules were not detected.'
$uppercase = Read-PolicyXml $standalone.OuterXml
foreach ($rule in $uppercase.SelectNodes('//*[@Id]')) { $rule.SetAttribute('Id', $rule.GetAttribute('Id').ToUpperInvariant()) }
Assert-DesiredPolicy $uppercase $exe
Assert-LocalPolicy $standalone $uppercase

$tampered = Read-PolicyXml $standalone.OuterXml
$tampered.SelectSingleNode('//FileHashRule').SetAttribute('UserOrGroupSid', 'S-1-5-18')
Assert-Throws { Merge-ClientPolicy $tampered $exe } 'Independently modified rule should cause a conflict.'
Assert-Throws { Assert-DesiredPolicy $tampered $exe } 'Incorrect scope passed effective verification.'
Assert-Throws { Read-PolicyXml '<!DOCTYPE AppLockerPolicy [<!ENTITY x SYSTEM "file:///etc/passwd">]><AppLockerPolicy Version="1">&x;</AppLockerPolicy>' } 'DTD accepted.'
Assert-Throws { Get-ServerBase ([uri]'http://example.test/windows/') } 'HTTP server accepted.'
Assert-Throws { Get-ServerBase ([uri]'https://user:password@example.test/windows/') } 'URL credentials accepted.'
Assert ((Get-ServerBase ([uri]'https://example.test/windows')).AbsoluteUri -eq 'https://example.test/windows/') 'Base URL normalization failed.'
$bad = @{ schema_version = 1; files = @(@{collection = 'Exe'; applocker_sha256 = 'wrong'; sources = @(@{path = 'tor.exe'; size = 1})}) }
Assert-Throws { New-DesiredPolicy $bad $false 'Enabled' } 'Invalid hash accepted.'
Assert-Throws { New-DesiredPolicy @{schema_version=1; files=@()} $false 'Enabled' } 'Empty feed would erase blocklist.'

# Publication races are retried before any policy composition/application.
$manifest.generated_at = '2026-01-01T00:00:00+00:00'
$script:FeedJson = $manifest | ConvertTo-Json -Depth 8
$script:FeedDigest = Get-TextHash $script:FeedJson
$script:DownloadCalls = 0
function Receive-File {
    param([uri]$Url, [string]$Destination)
    $script:DownloadCalls++
    if ($Url.AbsolutePath.EndsWith('/manifest.json')) { Save-Text $Destination $script:FeedJson }
    else {
        $digest = if ($script:DownloadCalls -le 3) { '0' * 64 } else { $script:FeedDigest }
        $status = @{schema_version=1; generated_at='2026-01-01T00:00:00+00:00'; errors=@(); outputs=@{'manifest.json'=$digest}}
        Save-Text $Destination ($status | ConvertTo-Json -Depth 4)
    }
}

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temporary)
try {
    $feed = Receive-Manifest ([pscustomobject]@{server_url='https://example.test/windows/'}) $temporary
    Assert ($feed.schema_version -eq 1 -and $script:DownloadCalls -eq 6) 'Mixed publication did not retry exactly once.'
    $path = Join-Path $temporary 'state.json'
    Save-Text $path 'first'
    Save-Text $path 'second'
    Assert (([System.IO.File]::ReadAllText($path)) -eq 'second') 'Atomic replacement failed.'
    Assert (@(Get-ChildItem $temporary -Filter '*.tmp').Count -eq 0) 'Temporary file left behind.'
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }

# Exercise the update transaction with in-memory Windows API substitutes.
# These functions never touch the host's services, tasks, or AppLocker policy.
$script:ModelPolicy = $empty.OuterXml
$script:SetCalls = 0
$script:FailVerification = $false
$script:ReceivedManifest = $manifest
function Enable-IdentityService { }
function Get-Service { param($Name) return [pscustomobject]@{Status='Running'} }
function Get-AppLockerPolicy {
    param([switch]$Local, [switch]$Effective, [switch]$Xml)
    if ($Effective -and $script:FailVerification -and $script:SetCalls -eq 1) { return '<AppLockerPolicy Version="1" />' }
    return $script:ModelPolicy
}
function Set-AppLockerPolicy {
    param([string]$XmlPolicy)
    $script:SetCalls++
    $script:ModelPolicy = [System.IO.File]::ReadAllText($XmlPolicy)
}
function Test-AppLockerPolicy {
    param([string]$XmlPolicy, $Path, [string]$User)
    return [pscustomobject]@{PolicyDecision='Allowed'}
}
function Receive-Manifest {
    param($Config, [string]$Staging)
    Save-Text (Join-Path $Staging 'manifest.json') ($script:ReceivedManifest | ConvertTo-Json -Depth 8)
    return $script:ReceivedManifest
}
$transactionDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $transactionDirectory)
$script:InstallRoot = $transactionDirectory
try {
    $manifest.generated_at = '2026-01-01T00:00:00+00:00'
    $config = [pscustomobject]@{enable_dll=$false; enforcement_mode='Enabled'}
    Invoke-ClientUpdate $config
    Assert ($script:SetCalls -eq 1) 'Initial update did not apply policy.'
    Assert-DesiredPolicy (Read-PolicyXml $script:ModelPolicy) $exe
    Invoke-ClientUpdate $config
    Assert ($script:SetCalls -eq 1) 'Unchanged update re-applied policy.'
    $script:ReceivedManifest = @{schema_version=1; generated_at='invalid'; files=@()}
    Assert-Throws { Invoke-ClientUpdate $config } 'Empty feed accepted by transaction.'
    Assert ($script:SetCalls -eq 1) 'Failed validation changed policy.'

    # A failed read-back must restore the exact original policy.
    $script:ReceivedManifest = $manifest
    $script:ModelPolicy = $empty.OuterXml
    $script:SetCalls = 0
    $script:FailVerification = $true
    Assert-Throws { Invoke-ClientUpdate $config } 'Missing effective rules did not fail.'
    Assert ($script:SetCalls -eq 2) 'Rollback did not apply the backup.'
    Assert ($script:ModelPolicy -eq $empty.OuterXml) 'Rollback changed the previous policy.'
    Assert (@(Get-ChildItem $transactionDirectory -Filter 'staging-*').Count -eq 0) 'Staging files retained after failed update.'
} finally { Remove-Item -LiteralPath $transactionDirectory -Recurse -Force }
Write-Output 'Client parser and policy tests passed; no device configuration was changed.'
