#Requires -Version 5.1
<#
.SYNOPSIS
Installs or updates the Hashgen Windows AppLocker blocklist client.
.EXAMPLE
.\HashgenClient.ps1 -Action Install -ServerUrl https://hashes.example/windows/
.EXAMPLE
.\HashgenClient.ps1 -Action Install -ServerUrl https://hashes.example/windows/ -EnableDll -AuditOnly
.NOTES
Run actions in elevated Windows PowerShell 5.1. Downloads are data, never code.
The scheduled task runs the protected installed copy as SYSTEM. This file is
distributed from the repository and is excluded from the server image.
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Update', 'Status', 'Uninstall')]
    [string]$Action = 'Status',
    [uri]$ServerUrl,
    [switch]$EnableDll,
    [switch]$AuditOnly,
    [ValidateRange(1, 168)] [int]$IntervalHours = 6
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ClientId = 'Hashgen.WindowsClient'
$script:TaskName = 'Hashgen blocklist update'
$script:RuleNamespace = [guid]'305850de-b10a-4c6b-9a2b-e1f140996650'
$script:InstallRoot = if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Hashgen' } else { $null }
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)

function Get-TextHash([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($script:Utf8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-RuleId([string]$Name) {
    # RFC 4122 UUIDv5; Guid.ToByteArray uses little-endian fields on .NET.
    $namespace = $script:RuleNamespace.ToByteArray()
    [array]::Reverse($namespace, 0, 4)
    [array]::Reverse($namespace, 4, 2)
    [array]::Reverse($namespace, 6, 2)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { [byte[]]$bytes = $sha.ComputeHash([byte[]]($namespace + $script:Utf8.GetBytes($Name)))[0..15] }
    finally { $sha.Dispose() }
    $bytes[6] = ($bytes[6] -band 15) -bor 80
    $bytes[8] = ($bytes[8] -band 63) -bor 128
    [array]::Reverse($bytes, 0, 4)
    [array]::Reverse($bytes, 4, 2)
    [array]::Reverse($bytes, 6, 2)
    return (New-Object System.Guid(,$bytes)).ToString()
}

function Read-PolicyXml([string]$Text) {
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $stringReader = New-Object System.IO.StringReader($Text)
    $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
    try {
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        if ($document.DocumentElement.Name -ne 'AppLockerPolicy' -or $document.DocumentElement.GetAttribute('Version') -ne '1') {
            throw 'Unsupported AppLocker policy document.'
        }
        return ,$document
    } finally { $reader.Dispose(); $stringReader.Dispose() }
}

function Get-RuleIndex([xml]$Policy) {
    $index = @{}
    foreach ($rule in $Policy.SelectNodes('/AppLockerPolicy/RuleCollection/*[@Id]')) {
        $id = ([guid]$rule.GetAttribute('Id')).ToString()
        if ($index.ContainsKey($id)) { throw 'Duplicate AppLocker rule ID.' }
        $index[$id] = $rule
    }
    return ,$index
}

function Test-OwnedRule([System.Xml.XmlElement]$Rule, [string]$Collection) {
    if ($Rule.GetAttribute('UserOrGroupSid') -ne 'S-1-1-0' -or $Rule.SelectSingleNode('Exceptions')) { return $false }
    $id = $Rule.GetAttribute('Id')
    if ($Rule.LocalName -eq 'FilePathRule' -and $Rule.GetAttribute('Action') -eq 'Allow') {
        $condition = $Rule.SelectSingleNode('Conditions/FilePathCondition')
        return ($null -ne $condition -and $condition.GetAttribute('Path') -eq '*' -and
                $id -eq (Get-RuleId "$Collection`:allow-all"))
    }
    if ($Rule.LocalName -eq 'FileHashRule' -and $Rule.GetAttribute('Action') -eq 'Deny') {
        $hashes = @($Rule.SelectNodes('Conditions/FileHashCondition/FileHash'))
        if ($hashes.Count -ne 1 -or $hashes[0].GetAttribute('Type') -ne 'SHA256') { return $false }
        $digest = $hashes[0].GetAttribute('Data')
        if ($digest -notmatch '^0x[0-9a-fA-F]{64}$') { return $false }
        return $id -eq (Get-RuleId ($Collection + ':' + $digest.Substring(2).ToLowerInvariant()))
    }
    return $false
}

function New-DesiredPolicy($Manifest, [bool]$DllEnabled, [ValidateSet('Enabled', 'AuditOnly')][string]$Mode) {
    if ($Manifest.schema_version -ne 1) { throw 'Unsupported manifest schema.' }
    $document = Read-PolicyXml '<AppLockerPolicy Version="1" />'
    $types = @('Exe')
    if ($DllEnabled) { $types += 'Dll' }
    $ids = @{}
    foreach ($type in $types) {
        $collection = $document.CreateElement('RuleCollection')
        $collection.SetAttribute('Type', $type)
        $collection.SetAttribute('EnforcementMode', $Mode)
        [void]$document.DocumentElement.AppendChild($collection)
        $entries = @($Manifest.files | Where-Object { $_.collection -eq $type } | Sort-Object applocker_sha256)
        if (-not $entries.Count) { throw "Manifest contains no $type hashes; existing policy retained." }
        foreach ($entry in $entries) {
            $digest = [string]$entry.applocker_sha256
            if ($digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid manifest Authenticode hash.' }
            $sources = @($entry.sources)
            if (-not $sources.Count) { throw 'Manifest hash has no source metadata.' }
            $source = $sources[0]
            [long]$size = 0
            if (-not [long]::TryParse([string]$source.size, [ref]$size) -or $size -lt 0) { throw 'Invalid source size.' }
            $fileName = ([string]$source.path -split '[/\\]')[-1]
            if (-not $fileName -or $fileName.Length -gt 260) { throw 'Invalid source filename.' }
            $id = Get-RuleId "$type`:$digest"
            if ($ids.ContainsKey($id)) { throw 'Duplicate manifest hash.' }
            $ids[$id] = $true
            $rule = $document.CreateElement('FileHashRule')
            $rule.SetAttribute('Id', $id)
            $rule.SetAttribute('Name', "Hashgen: $fileName [$($digest.Substring(0, 12))]")
            $rule.SetAttribute('Description', 'Managed by Hashgen.WindowsClient')
            $rule.SetAttribute('UserOrGroupSid', 'S-1-1-0')
            $rule.SetAttribute('Action', 'Deny')
            $conditions = $document.CreateElement('Conditions')
            $condition = $document.CreateElement('FileHashCondition')
            $hash = $document.CreateElement('FileHash')
            $hash.SetAttribute('Type', 'SHA256')
            $hash.SetAttribute('Data', '0x' + $digest.ToUpperInvariant())
            $hash.SetAttribute('SourceFileName', $fileName)
            $hash.SetAttribute('SourceFileLength', [string]$size)
            [void]$condition.AppendChild($hash)
            [void]$conditions.AppendChild($condition)
            [void]$rule.AppendChild($conditions)
            [void]$collection.AppendChild($rule)
        }
    }
    return ,$document
}

function Merge-ClientPolicy([xml]$Local, [xml]$Desired) {
    $result = Read-PolicyXml $Local.OuterXml
    $index = Get-RuleIndex $result
    foreach ($type in @('Exe', 'Dll')) {
        $collection = $result.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='$type']")
        $wanted = $Desired.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='$type']")
        $removed = $false
        if ($collection) {
            foreach ($rule in @($collection.SelectNodes('*[@Id]'))) {
                if (Test-OwnedRule $rule $type) {
                    [void]$index.Remove(([guid]$rule.GetAttribute('Id')).ToString())
                    [void]$collection.RemoveChild($rule)
                    $removed = $true
                }
            }
        }
        if (-not $wanted) {
            # Disabling DLLs/uninstalling removes only our rules. Other rules and
            # their enforcement settings remain. Remove our now-empty collection.
            if ($collection -and $removed -and $collection.ChildNodes.Count -eq 0) {
                [void]$result.DocumentElement.RemoveChild($collection)
            }
            continue
        }
        if (-not $collection) {
            $collection = $result.CreateElement('RuleCollection')
            $collection.SetAttribute('Type', $type)
            [void]$result.DocumentElement.AppendChild($collection)
        }
        $foreign = @($collection.SelectNodes('*[@Id]'))
        $mode = $wanted.GetAttribute('EnforcementMode')
        if ($foreign.Count -and $collection.GetAttribute('EnforcementMode') -ne $mode) {
            throw "Existing $type rules use a different enforcement mode. Configure them explicitly before using this client."
        }
        $collection.SetAttribute('EnforcementMode', $mode)
        if (-not $foreign.Count) {
            $allow = $result.CreateElement('FilePathRule')
            $allow.SetAttribute('Id', (Get-RuleId "$type`:allow-all"))
            $allow.SetAttribute('Name', 'Hashgen: allow other files')
            $allow.SetAttribute('Description', 'Standalone blocklist baseline')
            $allow.SetAttribute('UserOrGroupSid', 'S-1-1-0')
            $allow.SetAttribute('Action', 'Allow')
            $conditions = $result.CreateElement('Conditions')
            $condition = $result.CreateElement('FilePathCondition')
            $condition.SetAttribute('Path', '*')
            [void]$conditions.AppendChild($condition)
            [void]$allow.AppendChild($conditions)
            [void]$collection.AppendChild($allow)
        }
        foreach ($rule in $wanted.SelectNodes('FileHashRule')) {
            $id = ([guid]$rule.GetAttribute('Id')).ToString()
            if ($index.ContainsKey($id)) {
                throw 'A Hashgen rule ID conflicts with an independently modified local rule.'
            }
            $imported = $result.ImportNode($rule, $true)
            [void]$collection.AppendChild($imported)
            $index[$id] = $imported
        }
    }
    return ,$result
}

function Assert-LocalPolicy([xml]$Local, [xml]$Effective) {
    # Get-AppLockerPolicy -Effective covers Group Policy, not every MDM CSP.
    # MDM-managed machines are explicitly outside this standalone client's scope.
    $localRules = Get-RuleIndex $Local
    foreach ($collection in $Effective.SelectNodes('/AppLockerPolicy/RuleCollection')) {
        $type = $collection.GetAttribute('Type')
        $localCollection = $Local.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='$type']")
        foreach ($rule in $collection.SelectNodes('*[@Id]')) {
            $id = ([guid]$rule.GetAttribute('Id')).ToString()
            if (-not $localRules.ContainsKey($id)) {
                throw 'Group Policy contributes AppLocker rules. Manage Hashgen through that policy system instead.'
            }
        }
        if (-not $localCollection -and $collection.GetAttribute('EnforcementMode') -in @('Enabled', 'AuditOnly')) {
            throw 'Effective AppLocker collection is controlled outside local policy.'
        }
        if ($localCollection -and $localCollection.GetAttribute('EnforcementMode') -ne $collection.GetAttribute('EnforcementMode')) {
            throw 'Effective AppLocker enforcement differs from local settings; centralized policy may be active.'
        }
    }
}

function Assert-DesiredPolicy([xml]$Effective, [xml]$Desired) {
    $actualRules = Get-RuleIndex $Effective
    foreach ($collection in $Desired.SelectNodes('/AppLockerPolicy/RuleCollection')) {
        $type = $collection.GetAttribute('Type')
        $actual = $Effective.SelectSingleNode("/AppLockerPolicy/RuleCollection[@Type='$type']")
        if (-not $actual -or $actual.GetAttribute('EnforcementMode') -ne $collection.GetAttribute('EnforcementMode')) {
            throw "Effective $type enforcement was not updated."
        }
        foreach ($rule in $collection.SelectNodes('FileHashRule')) {
            $id = ([guid]$rule.GetAttribute('Id')).ToString()
            $found = $actualRules[$id]
            if (-not $found -or $found.ParentNode.GetAttribute('Type') -ne $type -or -not (Test-OwnedRule $found $type)) {
                throw "Effective policy is missing Hashgen rule $id."
            }
        }
    }
}

function Save-Text([string]$Path, [string]$Text) {
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [System.IO.File]::WriteAllText($temporary, $Text, $script:Utf8)
        if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value) }
        else { [System.IO.File]::Move($temporary, $Path) }
    } finally { if ([System.IO.File]::Exists($temporary)) { [System.IO.File]::Delete($temporary) } }
}

function Write-ClientLog([string]$Message) {
    $path = Join-Path $script:InstallRoot 'client.log'
    if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 1MB) {
        Move-Item -LiteralPath $path -Destination ($path + '.1') -Force
    }
    [System.IO.File]::AppendAllText($path, ([DateTime]::UtcNow.ToString('o') + ' ' + $Message + [Environment]::NewLine), $script:Utf8)
    Write-Verbose $Message
}

function Assert-WindowsAdministrator {
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Run this client in Windows PowerShell 5.1 on Windows.'
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open Windows PowerShell as administrator to run this action.'
    }
    Import-Module AppLocker -ErrorAction Stop
}

function Protect-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { [void](New-Item -ItemType Directory -Path $Path) }
    if ((Get-Item -LiteralPath $Path).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Installation directory cannot be a junction or link.' }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($administrators)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Read-ClientConfig {
    $path = Join-Path $script:InstallRoot 'config.json'
    if (-not (Test-Path -LiteralPath $path)) { throw 'Client is not installed.' }
    $config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.schema_version -ne 1 -or $config.client -ne $script:ClientId) { throw 'Unrecognized client configuration.' }
    return $config
}

function Get-ServerBase([uri]$Url) {
    if (-not $Url -or -not $Url.IsAbsoluteUri -or $Url.Scheme -ne 'https' -or $Url.UserInfo -or $Url.Query -or $Url.Fragment) {
        throw 'ServerUrl must be an absolute HTTPS directory URL without credentials, query, or fragment.'
    }
    return [uri]($Url.AbsoluteUri.TrimEnd('/') + '/')
}

function Receive-File([uri]$Url, [string]$Destination) {
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 90000
    $request.ReadWriteTimeout = 90000
    $request.Headers['Cache-Control'] = 'no-cache'
    $response = $request.GetResponse()
    try {
        if ([int]$response.StatusCode -ne 200) { throw 'Server must return files directly without redirects.' }
        $limit = 256MB
        if ($response.ContentLength -gt $limit) { throw 'Server response exceeds 256 MiB.' }
        $input = $response.GetResponseStream()
        $output = [System.IO.File]::Create($Destination)
        try {
            $buffer = New-Object byte[] 65536
            [long]$total = 0
            while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $count
                if ($total -gt $limit) { throw 'Server response exceeds 256 MiB.' }
                $output.Write($buffer, 0, $count)
            }
        } finally { $output.Dispose(); $input.Dispose() }
    } finally { $response.Dispose() }
}

function Receive-Manifest($Config, [string]$Staging) {
    $base = Get-ServerBase ([uri]$Config.server_url)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Receive-File ([uri]::new($base, 'status.json')) (Join-Path $Staging 'status.json')
        $status = Get-Content (Join-Path $Staging 'status.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($status.schema_version -ne 1 -or $status.outputs.'manifest.json' -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid server publication status.' }
        Receive-File ([uri]::new($base, 'manifest.json')) (Join-Path $Staging 'manifest.json')
        $actual = (Get-FileHash (Join-Path $Staging 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        Receive-File ([uri]::new($base, 'status.json')) (Join-Path $Staging 'status-after.json')
        $after = Get-Content (Join-Path $Staging 'status-after.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($actual -eq $status.outputs.'manifest.json' -and $after.schema_version -eq 1 -and
            $after.outputs.'manifest.json' -eq $actual -and $after.generated_at -eq $status.generated_at) {
            $manifest = Get-Content (Join-Path $Staging 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($manifest.generated_at -ne $status.generated_at) { throw 'Manifest generation does not match status.' }
            if (@($status.errors).Count) { Write-ClientLog 'Server reports partial coverage; using its validated accumulated inventory.' }
            return $manifest
        }
    }
    throw 'Server publication changed or checksums did not match after three attempts.'
}

function Enable-IdentityService {
    & "$env:WINDIR\System32\sc.exe" config AppIDSvc start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure Application Identity to start automatically.' }
    Start-Service AppIDSvc
    if ((Get-Service AppIDSvc).Status -ne 'Running') { throw 'Application Identity is not running.' }
}

function Invoke-ClientUpdate($Config) {
    $staging = Join-Path $script:InstallRoot ('staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $staging)
    try {
        $manifest = Receive-Manifest $Config $staging
        $desired = New-DesiredPolicy $manifest ([bool]$Config.enable_dll) $Config.enforcement_mode
        $originalText = Get-AppLockerPolicy -Local -Xml
        $local = Read-PolicyXml $originalText
        $effective = Read-PolicyXml (Get-AppLockerPolicy -Effective -Xml)
        Assert-LocalPolicy $local $effective
        if ((Get-Service AppIDSvc).Status -ne 'Running') {
            foreach ($collection in $local.SelectNodes('/AppLockerPolicy/RuleCollection')) {
                foreach ($rule in $collection.SelectNodes('*[@Id]')) {
                    if (-not (Test-OwnedRule $rule $collection.GetAttribute('Type'))) {
                        throw 'Application Identity is stopped with unrelated policy rules present. Configure that service before installing this client.'
                    }
                }
            }
        }
        $candidate = Merge-ClientPolicy $local $desired
        $desiredDigest = Get-TextHash $desired.OuterXml
        $lastPath = Join-Path $script:InstallRoot 'last-update.json'
        if (Test-Path -LiteralPath $lastPath) {
            $last = Get-Content $lastPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($last.desired_sha256 -eq $desiredDigest -and $last.local_policy_sha256 -eq (Get-TextHash $originalText)) {
                Assert-DesiredPolicy $effective $desired
                Enable-IdentityService
                Write-ClientLog 'Policy unchanged; no application needed.'
                return
            }
        }
        $backup = Join-Path $script:InstallRoot 'previous-policy.xml'
        $candidatePath = Join-Path $staging 'candidate.xml'
        Save-Text $backup $originalText
        Save-Text $candidatePath $candidate.OuterXml
        # Refuse an update that would prevent the SYSTEM task from running.
        $updaterPaths = @((Join-Path $script:InstallRoot 'HashgenClient.ps1'), "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe")
        if ($Config.enable_dll) {
            $updaterPaths += @([System.Diagnostics.Process]::GetCurrentProcess().Modules | ForEach-Object { $_.FileName } |
                Where-Object { [System.IO.Path]::GetExtension($_) -eq '.dll' })
        }
        foreach ($path in @($updaterPaths | Select-Object -Unique)) {
            $decision = Test-AppLockerPolicy -XmlPolicy $candidatePath -Path $path -User 'S-1-5-18'
            if ($decision.PolicyDecision.ToString() -notmatch '^Allowed') { throw "Candidate policy blocks the updater: $path" }
        }
        if ((Get-TextHash (Get-AppLockerPolicy -Local -Xml)) -ne (Get-TextHash $originalText)) {
            throw 'Local AppLocker policy changed during preparation; retry the update.'
        }
        Enable-IdentityService
        try {
            Set-AppLockerPolicy -XmlPolicy $candidatePath
            $readBack = Get-AppLockerPolicy -Local -Xml
            Assert-DesiredPolicy (Read-PolicyXml (Get-AppLockerPolicy -Effective -Xml)) $desired
            $state = @{ schema_version = 1; updated_at = [DateTime]::UtcNow.ToString('o');
                server_generated_at = $manifest.generated_at; desired_sha256 = $desiredDigest;
                local_policy_sha256 = (Get-TextHash $readBack); enable_dll = [bool]$Config.enable_dll;
                enforcement_mode = $Config.enforcement_mode; deny_rules = $desired.SelectNodes('//FileHashRule').Count }
            Save-Text $lastPath ($state | ConvertTo-Json)
            Save-Text (Join-Path $script:InstallRoot 'last-manifest.json') (Get-Content (Join-Path $staging 'manifest.json') -Raw -Encoding UTF8)
        } catch {
            $failure = $_
            try { Set-AppLockerPolicy -XmlPolicy $backup; Write-ClientLog 'Policy update failed; previous local policy restored.' }
            catch { throw "Update failed ($failure); rollback also failed ($_). Backup: $backup" }
            throw $failure
        }
        Write-ClientLog "Updated $($state.deny_rules) deny rules ($($Config.enforcement_mode)); DLL enabled: $($Config.enable_dll)."
    } finally { Remove-Item -LiteralPath $staging -Recurse -Force }
}

function Register-ClientTask([int]$Hours) {
    Import-Module ScheduledTasks
    $existing = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($existing -and $existing.Description -notlike "$($script:ClientId)*") { throw 'An unrelated task already uses the Hashgen task name.' }
    $powerShell = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $installed = Join-Path $script:InstallRoot 'HashgenClient.ps1'
    $action = New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$installed`" -Action Update"
    $startup = New-ScheduledTaskTrigger -AtStartup
    $periodic = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours $Hours)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Trigger @($startup, $periodic) -Principal $principal -Settings $settings -Description "$($script:ClientId): maintain the local Tor blocklist"
    [void](Register-ScheduledTask -TaskName $script:TaskName -InputObject $task -Force)
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $scheduler.GetFolder('\').GetTask($script:TaskName).SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)', 0)
}

function Invoke-ClientAction {
    Assert-WindowsAdministrator
    if ($Action -eq 'Install') {
        $base = Get-ServerBase $ServerUrl
        Import-Module ScheduledTasks
        $existingTask = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
        if ($existingTask -and $existingTask.Description -notlike "$($script:ClientId)*") {
            throw 'An unrelated task already uses the Hashgen task name.'
        }
        if (Test-Path -LiteralPath $script:InstallRoot) {
            $configPath = Join-Path $script:InstallRoot 'config.json'
            if (@(Get-ChildItem -LiteralPath $script:InstallRoot -Force).Count -and -not (Test-Path $configPath)) {
                throw 'Existing installation directory is not a recognized Hashgen client.'
            }
            if (Test-Path $configPath) { [void](Read-ClientConfig) }
        }
        Protect-Directory $script:InstallRoot
    } elseif (-not (Test-Path -LiteralPath $script:InstallRoot)) { throw 'Client is not installed.' }
    $lockPath = Join-Path $script:InstallRoot 'update.lock'
    $lock = [System.IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        switch ($Action) {
            'Install' {
                $installed = Join-Path $script:InstallRoot 'HashgenClient.ps1'
                if ([System.IO.Path]::GetFullPath($PSCommandPath) -ne $installed) { Copy-Item -LiteralPath $PSCommandPath -Destination $installed -Force }
                $config = @{ schema_version = 1; client = $script:ClientId; server_url = $base.AbsoluteUri;
                    enable_dll = [bool]$EnableDll; enforcement_mode = $(if ($AuditOnly) { 'AuditOnly' } else { 'Enabled' });
                    interval_hours = $IntervalHours; installed = $true }
                Save-Text (Join-Path $script:InstallRoot 'config.json') ($config | ConvertTo-Json)
                Invoke-ClientUpdate ([pscustomobject]$config)
                Register-ClientTask $IntervalHours
                Write-Output "Installed Hashgen client. Task: $($script:TaskName); directory: $($script:InstallRoot)."
            }
            'Update' {
                $config = Read-ClientConfig
                if (-not $config.installed) { throw 'Client was uninstalled.' }
                Invoke-ClientUpdate $config
            }
            'Status' {
                Read-ClientConfig | Format-List
                if (Test-Path (Join-Path $script:InstallRoot 'last-update.json')) { Get-Content (Join-Path $script:InstallRoot 'last-update.json') -Raw -Encoding UTF8 }
                Get-Service AppIDSvc | Select-Object Name, Status
                Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue | Select-Object TaskName, State
            }
            'Uninstall' {
                $config = Read-ClientConfig
                $localText = Get-AppLockerPolicy -Local -Xml
                $local = Read-PolicyXml $localText
                Assert-LocalPolicy $local (Read-PolicyXml (Get-AppLockerPolicy -Effective -Xml))
                $clean = Merge-ClientPolicy $local (Read-PolicyXml '<AppLockerPolicy Version="1" />')
                $backup = Join-Path $script:InstallRoot 'previous-policy.xml'
                Save-Text $backup $localText
                $cleanPath = Join-Path $script:InstallRoot 'uninstall-policy.xml'
                Save-Text $cleanPath $clean.OuterXml
                try { Set-AppLockerPolicy -XmlPolicy $cleanPath }
                catch { Set-AppLockerPolicy -XmlPolicy $backup; throw }
                $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
                if ($task -and $task.Description -like "$($script:ClientId)*") { Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false }
                $config.installed = $false
                Save-Text (Join-Path $script:InstallRoot 'config.json') ($config | ConvertTo-Json)
                Write-ClientLog 'Uninstalled task and Hashgen policy rules. Protected scripts, backups, and logs retained.'
                Write-Output 'Hashgen task and rules removed. Application Identity and unrelated rules were preserved.'
            }
        }
    } catch {
        Write-ClientLog "ERROR: $_"
        throw
    } finally { $lock.Dispose() }
}

# Dot-sourcing loads pure policy functions for tests; normal invocation performs
# exactly the requested action. Default invocation only displays status.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-ClientAction }
    catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit 1 }
}
