# Native AppLocker hash/policy verification only; no policy is installed.
param(
    [string]$WorkDir = (Join-Path $env:TEMP "hashgen-applocker"),
    [string]$TorVersion = "15.0.24"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
Import-Module AppLocker

# Compile unsigned EXEs and DLLs in both architectures, then sign copies.
$source = Join-Path $WorkDir "fixture.cs"
'public class Fixture { public static void Main() {} }' | Set-Content $source
$compiler = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
$certificate = New-SelfSignedCertificate -Subject "CN=Hashgen CI fixture" `
    -Type CodeSigningCert -CertStoreLocation "Cert:\CurrentUser\My"
try {
    foreach ($architecture in @("x86", "x64")) {
        foreach ($kind in @("exe", "dll")) {
            $target = if ($kind -eq "dll") { "library" } else { "exe" }
            $unsigned = Join-Path $WorkDir "unsigned-$architecture.$kind"
            & $compiler /nologo /target:$target /platform:$architecture /out:$unsigned $source
            if ($LASTEXITCODE -ne 0) { throw "Fixture compilation failed" }
            $signed = Join-Path $WorkDir "signed-$architecture.$kind"
            Copy-Item $unsigned $signed -Force
            $signature = Set-AuthenticodeSignature -FilePath $signed -Certificate $certificate -HashAlgorithm SHA256
            if (-not $signature.SignerCertificate) { throw "Fixture signing failed" }
        }
    }
    # Include native Windows PE images as well as the compiled .NET fixtures.
    Copy-Item (Join-Path $env:WINDIR "System32\cmd.exe") (Join-Path $WorkDir "native-x64.exe") -Force
    Copy-Item (Join-Path $env:WINDIR "System32\version.dll") (Join-Path $WorkDir "native-x64.dll") -Force
    Copy-Item (Join-Path $env:WINDIR "SysWOW64\cmd.exe") (Join-Path $WorkDir "native-x86.exe") -Force
    Copy-Item (Join-Path $env:WINDIR "SysWOW64\version.dll") (Join-Path $WorkDir "native-x86.dll") -Force

    if ($TorVersion) {
        foreach ($name in @("tor-browser-windows-x86_64-portable-$TorVersion.exe",
                            "tor-expert-bundle-windows-x86_64-$TorVersion.tar.gz")) {
            $url = "https://archive.torproject.org/tor-package-archive/torbrowser/$TorVersion/$name"
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile (Join-Path $WorkDir $name)
        }
    }

    python (Join-Path $PSScriptRoot "windows_hash_inventory.py") $WorkDir
    if ($LASTEXITCODE -ne 0) { throw "Python inventory generation failed" }
    $records = Get-Content (Join-Path $WorkDir "generated\hashes.json") -Raw | ConvertFrom-Json
    foreach ($record in $records) {
        $path = Join-Path $WorkDir $record.path
        [xml]$reference = Get-AppLockerFileInformation -Path $path |
            New-AppLockerPolicy -RuleType Hash -User Everyone -Xml
        $native = $reference.SelectSingleNode("//FileHash").GetAttribute("Data")
        if ($native.ToLowerInvariant() -ne ("0x" + $record.applocker_sha256)) {
            throw "Authenticode hash mismatch: $path"
        }
        $policy = Join-Path $WorkDir "generated\applocker-exe-dll.xml"
        $decision = Test-AppLockerPolicy -XmlPolicy $policy -Path $path -User "S-1-1-0"
        if ($decision.PolicyDecision.ToString() -ne "Denied") {
            throw "Expected explicit deny for $path; received $($decision.PolicyDecision)"
        }
    }
    $moved = Join-Path $WorkDir "moved\renamed.exe"
    New-Item -ItemType Directory -Force -Path (Split-Path $moved) | Out-Null
    Copy-Item (Join-Path $WorkDir "unsigned-x86.exe") $moved -Force
    $decision = Test-AppLockerPolicy -XmlPolicy $policy -Path $moved -User "S-1-1-0"
    if ($decision.PolicyDecision.ToString() -ne "Denied") { throw "Renamed/moved executable was allowed" }
    # An unrelated executable must still be allowed by the standalone baseline.
    $unrelated = Join-Path $env:WINDIR "System32\whoami.exe"
    $decision = Test-AppLockerPolicy -XmlPolicy $policy -Path $unrelated -User "S-1-1-0"
    if ($decision.PolicyDecision.ToString() -ne "Allowed") { throw "Unrelated executable was blocked" }
    Write-Output "Verified $($records.Count) fixture/Tor EXE/DLL hashes and policy decisions."
} finally {
    Remove-Item "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -ErrorAction SilentlyContinue
}
