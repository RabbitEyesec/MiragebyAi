#Requires -Version 5.1
<#
.SYNOPSIS
    Builds and Authenticode-signs the hardened MirageEndpoint MSI.
.DESCRIPTION
    LAB_VERIFICATION_REQUIRED — requires a Windows host with the WiX
    Toolset v5 (`dotnet tool install --global wix`), Python 3.12, and
    PyInstaller. Not executable in this development environment (ADR-0008).

    1. pip install -e the mirage_endpoint + mirage_contracts + mirage_common
       packages into a build venv.
    2. Stamps the release source/build hash, then PyInstaller-freezes
       mirage_endpoint.win_service into mirage-endpoint-service.exe.
    4. Stages Sysmon64.exe / elastic-agent-installer.exe payloads (from the
       locations configured in config/<environment>.yaml — never vendored
       into this repo, third-party binaries).
    5. Runs `wix build Product.wxs -o bin\MirageEndpoint.msi`.
    6. Runs `wix build Bundle.wxs -o dist\MirageEndpointSetup.exe`.
    7. Authenticode-signs the service, MSI, and Burn bundle using a protected
       Windows certificate-store identity.
#>
[CmdletBinding()]
param(
    [string]$Environment = "development",
    [string]$OutputDir = "$PSScriptRoot\dist",
    [Parameter(Mandatory=$true)][ValidatePattern("^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")]
    [string]$BuildHash,
    [string]$SigningCertificateThumbprint,
    [switch]$UnsignedLabBuild
)

$ErrorActionPreference = "Stop"
if (-not $UnsignedLabBuild -and -not $SigningCertificateThumbprint) {
    throw "SigningCertificateThumbprint is required unless -UnsignedLabBuild is explicitly selected"
}
Write-Host "Building hardened MirageEndpoint MSI for environment=$Environment"

$repoRoot = Resolve-Path "$PSScriptRoot\..\.."
$buildDir = "$PSScriptRoot\build"
New-Item -ItemType Directory -Force -Path $buildDir, $OutputDir | Out-Null

# --- 1. Python build venv -------------------------------------------------
python -m venv "$buildDir\venv"
& "$buildDir\venv\Scripts\pip.exe" install -e "$repoRoot" pyinstaller

# --- 2. Stamp source build identity and freeze ----------------------------
function Invoke-PyInstaller {
    & "$buildDir\venv\Scripts\pyinstaller.exe" `
        --onefile --name mirage-endpoint-service `
        --distpath "$buildDir\dist" --workpath "$buildDir\work" `
        "$repoRoot\agents\mirage-endpoint\mirage_endpoint\win_service.py"
}

$initPath = "$repoRoot\agents\mirage-endpoint\mirage_endpoint\__init__.py"
$initBackup = "$buildDir\endpoint-init.backup"
Copy-Item $initPath $initBackup -Force
try {
    (Get-Content $initPath) -replace '__build_hash__ = .*', "__build_hash__ = `"$($BuildHash.ToLower())`"" | Set-Content $initPath
    Invoke-PyInstaller
    Copy-Item "$buildDir\dist\mirage-endpoint-service.exe" "$OutputDir\mirage-endpoint-service.exe" -Force
} finally {
    Copy-Item $initBackup $initPath -Force
}

# --- 4. Stage third-party payloads ----------------------------------------
New-Item -ItemType Directory -Force -Path "$PSScriptRoot\payloads" | Out-Null
Write-Host "NOTE: signed Sysmon64.exe and MirageFleetBootstrap.exe must be staged from the approved internal mirror."
foreach ($payload in @("Sysmon64.exe", "MirageFleetBootstrap.exe")) {
    $path = "$PSScriptRoot\payloads\$payload"
    if (-not (Test-Path $path)) { throw "Required payload missing: $path" }
    if ((Get-AuthenticodeSignature $path).Status -ne "Valid") {
        throw "Third-party/bootstrap payload signature is invalid: $payload"
    }
}

if (-not $UnsignedLabBuild) {
    signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 `
        /tr http://timestamp.digicert.com /td SHA256 "$OutputDir\mirage-endpoint-service.exe"
}

# --- 5/6. wix build ---------------------------------------------------------
wix build "$PSScriptRoot\Product.wxs" -d "BuildOutputDir=$OutputDir" -o "$PSScriptRoot\bin\MirageEndpoint.msi"
if (-not $UnsignedLabBuild) {
    signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 `
        /tr http://timestamp.digicert.com /td SHA256 "$PSScriptRoot\bin\MirageEndpoint.msi"
}
wix build "$PSScriptRoot\Bundle.wxs" -o "$OutputDir\MirageEndpointSetup.exe"
if (-not $UnsignedLabBuild) {
    signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 `
        /tr http://timestamp.digicert.com /td SHA256 "$OutputDir\MirageEndpointSetup.exe"
    foreach ($signed in @(
        "$OutputDir\mirage-endpoint-service.exe",
        "$PSScriptRoot\bin\MirageEndpoint.msi",
        "$OutputDir\MirageEndpointSetup.exe"
    )) {
        if ((Get-AuthenticodeSignature $signed).Status -ne "Valid") {
            throw "Authenticode verification failed: $signed"
        }
    }
}
Write-Host "Built: $OutputDir\MirageEndpointSetup.exe"
