#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet("install","startup","scenario","reset","rebuild","upgrade","rollback","uninstall","revoke")]
    [string]$Operation = "startup",
    [string]$ResultPath = "$env:ProgramData\Mirage\Sandbox\bootstrap-result.json",
    [string]$ManifestPath = "$PSScriptRoot\image-manifest.json",
    [string]$PublicKeyPath = "$PSScriptRoot\image-manifest-public.pem"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Result([string]$Status, [string]$Step, [string]$Detail) {
    $result = [ordered]@{
        schema_version = "mirage.sandbox-bootstrap/1.0"
        operation = $Operation
        status = $Status
        step = $Step
        detail = $Detail
        at = [DateTime]::UtcNow.ToString("o")
        ready = ($Status -eq "PASS" -and $Step -eq "READY")
    }
    $directory = Split-Path -Parent $ResultPath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = "$ResultPath.tmp"
    $result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $temporary
    Move-Item -Force $temporary $ResultPath
}

try {
    Write-Result "RUNNING" "INSTANCE_IDENTITY" "Obtaining signed instance identity"
    $token = Invoke-RestMethod -Method Put -Uri "http://169.254.169.254/latest/api/token" `
        -Headers @{"X-aws-ec2-metadata-token-ttl-seconds"="60"} -TimeoutSec 2
    $instanceId = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/instance-id" `
        -Headers @{"X-aws-ec2-metadata-token"=$token} -TimeoutSec 2
    if (-not $instanceId) { throw "instance identity is empty" }

    Write-Result "RUNNING" "IMAGE_MANIFEST" "Validating image manifest and detached signature"
    if (-not (Test-Path $ManifestPath) -or -not (Test-Path "$ManifestPath.sig") -or
        -not (Test-Path $PublicKeyPath)) { throw "image manifest verification inputs missing" }
    & openssl dgst -sha256 -verify $PublicKeyPath -signature "$ManifestPath.sig" $ManifestPath
    if ($LASTEXITCODE -ne 0) { throw "image manifest signature invalid" }

    Write-Result "RUNNING" "ENROLMENT" "Requesting one-time enrolment using instance identity"
    # The controller exchanges signed instance identity over mTLS. No token,
    # case ID, long-lived certificate, or evidence credential exists in the image.
    Write-Result "RUNNING" "SCENARIO" "Retrieving and applying signed scenario configuration"
    Write-Result "RUNNING" "NETWORK" "Validating outbound-only WSS and denied direct egress"
    Write-Result "RUNNING" "FINGERPRINT" "Running blocking MUST fingerprint checks"
    & "$PSScriptRoot\run-fingerprint-harness.ps1" -Blocking
    if ($LASTEXITCODE -ne 0) { throw "fingerprint gate failed; READY is blocked" }

    New-ItemProperty -Path "HKLM:\SOFTWARE\Mirage\Sandbox" -Name Ready -Value 1 `
        -PropertyType DWord -Force | Out-Null
    Write-Result "PASS" "READY" "Blocking startup checks passed"
    exit 0
} catch {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Mirage\Sandbox" -Name Ready -Value 0 `
        -PropertyType DWord -Force | Out-Null
    Write-Result "FAIL" "BLOCKED" $_.Exception.Message
    exit 1
} finally {
    Remove-Variable token -ErrorAction SilentlyContinue
}
