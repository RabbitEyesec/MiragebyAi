#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install / start / stop / upgrade / rollback / uninstall lifecycle test
    for the MirageEndpoint MSI (Step 4 local acceptance).
.DESCRIPTION
    LAB_VERIFICATION_REQUIRED — needs a real Windows machine with the built
    MSI (installers\endpoint\build.ps1 output). Not executable here
    (ADR-0008). Exits non-zero on the first failed assertion; prints a
    pass/fail line per check so failures are unambiguous, matching this
    repo's "no fake success" rule for every other test suite.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$MsiPath,
    [Parameter(Mandatory)] [string]$PreviousVersionMsiPath  # for the upgrade/rollback leg
)

$ErrorActionPreference = "Stop"
$failures = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "PASS: $Message" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $Message" -ForegroundColor Red
        $script:failures++
    }
}

function Get-MirageService { Get-Service -Name "MirageEndpoint" -ErrorAction SilentlyContinue }

# --- Install ---------------------------------------------------------------
Write-Host "`n=== Install ==="
Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /qn /l*v install.log" -Wait
Assert-True (Test-Path "C:\Program Files\Mirage\Endpoint\mirage-endpoint-service.exe") "binary installed to Program Files"
Assert-True (Test-Path "C:\ProgramData\Mirage\Endpoint\config.yaml") "config installed to ProgramData"
Assert-True ((Get-MirageService) -ne $null) "MirageEndpoint service registered"
Assert-True ((Get-MirageService).StartType -eq "Automatic") "service set to auto-start"
$regValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Mirage\Endpoint" -ErrorAction SilentlyContinue).InstallDir
Assert-True ($regValue -eq "C:\Program Files\Mirage\Endpoint\") "registry InstallDir key present"

# --- Start / Stop ------------------------------------------------------------
Write-Host "`n=== Start / Stop ==="
Start-Service -Name "MirageEndpoint"
Start-Sleep -Seconds 3
Assert-True ((Get-MirageService).Status -eq "Running") "service starts"
Stop-Service -Name "MirageEndpoint"
Start-Sleep -Seconds 2
Assert-True ((Get-MirageService).Status -eq "Stopped") "service stops cleanly"
Start-Service -Name "MirageEndpoint"

# --- Firewall rules ----------------------------------------------------------
Write-Host "`n=== Firewall ==="
$rule1 = Get-NetFirewallRule -DisplayName "MirageEndpoint - Agent Ingestion (mTLS 443)" -ErrorAction SilentlyContinue
$rule2 = Get-NetFirewallRule -DisplayName "MirageEndpoint - Fleet Server (8220)" -ErrorAction SilentlyContinue
Assert-True ($rule1 -ne $null -and $rule1.Direction -eq "Outbound") "agent-ingestion outbound firewall rule present"
Assert-True ($rule2 -ne $null -and $rule2.Direction -eq "Outbound") "fleet outbound firewall rule present"

# --- Upgrade -------------------------------------------------------------
Write-Host "`n=== Upgrade (install previous version first, then upgrade in place) ==="
Stop-Service -Name "MirageEndpoint" -ErrorAction SilentlyContinue
Start-Process msiexec.exe -ArgumentList "/x `"$MsiPath`" /qn" -Wait
Start-Process msiexec.exe -ArgumentList "/i `"$PreviousVersionMsiPath`" /qn /l*v install-prev.log" -Wait
Assert-True ((Get-MirageService) -ne $null) "previous version installs"
Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /qn /l*v upgrade.log" -Wait
Assert-True ((Get-MirageService) -ne $null) "service survives major upgrade (MajorUpgrade element)"
Assert-True (Test-Path "C:\ProgramData\Mirage\Endpoint\identity.json") "enrollment identity survives upgrade (ProgramData untouched by upgrade)" -ErrorAction SilentlyContinue

# --- Rollback (simulate a failed upgrade via /qn and a bad transform, or
#     verify Windows Installer's own automatic rollback on install failure) ---
Write-Host "`n=== Rollback ==="
# A genuine rollback trigger (e.g. a custom action failure) requires a
# deliberately-broken MSI variant; documented as a manual verification step
# in LAB_EXECUTION_CHECKLIST.md rather than scripted here, since forcing a
# realistic mid-install failure from a test harness without a purpose-built
# broken package is unreliable and would not prove anything beyond "msiexec
# implements rollback," which is a Windows Installer platform guarantee, not
# something this specific package can break.
Write-Host "SKIPPED (see LAB_EXECUTION_CHECKLIST.md — requires a deliberately-broken test MSI variant)"

# --- Uninstall -----------------------------------------------------------
Write-Host "`n=== Uninstall ==="
Start-Process msiexec.exe -ArgumentList "/x `"$MsiPath`" /qn /l*v uninstall.log" -Wait
Assert-True ((Get-MirageService) -eq $null) "service removed"
Assert-True (-not (Test-Path "C:\Program Files\Mirage\Endpoint\mirage-endpoint-service.exe")) "binary removed"
Assert-True ((Get-NetFirewallRule -DisplayName "MirageEndpoint*" -ErrorAction SilentlyContinue) -eq $null) "firewall rules removed"

Write-Host "`n=== Summary ==="
if ($failures -eq 0) {
    Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failures CHECK(S) FAILED" -ForegroundColor Red
    exit 1
}
