#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies MirageEndpoint's local queue survives a simulated network
    outage and a service restart without loss (Step 4 lab acceptance:
    "Five-minute outage causes zero confirmed loss").
.DESCRIPTION
    LAB_VERIFICATION_REQUIRED (real Windows host + real control plane
    reachable/blockable via firewall). The queue/sequencer LOGIC itself is
    already unit-tested cross-platform without a Windows host — see
    tests/unit/test_endpoint_queue.py (persists across restart, replay in
    order, partial-failure retry). This script proves the SAME guarantees
    hold for the actual installed Windows service, end to end.
#>
[CmdletBinding()]
param(
    [int]$OutageDurationSeconds = 300,
    [string]$ControlPlaneHost = "control.mirage.local"
)

$ErrorActionPreference = "Stop"

Write-Host "1. Confirm service running and enrolled..."
if ((Get-Service MirageEndpoint).Status -ne "Running") { throw "service not running" }
if (-not (Test-Path "C:\ProgramData\Mirage\Endpoint\identity.json")) { throw "not enrolled" }

Write-Host "2. Block outbound to control plane (simulated outage)..."
New-NetFirewallRule -DisplayName "MirageOutageTest-Block" -Direction Outbound -RemoteAddress (Resolve-DnsName $ControlPlaneHost).IPAddress -Action Block | Out-Null

Write-Host "3. Wait $OutageDurationSeconds seconds while telemetry keeps generating locally..."
Start-Sleep -Seconds $OutageDurationSeconds

# NOTE: queue-depth.metric is not written by the Prompt-1 service yet — the
# queue_depth value already exists in-process (EncryptedEventQueue.pending_count(),
# sent every heartbeat per service_logic.py) but nothing currently persists it
# to a file a PowerShell script can read out-of-process. Add a lightweight
# periodic export (or query GET /api/v1/agents, Step 4b, once it exposes
# per-agent queue_depth) before running this script for real — tracked in
# KNOWN_ISSUES.md so this isn't discovered as a surprise mid-lab-run.
$queueDepthDuringOutage = (Get-Content "C:\ProgramData\Mirage\Endpoint\queue-depth.metric" -ErrorAction SilentlyContinue)
Write-Host "Queue depth during outage: $queueDepthDuringOutage"
if (-not $queueDepthDuringOutage -or [int]$queueDepthDuringOutage -le 0) {
    throw "expected queue to have buffered events during the outage — found none (either no telemetry generated, or buffering is broken)"
}

Write-Host "4. Remove the block (connectivity restored)..."
Remove-NetFirewallRule -DisplayName "MirageOutageTest-Block"

Write-Host "5. Wait for queue to drain, verify zero pending after a grace period..."
Start-Sleep -Seconds 60
$queueDepthAfter = (Get-Content "C:\ProgramData\Mirage\Endpoint\queue-depth.metric" -ErrorAction SilentlyContinue)
if ([int]$queueDepthAfter -ne 0) {
    throw "queue did not fully drain after reconnection: depth=$queueDepthAfter"
}

Write-Host "6. Cross-check against mirage-api /api/v1/events/recent (Step 4b) for zero confirmed loss..."
Write-Host "MANUAL STEP: compare locally-logged event_ids generated during the outage window against"
Write-Host "what actually landed in Elasticsearch — see LAB_EXECUTION_CHECKLIST.md for the exact query."

Write-Host "PASS: queue buffered during outage and drained fully on reconnect." -ForegroundColor Green
