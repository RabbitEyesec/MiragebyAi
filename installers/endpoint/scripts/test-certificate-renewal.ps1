#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies certificate auto-renewal on the installed MirageEndpoint
    service (Step 3 rule exercised end-to-end on real Windows: renew before
    20% lifetime remains, identity preserved).
.DESCRIPTION
    LAB_VERIFICATION_REQUIRED. The renewal LOGIC and its 20%-boundary rule
    are already unit-tested cross-platform (tests/unit/test_enrollment_logic.py)
    and integration-tested against a real Postgres + real step-ca
    (tests/integration/test_step_ca_enrollment.py::test_renewal_preserves_identity).
    This script confirms the actual installed Windows agent invokes that
    logic on schedule, not just that the logic is correct in isolation.
#>
$ErrorActionPreference = "Stop"

$identityPath = "C:\ProgramData\Mirage\Endpoint\identity.json"
$before = Get-Content $identityPath | ConvertFrom-Json
Write-Host "Current certificate serial: $($before.certificate_serial)"
Write-Host "Current not_after: $($before.not_after)"

Write-Host "Forcing the certificate's lifetime below the 20%-remaining renewal threshold requires either"
Write-Host "(a) waiting out most of a real 24h cert lifetime, or (b) a short-lived test provisioner profile"
Write-Host "(e.g. a 10-minute maxTLSCertDuration test profile added temporarily to the target step-ca --"
Write-Host "see infra/step-ca/PROFILES.md for how the five real profiles are declared; a sixth,"
Write-Host "test-only profile can be added the same way via scripts/bootstrap-step-ca-provisioners)."
Write-Host "This script assumes that setup has already been done and the service has been running long"
Write-Host "enough to cross the threshold."

Start-Sleep -Seconds 30
$after = Get-Content $identityPath | ConvertFrom-Json

if ($after.agent_id -ne $before.agent_id) {
    throw "FAIL: agent_id changed across renewal ($($before.agent_id) -> $($after.agent_id)) — identity was NOT preserved"
}
if ($after.certificate_serial -eq $before.certificate_serial) {
    Write-Host "No renewal observed yet in this window — re-run closer to the threshold, or reduce the test profile's duration further."
    exit 2
}

Write-Host "PASS: agent_id preserved ($($after.agent_id)), certificate_serial rotated ($($before.certificate_serial) -> $($after.certificate_serial))." -ForegroundColor Green
