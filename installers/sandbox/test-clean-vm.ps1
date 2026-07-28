#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$MsiPath)
$ErrorActionPreference = "Stop"
$result = [ordered]@{ package=$MsiPath; install="NOT_RUN"; startup="NOT_RUN"; reset="NOT_RUN"; uninstall="NOT_RUN" }
try {
    Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /qn /norestart" -Wait
    $result.install = "PASS"
    & "$env:ProgramFiles\Mirage\Sandbox\bootstrap.ps1" startup
    $result.startup = if ($LASTEXITCODE -eq 0) { "PASS" } else { "FAIL" }
    & "$env:ProgramFiles\Mirage\Sandbox\bootstrap.ps1" reset
    $result.reset = if ($LASTEXITCODE -eq 0) { "PASS" } else { "FAIL" }
    Start-Process msiexec.exe -ArgumentList "/x `"$MsiPath`" /qn /norestart" -Wait
    $result.uninstall = "PASS"
} finally {
    $result | ConvertTo-Json | Set-Content ".\mirage-sandbox-installer-result.json"
}
