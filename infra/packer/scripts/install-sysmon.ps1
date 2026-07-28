# Step 9a "install" stage: Sysmon, using the SAME config Step 4's
# MirageEndpoint installer already ships (installers/endpoint/config/sysmon-config.xml)
# — one Sysmon baseline for both the employee endpoint and the sandbox
# golden image, not two configs to keep in sync.
$ErrorActionPreference = "Stop"

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$downloadDir = "C:\mirage-build\sysmon"
New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null

Invoke-WebRequest -Uri $sysmonUrl -OutFile "$downloadDir\Sysmon.zip"
Expand-Archive -Path "$downloadDir\Sysmon.zip" -DestinationPath $downloadDir -Force

& "$downloadDir\Sysmon64.exe" -accepteula -i "C:\mirage-build\sysmon-config.xml"

$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    throw "Sysmon64 service is not running after install — aborting build."
}

Write-Output "Sysmon installed and running."
