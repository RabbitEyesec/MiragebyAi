# Step 9a "install" stage: Elastic Agent, enrolled into Fleet — the
# topology's own "Endpoint Elastic Agent -> 8220 -> Fleet Server" path, a
# SEPARATE ingestion route from MirageSpider's own mTLS -> Agent Ingestion
# channel (see infra/elastic/index_templates/mirage-telemetry-endpoint.json's
# own _meta description for why these are two physical paths for one
# conceptual Appendix E stream).
$ErrorActionPreference = "Stop"

# MIRAGE_FLEET_URL / MIRAGE_FLEET_ENROLLMENT_TOKEN are provided as Packer
# environment_vars at build time (never baked into the image itself — a
# fresh, per-environment enrollment token is minted for every build,
# consistent with Step 3's own "one-time token" enrollment philosophy).
if (-not $env:MIRAGE_FLEET_URL -or -not $env:MIRAGE_FLEET_ENROLLMENT_TOKEN) {
    throw "MIRAGE_FLEET_URL / MIRAGE_FLEET_ENROLLMENT_TOKEN must be set — refusing to build an unenrolled golden image."
}

$agentUrl = "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.15.0-windows-x86_64.zip"
$downloadDir = "C:\mirage-build\elastic-agent"
New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null

Invoke-WebRequest -Uri $agentUrl -OutFile "$downloadDir\elastic-agent.zip"
Expand-Archive -Path "$downloadDir\elastic-agent.zip" -DestinationPath $downloadDir -Force

$agentDir = Get-ChildItem -Path $downloadDir -Directory | Select-Object -First 1
Push-Location $agentDir.FullName
& .\elastic-agent.exe install --url=$env:MIRAGE_FLEET_URL --enrollment-token=$env:MIRAGE_FLEET_ENROLLMENT_TOKEN --non-interactive
Pop-Location

$svc = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    throw "Elastic Agent service is not running after enrollment — aborting build."
}

Write-Output "Elastic Agent installed and enrolled."
