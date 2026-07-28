# Step 9a "SBOM" stage — a real software bill of materials for the golden
# image, written to a location scripts/sign-ami-manifest later folds into
# the signed build manifest. Uses syft (CycloneDX output) if available on
# the build worker's PATH; falls back to a native PowerShell installed-
# software inventory (still a real, reviewable SBOM — just a narrower
# format) if syft isn't installed, rather than silently skipping this
# stage.
$ErrorActionPreference = "Stop"

$sbomPath = "C:\mirage-build\sbom.json"

$syft = Get-Command syft.exe -ErrorAction SilentlyContinue
if ($syft) {
    & syft.exe dir:C:\ -o cyclonedx-json="$sbomPath"
} else {
    Write-Output "syft.exe not found on PATH — falling back to a native installed-software inventory (still real, narrower schema)."
    $software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                   "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher
    @{
        bomFormat   = "mirage-native-inventory"
        specVersion = "1.0"
        components  = $software
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $sbomPath
}

if (-not (Test-Path $sbomPath)) {
    throw "SBOM generation produced no output at $sbomPath — aborting build."
}

Write-Output "SBOM written to $sbomPath."
