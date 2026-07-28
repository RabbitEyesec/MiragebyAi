# Step 9a final "cleanliness" gate, run immediately before the amazon-ebs
# builder captures the AMI. A golden image is shared across every future
# instance launched from it — it must carry the SOFTWARE (Spider, the
# Controller, Sysmon, Elastic Agent) but NONE of the state a specific build
# run or a specific live case could have left behind: no active case ID, no
# live one-time enrollment token, no baked-in private key material, and no
# leftover build-staging files (which could themselves contain secrets — the
# build's own git checkout, the downloaded Elastic Agent zip, the fingerprint
# baseline/report). Covers BOTH MirageSpider's and MirageEnvironmentController's
# own state directories (F-05 remediation: "extend the image-cleanliness
# checks... to cover the Controller's own files").
#
# Fails the build (non-zero exit) on ANY violation — matching
# run-fingerprint-harness.ps1's own "the pipeline emits a signed image
# automatically, not via a human sign-off step" pattern; this is exactly as
# real a gate as that one, just checked here instead of in that harness.
$ErrorActionPreference = "Stop"

$violations = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# No private key material baked into either agent's own cert directory —
# both directories are created empty by apply-mirage-config.ps1 /
# install-mirage-env-controller.ps1 and only ever populated by a REAL
# enrollment against a REAL step-ca at first live service start, never
# during the build itself.
# ---------------------------------------------------------------------------

$certDirs = @(
    "C:\ProgramData\Mirage\Spider\certs",
    "C:\ProgramData\Mirage\EnvController\certs"
)
foreach ($dir in $certDirs) {
    if (Test-Path $dir) {
        $keyFiles = Get-ChildItem -Path $dir -Recurse -Include "*.pem", "*.key", "*.crt", "*.p12", "*.pfx" -ErrorAction SilentlyContinue
        if ($keyFiles) {
            $violations.Add("private key material found in $dir : $($keyFiles.Name -join ', ')")
        }
    }
}

# ---------------------------------------------------------------------------
# No active case ID — a golden image is built once and reused by many future
# cases; any file that already names a specific, non-placeholder case_id
# would mean this image was contaminated by a real run instead of only the
# build pipeline's own generic provisioning.
# ---------------------------------------------------------------------------

$stateDirs = @(
    "C:\ProgramData\Mirage\Spider",
    "C:\ProgramData\Mirage\EnvController",
    "C:\Program Files\Mirage\Spider",
    "C:\Program Files\Mirage\EnvController"
)
foreach ($dir in $stateDirs) {
    if (Test-Path $dir) {
        $stateFiles = Get-ChildItem -Path $dir -Recurse -File -Include "*.json", "*.db", "*.sqlite", "*.sqlite3" -ErrorAction SilentlyContinue
        foreach ($f in $stateFiles) {
            $content = Get-Content -Path $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '"case_id"\s*:\s*"(?!REPLACE_ME|00000000-0000-0000-0000-000000000000)[^"]+"') {
                $violations.Add("possible real case_id baked into $($f.FullName)")
            }
        }
    }
}

# Neither agent's persisted-state database should even exist yet on a
# freshly built image — their first real write only happens once a real
# service is running against a real case.
$persistedStateFiles = @(
    "C:\ProgramData\Mirage\EnvController\journal.db",
    "C:\ProgramData\Mirage\Spider\Queue"
)
foreach ($path in $persistedStateFiles) {
    if (Test-Path $path) {
        $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
        if ($items) {
            $violations.Add("$path already contains persisted state ($($items.Count) file(s)) — should be empty on a freshly built image")
        }
    }
}

# ---------------------------------------------------------------------------
# No live Fleet enrollment token baked into any file on disk — the token is
# passed to elastic-agent.exe's own install command as a one-time
# credential (install-elastic-agent.ps1) and must never be persisted in
# plaintext anywhere this script can see after that install completes.
# ---------------------------------------------------------------------------

if ($env:MIRAGE_FLEET_ENROLLMENT_TOKEN) {
    $scanRoots = @("C:\Program Files\Mirage", "C:\ProgramData\Mirage", "C:\mirage-build")
    foreach ($root in $scanRoots) {
        if (Test-Path $root) {
            $hit = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                Select-String -Pattern ([regex]::Escape($env:MIRAGE_FLEET_ENROLLMENT_TOKEN)) -ErrorAction SilentlyContinue
            if ($hit) {
                $violations.Add("Fleet enrollment token found baked into a file under $root")
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Remove the build-staging tree — the git checkout, downloaded installers,
# and intermediate baseline/report files used DURING the build must not
# ship on the final AMI (they can contain the very secrets checked above,
# plus the repository's own history). Nothing later in the pipeline needs
# C:\mirage-build — the fingerprint-report.json/sbom.json `file` download
# provisioners that read from it already ran before this, final, stage.
# Active removal here (not just a check that fails if someone else forgot
# to clean it up) because no earlier stage does this today.
# ---------------------------------------------------------------------------

if (Test-Path "C:\mirage-build") {
    Remove-Item -Path "C:\mirage-build" -Recurse -Force
    if (Test-Path "C:\mirage-build") {
        $violations.Add("C:\mirage-build build-staging directory could not be removed")
    }
}

# ---------------------------------------------------------------------------
# Report and fail closed on any violation.
# ---------------------------------------------------------------------------

if ($violations.Count -gt 0) {
    Write-Output "Image cleanliness check FAILED:"
    foreach ($v in $violations) {
        Write-Output "  - $v"
    }
    throw "Golden image failed the pre-capture cleanliness gate ($($violations.Count) violation(s)) — aborting build."
}

Write-Output "Image cleanliness check passed — no active case ID, no live enrollment token, no fleet-token residue, no baked-in private key; build-staging files removed before capture."
