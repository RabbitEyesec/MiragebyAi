# Step 9a "install" stage: MirageSpider, deployed as a plain Python
# service (not an MSI) — Step 5's own title was "Sandbox sensing (Spider) +
# service spec," with no "(dev MSI)" qualifier the way Step 4's title had
# for MirageEndpoint, so Step 5 never built a WiX installer for it (see
# KNOWN_ISSUES.md). This script is the real install mechanism for the
# golden image: deploy the package, install pywin32's service wrapper, and
# register mirage_spider.win_service under LocalService (Appendix G) —
# never LocalSystem.
$ErrorActionPreference = "Stop"

$installDir = "C:\Program Files\Mirage\Spider"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# The build's own git checkout is staged to C:\mirage-build\repo by an
# earlier (implicit) step in a real pipeline run — referenced here rather
# than re-vendored, so this script and the actual source never drift.
# mirage_contracts is required too (service_logic.py imports
# mirage_contracts.envelope/timestamps directly) — a real gap found while
# writing install-mirage-env-controller.ps1's equivalent copy step: every
# environment that has actually run this script so far did so with this
# repo's own editable install already on sys.path, silently masking the
# missing package, the exact same class of gap F-11 found and fixed for
# scripts/install-server's release-package path.
Copy-Item -Recurse -Force "C:\mirage-build\repo\contracts\python\mirage_contracts" "$installDir\mirage_contracts"
Copy-Item -Recurse -Force "C:\mirage-build\repo\libs\mirage_common" "$installDir\mirage_common"
Copy-Item -Recurse -Force "C:\mirage-build\repo\agents\mirage-spider\mirage_spider" "$installDir\mirage_spider"

# python.exe is assumed pre-baked onto the base AMI's golden layer (a
# separate, earlier bootstrap concern, same as Step 4's PyInstaller-based
# MirageEndpoint build already assumes a Python toolchain exists).
& python.exe -m pip install --target "$installDir\vendor" pywin32 cryptography httpx psycopg jsonschema

$env:PYTHONPATH = "$installDir;$installDir\vendor"
& python.exe "$installDir\mirage_spider\win_service.py" --startup auto install

# Appendix G: "Account: LocalService" — never LocalSystem.
& sc.exe config MirageSpider obj= "NT AUTHORITY\LocalService"
& sc.exe start MirageSpider

Start-Sleep -Seconds 5
$svc = Get-Service -Name "MirageSpider" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    throw "MirageSpider service is not running after install — aborting build."
}

$actualAccount = (Get-CimInstance Win32_Service -Filter "Name='MirageSpider'").StartName
if ($actualAccount -notlike "*LocalService*") {
    throw "MirageSpider is NOT running as LocalService (found: $actualAccount) — Appendix G violation, aborting build."
}

Write-Output "MirageSpider installed, running as LocalService."
