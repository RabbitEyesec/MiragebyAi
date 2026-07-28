# Step 9a "install" stage: MirageEnvironmentController (Step 9b), added to
# the golden image now that the component itself exists (Task #15). Mirrors
# install-mirage-spider.ps1's shape, with the one real difference Appendix G
# requires: MirageSpider runs as the built-in LocalService virtual account,
# but the Controller's own service account is a DEDICATED, RESTRICTED local
# account (config.SERVICE_ACCOUNT, "never LocalSystem" — see
# ARCHITECTURE_DECISIONS.md ADR-0022 decision 4 and KNOWN_ISSUES.md's Step
# 9b entry, which named exactly this script as the missing piece), because
# the Controller (unlike Spider, which only ever reads/reports) actually
# mutates the filesystem and toggles decoy services — it needs an identity
# an OS-level ACL can be scoped down to, on top of (not instead of)
# actions.py's own in-code `_resolve_within_roots`/`APPROVED_DECOY_SERVICES`
# allowlists.
$ErrorActionPreference = "Stop"

$installDir = "C:\Program Files\Mirage\EnvController"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# The build's own git checkout is staged to C:\mirage-build\repo by an
# earlier (implicit) step in a real pipeline run — referenced here rather
# than re-vendored, so this script and the actual source never drift.
Copy-Item -Recurse -Force "C:\mirage-build\repo\contracts\python\mirage_contracts" "$installDir\mirage_contracts"
Copy-Item -Recurse -Force "C:\mirage-build\repo\libs\mirage_common" "$installDir\mirage_common"
Copy-Item -Recurse -Force "C:\mirage-build\repo\agents\mirage-env-controller\mirage_env_controller" "$installDir\mirage_env_controller"

# python.exe is assumed pre-baked onto the base AMI's golden layer, same
# assumption install-mirage-spider.ps1 already makes.
& python.exe -m pip install --target "$installDir\vendor" pywin32 cryptography httpx psycopg jsonschema websockets

# ---------------------------------------------------------------------------
# Restricted service account — created fresh per build, never a fixed
# literal password (mirrors scripts/_lib.get_or_create_dev_user_password's
# "never one shared hardcoded credential in tracked source" rule, Priority-3
# remediation, applied here to a Windows local account instead of a
# Keycloak user). Standard-user group only: no local Administrators
# membership, no interactive/RDP logon right — only the one right the
# service itself needs (Log on as a service).
# ---------------------------------------------------------------------------

$serviceAccountName = "svc-mirage-envctl"
Add-Type -AssemblyName System.Web
$password = [System.Web.Security.Membership]::GeneratePassword(24, 6)
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

$existingAccount = Get-LocalUser -Name $serviceAccountName -ErrorAction SilentlyContinue
if (-not $existingAccount) {
    New-LocalUser -Name $serviceAccountName -Password $securePassword `
        -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires `
        -Description "Mirage Environment Controller service account (Appendix G: never LocalSystem)" | Out-Null
    Add-LocalGroupMember -Group "Users" -Member $serviceAccountName -ErrorAction SilentlyContinue
} else {
    # Re-running this provisioner against an already-provisioned image
    # (e.g. a repair build) must not leave a stale password from a prior
    # run active — same "reset on every run, don't just create-if-missing"
    # principle scripts/bootstrap-keycloak-realm's Priority-3 fix applied
    # to Keycloak dev users.
    Set-LocalUser -Name $serviceAccountName -Password $securePassword
}

$env:PYTHONPATH = "$installDir;$installDir\vendor"
& python.exe "$installDir\mirage_env_controller\win_service.py" --startup auto install

# `sc.exe config ... obj= ... password= ...` both sets the service's logon
# account AND grants that account "Log on as a service" (SeServiceLogonRight)
# as a side effect of the Service Control Manager's ChangeServiceConfig call
# if it doesn't already hold that right — no separate secedit/ntrights step
# needed. Documented SCM behavior, not assumed.
& sc.exe config MirageEnvironmentController obj= ".\$serviceAccountName" password= "$password"

# ---------------------------------------------------------------------------
# Filesystem ACL for the approved decoy-content root — defense in depth
# alongside (never instead of) actions.py's own code-enforced
# _resolve_within_roots policy (ADR-0022 decision 4). This grants the
# restricted service account Modify rights on exactly the one directory
# tree PLACE_ARTIFACT/decoy-file actions are allowed to touch; every other
# path on the golden image remains outside this account's write access by
# ordinary NTFS inheritance (it was never granted anywhere else).
# ---------------------------------------------------------------------------

$decoyContentRoot = "C:\MirageDecoyContent"
New-Item -ItemType Directory -Force -Path $decoyContentRoot | Out-Null
$acl = Get-Acl $decoyContentRoot
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $serviceAccountName, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $decoyContentRoot $acl

# ---------------------------------------------------------------------------
# Decoy service control rights — the restricted account may start/stop/query
# ONLY the services in actions.py's own APPROVED_DECOY_SERVICES allowlist,
# never reconfigure or delete them (no SERVICE_CHANGE_CONFIG grant). Composing
# the exact SDDL edit requires reading each decoy service's PRE-EXISTING
# security descriptor first (`sc.exe sdshow <service>`) and appending this
# account's ACE to it — overwriting it blind would risk clobbering whatever
# ACEs that service already needs from its own installer, which runs at an
# unknown point relative to this script depending on provisioner ordering on
# a real build host. Left as an explicit TODO for whoever wires the decoy
# services' own installers, rather than fabricating an SDDL string this
# environment has no way to verify — the same "real up to the point of a
# genuinely environment-dependent unknown, then an explicit TODO" boundary
# docs/architecture/rdp-steering.md already documents for the RD Gateway COM
# interop signature.
foreach ($decoyServiceName in @("MirageDecoyPrintSpooler", "MirageDecoyRemoteRegistry", "MirageDecoyFtp")) {
    $decoyService = Get-Service -Name $decoyServiceName -ErrorAction SilentlyContinue
    if ($decoyService) {
        Write-Output "TODO(WINDOWS_VERIFICATION_REQUIRED): grant $serviceAccountName start/stop/query-only rights on $decoyServiceName via 'sc.exe sdshow'-derived SDDL, once that service's own installer/ACL baseline is known."
    } else {
        Write-Output "$decoyServiceName not yet registered on this image — ACL grant skipped (no-op if a later provisioner stage registers it)."
    }
}

Start-Sleep -Seconds 5
$svc = Get-Service -Name "MirageEnvironmentController" -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    throw "MirageEnvironmentController service is not running after install — aborting build."
}

$actualAccount = (Get-CimInstance Win32_Service -Filter "Name='MirageEnvironmentController'").StartName
if ($actualAccount -notlike "*$serviceAccountName*") {
    throw "MirageEnvironmentController is NOT running as $serviceAccountName (found: $actualAccount) — Appendix G violation (never LocalSystem), aborting build."
}
if ($actualAccount -like "*LocalSystem*") {
    throw "MirageEnvironmentController is running as LocalSystem — explicit Appendix G violation, aborting build."
}

Write-Output "MirageEnvironmentController installed, running as $actualAccount."
