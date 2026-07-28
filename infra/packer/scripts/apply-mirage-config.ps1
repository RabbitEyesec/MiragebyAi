# Step 9a "config" stage: exact paths / registry keys (Appendix G), the
# same pattern Step 4 defined for MirageEndpoint
# (agents/mirage-endpoint/mirage_endpoint/config.py), applied here for
# MirageSpider (agents/mirage-spider/mirage_spider/config.py) since this
# golden image runs Spider, not Endpoint.
$ErrorActionPreference = "Stop"

$programData = "C:\ProgramData\Mirage\Spider"
New-Item -ItemType Directory -Force -Path "$programData\Logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$programData\Queue" | Out-Null
New-Item -ItemType Directory -Force -Path "$programData\certs" | Out-Null

$registryRoot = "HKLM:\SOFTWARE\Mirage\Spider"
New-Item -Path $registryRoot -Force | Out-Null

# LocalService needs read/write on its own ProgramData tree, nothing more
# (Appendix G: "Privilege: Read telemetry only... Never: writes to
# sandbox"). This grants LocalService rights to ITS OWN state directory —
# a completely different thing from writing to the sandbox filesystem it
# observes.
$acl = Get-Acl $programData
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\LocalService", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl -Path $programData -AclObject $acl

# Event-log provider (matches the shim's own SERVICE_NAME/EVENT_LOG_PROVIDER
# constants).
New-EventLog -LogName Application -Source "MirageSpider" -ErrorAction SilentlyContinue

Write-Output "Mirage config paths and registry keys applied."
