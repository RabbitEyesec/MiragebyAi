#Requires -Version 5.1
<#
.SYNOPSIS
    Registers the Mirage RD Gateway policy plugin (Priority 5).
.DESCRIPTION
    LAB_VERIFICATION_REQUIRED — requires a Windows Server host with the
    RDS-Gateway role installed. Not executable in this development
    environment (no Windows host — see docs/architecture/rdp-steering.md).

    1. Validates the plugin config file against
       config/rdp-plugin-config.schema.json's required fields (a light
       PowerShell-side check; the authoritative validation is
       MirageRdpPluginConfig.Validate() at plugin load time).
    2. Creates the Windows Event Log source named by the config's
       event_log_source field, if it does not already exist.
    3. Copies the built plugin assembly (MirageRdpPlugin.dll, produced by
       `dotnet build` on a Windows build host — not by this script) into
       the RD Gateway plugin directory.
    4. Registers the plugin with RD Gateway via TSGatewayPluginConfig (the
       real COM registration step — see the TODO in
       src/MirageRdGatewayPlugin.cs for why this script cannot itself
       finish that interop without a real Windows host and the actual
       Terminal Services Gateway Plugin type library).
    5. Restarts the TSGateway service so the newly registered plugin takes
       effect.

    This script does not build the plugin (`dotnet build` on a Windows
    host with the real COM type library reference is a separate,
    prerequisite step) and does not itself implement the COM registration
    call — it prepares everything up to that point and documents the exact
    remaining command.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PluginAssemblyPath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$PluginInstallDir = "$env:ProgramFiles\Mirage\RdpPlugin"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PluginAssemblyPath)) {
    throw "Plugin assembly not found: $PluginAssemblyPath — build it first with 'dotnet build' on a Windows host (see infra/broker/rdp/src/MirageRdpPlugin.csproj)."
}
if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath — see infra/broker/rdp/config/rdp-plugin-config.example.json."
}

$config = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json
$requiredFields = @(
    "mirage_api_url", "gateway_listener_id", "client_cert_path", "client_key_path",
    "root_ca_path", "client_cert_serial", "proxy_shared_secret_env_var",
    "timeout_ms", "fail_safe_target", "event_log_source"
)
foreach ($field in $requiredFields) {
    if (-not $config.PSObject.Properties.Name.Contains($field)) {
        throw "Config file is missing required field '$field' — see config/rdp-plugin-config.schema.json."
    }
}
if ($config.fail_safe_target -notin @("ENDPOINT", "DENY")) {
    throw "fail_safe_target must be 'ENDPOINT' or 'DENY', got '$($config.fail_safe_target)' — never 'SANDBOX'."
}

if (-not [System.Diagnostics.EventLog]::SourceExists($config.event_log_source)) {
    New-EventLog -LogName Application -Source $config.event_log_source
    Write-Host "Created Event Log source '$($config.event_log_source)'."
} else {
    Write-Host "Event Log source '$($config.event_log_source)' already exists."
}

New-Item -ItemType Directory -Force -Path $PluginInstallDir | Out-Null
Copy-Item -Path $PluginAssemblyPath -Destination $PluginInstallDir -Force
Copy-Item -Path $ConfigPath -Destination (Join-Path $PluginInstallDir "rdp-plugin-config.json") -Force
Write-Host "Copied plugin assembly and config to $PluginInstallDir."

Write-Warning @"
Remaining manual step (WINDOWS_VERIFICATION_REQUIRED, real RD Gateway host
only): register the plugin with RD Gateway via TSGatewayPluginConfig, e.g.:

    Import-Module TSGateway
    Set-Item WSMan:\localhost\Plugin\... # or the equivalent TSGatewayPluginConfig
    # exact cmdlet/registry path depends on the target Windows Server
    # version's RDS-Gateway role implementation - consult
    # Microsoft's Terminal Services Gateway Plugin documentation on the
    # build host, then:
    Restart-Service TSGateway
"@
