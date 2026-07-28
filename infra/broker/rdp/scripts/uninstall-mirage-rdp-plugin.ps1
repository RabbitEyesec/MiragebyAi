#Requires -Version 5.1
<#
.SYNOPSIS
    Unregisters the Mirage RD Gateway policy plugin (Priority 5).
.DESCRIPTION
    LAB_VERIFICATION_REQUIRED — see install-mirage-rdp-plugin.ps1's own
    description; this is its inverse. Does not remove the Windows Event
    Log source by default (event history is evidence, not disposable
    state) — pass -RemoveEventLogSource to also remove it.
#>
[CmdletBinding()]
param(
    [string]$PluginInstallDir = "$env:ProgramFiles\Mirage\RdpPlugin",
    [string]$EventLogSource = "MirageRdpPlugin",
    [switch]$RemoveEventLogSource
)

$ErrorActionPreference = "Stop"

Write-Warning @"
Remaining manual step (WINDOWS_VERIFICATION_REQUIRED, real RD Gateway host
only): unregister the plugin from RD Gateway via TSGatewayPluginConfig
BEFORE removing its files, then:

    Restart-Service TSGateway
"@

if (Test-Path $PluginInstallDir) {
    Remove-Item -Recurse -Force -Path $PluginInstallDir
    Write-Host "Removed $PluginInstallDir."
} else {
    Write-Host "$PluginInstallDir does not exist; nothing to remove."
}

if ($RemoveEventLogSource -and [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    Remove-EventLog -Source $EventLogSource
    Write-Host "Removed Event Log source '$EventLogSource'."
}
