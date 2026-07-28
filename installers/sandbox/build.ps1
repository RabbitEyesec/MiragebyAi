#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SigningCertificateThumbprint,
    [string]$OutputDir = "$PSScriptRoot\dist"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $OutputDir | Out-Null
wix build "$PSScriptRoot\Product.wxs" -o "$OutputDir\MirageSandbox.msi"
signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr http://timestamp.digicert.com `
    /td SHA256 "$OutputDir\MirageSandbox.msi"
if ((Get-AuthenticodeSignature "$OutputDir\MirageSandbox.msi").Status -ne "Valid") {
    throw "MirageSandbox.msi Authenticode verification failed"
}
