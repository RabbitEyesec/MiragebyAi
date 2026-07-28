# Mirage endpoint installer

Build on the approved Windows signing host with WiX v5, Python 3.12,
PyInstaller, SignTool, signed Sysmon, and the protected Fleet bootstrap:

```powershell
.\installers\endpoint\build.ps1 -Environment production `
  -BuildHash <release-source-sha> `
  -SigningCertificateThumbprint <certificate-store-thumbprint>
.\installers\endpoint\scripts\test-install-lifecycle.ps1 `
  -InstallerPath .\installers\endpoint\dist\MirageEndpointSetup.exe
```

The one-time enrolment token is delivered through a SYSTEM-only named pipe or
protected file and invalidated after use. It is never a Burn variable or
process argument. Validate clean, silent, interactive, upgrade, repair,
rollback, uninstall, renewal, revocation, heartbeat, and result JSON on a clean
Windows VM. macOS/Linux results remain `LAB_VERIFICATION_REQUIRED`.
