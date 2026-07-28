# Mirage sandbox installer

Build and sign on the approved Windows host:

```powershell
.\installers\sandbox\build.ps1 `
  -SigningCertificateThumbprint <certificate-store-thumbprint>
.\installers\sandbox\test-clean-vm.ps1 `
  -MsiPath .\installers\sandbox\dist\MirageSandbox.msi
```

At startup the bootstrap uses IMDSv2 instance identity, validates the signed
image manifest, performs one-time enrolment, retrieves a signed scenario,
validates outbound-only networking, runs blocking fingerprint checks, records
the baseline hash, and enters READY only after every blocking check passes.
Golden images must contain no case ID, enrolment token, long-lived certificate,
secret, AI credential, or evidence credential.
