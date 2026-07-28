# Security sign-off checklist

- [x] Local controlled security suite has executable assertions.
- [x] RBAC matrix reviewed against registered routes.
- [x] Prompt injection command executions expected and observed locally: zero.
- [x] Repository/package secret scans exist.
- [x] Dependency vulnerability commands exist.
- [x] Release/report tampering is rejected.
- [ ] Windows Authenticode and clean-VM lifecycle — LAB_VERIFICATION_REQUIRED.
- [ ] AWS IAM/KMS/S3 Object Lock misuse tests — LAB_VERIFICATION_REQUIRED.
- [ ] Profile B network isolation and external canary — LAB_VERIFICATION_REQUIRED.
- [ ] Final Profile B run repeated after teardown — LAB_VERIFICATION_REQUIRED.
