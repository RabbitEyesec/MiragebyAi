# Security testing runbook

`security/security-test-plan.json` contains 31 versioned checks. The RBAC
matrix, threat-model verification, result template, and sign-off checklist are
in `security/`.

```sh
make test-security
make scan-secrets
cd dashboard && npm audit
make scan-dependencies
```

Local automation covers BFF path confinement, OIDC/session/CSRF properties,
role separation, parameterized SQL, single-use downloads, non-root images,
installer token handling, prompt injection, canary attribution, and teardown
scope. Profile B must add authenticated and unauthenticated probing, real TLS,
Windows ACL/service checks, external scanner/canary traffic, cloud IAM/KMS/S3
policy tests, and a human sign-off.

A scanner or internal canary is not an attacker. A finding remains open until
the evidence, owner, severity, fix, and retest are recorded.
