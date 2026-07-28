# Security test report

The executable local report is produced by `make test-security`. It combines
the security control matrix with existing OIDC, certificate, schema, artifact,
prompt-injection, canary, evidence, dashboard CSP/CSRF, report-download, and
release-tamper tests. A passing local run is not Profile B sign-off.

No test may address or send payloads to a system outside a controlled Mirage
environment. Dynamic Windows, AWS, public-DNS, and real-signing rows remain
`NOT_RUN` until the lab result package records measured evidence.

Defects found during this stage: vulnerable initial dashboard dependency pins
were upgraded; a nonce-less CSP that prevented secure Next.js streaming was
replaced with per-request nonces; logout gained Origin/double-submit CSRF; SSE
resume now retains its last applied sequence; endpoint Fleet enrolment was
removed from process arguments.
