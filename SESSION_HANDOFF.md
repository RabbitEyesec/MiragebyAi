# Final engineering handoff

## Current status

```text
CODE_COMPLETE: yes
LOCALLY_VERIFIED: yes
LAB_VERIFICATION_REQUIRED: yes
ACCEPTED: no
GITHUB_PUSH_READINESS: READY_FOR_REVIEW (see GITHUB_READINESS_REPORT.md)
```

Prompts 1–3 are code-complete to the extent executable in this workspace and
locally verified as recorded in `TEST_RESULTS.md`. Mirage is not accepted.
Profile B has not run once or twice, so the product status remains
`LAB_VERIFICATION_REQUIRED` for final acceptance.

The completed Prompt 1–3 implementation is approved for a source commit, but
this does not approve Mirage product acceptance or a release tag.

**27 July 2026 update:** a separate GitHub-push-readiness pass (safety branch
`remediation/github-readiness`) independently re-ran every command the
`ENGINEERING_REMEDIATION_STATUS.md` F-01..F-13 findings cite as evidence —
all matched exactly, nothing regressed. Two real bugs were found and fixed in
F-12's own repo-hygiene tooling (a self-referential false-positive in
`scripts/audit-public-repository`, and a `gitleaks` history-immutability gap
closed with a fingerprint-scoped `.gitleaksignore`, no history rewrite) — see
F-14 in `ENGINEERING_REMEDIATION_STATUS.md` and `GITHUB_READINESS_REPORT.md`
for full detail. No verified secret was found in git history. Nothing has
been committed or pushed; that remains an explicit operator decision.

## Final local evidence

- `make ci`: 274 core tests and 71 focused Prompt 3 tests passed; ruff, mypy,
  generated-contract drift, breaking-change, and secret checks passed.
- `make test-integration`: 88 real-service tests passed with 11 upstream
  WebSocket deprecation warnings.
- TypeScript contracts 9/9, dashboard unit/component/graph 27/27, Chromium
  browser acceptance 4/4, local acceptance target 9 integration + 6 package
  tests all passed.
- Python and dashboard production advisory scans found zero known
  vulnerabilities.
- All eight images built and configure non-root runtime users. The optimized
  dashboard production build passed.
- The 24-file signed release payload independently verified. A disposable,
  fresh Ubuntu 24.04 container passed the non-mutating server-install
  preflight.
- `tests/acceptance/reports/local-latest/acceptance-package.zip` independently
  verifies. Local numeric results are 15 PASS/10 NOT_RUN, the named-substitution
  scenario is 36 PASS, all 61 Profile B numeric/scenario rows are NOT_RUN, and
  `accepted=false`.
- The corrected package-wide NOT_RUN count is 71: 10 local numeric + 61
  Profile B (25 numeric + 36 scenario). Across all 122 result rows, the package
  records 51 PASS and 71 NOT_RUN.
- Signed release and acceptance ZIP outputs are excluded from source control
  and referenced only by verified SHA-256 digests in `TEST_RESULTS.md`.

## Code complete and locally verified

- Canonical contracts, NATS topology, PostgreSQL workflow/outbox/correlation,
  agent enrollment/telemetry, routing/brokers, sandbox controller/fingerprint,
  evidence/export, AI/policy, artifacts/canaries, and analyst channels from
  Prompts 1–2.
- Six-workspace Next.js dashboard; OIDC BFF; API and case RBAC; gap-aware
  projection and SSE; shared Cytoscape 2D/Three.js 3D model; evidence pivots;
  directive and explicit preview/create/confirm message controls.
- Asynchronous 27-section PDF/DOCX/JSON reporting, classified statements,
  provenance, canonical signature package, independent verification,
  idempotency/cancel/progress/timeouts, and hashed single-use downloads.
- Ubuntu installer operations, protected bootstrap recipes, signed install
  report and independent verifier, release/SBOM/signature tooling, and fresh
  Ubuntu non-mutating preflight; hardened endpoint and sandbox WiX/PowerShell
  sources.
- Thirteen failure definitions and safe Profile B recipe runner; 31-check
  security plan; reduced load/replay harness; 40 core OTel metrics, collector,
  dashboard, and alert rules.
- Exact 25-step teardown model, dry-run, exact confirmation, protected evidence,
  gap override, journal/resume/idempotence, local/AWS inventory adapters, and
  executable case drain/final-report/certificate-revocation tools.
- Machine-readable 25-target/36-step acceptance spec, local synthetic result,
  named substitutions, signed JSON/HTML/PDF/DOCX package, hardened independent
  verifier, Profile B evidence ingestion, and twice-run orchestration.
- Required Make targets and CI jobs. Exact local results are in
  `TEST_RESULTS.md`.

## Requires AWS

Terraform apply/destroy, Packer AMI build, real S3 Object Lock, asymmetric KMS,
Secrets Manager/IAM policies, public canary infrastructure, exact-tag resource
inventory, and real teardown. Apply billing and containment gates before use.

## Requires Windows

WiX/Burn compilation, Authenticode signing, clean endpoint/sandbox installation,
upgrade/rollback/repair/uninstall, real services/ACLs/Sysmon/Elastic Agent,
environment-controller reset/rebuild timing, RD Gateway, message surfaces, and
revoked-certificate reconnection.

## Requires public DNS or external providers

Public canary DNS/TLS and controlled external callbacks; trusted RFC 3161;
production scanner feeds; approved AI provider, model, credential rotation, and
billing reconciliation. Local callback and fake-AI tests are not substitutes.

## Requires Profile B

Real Kali/Fleet/Elastic traffic; endpoint-to-Elasticsearch and
sandbox-to-dashboard latency; 1,000 events/second for five minutes with a
five-minute outage; 15-minute buffering; zero loss/duplicates; deployment,
reset, rebuild, certificate, heartbeat, lag, and alert timing; all 13 injected
failures; 31 security checks; all 36 scenario steps; AWS teardown; and a clean
second run after reprovision.

## Exact lab commands

Prepare real configuration and packages, then:

```sh
source .venv/bin/activate
./scripts/acceptance-plan plan --profile profile-b > acceptance-plan.json
./scripts/acceptance-provision --profile profile-b \
  --var-file infra/terraform/environments/acceptance/terraform.tfvars \
  --execute --confirm 'PROVISION profile-b'
./scripts/acceptance-install --profile profile-b \
  --server-package dist/mirage-VERSION.zip --config config/acceptance.yaml \
  --endpoint-msi dist/MirageEndpoint.msi \
  --sandbox-msi dist/MirageSandbox.msi \
  --execute --confirm 'INSTALL profile-b'
```

The exact first Profile B command, after activating the virtual environment,
is:

```sh
./scripts/acceptance-plan plan --profile profile-b > acceptance-plan.json
```

Run each completed fault recipe:

```sh
./scripts/run-failure-scenario FAIL-NN --profile-b \
  --recipe config/failure-profile-b.json \
  --confirm 'FAULT FAIL-NN PROFILE_B'
```

After producing the required raw results:

```sh
./scripts/acceptance-run run --profile profile-b \
  --results-input /protected/profile-b/run-1 \
  --output acceptance-profile-b/run-1 --confirm-controlled-lab
./scripts/acceptance-verify verify \
  acceptance-profile-b/run-1/acceptance-package.zip
./scripts/acceptance-teardown --profile profile-b --region us-east-1 \
  --execute --confirm 'TEARDOWN profile-b'
./scripts/acceptance-provision --profile profile-b \
  --execute --confirm 'PROVISION profile-b'
```

Repeat the full install/scenario/failure/security/load/report/verify/teardown
sequence into `run-2`, or invoke the controlled lab collector through:

```sh
./scripts/acceptance-repeat \
  --run-command /opt/mirage-lab/profile-b-runner \
  --output acceptance-profile-b \
  --confirm 'REPEAT PROFILE_B TWICE'
```

## Expected outputs

Each run must contain `acceptance-results` in JSON/HTML/PDF/DOCX, command log,
environment inventory, performance, failure, security, load, installer, and
teardown results, canonical signed manifest/package, public verification
material, and an independent verification report. Every numeric row needs all
required fields and a real measured value before `PASS`.

## Failure troubleshooting

- Evidence/report verification: stop teardown, preserve storage/version IDs,
  compare the manifest and ledger, and rerun the independent verifier.
- Consumer/outbox gap: leave the gap visible, restore the dependency, replay
  idempotently, and reconcile event IDs before continuing.
- Fault recovery failure: the runner always attempts recovery and verification;
  keep the environment isolated and follow the scenario recovery record.
- Windows identity reconnect: keep the case blocked, validate Postgres status
  and step-ca revocation, rotate control credentials, then retest the old
  identity.
- AWS residue: do not broaden deletion. Inspect exact Project, Environment,
  CaseId, Temporary, and EvidenceRetention tags and use the service-specific
  owner.

## Final acceptance criteria

All 25 numeric targets and all 36 scenario steps must be `PASS` on Profile B;
all report/export/acceptance signatures must independently verify; teardown
must preserve protected evidence, reject revoked identities, and leave zero
disallowed temporary resources; no blocking issue may remain; and the complete
result must pass again after clean teardown and reprovision. Until then,
`ACCEPTED` is false.
