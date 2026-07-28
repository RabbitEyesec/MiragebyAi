# Engineering Remediation Status

Tracking file for the remediation pass requested against the 12 priorities in
the engineering-completion directive. Created after reproducing the actual
baseline (not trusting prior claims without re-running them). Cross-references
`IMPLEMENTATION_STATUS.md`, `KNOWN_ISSUES.md`, `TEST_RESULTS.md`,
`EXTERNAL_DEPENDENCIES.md`, which already track most of Mirage's history in
detail and are NOT being replaced by this file — this file tracks only the
NEW remediation findings from this pass.

Statuses: `NOT_STARTED` · `IN_PROGRESS` · `CODE_COMPLETE` · `LOCALLY_VERIFIED` ·
`WINDOWS_VERIFICATION_REQUIRED` · `AWS_VERIFICATION_REQUIRED` · `ACCEPTED` ·
`BLOCKED`

## Baseline reproduced this session (not assumed)

| Command | Result |
|---|---|
| `make lint` (ruff) | PASS — clean |
| `make typecheck` (mypy, 76 files) | PASS — no issues |
| `make test` (`tests/unit` + `tests/contract`) | PASS — 274/274 |
| `dashboard && npx playwright test --config=playwright.auth.config.ts` (real local Keycloak, no mocks) | PASS — 1/1, full landing→login→callback→dashboard→refresh→logout→re-login cycle |
| `scripts/dev-auth-doctor` | PASS — all 5 checks green against the live dev stack |
| Dev Compose stack (`docker compose ps`) | 10 Mirage containers already up and healthy (postgres, nats, elasticsearch, keycloak, step-ca, api, agent-ingestion, sandbox-gateway, worker, outbox-relay, minio, artifact-scanner, report-worker) |

This confirms the 274-test and dashboard-auth claims in `TEST_RESULTS.md` /
`SESSION_HANDOFF.md` are real, reproducible, not fabricated. Full
`make test-integration` / `make test-all` were not yet run this session (large
suite, queued — see Next Steps).

## Uncommitted work found already in progress (not started by this session)

`git status` at session start showed 22 modified/added/deleted paths, all
concentrated in dashboard auth (Priority 3) and step-ca/Keycloak admin
(Priority 4 adjacent): `dashboard/app/api/auth/{callback,login}/route.ts`,
`dashboard/lib/{config,session}.ts`, `dashboard/components/DashboardApp.tsx`,
`scripts/dev-auth-doctor` (new), `scripts/bootstrap-keycloak-realm`,
`libs/mirage_common/keycloak_admin.py`, `dashboard/tests/e2e-auth/real-auth.spec.ts`
(new), `dashboard/playwright.auth.config.ts` (new), `infra/compose/docker-compose.yml`.
This is real, substantially working code (verified above), not a stub — it is
being finished, not redone.

---

## Findings

### F-01 — Release/report/evidence verifiers trust a public key embedded in the package being verified

- **Priority:** 11 (signature trust model)
- **Problem:** `verify_release()` in `libs/mirage_common/release.py:173-179`, when
  no `--public-key` is passed, falls back to reading
  `public-keys/release-signing.pem` **from inside the same ZIP it is
  verifying** and trusts it. An attacker who modifies a release package can
  generate a new keypair, re-sign the modified manifest, embed their own
  public key at that path, and `verify-release` (invoked with no
  `--public-key` argument, which is the documented default usage) reports
  `valid: true`.
- **Root cause:** No external trust anchor is enforced; the embedded key is
  informational metadata but is being used as the actual trust root when the
  caller doesn't override it.
- **Files affected:** `libs/mirage_common/release.py`, `scripts/verify-release`,
  and (need to confirm during fix) the equivalent code paths in
  `scripts/verify-evidence-export`, `scripts/verify-install-report`,
  `scripts/verify-report-package`, `scripts/verify-teardown`,
  `scripts/acceptance-verify` — same author, likely same pattern, not yet
  individually re-read.
- **Fix (not yet applied):** Require an external trusted-key source by
  default: CLI `--trusted-public-key`, a trusted-key directory
  (`/etc/mirage/trust/release-keys/` equivalent for dev,
  configurable), or a fingerprint allowlist. Verification must fail closed
  when no external trust source is configured, not silently fall back to the
  embedded key. Embedded key remains as informational signer metadata only.
- **Tests:** `tests/unit/test_signature_trust.py` (9 tests) — fail-closed
  default, explicit-key precedence, fingerprint matching, revocation,
  rotation, and two full end-to-end adversarial scenarios (forged release
  package, forged acceptance package, each re-signed with an attacker-owned
  key carrying the attacker's own embedded public key — both rejected
  against a trust store containing only the real key). Existing
  success-path tests in `test_prompt3_installers.py`, `test_reports.py`,
  `test_evidence_export.py`, `test_stage_0_12.py`, `test_profile_b_gate.py`
  updated to supply an externally-sourced key (simulating an operator who
  received it out of band) instead of relying on the old embedded-key
  fallback; each now also asserts the old default-fallback call now
  correctly returns `valid: False`.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** New shared module `libs/mirage_common/trust_anchor.py`
  (`resolve_trusted_key`). Applied to `verify_release`,
  `verify_install_report` (`libs/mirage_common/release.py`),
  `verify_export_package` (`libs/mirage_common/evidence_export.py`),
  `verify_report_package` (`libs/mirage_common/reports.py`),
  `verify_acceptance_package` (`libs/mirage_common/acceptance.py` — this one
  also gained a real `--signing-key`/`signing_key=` option since it
  previously had no persistent signing identity at all, only a
  throwaway-per-build key). CLI scripts `verify-release`,
  `verify-install-report`, `verify-evidence-export`, `verify-report-package`,
  and `acceptance-run`/`acceptance-verify` updated with `--trust-store`
  (and `--signing-key` for `run`). Internal build-time self-checks in
  `mirage-report-worker`'s exporter/reporter and `acceptance.py`'s package
  builders now pass the actual signing key explicitly rather than relying on
  the removed embedded-key fallback. `make lint`, `make typecheck`,
  `make test` (283/283), and `make test-integration` (full suite) all pass.
  `make test-signature-trust` added. Documented in
  `docs/architecture/signature-trust.md` and
  `docs/runbooks/release-verification.md`.
- **Remaining lab dependency:** none for the trust-anchor mechanism itself.
  Real deployments must populate `/etc/mirage/trust/release-keys/` (or
  `$MIRAGE_TRUST_STORE_DIR`) with real signer public keys operationally —
  that populated-in-production step is an operational task, not a code gap.

### F-02 — Shared dashboard dev password hardcoded in tracked source

- **Priority:** 3 (dashboard authentication)
- **Problem:** `mirage_dev_local_only` is a literal default value in
  `scripts/bootstrap-keycloak-realm:21` (`MIRAGE_KEYCLOAK_ADMIN_PASSWORD`
  fallback) and in `dashboard/tests/e2e-auth/real-auth.spec.ts:14`
  (`MIRAGE_E2E_AUTH_PASSWORD` fallback) — both tracked files.
- **Root cause:** Convenience default written before this remediation's
  explicit requirement ("do not hardcode one shared development password in
  tracked source; generate random local test credentials during bootstrap and
  write them to a gitignored protected file").
- **Files affected:** `scripts/bootstrap-keycloak-realm`,
  `dashboard/tests/e2e-auth/real-auth.spec.ts`, `scripts/dev-auth-doctor`.
- **Fix:** `scripts/_lib.get_or_create_dev_user_password()` generates a
  random per-machine password (`secrets.token_urlsafe(18)`) on first run,
  writes it to `.dev-auth-keys/dev-credentials.json` (new `.gitignore` rule,
  `chmod 0600`), and reuses it on subsequent runs (idempotent — doesn't
  lock out an in-progress session). `scripts/bootstrap-keycloak-realm` now
  calls this and passes the result as `dev_user_password` to
  `bootstrap_realm()`. `scripts/dev-auth-doctor` and
  `dashboard/tests/e2e-auth/real-auth.spec.ts` both read the same file
  instead of a hardcoded literal default. Also fixed a related correctness
  gap found while implementing this: `bootstrap_realm()` previously only
  set a dev user's password at USER-CREATION time — re-running bootstrap
  against an already-existing user (the normal case after this fix, since
  users from a prior run already exist) silently left the OLD password
  active. Added a `reset-password` call in the "user already exists"
  branch so the current `dev_user_password` always actually takes effect,
  matching the same "re-applied on every run" pattern already used for the
  OIDC client config a few lines above it.
- **Tests:** verified live end-to-end, not just unit-level: deleted the
  credentials file, re-ran `bootstrap-keycloak-realm` against the existing
  live dev stack (users already existed from a prior run), confirmed a
  fresh random password was generated, confirmed `dev-auth-doctor` reports
  it, and confirmed the real Playwright auth e2e test
  (`make test-dashboard-auth-e2e`) passes using ONLY the newly generated
  password — proving the reset-password fix actually changed the live
  credential, not just the local file.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `.dev-auth-keys/dev-credentials.json` generated fresh this
  session; `dev-auth-doctor` all-green; `npx playwright test
  --config=playwright.auth.config.ts` 1/1 pass using the new password;
  `make lint`/`make typecheck`/`make test` (283/283)/`make test-integration`
  all still pass; dashboard `npm run lint`/`npx tsc --noEmit`/`npm test`
  (27/27) all pass. Documented in `docs/runbooks/dashboard-auth.md`.
- **Remaining lab dependency:** none. Noted but deliberately NOT changed:
  `dashboard/lib/config.ts`'s `sessionSecret` fallback
  (`"mirage_dev_local_only_dashboard_session"`) is a similar-looking but
  lower-severity, explicitly non-production-only (`NODE_ENV !== "production"`
  gated) defense-in-depth default — `dev-auth-doctor`'s `check_env_local()`
  already requires a real 32+ char `MIRAGE_SESSION_SECRET` in
  `dashboard/.env.local` for a correctly-bootstrapped dev environment, so
  this fallback is a last resort for developers who bypass that script, not
  the primary configured value. Flagged here for visibility, not fixed, to
  keep this session's scope on the actual login credential the directive
  named.

### F-03 — step-ca AWS Secrets Manager provisioner source is an unimplemented stub

- **Priority:** 4 (step-ca secret/PKI)
- **Problem:** `services/mirage-agent-ingestion/mirage_agent_ingestion/provisioners.py:71`
  raises `NotImplementedError` for `SecretsManagerProvisionerSource`. This was
  previously and correctly documented in `KNOWN_ISSUES.md` as deferred for lack
  of an AWS account — but the remediation directive explicitly asks for this
  provider to be **fully implemented and unit-tested using SDK stubs**, which
  does not require a real AWS account.
- **Root cause:** Previously scoped out for lack of AWS access; the actual
  blocker (a live account) only applies to an *integration* test, not to
  writing and unit-testing the boto3 client code itself.
- **Files affected:** `services/mirage-agent-ingestion/mirage_agent_ingestion/provisioners.py`,
  its test file, `docs/runbooks/secrets.md` (referenced schema).
- **Fix:** `SecretsManagerProvisionerSource` fully implemented against the
  existing `ProvisionerSource` interface (matching this codebase's actual
  established pattern rather than inventing a parallel
  `get_secret`/`refresh_secret`/`invalidate`-named abstraction that doesn't
  exist anywhere else in the codebase): real `boto3` retrieval of
  `mirage/<environment>/step-ca` per `docs/runbooks/secrets.md`'s schema,
  typed errors (`SecretAccessDeniedError`, `SecretNotFoundError`,
  `SecretMalformedError`, `SecretRetrievalError`), last-known-good caching
  with a TTL (`refresh_interval_seconds`, default 300s) and an explicit
  `invalidate()`, and secret values never appearing in any log/exception
  message (only field names and AWS error codes). New
  `build_provisioner_source(environment, ...)` factory is the single
  decision point between `DevFileProvisionerSource` and
  `SecretsManagerProvisionerSource` — production without a `secret_name`
  raises immediately rather than silently falling back to the file
  provider.
- **Tests:** new `tests/unit/test_secrets_manager_provisioner.py` (15
  tests) using `botocore.stub.Stubber` — successful fetch + cache reuse,
  role-specific JWK decryption, missing `SecretString`, invalid JSON,
  missing required fields (asserts only field names appear, not values),
  access-denied/not-found/generic AWS errors with no cache (raise),
  transient failure WITH a cache (falls back — the core "last-known-good"
  requirement), `invalidate()` forcing a fresh fetch, and all four
  `build_provisioner_source` branches including the production guard.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `make lint`, `make typecheck` (77 files), `make test`
  (308/308), `make test-integration` all pass. Documented in
  `docs/runbooks/step-ca-secrets.md`.
- **Remaining lab dependency:** only the live-AWS call itself (a real IAM
  role reaching a real Secrets Manager secret) remains
  `AWS_VERIFICATION_REQUIRED`; the retrieval/parsing/caching/error-handling
  logic is implemented and locally verified via SDK stubs, not a stub
  itself.

### F-04 — Terraform has no compute (EC2), KMS, or full subnet/segmentation module

- **Priority:** 6 (Terraform completeness)
- **Problem:** `infra/terraform/modules/` contains only `vpc`, `iam`,
  `evidence`, `canary`. No `aws_instance` resource exists anywhere in the
  module tree (server, endpoint, sandbox, attacker instances are all
  missing). The five-subnet segmentation (public edge/control/endpoint/
  sandbox/attacker) and the evidence module's two `aws_kms_key` resources
  (signing + SSE-KMS encryption) were confirmed already present this
  session — that part of the original finding was stale — but neither KMS
  key had an explicit, least-privilege `policy`; both relied on the
  AWS-default (any sufficiently-privileged account principal can use the
  key).
- **Root cause:** Prompt 1 scope (per `IMPLEMENTATION_STATUS.md` Step 2) was
  "VPC/IAM/evidence/log modules" only; compute (and a restrictive KMS key
  policy specifically) were out of that step's stated scope, not an
  oversight.
- **Fix:** New `infra/terraform/modules/compute` — one `aws_instance` per
  topology role (broker/control/endpoint/sandbox/attacker), wired 1:1 to the
  vpc module's existing subnet/security-group outputs; only `broker` gets a
  public IP, only `control` gets an IAM instance profile (ADR-0011's single
  control-node role); every instance gets an encrypted root volume,
  IMDSv2-only metadata options, and a `Role` tag. AMI IDs default to the
  project's established `"LAB_VERIFICATION_REQUIRED"` placeholder
  convention (matching `canary_*` vars) so validation stays offline; gated
  behind new `var.enable_compute` (default `false`, same pattern as
  `enable_canary`). `infra/terraform/modules/evidence`'s two KMS keys gained
  an explicit `policy`: mandatory root statement plus a `dynamic` statement
  scoped to exactly `kms:Sign`/`kms:GetPublicKey`/`kms:DescribeKey` (signing)
  or `kms:Decrypt`/`kms:GenerateDataKey`/`kms:DescribeKey`/S3-service-via-
  bucket-owner (encryption) for caller-supplied authorized-principal ARNs —
  never `kms:*` for an arbitrary principal. `environments/{dev,acceptance}/main.tf`
  wire in the control-node role's ARN as a plain computed string (not a
  `module.iam.*` reference, which would create an iam↔evidence circular
  module dependency, since `module.iam` already takes these key ARNs as
  input). See ADR-0026 for the full design rationale.
- **Tests:** new `tests/unit/test_terraform_compute_policy.py` (30 tests) —
  every role has exactly one instance, only broker has a public IP, no
  `aws_eip` resource exists, only control has an IAM instance profile, every
  instance has an encrypted root volume + IMDSv2 enforced + is wired to its
  own (and only its own) subnet/security group, tag presence including a
  `Role` tag matching the instance name. New
  `tests/unit/test_terraform_evidence_kms_policy.py` (13 tests) — evidence
  bucket versioning enabled, Object Lock COMPLIANCE mode, public-access
  fully blocked, both KMS keys carry an explicit `policy`, each scoped
  statement grants only its intended actions (never `kms:*`), the scoped
  statements are gated on caller-supplied ARNs (not hardcoded), the root
  statement is always present, both environments wire the control-node ARN
  in as a plain string (not a `module.iam.*` reference), IAM least privilege
  (sandbox-gateway/agent-ingestion policies never reference the AI-provider
  secret; only `control_node` gets an instance profile). Two new tests
  added to the existing `tests/unit/test_terraform_network_policy.py`
  (16 → 18 checks): endpoint security group never references sandbox in
  either direction, endpoint egress restricted to control only — closing
  "endpoint cannot reach sandbox management." ("Attacker cannot reach
  control DB" and "sandbox cannot reach management except approved
  endpoints" were already fully covered by that file's existing tests once
  re-examined; no new test was needed for those two.)
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `terraform fmt -check -recursive infra/terraform/`,
  `terraform validate` (both `environments/dev` and `environments/acceptance`,
  after `terraform init -backend=false`), and `tfsec infra/terraform` (310
  passed, 89 ignored, 3 pre-existing findings — all in the untouched
  `canary` module, none introduced by this change) all pass. `make lint`,
  `make typecheck` (79 files), `make test` (415/415, +45 from this finding),
  `scripts/validate-config --scan-secrets` (clean — the `http_tokens =
  "required"` IMDSv2 setting needed one `# secret-scan: ignore` marker per
  instance, the established convention for a name that coincidentally
  matches the secret-field heuristic) all pass. Documented in
  ARCHITECTURE_DECISIONS.md ADR-0026.
- **Remaining lab dependency:** `terraform plan`/`apply` against a real AWS
  account remain `AWS_VERIFICATION_REQUIRED` (unchanged scope boundary,
  ADR-0012) — real AMI IDs (Ubuntu, Step 9a's golden Windows AMI, a Kali
  AMI) and a real account are both needed before `var.enable_compute = true`
  can actually provision anything; the module/policy code itself is real
  and locally verified, not a stub.

### F-05 — Packer golden image does not install MirageEnvironmentController

- **Priority:** 7 (Packer / golden image)
- **Problem:** Confirmed via `KNOWN_ISSUES.md` (Stage 4/Step 9a note),
  re-verified directly against the current Packer template this session:
  `install-mirage-env-controller.ps1` did not exist; only
  `install-mirage-spider.ps1` was wired into `employee-sandbox.pkr.hcl`'s
  provisioner list. No image-cleanliness gate of any kind existed either
  (the finding's original fix text assumed one existed for Spider that just
  needed "extending" — it did not; this session built it from scratch,
  covering both agents from the start).
- **Root cause:** MirageEnvironmentController did not exist yet when the
  Packer template was first written (documented placeholder comment);
  Controller was subsequently built (Step 9b) but the Packer template was
  never revisited.
- **Fix:** New `infra/packer/scripts/install-mirage-env-controller.ps1`,
  wired into `employee-sandbox.pkr.hcl` immediately after
  `install-mirage-spider.ps1`. Creates the dedicated restricted local
  account (`svc-mirage-envctl`, matching `config.SERVICE_ACCOUNT` exactly),
  a fresh random password every run (never a fixed literal — same principle
  as Priority 3's `get_or_create_dev_user_password`, and re-rotated on a
  repair build the same way that fix reset Keycloak passwords on re-run),
  installs the service under that account via `sc.exe config ... obj=`
  (whose `ChangeServiceConfig` call grants "Log on as a service"
  automatically — documented SCM behavior, not a separate secedit step),
  and grants that account Modify-only (never `FullControl`) NTFS rights on
  the approved decoy-content root. The script's own final check aborts the
  build if the service ends up running as LocalSystem or LocalService.
  Granting the account start/stop/query-only rights on the three
  `APPROVED_DECOY_SERVICES` themselves is left as an explicit in-script
  `TODO` — the correct SDDL edit requires reading each service's own
  pre-existing security descriptor on a real build host first (`sc.exe
  sdshow`), which doesn't exist here; the same "real up to a genuinely
  environment-dependent unknown, then an explicit TODO" boundary F-07's RDP
  scaffold already uses for its COM interop signature, not a fabricated
  value. New `infra/packer/scripts/verify-image-cleanliness.ps1` runs as the
  pipeline's final provisioner (after the fingerprint-report.json/sbom.json
  downloads, which still need `C:\mirage-build` present): checks both
  agents' cert directories for baked-in private key material, checks their
  state directories for a non-placeholder `case_id`, checks for Fleet
  enrollment-token residue anywhere on disk, and actively removes
  `C:\mirage-build` (nothing else in the pipeline did) — failing the build
  closed on any violation, the same no-human-sign-off pattern
  `run-fingerprint-harness.ps1` already established. A real, pre-existing
  gap was found and fixed in passing: `install-mirage-spider.ps1` never
  copied `mirage_contracts` despite `service_logic.py` importing
  `mirage_contracts.envelope`/`timestamps` directly — masked because every
  environment that ran it so far had this repo's own editable install
  already on `sys.path` (the same class of gap F-11 found for
  `scripts/install-server`'s release-package path). Fixed in both scripts.
- **Tests:** 12 new tests in `tests/unit/test_packer_pipeline.py` (28
  total) — provisioner stage order includes both new scripts in the right
  position, Controller installs immediately after Spider, the cleanliness
  gate runs strictly after the artifact downloads and is the last
  provisioner overall, the service account name/decoy-service names in the
  install script are cross-checked byte-for-byte against
  `config.py`/`actions.py` (so they can never silently drift apart), never
  LocalSystem/LocalService, password is always generated not a literal,
  both packages get copied, decoy-root ACL grants Modify not FullControl,
  the cleanliness script checks all four named categories and covers both
  agents' state directories and fails closed. One pre-existing test
  (`test_fingerprint_and_sbom_artifacts_downloaded_after_being_produced`)
  updated: its old assumption ("the last powershell provisioner runs before
  any file download") no longer holds now that the cleanliness gate
  intentionally runs after the downloads by design — narrowed to check
  specifically that `generate-sbom.ps1` (the last artifact-*producing*
  script) precedes them, which is what the test actually needed to prove.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `packer fmt -check infra/packer/`, `make lint`, `make
  typecheck` (79 files), `make test` (427/427, +12 from this finding),
  `scripts/validate-config --scan-secrets` (clean) all pass. Documented in
  `ARCHITECTURE_DECISIONS.md` (extends ADR-0021/ADR-0022) and
  `KNOWN_ISSUES.md`'s Stage 4 / Step 9a and Step 9b entries.
- **Remaining lab dependency:** actual `packer build` stays
  `AWS_VERIFICATION_REQUIRED`/`WINDOWS_VERIFICATION_REQUIRED` (a real EC2
  instance, real WinRM, a real Windows guest for every PowerShell
  provisioner — the same constraint ADR-0012/ADR-0021 already recorded); the
  decoy-service SDDL grant is an explicit, honestly-tracked `TODO` pending a
  real build host. The provisioner wiring and static structural/cross-
  reference tests do not depend on either.

### F-06 — No separate development/production/test Compose files

- **Priority:** 9 (server installer / production Compose)
- **Problem:** `infra/compose/` has only `docker-compose.yml` (390 lines,
  dev-oriented — 7 hardcoded password-like references),
  `docker-compose.broker.yml`, `docker-compose.dev-sandbox.yml`. No
  `docker-compose.production.yml` or `docker-compose.test.yml` exists.
- **Root cause:** Single Compose file has served all local dev/integration
  work so far; production hardening (non-root, read-only FS, capability
  drops, secret references instead of literals, no default passwords, closed
  management ports) was not yet a separate scoped task.
- **Files affected:** `infra/compose/docker-compose.yml` (becomes
  `docker-compose.development.yml`), new
  `infra/compose/docker-compose.production.yml`,
  `infra/compose/docker-compose.test.yml`, the Ubuntu server installer
  (`installers/server/...`, path to be confirmed) that currently deploys the
  one Compose file.
  Note: current uncommitted diff already touches `infra/compose/docker-compose.yml`
  for the auth-port fixes — that work should land before this file is split,
  to avoid re-deriving the same fix twice.
- **Fix:** `infra/compose/docker-compose.yml` renamed (`git mv`, history
  preserved) to `docker-compose.development.yml`; all references updated
  (`Makefile`, `scripts/bootstrap-development`, `scripts/acceptance-provision`,
  `scripts/acceptance-teardown`, `libs/mirage_common/server_installer.py`,
  `docs/runbooks/bootstrap.md`, comments in `tests/integration/conftest.py`
  and `scripts/run-mirage-api`/`bootstrap-keycloak-realm`). New
  `docker-compose.production.yml`: every credential required
  (`${VAR:?message}`, no dev-shaped fallback anywhere), no MinIO (real S3
  endpoint required), no `DOCKER_STEPCA_INIT_*` (step-ca never
  auto-initializes a throwaway CA in production), Keycloak runs
  `start --optimized` not `start-dev`, application images are pinned
  digests (never `build:`), every app container is read-only root FS +
  `cap_drop: [ALL]` + `no-new-privileges` + resource limits, named volumes
  are explicit `/var/lib/mirage/*` bind mounts, ports stay loopback-only.
  New `docker-compose.test.yml` (a Compose *override* on top of
  development, not a third duplicate — see its own file header for the
  reasoning) gives CI a `restart: "no"`, fully-ephemeral-`tmpfs` variant.
  New guard script `scripts/validate-production-compose` resolves the full
  merged config and fails on any development-only setting; wired into
  `server_installer.py`'s existing `secret-references` step (which
  previously had no concrete command at all) so a production install
  cannot proceed past preflight with a leaked dev value. `bootstrap_realm()`
  gained `create_dev_users: bool`; `scripts/bootstrap-keycloak-realm` skips
  creating the 5 dev test accounts entirely when `MIRAGE_ENV=production`.
- **Tests:** new `tests/unit/test_production_compose.py` (10 tests) —
  fail-closed with no secrets, clean resolution with real-looking values, no
  `build:`/MinIO, no `start-dev`, no step-ca auto-init vars, loopback-only
  ports, hardening flags present on every app service, the test-override
  merge producing the intended ephemeral shape, and both guard-script
  outcomes (rejects a leaked dev value, passes on clean ones).
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `docker compose -f docker-compose.production.yml config`
  fails closed with no env and resolves cleanly with dummy real-shaped
  values (verified manually + in the test suite); `make scan-secrets`,
  `make lint`, `make typecheck`, `make test` (293/293), `make
  test-integration`, `make test-production-compose` (10/10) all pass.
  `tests/unit/test_prompt3_installers.py` (14/14) still passes after the
  `server_installer.py` step-command change (step count unchanged at 25).
  Documented in `docs/runbooks/production-compose.md`.
- **Remaining lab dependency:** an actual clean-host production deploy
  (real AWS S3 endpoint, real pinned image digests from a real release
  build, a real reverse proxy in front) stays lab/AWS work per the
  installer's existing lifecycle test pattern — this remediation makes the
  file and its guard real and locally verified, not a live deployment.

### F-07 — RDP steering has a design document only, no project scaffold

- **Priority:** 5 (RDP steering)
- **Problem:** Confirmed via `KNOWN_ISSUES.md`/`IMPLEMENTATION_STATUS.md`:
  `infra/broker/rdp/README.md` documents the `IRDGPolicyEngine` COM plugin
  design; no source scaffold, no config schema, no PowerShell install/
  uninstall, no fake-routing-API test harness exists yet.
- **Root cause:** Correctly deferred as lab-only in Prompt 1/2 because full
  compilation needs a Windows host with the RD Gateway role. However, per
  this directive, the portable parts (decision-logic core, config schema,
  fake-routing-API test harness, PowerShell install/uninstall scripts,
  correlation-ID/audit event plumbing) do not require Windows to write or
  unit-test, following the same logic/binding split already used for
  `win_service.py` shims elsewhere in this codebase (ADR-0002 pattern).
- **Fix:** New `infra/broker/rdp/` project tree: `src/MirageRouteDecisionClient.cs`
  (portable .NET decision-core — builds the canonical
  `RDP|<gateway_listener_id>|<client_ip>|<principal>` match key, calls
  `/route` with the same `X-Mirage-Client-Cert-Serial`/`X-Mirage-Proxy-Auth`
  header contract the HTTP/SSH brokers already use, per-connection
  correlation ID, timeout budget, fails safe to `ENDPOINT`/`DENY` — never
  `SANDBOX` — on any error), `MirageRdGatewayPlugin.cs` (the `ITSGatewayPlugin`
  COM entry point, with the actual interop signature left as an explicit
  documented TODO rather than an invented/unverifiable one),
  `MirageRdpPluginConfig.cs`, `RouteDecisionResult.cs`,
  `MirageDecisionLogger.cs`; `config/rdp-plugin-config.schema.json` (Draft
  2020-12, proxy secret is always an env-var name, never a literal value)
  + example; `tests/MirageRouteDecisionClientTests.cs` (fake
  `HttpMessageHandler` routing-API test harness); `scripts/{install,uninstall}-mirage-rdp-plugin.ps1`.
- **Tests:** new `tests/unit/test_rdp_steering_scaffold.py` (13 tests) —
  config schema validity/example validation, schema never permits `SANDBOX`
  as `fail_safe_target`, rejects out-of-range/unsafe values, C# source's
  match-key format string and header names cross-checked byte-for-byte
  against the real `/route` contract tests below (so they can't silently
  drift apart), fail-safe branch never resolves to `Sandbox`, config schema
  never has a literal-secret-value field, every scaffold file exists, test
  project references the main project, install script rejects `SANDBOX` as
  a fail-safe target. Two new real end-to-end tests added to
  `tests/integration/test_routing_api.py`
  (`test_route_resolves_rdp_match_key_to_endpoint_by_default`,
  `test_steer_then_route_returns_sandbox_for_rdp_match_key`) proving the
  RDP-protocol match-key convention against the actual running `mirage-api`
  `/route` endpoint with a real enrolled `BROKER_CLIENT` identity (real
  Postgres, no mocks) — the same live contract the C# scaffold test
  cross-checks against.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `make test-rdp-contract` (new target: 13 unit + 2
  integration, all pass). `make lint`, `make typecheck` (79 files), `make
  test` (370/370 unit+contract), `scripts/validate-config --scan-secrets`
  (clean over tracked+untracked files, including the new C#/PowerShell/JSON
  tree) all pass. Documented in `docs/architecture/rdp-steering.md`.
- **Remaining lab dependency:** actual COM compilation and RD Gateway
  integration remain `WINDOWS_VERIFICATION_REQUIRED`, exactly as the
  directive's own acceptance criteria state ("Windows compilation remains
  WINDOWS_VERIFICATION_REQUIRED until executed") — no .NET SDK or Windows
  host exists in this environment to build or run the `.csproj` projects;
  the COM interop signature itself is an explicit TODO, not fabricated.

### F-08 — Environment Controller decoy-service/metadata actions have no real Windows implementation behind them yet

- **Priority:** 8 (real controller actions)
- **Problem:** Per `KNOWN_ISSUES.md` (Step 9b), `actions.py` is deliberately
  pywin32-free; `ENABLE/DISABLE_DECOY_SERVICE` and the Windows-attribute half
  of `CHANGE_VISIBLE_METADATA` only have the portable local mechanism (marker
  file / `os.utime`), not real `win32serviceutil`/SCM calls.
- **Root cause:** Deliberate cross-platform-testability boundary, not an
  oversight — but the directive explicitly asks for the real Windows handler
  to now be added behind a platform abstraction, matching the existing
  `win_service.py` pattern.
- **Fix:** Added `DecoyServiceController`/`MetadataAttributeController`
  ABCs to `actions.py` (still pywin32-free), with
  `MarkerFileDecoyServiceController`/`NoopMetadataAttributeController` as
  the formalized portable defaults (same externally-observable behavior as
  before). New `agents/mirage-env-controller/mirage_env_controller/windows_actions.py`
  (the only other module besides `win_service.py` allowed to import pywin32)
  implements `WindowsDecoyServiceController` (real
  `win32serviceutil.StartService`/`StopService`/`QueryServiceStatus`) and
  `WindowsMetadataAttributeController` (real `win32file.GetFileAttributes`/
  `SetFileAttributes` for hidden/read-only). New
  `resolve_approved_service_name()`/`APPROVED_DECOY_SERVICES` allowlist
  moved into the cross-platform module so the "unregistered service is
  rejected" policy is unit-testable without any pywin32 mock — both
  controllers share the same allowlist check. `win_service.py` now
  constructs `ExecutorContext` with the real Windows controllers instead of
  the defaults. `pyproject.toml`'s mypy overrides extended with
  `win32file`/`pywintypes`.
- **Tests:** `tests/unit/test_env_controller_actions.py` (+3: unregistered-
  service rejection, rollback of `DISABLE_DECOY_SERVICE` re-enabling via
  the same controller, `CHANGE_VISIBLE_METADATA` delegating Windows fields
  to an injected fake controller); one pre-existing test updated to use an
  allowlisted service ID instead of an arbitrary string (24/24 pass).
- **Status:** LOCALLY_VERIFIED (mechanism); WINDOWS_VERIFICATION_REQUIRED
  (the real Windows API calls)
- **Evidence:** `make lint`, `make typecheck` (78 files — `windows_actions.py`
  statically typechecks cleanly despite being unimportable on this platform,
  same as `win_service.py` already was), `make test` (312/312), `make
  test-integration` all pass. Documented in
  `docs/runbooks/windows-controller-actions.md`.
- **Remaining lab dependency:** real SCM state changes and file-attribute
  verification against a real decoy file/service on a real Windows sandbox
  remain `WINDOWS_VERIFICATION_REQUIRED`; the handler code, allowlist
  policy, and rollback/audit pipeline around it are implemented and locally
  verified.

### F-09 — Windows telemetry: revised scope, real coverage gaps closed

- **Priority:** 1 (revised by explicit user direction — see conversation:
  "Keep Elastic Agent/Fleet as the authoritative collector... Do not add a
  duplicate native Windows EventLog collector to MirageEndpoint or Spider")
- **Original finding, now confirmed architecturally incorrect as stated:**
  this session's initial baseline pass treated "MirageEndpoint/Spider don't
  natively collect Sysmon/Security/System/PowerShell logs via
  `EventLogWatcher`" as a missing-native-collector gap. It is not — that
  telemetry is deliberately owned by **Elastic Agent → Fleet →
  Elasticsearch** (`infra/elastic/README.md`'s pre-existing "two physical
  paths" section, `infra/packer/scripts/install-elastic-agent.ps1`/
  `install-sysmon.ps1`), a real, already-implemented architecture decision,
  not a stub. Building a second native collector would duplicate Elastic
  Agent, not fix a bug. This entry replaces that finding entirely.
- **Real coverage gaps found and fixed instead:**
  1. Spider's `PROCESS_START/STOP/FILE_*/NETWORK_CONNECTION/REGISTRY_MODIFY`
     observation types overlapped what Sysmon/Elastic Agent already collects
     natively, with no way to tell a Spider observation and a Sysmon event
     were the same real action. Fixed: `host_id`/`process_guid`/
     `correlation_id` added to `spider.observation`'s schema (optional,
     backward-compatible — `schemas/events/spider.observation.v1.schema.json`,
     regenerated via `scripts/generate-contracts`); Spider auto-populates
     `host_id` on every observation
     (`agents/mirage-spider/mirage_spider/service_logic.py`); new
     `libs/mirage_common/telemetry_correlation.py` classifies every
     observation type as Elastic-Agent-owned or Mirage-specific and
     provides `is_duplicate_of_elastic_agent_event()` for any future
     consumer showing both sources together. Five new Mirage-specific
     observation types added (`DECOY_INTERACTION`,
     `CONTROLLER_ACTION_OBSERVED`, `ANALYST_INTERACTION_OBSERVED`,
     `AI_INTERACTION_OBSERVED`, `USER_INTERACTION_INDICATOR`) — signals
     Elastic Agent has no way to observe at all.
  2. No telemetry-gap (agent-liveness) detection existed — only evidence-
     sequence-gap detection (a different concept) did. Fixed:
     `GET /api/v1/agents` now flags `telemetry_gap`/`seconds_since_last_seen`
     for any `ACTIVE` agent that has gone quiet past
     `TELEMETRY_GAP_THRESHOLD_SECONDS` (90s, matching the pre-existing
     export-eligibility threshold) or never reported at all.
- **Real gaps NOT closed this session (honestly tracked, not hidden):**
  1. No Fleet Agent Policy / Windows-integration-package template exists as
     a checked-in artifact enumerating required channels.
  2. No Fleet Server health-check client exists — and no Fleet Server
     infrastructure exists anywhere in this repo to build one against
     (unlike Priority 4's AWS Secrets Manager work, which had a real
     specified schema to implement against even without a live account).
  3. No bookmark/checkpoint validation against Elastic Agent's own internal
     state — no external API surface for it was identified.
- **Tests:** new `tests/unit/test_telemetry_correlation.py` (20 tests,
  including an exhaustive schema-enum-coverage check), 2 new
  `tests/unit/test_spider_service_logic.py` tests (host_id auto-population,
  process_guid/correlation_id threading), 2 new
  `tests/integration/test_mirage_api.py` tests (telemetry-gap flagging,
  real Postgres) plus 46/46 contract tests re-verified after the schema
  regeneration.
- **Status:** LOCALLY_VERIFIED (scope as revised); the 3 gaps above remain
  NOT_STARTED and are explicitly not claimed as done.
- **Evidence:** `make lint`, `make typecheck` (79 files), `make test`,
  `make test-integration`, `scripts/validate-contracts` (confirms the
  schema/generated-code pair is in sync with the working tree) all pass.
  Documented in `docs/architecture/windows-telemetry.md`.
- **Remaining lab dependency:** none for what was built (schema/correlation
  logic and gap detection are fully local); the three NOT_STARTED items
  above are ordinary follow-on engineering work, not lab-gated — a Fleet
  policy template and a Fleet health-check client (unit-tested via a mocked
  transport, matching the AWS Secrets Manager precedent) could both be
  built without a live Fleet Server, they simply were not reached this
  session.

### F-10 — Agent event-delivery had a real crash-recovery deadlock bug

- **Priority:** 2 (agent delivery/acknowledgement correctness)
- **Problem:** `SpiderServiceLogic.flush_queue()` only called
  `queue.ack(acked_ids)` once, after an entire `peek_batch()` page finished
  sending — not immediately after each event's own successful send. The
  server's only duplicate-submission defense was a plain
  `sequence > last_sequence` check. Combined: if the process crashed after
  the server durably accepted events 1..N (each already advanced
  `last_sequence`, each already returned 202) but before the batch-ending
  `ack()` call ran, every one of those events would still show `PENDING`
  locally — and resending event 1 on restart would get 409 forever (its
  sequence could never be "next" again), permanently blocking delivery of
  everything queued behind it. This is precisely the "crash after send,
  before ack" scenario the remediation directive calls out by name.
- **Root cause:** No idempotent-replay path existed for "I already sent
  this and the server already durably accepted it, but I don't know that
  locally" — the server could only say "yes, new" or "no, stale/conflict,"
  with no way to distinguish a safe replay from a genuine conflict.
- **Files affected:** new migration `infra/migrations/0011_agent_telemetry_receipts.{up,down}.sql`;
  `services/mirage-agent-ingestion/mirage_agent_ingestion/app.py` (idempotent
  replay check before the sequence comparison); `libs/mirage_common/agent_queue.py`
  (explicit PENDING/ACKNOWLEDGED/DEAD_LETTER states, `dead_letter()`,
  `record_attempt_failure()`, corrupt-file quarantine-and-recover,
  `QueueCapacityExceeded` backpressure); `libs/mirage_common/agent_http_client.py`
  (`TelemetryAckMismatch` — a 202 is never sufficient proof of acceptance
  without a matching `event_id` in the body; added a `transport=` test seam);
  `agents/mirage-spider/mirage_spider/service_logic.py` (`flush_queue` acks
  per-event immediately, dead-letters permanent 400s, stops-without-acking
  on ack mismatch); `agents/mirage-endpoint/mirage_endpoint/service_logic.py`
  (same per-event-ack fix for its generic `send_fn` contract).
- **Tests:** `tests/unit/test_agent_queue.py` (+5: dead-letter, attempt
  tracking, capacity refusal, corrupt-file recovery), new
  `tests/unit/test_agent_http_client.py` (5 tests, `httpx.MockTransport`),
  `tests/unit/test_spider_service_logic.py` (+3: immediate per-event ack
  proven via observed `pending_count()` sequence, dead-letter-and-continue,
  no-ack-on-mismatch), and a new real end-to-end integration test,
  `tests/integration/test_agent_ingestion_api.py::test_telemetry_endpoint_idempotently_replays_the_exact_same_event`,
  against real Postgres + real NATS JetStream, proving 3 identical replays
  of the same event all return the same acknowledgement and exactly one
  copy is ever published.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** Migration 0011 applied up/down/up against the real dev
  Postgres. `make test-agent-delivery` (new target) passes: 24 unit + 6
  integration. Full `make lint`, `make typecheck` (77 files), `make test`
  (283/283), `make test-integration` (full suite) all pass after this
  change. Documented in `docs/architecture/event-delivery.md` and
  `docs/runbooks/agent-recovery.md`.
- **Remaining lab dependency:** the numeric Profile B targets (1,000
  events/second for 5 minutes, a 5-minute real outage, zero measured loss at
  that scale) remain `AWS_VERIFICATION_REQUIRED`/lab work — this fix
  addresses a correctness bug reproducible today, not the separate
  large-scale performance measurement.

---

## Not yet independently re-verified this session (carried from existing docs, needs a fresh look before claiming a finding)

- P12 (test/acceptance honesty audit) — see F-13 below; performed this
  session.
- P0 (repo/secret hygiene mechanics) — see F-12 below; resolved this
  session.

### F-11 — Release package's own scripts could not actually run standalone

- **Priority:** 10 (standalone release package)
- **Problem:** `scripts/install-server` (and `upgrade-server`,
  `rollback-server`, `uninstall-server`, `verify-install-report`) all do
  `from mirage_common... import ...` / `from mirage_contracts... import
  ...`, but neither package existed anywhere in the release ZIP as
  installable code — confirmed by direct reproduction: a brand-new
  virtualenv with no knowledge of this repository raises
  `ModuleNotFoundError: No module named 'mirage_common'`. The only reason
  this wasn't already obvious is that the machine building/testing releases
  always has this repo's editable install (`pip install -e .`) already on
  its `sys.path`, silently masking the gap.
- **Root cause:** `build_release()` bundled scripts and static assets but
  never the actual Python packages those scripts import.
- **Files affected:** `libs/mirage_common/release.py` (`_build_wheel()`,
  wired into `build_release()`), new `scripts/install-mirage-package`,
  `libs/mirage_common/server_installer.py` (new `python-package` install
  step, first in the `install` operation; `repair`'s slice offset adjusted
  accordingly).
- **Tests:** new `tests/integration/test_release_clean_room.py` — builds a
  real release, then working ONLY from an isolated copy of the extracted
  ZIP plus a brand-new virtualenv (never touching this repo's own
  `.venv`/editable install), proves `mirage_common` is unimportable before
  the wheel is installed, `scripts/install-mirage-package` succeeds using
  only clean-room files, `mirage_common` resolves from the fresh venv
  afterward (not this repo's path), and `scripts/install-server --help`
  actually runs. `tests/unit/test_prompt3_installers.py`'s step-count test
  updated (25 → 26 steps; the new step is a real, required capability, not
  cosmetic).
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `make test-release-clean-room` passes (12s, real `pip
  wheel`/`python -m venv`/`pip install`). `make lint`, `make typecheck`,
  `make test` (293/293), `make test-integration` (including the new
  clean-room test) all pass. Documented in
  `docs/runbooks/release-clean-room.md`.
- **Remaining lab dependency:** container image digests, WiX-compiled
  MSIs, and a full clean-host Ubuntu install/upgrade/rollback lifecycle
  remain lab work — this closes the Python-package standalone-ness gap
  specifically.

### F-12 — No gitleaks/trufflehog wiring, no public-repository audit or clean source-archive script

- **Priority:** 0 (repo/secret hygiene mechanics)
- **Problem:** `.env` was confirmed gitignored and not tracked, and no
  private-key-shaped filenames were tracked, but this had never been
  checked against actual content (a `*.pem` could in principle be a real
  private key despite a safe-looking name, or vice versa) or against
  `node_modules`/`.next` actually being absent from `git ls-files` (they
  exist on disk, gitignored, but that had not been positively confirmed
  against the tracked list). The only secret-scanning in the repo was the
  custom heuristic in `scripts/validate-config --scan-secrets`
  (field-name-plus-value-shape regex) — a real, working check, but a single
  engine with a single blind spot is still a single point of failure.
  `scripts/audit-public-repository` and `scripts/build-source-archive` did
  not exist.
- **Root cause:** Never previously scoped as its own task; secret hygiene
  had been handled ad hoc (`.gitignore` rules, the one custom scanner) as
  each individual gap was found (e.g. F-02's dev-password fix), not as a
  single audited gate.
- **Fix:** New `scripts/audit-public-repository` — checks (1) no forbidden
  tracked path (`node_modules/`, `.next/`, `__pycache__/`, `.venv/`,
  `dev-provisioner-keys/`, `.dev-auth-keys/`) via `git ls-files` (not just
  trusting `.gitignore`'s intent), (2) no tracked file's actual CONTENT
  contains a PEM private-key header (content-based, not filename-based —
  a `*.pem` could legitimately be a public key, e.g.
  `public-keys/release-signing.pem`, bundled into every release on
  purpose), (3) the existing `validate-config --scan-secrets` check, (4)
  `gitleaks detect` against git HISTORY (not just the working tree — catches
  a secret that was committed and later removed, which a working-tree-only
  check never sees), soft-skipped with a clear warning (not silently
  passed) if the binary isn't installed, exactly like this codebase already
  treats Terraform/Packer/tfsec as assumed-present dev tools it doesn't
  vendor. Fails closed: any hard finding is a non-zero exit. New
  `scripts/build-source-archive` uses `git archive` (which by construction
  includes only committed, tracked files) and refuses to build anything
  until `audit-public-repository` passes for the exact ref being archived
  — an explicit `--skip-audit` escape hatch exists for local, throwaway
  inspection copies only, and prints a loud warning when used. New
  Makefile targets `audit-public-repository`/`build-source-archive`,
  deliberately NOT folded into `scan-secrets`/`ci` (a broader publish-
  readiness gate, not a per-commit lint step — same reasoning
  `test-integration`/`docker-build` stay out of `ci`). One real, actionable
  finding surfaced by actually running gitleaks against git history (not
  hypothetical): `tests/unit/test_config_schema.py`'s deliberate fake-AWS-
  key test fixture (already marked `# secret-scan: ignore (test fixture)`
  for the custom scanner) had no equivalent suppression for gitleaks — a
  second engine catching what the first engine's own maintainers had
  already declared safe, exactly the point of running two independently-
  implemented scanners. Fixed by adding gitleaks' own native `gitleaks:allow`
  inline-comment suppression alongside the existing marker.
- **Tests:** new `tests/unit/test_repository_hygiene.py` (8 tests) — the
  audit script never crashes, finds no forbidden tracked paths or private-
  key content (both current-tree-based, so deterministic regardless of
  commit timing), any gitleaks finding is provably only the one known/
  suppressed fixture and nothing else, both scripts are executable, the
  archive script's `--skip-audit` output contains no forbidden paths,
  archiving refuses to proceed (no output file written) when the audit
  fails and `--skip-audit` wasn't passed, and passing HEAD's own resolved
  SHA as `--ref` is correctly treated as equivalent to the default (no
  false-positive "ref doesn't match checked-out HEAD" refusal).
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `make lint`, `make typecheck`, `make test` (435/435, +8
  from this finding) all pass. Manually verified end-to-end this session:
  `gitleaks detect` against real git history found exactly the one
  expected pre-existing fixture and nothing else; `gitleaks protect
  --staged` confirmed the new `gitleaks:allow` comment actually suppresses
  it; `build-source-archive --skip-audit` produced a real `.tar.gz` with
  zero `node_modules`/`.env`/`dev-provisioner-keys` entries; running
  without `--skip-audit` while the audit still fails correctly refused to
  write any output file.
- **Remaining lab dependency:** none — this is fully local tooling. The one
  transient note: `gitleaks detect`'s git-history scan will only show a
  fully clean result once this session's `gitleaks:allow` fix to
  `test_config_schema.py` is itself committed (it scans committed history,
  by design, not the working tree) — expected and accounted for by
  `test_audit_gitleaks_finding_if_any_is_only_the_known_test_fixture`, not
  a gap in the mechanism itself.

### F-13 — Systematic test/acceptance honesty audit (P12)

- **Priority:** 12 (test/acceptance honesty audit)
- **Problem:** No systematic pass over the full test tree (62 files, 410
  test functions, ~10.8k lines across `tests/unit`, `tests/integration`,
  `tests/contract`, `tests/acceptance`, `tests/failure`) had been performed
  looking for fabricated/weak assertions, mock-theater in tests that claim
  to be real integration coverage, silently-skipped verification, or stale
  self-reported caveats. `KNOWN_ISSUES.md` already self-reported two
  honesty-relevant caveats (the orphaned-container fixture leak, the
  regex-based contract-agreement check) — real evidence the project's own
  culture already does this, but neither had been independently
  re-verified against current code.
- **Method:** An AST-based sweep (not just grep) over every `test_*.py`
  file: every `test_` function checked for at least one `assert` /
  `pytest.raises` / `.fail()` call (410 functions; 1 exception, a
  legitimate raise-on-failure schema-validation call with no explicit
  `assert` needed); grep sweeps for `assert_called`/`Mock()`/`@patch` usage
  in `tests/integration` specifically (none found — matches this project's
  stated "real, not mocked" integration-test philosophy); grep for
  unexplained `pytest.mark.skip`/`xfail` (only two skips found, both with
  clear, legitimate environmental reasons: no `step` CLI on PATH, an
  empty-required-fields schema case); an AST sweep for early `return`
  statements inside `if` blocks within test bodies that could silently
  skip verification without a `pytest.skip()` marker (2 hits, both false
  positives on inspection — one a legitimate idempotent-handler callback
  being exercised as real application logic, not test control flow; the
  other this session's own new, deliberately-conditional test with a
  documented reason). Manually re-verified both existing self-reported
  caveats against current source: the regex-based contract-agreement check
  is still accurately described; the orphaned-container fixture leak was
  only PARTIALLY still true (see fix below).
- **Real finding, fixed:** `KNOWN_ISSUES.md`'s fixture-leak note was itself
  stale. `keycloak_realm` had already been partially fixed since that note
  was written (its health-check-timeout branch alone called
  `container.stop()`), but its later `bootstrap_realm()` call — added
  after that partial fix — had no equivalent protection and would leak the
  container exactly the same way if it ever raised. `elasticsearch_url`
  and `step_ca_container` still had the original, undocumented-partial-fix
  gap in full. All three fixtures in `tests/integration/conftest.py` now
  wrap their ENTIRE setup (not just one branch) in `try: ... finally:
  container.stop()`, so any exception anywhere during setup stops the
  container instead of leaking it.
- **Tests:** no new test files (this is a fixture-robustness fix, not new
  product behavior) — verified by re-running every test that exercises the
  three touched fixtures: `tests/integration/test_elastic_templates.py`,
  `test_step_ca_enrollment.py`, `test_routing_api.py`, plus the full
  `tests/integration` suite (94/94) to confirm no regression from the
  refactor.
- **Status:** LOCALLY_VERIFIED
- **Evidence:** `make lint`, `make typecheck`, `make test` (435/435, no
  count change — this finding didn't add tests, it fixed fixture
  robustness), full `tests/integration` suite (94/94) against the real dev
  Docker stack, all pass. `KNOWN_ISSUES.md`'s Step 9b fixture-leak entry
  updated from "FOUND, not fixed" to "RESOLVED," with the corrected,
  more-precise description of exactly which fixture/branch actually still
  had the gap.
- **Remaining lab dependency:** none. Overall audit conclusion: the test
  suite is well-disciplined — no stub tests, no mock-theater in integration
  tests, no unexplained skips, no fabricated-success patterns found beyond
  the one concrete fixture-leak gap (now fixed). This is a conclusion
  reached by systematic automated sweep plus targeted manual verification,
  not an assumption.

### F-14 — GitHub-readiness verification pass: two real bugs found in F-12's own tooling before first commit

- **Priority:** 0 (repo/secret hygiene mechanics), found while executing the
  GitHub-push-readiness directive (Phases 1–3, 11–12) against the working
  tree left by F-01..F-13. This is a verification pass, not new product
  work — every F-01..F-13 finding's own documented evidence (test files,
  test counts, `make` targets) was independently re-run from a clean
  `remediation/github-readiness` branch, not re-read and trusted. All
  counts matched exactly (435 unit+contract, 94 integration, 27+4+1
  dashboard, 9+6 acceptance, 71 prompt3-local, 9 signature-trust, 10
  production-compose, 25+2 rdp-contract, 1 release-clean-room, 26+6
  agent-delivery, 310/89/3 tfsec — the 3 pre-existing findings confirmed
  still isolated to `modules/canary/main.tf`, none introduced by F-01..F-13).
  Two real, previously-untested gaps surfaced specifically from testing
  F-12's scripts in the state they'll actually run in once committed (they
  were untracked/unstaged for the entirety of the F-12 session, so `git
  ls-files`-driven and git-history-driven logic never actually saw them):
- **Problem 1 — `scripts/audit-public-repository` would fail permanently on
  itself once committed.** `check_no_private_key_content()` scans every
  git-tracked file's raw bytes for PEM private-key headers. The script's
  own `PRIVATE_KEY_MARKERS` tuple (lines 45-50) legitimately embeds each of
  those header strings as a detection signature — once the script itself
  becomes a tracked file, that check finds its own signature list and
  reports `scripts/audit-public-repository: contains a -----BEGIN RSA
  PRIVATE KEY----- header`, a guaranteed permanent self-match. Reproduced
  by staging the file (`git add`) and running the script directly, which is
  exactly the state a real commit puts it in — `git ls-files` (what the
  script actually scans) includes staged files, not just committed ones,
  so this was never exercised while the file sat untracked.
- **Fix:** `check_no_private_key_content()` now skips its own file path
  (`Path(__file__).resolve().relative_to(REPO_ROOT)`), with a comment
  explaining why — the one file allowed to contain these byte strings
  because it's the detector, not a key.
- **Problem 2 — `gitleaks:allow` inline comments do not retroactively
  suppress a finding in an already-existing historical commit.** F-12's own
  "Remaining lab dependency" note assumed `gitleaks detect`'s history scan
  "will only show a fully clean result once this session's `gitleaks:allow`
  fix... is itself committed" — empirically false. Verified directly (a
  disposable two-commit sandbox repo: commit 1 adds an unsuppressed
  fake-AWS-key line, commit 2 adds `gitleaks:allow` to that same line, then
  `gitleaks detect` was run against the sandbox): gitleaks still reports 1
  leak, because it scans each historical commit's own diff content
  independently — commit 1's diff never contained the suppression, and
  commit 2 fixing the line going forward does not rewrite commit 1's
  already-recorded diff. Since this repository's single existing commit
  (`e27cc86`, before the `gitleaks:allow` convention existed) introduced
  `tests/unit/test_config_schema.py`'s synthetic `AKIAABCDEFGHIJKLMNOP` <!-- secret-scan: ignore (documentation reference to the known non-functional test fixture, not a live value) gitleaks:allow -->
  fixture without that comment, `make audit-public-repository` would have
  failed on this specific check forever, for any future commit, without
  either a `.gitleaksignore` entry or a history rewrite.
- **Fix (no history rewrite):** new root `.gitleaksignore` containing the
  exact fingerprint
  (`e27cc8638abf029552d3993079df9e9c1e89d2ac:tests/unit/test_config_schema.py:aws-access-token:115`),
  which gitleaks honors globally regardless of which commit introduced the
  finding — verified empirically in the same disposable sandbox (adding the
  equivalent fingerprint to `.gitleaksignore` there took the scan from 1
  leak to `no leaks found` with zero commits changed). The inline
  `gitleaks:allow` comment (already added by F-12) is kept alongside it,
  not redundant: the `.gitleaksignore` entry retroactively clears the
  existing historical commit; the inline comment prevents the same line
  from re-triggering in any *future* commit that touches it.
- **Tests:** no new automated test added (both are tooling/process fixes
  discovered and fixed via direct reproduction, not product code paths);
  re-verified by staging every currently-untracked F-01..F-13 file
  (`git add -A`) and running `scripts/audit-public-repository` in exactly
  that state — clean exit 0 — then unstaging again to leave the working
  tree as this session found it (commit/staging decisions belong to the
  operator, not this pass).
- **Status:** LOCALLY_VERIFIED
- **Remaining lab dependency:** none.

## Full regression suite — run to completion this session

All of the following passed against the real dev Docker stack (postgres,
nats, elasticsearch, keycloak, step-ca, minio, and the five Mirage
services) and a real dashboard dev server:

| Command | Result |
|---|---|
| `make lint` (ruff) | PASS — clean |
| `make typecheck` (mypy, 79 files) | PASS |
| `make test` (`tests/unit` + `tests/contract`) | PASS — 435/435 |
| `tests/integration` (full directory, real Postgres/NATS/Elasticsearch/Keycloak/step-ca) | PASS — 94/94 |
| `make test-prompt3-local` (reports/installers/failure/security/load/observability/teardown/acceptance) | PASS — 71/71 |
| `make test-acceptance-local` (dashboard read model, elastic templates, prompt2-e2e + `tests/acceptance`) | PASS — 9/9 + 6/6 |
| `make test-dashboard` (`oxlint`, `tsc --noEmit`, `vitest` 27/27, `next build`) | PASS |
| `make test-dashboard-e2e` (Playwright, mocked-fixture suite) | PASS — 4/4 |
| `make test-dashboard-auth-e2e` (Playwright, real Keycloak login end-to-end) | PASS — 1/1 |
| `scripts/dev-auth-doctor` | PASS — all 6 checks green |

Every per-domain named target in the directive's own checklist
(`test-ai`, `test-policy`, `test-artifacts`, `test-canary`, `test-analyst`,
`test-evidence`, `test-injection`, `test-reports`, `test-installers`,
`test-security`, `test-observability`, `test-teardown`, `test-steering`,
`test-fingerprint`, `test-agent-delivery`, `test-signature-trust`,
`test-production-compose`, `test-release-clean-room`, `test-rdp-contract`)
is a proper subset of one of the runs above (each one just filters
`tests/unit`/`tests/integration`/`tests/acceptance` down to a narrower
`-k`/path selection for fast iteration) — confirmed by reading each
target's own Makefile recipe, not assumed. `test-windows-telemetry-contract`
and `test-controller-actions`, named in this file's own earlier "new
targets" note, were never actually added as separate Makefile entries;
their tests (`test_telemetry_correlation.py`, `test_env_controller_actions.py`)
already run under the plain `make test` umbrella, which is real coverage
either way. `test-auth-real` doesn't exist under that exact name either —
`test-dashboard-auth-e2e` is the real, unmocked equivalent and is green
above.
