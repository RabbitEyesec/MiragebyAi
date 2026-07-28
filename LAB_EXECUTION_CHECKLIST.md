# Lab Execution Checklist

## Prompt 3 / Profile B final checklist

Nothing in this section has been run in the current environment.

1. Configure the isolated AWS account, billing alarms, remote state, exact
   `Project=mirage`/`Environment=acceptance`/`CaseId` tags, public DNS/TLS,
   S3 Object Lock, asymmetric KMS, trusted RFC 3161, Fleet/Elastic, OTel, Kali,
   clean Windows endpoint/sandbox, clean Ubuntu server, and code signing.
2. Replace every `REPLACE_ME_` value in a non-repository
   `config/acceptance.yaml`; validate it and store credentials only in the
   approved secret stores.
3. Compile and Authenticode-sign endpoint and sandbox packages; run clean
   install, upgrade, rollback, repair, and uninstall lifecycle scripts.
4. Build the Ubuntu/release package with real image digests and SBOMs, verify
   offline, install on clean Ubuntu, and exercise validate/upgrade/rollback/
   repair/status/uninstall.
5. Run the exact command sequence in `docs/runbooks/lab-execution.md`.
6. Exercise all 36 live steps, including new-connection steering without a
   mid-session migration claim, all four canary classifications, directive,
   direct message, graph parity/evidence pivots, report, verifier, teardown,
   identity rejection, and zero disallowed resources.
7. Execute all 13 configured failure recipes after copying
   `config/failure-profile-b.example.json` to a protected completed recipe.
   Each command requires `--confirm 'FAULT FAIL-NN PROFILE_B'`.
8. Execute the 31 security checks and complete the threat-model/sign-off
   records.
9. Run deployed load and measure all 25 numeric rows. Do not use the reduced
   local result for Profile B.
10. Produce all required JSON/HTML/PDF/DOCX/log/inventory/performance/failure/
    security/load/installer/teardown files; ingest with:

    ```sh
    source .venv/bin/activate
    ./scripts/acceptance-run run --profile profile-b \
      --results-input /protected/profile-b/run-1 \
      --output acceptance-profile-b/run-1 --confirm-controlled-lab
    ./scripts/acceptance-verify verify \
      acceptance-profile-b/run-1/acceptance-package.zip
    ```

11. Run the exact 25-step teardown, verify revoked identities cannot reconnect,
    and verify zero disallowed exact-tag resources while retaining only
    `EvidenceRetention=protected`.
12. Cleanly reprovision and repeat steps 3–11 as run 2. Verify its independent
    package separately.
13. Stop with `FAIL`, `BLOCKED`, or `NOT_RUN` if any target, scenario,
    signature, evidence check, containment check, or inventory check is not
    proven. Only a human acceptance authority may update status after both
    complete runs.

Genuine environment-dependent actions only — things that cannot be done on a
developer laptop because they require AWS, a Windows host, or real network
hardware. Every item links back to the requirement ID(s) it unblocks in
`REQUIREMENTS_TRACEABILITY.md`. Populated as each step's lab-only edges are
identified during implementation; this is not a wishlist, it is the literal
remaining work to reach ACCEPTED for Prompt 1's scope.

Prerequisites for ANY item below: billing alarms at $20/$50/$80 configured
(Appendix L), `Project=mirage` tagging convention in force, AWS credentials with
least-privilege access to a dedicated dev/sandbox account — never a production
account.

---

## Stage 0 / Step 2 — AWS foundation (Terraform apply)

Unblocks: S0-2-010 (LAB_VERIFICATION_REQUIRED).

1. Configure billing alarms at $20 / $50 / $80 (Appendix L) before anything below.
2. `aws configure` with a least-privilege principal for a DEDICATED mirage dev/acceptance account (never production/shared).
3. `cd infra/terraform/environments/dev && cp terraform.tfvars.example terraform.tfvars` — fill in real `aws_account_id`, `availability_zone`, and a real `allowed_analyst_cidr` (never `0.0.0.0/0`).
4. `terraform init -input=false && terraform plan` — review the plan; it must create only `Project=mirage` tagged resources (VPC, 5 subnets, IGW, route tables, security groups, VPC endpoints, IAM roles/policies, KMS keys, evidence + access-log S3 buckets, CloudWatch log groups, VPC Flow Logs).
5. `terraform apply`.
6. Reachability tests (do these from real instances once Stage 1+ actually launches EC2 instances into these subnets — Step 2 itself provisions no compute):
   - From an instance in the attacker subnet: confirm TCP connect succeeds to the public_edge subnet on 443, and FAILS to control subnet's Postgres (5432), NATS (4222), Elasticsearch (9200), and to the KMS/Secrets Manager VPC endpoint IPs.
   - From an instance in the sandbox subnet: confirm TCP connect succeeds to control subnet on 443 only, and fails everywhere else including direct S3.
7. `./scripts/inventory-aws --environment development` — confirm the resource list matches exactly what `terraform apply` created.
8. `terraform destroy`.
9. `./scripts/verify-teardown --environment development` — must report zero resources.
10. Repeat steps 3-9 for `infra/terraform/environments/acceptance` (Profile B) once ready for the Step 24 full acceptance run — that environment additionally needs `terraform init -backend-config=...` for its S3 remote backend (see that environment's `versions.tf`).

---

## Stage 1 / Step 4 — MirageEndpoint dev MSI

Unblocks: S1-4-008, S1-4-010, S1-4-012, S1-4-013, S1-4-015 (MSI compile leg), S1-4-016.

1. On a Windows Server 2022 (or Windows 10/11) build host: install WiX
   Toolset v5 (`dotnet tool install --global wix`), Python 3.12, PyInstaller.
2. Stage `Sysmon64.exe` and `elastic-agent-installer.exe` into
   `installers/endpoint/payloads/` (see `Bundle.wxs` comments — not vendored
   into this repo).
3. `installers/endpoint/build.ps1 -Environment development` — produces
   `dist/MirageEndpointSetup.exe` (unsigned dev bundle).
4. Provision a real dev sandbox/employee VM per Step 7b (or a plain Windows
   VM for this step alone) in the AWS `endpoint` subnet from
   `infra/terraform/environments/dev` (Step 2 must be applied first).
5. Copy `MirageEndpointSetup.exe` to that VM and run
   `installers/endpoint/scripts/test-install-lifecycle.ps1 -MsiPath ... -PreviousVersionMsiPath ...`
   — requires building two versions to exercise the upgrade leg.
6. Run `installers/endpoint/scripts/test-queue-recovery.ps1` (needs the
   `queue-depth.metric` export gap in KNOWN_ISSUES.md closed first, or the
   script adapted to query `GET /api/v1/agents` once Step 4b exists).
7. Run `installers/endpoint/scripts/test-certificate-renewal.ps1` — add a
   short-lived test provisioner profile to the target step-ca first (see the
   script's own instructions) so the 20%-remaining threshold is reachable in
   a practical test window.
8. Numeric Definition of Done lines for this step (Part 4): endpoint event →
   Elasticsearch p95 < 3s; agent buffers >= 15 min at peak; 5-minute outage →
   zero confirmed loss. Measure with a synthetic load generator against the
   real deployed stack on Profile B sizing (Appendix L).

---

## Stage 1 / Step 4b — Early engineering console

No lab-only items. Every Step 4b acceptance line was verified against real
(local or ephemeral-container) infrastructure — real Postgres, real NATS
JetStream, real Elasticsearch, real Keycloak, and a real (temporary) Kibana
instance for the dashboard import. See TEST_RESULTS.md and
REQUIREMENTS_TRACEABILITY.md (S1-4B-001 .. S1-4B-012) for evidence.

---

## Stage 1 / Step 5 — MirageSpider

Unblocks: S1-5-001 (service-shim leg only).

1. On a Windows host: confirm `mirage_spider.win_service` imports and the
   service installs/starts under the LocalService account (no MSI packaging
   exists for Spider yet in this prompt — unlike MirageEndpoint, Step 5 did
   not include a WiX installer; that would need to be built the same way
   Step 4's was before this item can be run against an installed service
   rather than a manually-started Python process).
2. Confirm the service genuinely runs as LocalService, not LocalSystem
   (`sc qc MirageSpider` or Services MMC snap-in) and that it cannot write
   to any sandbox path it observes (attempt a write from within the running
   service process context and confirm OS-level access denial — the code
   itself has no write path, but this closes the loop on the account's
   actual OS privileges, not just the code review).
3. Run against a real dev sandbox target (Step 7b, not yet built) to
   confirm Spider observes real process/file/network activity, not just
   the synthetic observation calls this prompt's tests use.

---

## Stage 2 / Step 6 — Case state machine + migrations + outbox

No lab-only items. Every Step 6 acceptance line was verified against real
(local or ephemeral-container) Postgres and NATS JetStream, plus manually
confirmed against the persistent dev stack (migration up/down/up, a real
case transitioned, the relay run once and confirmed to publish). See
TEST_RESULTS.md and REQUIREMENTS_TRACEABILITY.md (S2-6-001 .. S2-6-007) for
evidence.

---

## Stage 2 / Step 7 — Detection into cases

No lab-only items. Every Step 7 acceptance line was verified against real
(local or ephemeral-container) Postgres and NATS JetStream, plus manually
confirmed against the persistent dev stack. See TEST_RESULTS.md and
REQUIREMENTS_TRACEABILITY.md (S2-7-001 .. S2-7-006) for evidence.

---

## Stage 2 / Step 7b — Development sandbox target

Unblocks: S2-7B-003 (RDP leg only).

1. On a real Windows host (or once Step 9a's golden AMI exists): stand up
   an RD Gateway-fronted Windows target and confirm an RDP client can
   connect through it. There is no local substitute — no viable
   macOS/Linux-native RDP server exists to test even minimal protocol
   acceptance (see ADR-0018, KNOWN_ISSUES.md). HTTP and SSH legs of this
   step are LOCALLY_VERIFIED and need no lab work.

---

## Stage 3 / Step 8a — The /route decision API

No lab-only items. Every Step 8a acceptance line was verified against real
(local or ephemeral-container) Postgres, NATS, and Keycloak, plus manually
confirmed against the persistent dev stack (migration up/down/up). See
TEST_RESULTS.md and REQUIREMENTS_TRACEABILITY.md (S3-8A-001 .. S3-8A-007)
for evidence.

---

## Stage 3 / Step 8b/8c/8d — The three brokers

Unblocks: S3-8BCD-005 (RDP, in full).

1. On a real Windows Server: install the RD Gateway role
   (`Install-WindowsFeature RDS-Gateway`), configure a Connection
   Authorization Policy requiring NLA, and bind a real certificate.
2. Implement the `IRDGPolicyEngine` COM plugin described in
   `infra/broker/rdp/README.md` — a small .NET class calling
   `GET /route` with the same mTLS/proxy-header contract the HTTP and SSH
   brokers already use, returning the resolved backend as the session's
   authorized target.
3. Register the plugin with the Gateway service (`TSGatewayPluginConfig`)
   and confirm: a controlled RDP client connects through the gateway,
   receives the expected desktop (employee or sandbox, per an approved
   `routing_decisions` row), and gateway + backend events correlate to one
   session (Appendix H.3's acceptance wording).
4. Apply the same per-scenario GPO locks (NLA, resolution, graphics
   policy, clipboard, drive redirection, audio, printer, reconnect)
   identically to both the employee and sandbox RDP hosts, and confirm no
   connection-parameter difference lets a client fingerprint which one it
   reached.

The HTTP (Step 8b) and SSH (Step 8c) legs need no lab work — both are
LOCALLY_VERIFIED against real Nginx/OpenSSH containers plus a real
mirage-api process. See TEST_RESULTS.md and REQUIREMENTS_TRACEABILITY.md
(S3-8BCD-001 .. S3-8BCD-006) for evidence.

---

## Stage 4 / Step 9a — Golden image (Packer)

Unblocks: S4-9A-002 (live build), S4-9A-003, S4-9A-004, S4-9A-005,
S4-9A-006, S4-9A-007.

1. Real AWS account with permissions to launch EC2 instances into Step 2's
   sandbox subnet (`subnet_ids.sandbox` Terraform output), plus an AMI
   published for "Windows_Server-2022-English-Full-Base-*".
2. A KMS asymmetric signing key (`RSASSA_PKCS1_V1_5_SHA_256` capable) —
   set `manifest_kms_key_arn` (Packer variable) and pass the same ARN to
   `scripts/sign-ami-manifest --kms-key-arn`.
3. A Fleet Server URL and a **fresh, per-build** enrollment token (never
   reused, never committed) — passed as `fleet_url` /
   `fleet_enrollment_token` Packer variables.
4. Run `packer init infra/packer/` then
   `packer build -var-file=<environment>.pkrvars.hcl infra/packer/employee-sandbox.pkr.hcl`.
   Confirm: the build reaches the fingerprint-harness provisioner and it
   PASSES (100% MUST, >=75% SHOULD) — a failing harness aborts the build
   by design (§6.5's own "an inconsistent sandbox is worse than none").
5. Confirm the malware-scan provisioner reports zero threats and the SBOM
   provisioner produces a non-empty `sbom.json`.
6. Confirm `infra/packer/manifest.packer.json` and
   `infra/packer/build-artifacts/{fingerprint-report.json,sbom.json}`
   exist, then run
   `scripts/sign-ami-manifest --build-version <ver> --environment <env> --kms-key-arn <arn>`
   (no `--dry-run`) and confirm the resulting AMI carries a
   `ManifestSha256` tag matching the written `signed-manifest-*.json`.
7. Confirm Terraform's own AMI-ID variable (Step 2 module, once an
   `aws_instance`/ASG resource consumes it — not yet built in this prompt)
   is intended to be pointed only at AMIs this script has actually signed
   — there is no automated enforcement of that in Prompt 1's scope, only
   the documented convention (ADR-0021 decision 6).

---

## Stage 4 / Step 9b — Environment Controller + output tagging

Unblocks: S4-9B-002 (restricted account + golden image), S4-9B-008 (real
AWS reset/rebuild timing).

1. Write `infra/packer/scripts/install-mirage-env-controller.ps1`
   (Step 9a's placeholder), provisioning `config.SERVICE_ACCOUNT`
   (`MirageSandbox\svc-mirage-envctl`) as a real dedicated Windows local
   account — never LocalSystem, never the same account as MirageSpider's
   LocalService — and granting it write access ONLY to
   `config.DEFAULT_ALLOWED_MUTATION_ROOTS` (`C:\Mirage\DecoyContent`,
   `C:\Users\Public\Mirage`) via `icacls`, confirming via a real ACL query
   that the account cannot write anywhere else.
2. On that same host, confirm the WSS connection to a real
   mirage-sandbox-gateway deployment (behind Nginx TLS termination, per the
   established mTLS pattern) succeeds and a real command round-trips.
3. Implement the win32service/win32file-specific execution paths this
   step's `actions.py` deliberately left as a portable local mechanism
   (ENABLE/DISABLE_DECOY_SERVICE's real `sc.exe`/`win32serviceutil` calls
   against a real decoy service on the golden image; CHANGE_VISIBLE_METADATA's
   hidden/read-only/owner attribute bits via `win32file`) and re-run this
   step's own test scenarios against them.
4. Measure REAL SOFT_RESET/FULL_REBUILD timing against a real AWS EC2
   instance replaced from Step 9a's signed golden AMI, and confirm both
   are under the spec's 3-minute/10-minute thresholds — the local timing
   proven in this prompt is a proxy for the mechanism's correctness only,
   not for this number (ADR-0022 decision 7).
5. Confirm cert revocation actually happens as part of FULL_REBUILD/
   destruction (Appendix G: "destruction with cert revocation") — Step
   9b's own scope built the reset/rebuild filesystem mechanism only; wiring
   it to step-ca revocation (ADR-0013's passive-revocation flow, already
   proven in Step 3) is a straightforward integration this lab step should
   confirm, not new design.

---

## Stage 4 / Step 10 — Deception-quality gate (blocking)

Unblocks: S4-10-006 (live observation collection).

1. On a real Windows sandbox host (once Step 9a's golden AMI and Step 9b's
   Controller/Spider are both actually running there): write the
   PowerShell-side observation collector — the run-time counterpart of
   Step 9a's `run-fingerprint-harness.ps1`, collecting the same 8 checks
   (`Get-CimInstance`, `Get-LocalUser`, etc.) but calling
   `SpiderServiceLogic.submit_fingerprint_snapshot(identity, sandbox_id=..., checks=...)`
   instead of writing a local `fingerprint-report.json`.
2. Confirm it runs on a real cadence (e.g. every N minutes, or triggered
   before an analyst attempts to advance a case) so
   `sandbox_fingerprint_snapshots` never goes stale relative to what the
   gate is about to evaluate.
3. Drive a real case through CREATED -> ... -> SANDBOX_ACTIVE against this
   real sandbox, then attempt the ENGAGING transition and confirm: a
   genuinely fingerprint-consistent sandbox advances; deliberately breaking
   one MUST check (e.g. starting a forbidden-pattern process) blocks it,
   with the block visible in the real Kibana dashboard / mirage-api's own
   audit view (Step 4b).
4. Confirm the full round trip's real latency (Spider observes -> reports
   -> Postgres upsert -> gate evaluates -> case advances or blocks) is
   acceptable for an interactive analyst workflow — nothing in this
   prompt's local testing measures real network/OS-collection latency on
   an actual Windows host.

---

## Task #17 — CI/Docker/Makefile wiring (cross-cutting, not a spec Step)

Unblocks: a real GitHub Actions execution of `.github/workflows/ci.yml`.

1. Push this repository to a real GitHub remote and confirm all 4 jobs
   (`lint-typecheck-unit`, `terraform-and-packer-static-checks`,
   `integration`, `docker-build-and-boot`) actually run and pass on
   GitHub's own `ubuntu-latest` runners — every individual command has
   been verified locally (see TEST_RESULTS.md) but the workflow as a
   whole, GitHub's specific Docker/testcontainers environment, and action
   version pins (`actions/checkout@v4`, `actions/setup-python@v5`, etc.)
   have not been exercised.
2. If available, run `actionlint` against `.github/workflows/ci.yml` for a
   deeper static check than the YAML-syntax-only validation performed
   locally (neither `actionlint` nor `act` was available in this
   environment).
3. Confirm branch protection / required-status-check wiring in the GitHub
   repo settings actually gates merges on these jobs — that configuration
   lives in GitHub itself, not in this repository's tracked files.

---

*(Populated incrementally; see each step's section as it is implemented.)*

## Prompt 2 — Stage 5 evidence and exports

Unblocks: P2-11-001, P2-11-006.

1. In a dedicated account with billing alarms, apply the evidence/KMS
   Terraform and confirm versioning plus Object Lock were enabled at bucket
   creation.
2. Acquire small and multipart evidence through the production role; record
   CloudTrail, version IDs, retention dates, and KMS key ARN.
3. Attempt overwrite/delete/retention shortening with both application and
   administrative roles; confirm policy and Object Lock enforcement.
4. Inject timeout, denied KMS, interrupted multipart, throttling, and
   cancellation faults; verify bounded failure, cleanup, sequence-safe retry,
   and no false ledger success.
5. Export with the real asymmetric KMS key and verify RSA-PSS off-system.
6. Configure an approved RFC 3161 authority and CA chain; verify the response
   independently and confirm a tampered response/package fails.

## Prompt 2 — Stage 6 live AI and secrets

Unblocks: P2-13-002, P2-13-003, P2-13-006.

1. Place a least-privilege provider credential in the configured secrets
   backend and enable only an approved model.
2. Run bounded benign, malformed, injection, timeout, 429, 5xx, and
   connection-loss cases; confirm deterministic fallback, circuit state, and no
   secret/content leakage.
3. Rotate the secret through new-version, staged rollout, and old-key revoke.
4. Reconcile persisted Mirage token/cost usage with provider billing and prove
   per-case/daily/monthly cutoff behavior.

## Prompt 2 — Stage 7 artifacts and public canary

Unblocks: P2-14-002, P2-14-003, P2-15-002.

1. On a disposable Windows sandbox, deploy an approved controlled artifact to
   every allowed root, verify the observed hash and output attribution, then
   revoke and confirm the real filesystem rollback before status becomes
   `REVOKED`.
2. Exercise production ClamAV/YARA feeds and representative Office/archive
   samples; verify timeouts and unavailable adapters fail closed.
3. Apply the canary module with a real domain/certificate. Validate WAF rate
   limiting, API Gateway/Lambda HMAC forwarding, DLQ/log alarms, trusted proxy
   handling, token expiry/revocation/replay, and an external callback.
4. Prove internal, scanner, stale-known, and external sources render as
   INTERNAL/SCANNER/UNKNOWN/EXTERNAL respectively.

## Prompt 2 — Stage 8 analyst surfaces and hosted CI

Unblocks: P2-17-002 and Prompt 2 hosted checks.

1. Deliver confirmed analyst messages to each real Windows/decoy surface and
   verify `ANALYST_MESSAGE` attribution, displayed content, audit, and acquired
   evidence.
2. Disable case and platform channels during an in-flight delivery and confirm
   the final pre-dispatch recheck prevents output.
3. Run all GitHub Actions jobs, including dependency vulnerability audit,
   integration, image build, and full Compose boot; attach the immutable run
   URL and resolve every non-zero audit finding.
