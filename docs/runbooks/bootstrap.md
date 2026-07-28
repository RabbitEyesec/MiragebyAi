# Bootstrap Runbook

Exact steps to go from a clean checkout to a running local development stack,
and separately, exact prerequisites for an AWS acceptance environment. Read
this before running any `scripts/bootstrap-*`.

## Local prerequisites (development)

| Tool | Minimum version | Check |
|---|---|---|
| Docker + Docker Compose | 24+ / Compose v2 | `docker compose version` |
| Python | 3.12 | `python3.12 --version` (falls back to 3.13 host default with a warning — see ARCHITECTURE_DECISIONS.md ADR-0003) |
| Node.js | 20+ | `node --version` |
| git | any recent | `git --version` |

Run `scripts/check-prerequisites` — it fails fast (non-zero exit) if any of the
above is missing. Run `scripts/doctor` for a full non-fatal diagnostic report
(also covers optional tools: terraform, packer, tfsec, aws cli, nats cli).

## Local prerequisites (acceptance / AWS-dependent work)

These are **not** needed to develop or run unit/contract/integration tests —
only to execute anything in `LAB_EXECUTION_CHECKLIST.md`:

1. An AWS account dedicated to Mirage dev/acceptance (never a shared
   production account).
2. Billing alarms configured at $20 / $50 / $80 (Appendix L) — **before** the
   first `terraform apply`.
3. An IAM principal with least-privilege access to create: VPC + subnets +
   security groups + VPC endpoints, IAM roles, KMS keys, S3 buckets (with
   Object Lock), Secrets Manager secrets, CloudWatch log groups.
4. `aws configure` (or `AWS_PROFILE`) pointed at that principal.
5. A Windows Server 2022 build host (EC2 instance or otherwise) with the WiX
   Toolset v5 installed, for MSI compilation (Steps 4, 5, 9b, 21).
6. A code-signing certificate (see `docs/runbooks/secrets.md` →
   `mirage/<environment>/installer-signing`) — only required for Step 21
   hardened installers, not for the Prompt 1 development MSIs.

## Step-by-step: local development bootstrap

```
cp .env.example .env
cp config/development.example.yaml config/development.yaml
scripts/check-prerequisites
scripts/validate-config config/development.yaml
scripts/bootstrap-development
```

`scripts/bootstrap-development`:
1. Confirms `.env` and `config/development.yaml` exist and validate.
2. Generates a local step-ca root (dev-only, written under
   `infra/step-ca/data/`, gitignored) if one does not already exist, and backfills
   `MIRAGE_STEP_CA_ROOT_FINGERPRINT` into `.env`.
3. Runs `docker compose --env-file .env -f infra/compose/docker-compose.development.yml
   up -d` for the five stateful infra containers (Postgres, NATS,
   Elasticsearch, Keycloak, step-ca) AND the five application services
   (mirage-api, mirage-agent-ingestion, mirage-sandbox-gateway,
   mirage-worker, mirage-outbox-relay — each its own image, built from
   `services/<name>/Dockerfile`, Task #17). The Nginx HTTP broker and
   OpenSSH bastion are a SEPARATE compose file
   (`infra/compose/docker-compose.broker.yml`, Step 8b/8c) with its own
   bring-up step — they steer traffic between targets this file has no
   opinion about.
4. Waits for each service's health check, printing a pass/fail table (reuses
   the same health logic as `GET /api/v1/health`, Step 4b). mirage-worker
   and mirage-outbox-relay have no HTTP healthcheck (background loops, no
   endpoint to probe) — "running" is their success state, not "healthy".
5. Runs `make migrate` (Stage 2) and NATS stream provisioning (Step 1b).

**Application-service prerequisites**: mirage-api/mirage-agent-ingestion
mount `infra/step-ca/dev-provisioner-keys/` (read-only) for CA trust —
run `scripts/bootstrap-step-ca-provisioners` first if that directory is
empty. mirage-api/mirage-sandbox-gateway validate OIDC tokens against the
`mirage` Keycloak realm — run `scripts/bootstrap-keycloak-realm` first if
it doesn't exist yet. Both are idempotent and safe to re-run.

Idempotent: running it twice does not duplicate streams, migrations, or
Keycloak realm objects.

## Step-by-step: acceptance bootstrap (AWS)

```
cp config/acceptance.example.yaml config/acceptance.yaml
# fill in every REPLACE_ME_* value using real resources created by
# infra/terraform/environments/acceptance and secrets registered per
# docs/runbooks/secrets.md
scripts/bootstrap-acceptance
```

`scripts/bootstrap-acceptance` **does not call AWS**. In this environment (no
AWS account configured) it:
1. Validates `config/acceptance.yaml` against `config/schema.json` in strict
   mode, listing every remaining `REPLACE_ME_*` placeholder as a blocking
   error.
2. Prints the exact ordered list of commands a human runs against a real AWS
   account (`terraform init/plan/apply` in `infra/terraform/environments/acceptance`,
   Secrets Manager `put-secret-value` calls per the catalogue, Fleet Server
   bring-up, step-ca CA initialization).
3. Exits non-zero until those commands have actually been run and the config
   has zero placeholders — it never claims success it cannot verify.

That printed list is also captured verbatim in `LAB_EXECUTION_CHECKLIST.md`.

## Bootstrap acceptance criteria (from the Prompt 1 brief)

- [x] Configuration validation rejects missing mandatory values — `scripts/validate-config`, tested in `tests/unit/test_config_schema.py`.
- [x] No secret values exist in git — enforced by `.gitignore` + `scripts/validate-config --scan-secrets`.
- [x] `scripts/doctor` reports tools, versions, ports, and missing external dependencies.
- [x] Development Compose starts with local development credentials — `infra/compose/docker-compose.development.yml` + `scripts/bootstrap-development`.
- [x] AWS-dependent values remain clearly marked LAB_VERIFICATION_REQUIRED — `config/acceptance.example.yaml`, `config/production.example.yaml`, `EXTERNAL_DEPENDENCIES.md`.

See `TEST_RESULTS.md` for the exact commands run and their output.
