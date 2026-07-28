.PHONY: doctor setup generate generate-contracts validate-contracts test-contracts \
        lint typecheck test test-contract test-integration test-steering test-fingerprint \
        test-evidence test-ai test-injection test-policy test-artifacts test-canary \
        test-analyst test-prompt2-e2e test-all validate-config scan-secrets \
        scan-dependencies test-dashboard test-dashboard-e2e test-graph-2d \
        test-graph-3d test-graph-parity test-reports test-installers \
        build-release verify-release test-failure test-security test-load-local \
        test-observability test-teardown test-acceptance-local test-prompt3-local ci \
        compose-dirs compose-up compose-down compose-logs compose-ps docker-build \
        migrate migrate-rollback dev-auth-doctor test-dashboard-auth-e2e \
        audit-public-repository build-source-archive

PYTHON := .venv/bin/python
PYTEST := .venv/bin/pytest
COMPOSE := docker compose --env-file .env -f infra/compose/docker-compose.development.yml
RELEASE_VERSION ?= 0.0.0-local
RELEASE_OUTPUT ?= dist/mirage-$(RELEASE_VERSION).zip
RELEASE_SIGNING_KEY ?=
RELEASE_PUBLIC_KEY ?=

doctor:
	./scripts/doctor

setup:
	python3.12 -m venv .venv || python3 -m venv .venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
	cd contracts/typescript && npm install

generate: generate-contracts

generate-contracts:
	$(PYTHON) scripts/generate-contracts

validate-contracts:
	$(PYTHON) scripts/validate-contracts

test-contracts:
	$(PYTEST) tests/contract -v
	cd contracts/typescript && npm test

lint:
	.venv/bin/ruff check contracts/python libs services agents canary tests scripts

typecheck:
	.venv/bin/mypy libs services agents canary

test:
	$(PYTEST) tests/unit tests/contract -v

test-contract: test-contracts

test-integration:
	$(PYTEST) tests/integration -v -m integration

# Focused re-runs for the two areas of the build with their own explicit
# spec acceptance lines (§6.1 steering, §6.5 fingerprint) — narrower and
# faster than the full integration suite when iterating on just one.
test-steering:
	$(PYTEST) tests/integration -v -k steering

test-agent-delivery:
	$(PYTEST) tests/unit/test_agent_queue.py tests/unit/test_agent_http_client.py \
		tests/unit/test_spider_service_logic.py -v
	$(PYTEST) tests/integration/test_agent_ingestion_api.py -v -k "telemetry"

test-fingerprint:
	$(PYTEST) tests/unit tests/integration -v -k fingerprint

test-evidence:
	$(PYTEST) tests/unit/test_evidence.py tests/unit/test_evidence_export.py -v

test-ai:
	$(PYTEST) tests/unit/test_behaviour_profiler.py tests/unit/test_ai.py -v

test-injection:
	$(PYTEST) tests/unit/test_ai.py -v -k "untrusted or injection"

test-policy:
	$(PYTEST) tests/unit/test_ai.py -v -k policy

test-artifacts:
	$(PYTEST) tests/unit/test_artifacts.py -v

test-canary:
	$(PYTEST) tests/unit/test_canary.py -v

test-analyst:
	$(PYTEST) tests/unit/test_analyst.py -v

test-prompt2-e2e:
	$(PYTEST) tests/integration/test_prompt2_e2e.py -v

test-dashboard:
	cd dashboard && npm run lint && npm run typecheck && npm test && npm run build

test-dashboard-e2e:
	cd dashboard && npm run test:e2e

# Gate: fails loudly if the dashboard/Keycloak OIDC wiring is misconfigured.
# Run before testing sign-in by hand, and whenever login misbehaves.
dev-auth-doctor:
	$(PYTHON) scripts/dev-auth-doctor

# Real, unmocked login flow against the full stack this Makefile brings up
# with `make compose-up` + `scripts/bootstrap-keycloak-realm` — not the
# MIRAGE_E2E_FIXTURE-mocked suite in test-dashboard-e2e.
test-dashboard-auth-e2e:
	cd dashboard && npx playwright test --config=playwright.auth.config.ts

test-graph-2d:
	cd dashboard && npm run test:graph-2d

test-graph-3d:
	cd dashboard && npm run test:graph-3d

test-graph-parity:
	cd dashboard && npm run test:graph-parity

test-reports:
	$(PYTEST) tests/unit/test_reports.py tests/integration/test_dashboard_read_model.py -v

test-installers:
	$(PYTEST) tests/unit/test_prompt3_installers.py -v

test-production-compose:
	$(PYTEST) tests/unit/test_production_compose.py -v

test-release-clean-room:
	$(PYTEST) tests/integration/test_release_clean_room.py -v -s

test-rdp-contract:
	$(PYTEST) tests/unit/test_rdp_steering_scaffold.py -v
	$(PYTEST) tests/integration/test_routing_api.py -v -k rdp

test-signature-trust:
	$(PYTEST) tests/unit/test_signature_trust.py -v

build-release:
	test -n "$(RELEASE_SIGNING_KEY)"
	$(PYTHON) scripts/build-release --version "$(RELEASE_VERSION)" --output "$(RELEASE_OUTPUT)" --signing-key "$(RELEASE_SIGNING_KEY)"

verify-release:
	test -n "$(RELEASE_PUBLIC_KEY)"
	$(PYTHON) scripts/verify-release "$(RELEASE_OUTPUT)" --public-key "$(RELEASE_PUBLIC_KEY)"

test-failure:
	$(PYTEST) tests/failure -v

test-security:
	$(PYTEST) tests/security -v

test-load-local:
	$(PYTEST) tests/load -v

test-observability:
	$(PYTEST) tests/observability -v

test-teardown:
	$(PYTEST) tests/teardown -v

# The three real-infrastructure tests supply PostgreSQL, NATS JetStream,
# Elasticsearch, and S3-compatible Object Lock evidence to the composite
# Stage 0–12 local acceptance result. The final test renders and verifies
# the signed result package and keeps all Profile B rows as NOT_RUN.
test-acceptance-local:
	$(PYTEST) tests/integration/test_prompt2_e2e.py tests/integration/test_dashboard_read_model.py tests/integration/test_elastic_templates.py -v -m integration
	$(PYTEST) tests/acceptance -v

test-prompt3-local:
	$(PYTEST) tests/unit/test_reports.py tests/unit/test_prompt3_installers.py tests/failure tests/security tests/load tests/observability tests/teardown tests/acceptance -v

test-all: lint typecheck test test-prompt3-local test-dashboard test-dashboard-e2e test-integration

validate-config:
	$(PYTHON) scripts/validate-config config/development.yaml

scan-secrets:
	$(PYTHON) scripts/validate-config --scan-secrets

scan-dependencies:
	.venv/bin/pip-audit

# Broader pre-publish gate than scan-secrets: forbidden tracked paths
# (node_modules/.next/dev-provisioner-keys/.env), content-based private-key
# detection, the existing custom scan, AND gitleaks (an independent,
# differently-implemented engine run against git HISTORY, not just the
# working tree) — soft-skipped with a warning, not silently passed, if the
# gitleaks binary isn't installed. Not part of `ci`/`scan-secrets` on
# purpose: this is a publish-readiness check, not a per-commit lint step
# (same reasoning test-integration/docker-build stay out of `ci`).
audit-public-repository:
	$(PYTHON) scripts/audit-public-repository

build-source-archive:
	$(PYTHON) scripts/build-source-archive --output dist/mirage-source-$(RELEASE_VERSION).tar.gz

# What CI runs (see .github/workflows/ci.yml) — offline-only jobs a
# developer can run identically before pushing. Live-infra jobs
# (test-integration, docker-build) are separate CI jobs, not part of this
# target, since they need Docker/testcontainers CI doesn't always have
# warm, and are already covered by `make test-all` / `make docker-build`.
ci: lint typecheck test test-prompt3-local validate-contracts scan-secrets

# Every host directory the compose file bind-mounts must exist BEFORE
# `docker compose up`. Where it does not, the Docker daemon creates it
# itself — and the daemon runs as root, so on native Linux the directory
# lands as root:root 0755 and the unprivileged user who invoked make can no
# longer write into it (scripts/bootstrap-step-ca-provisioners then dies with
# "PermissionError: .../dev-provisioner-keys/mirage-endpoint.priv.json").
# Docker Desktop on macOS/Windows hides this by remapping bind-mount
# ownership to the calling user, which is why it only ever failed in CI.
# config/yara needs no entry here: it is tracked, so a checkout always has it.
compose-dirs:
	mkdir -p infra/step-ca/dev-provisioner-keys

compose-up: compose-dirs
	$(COMPOSE) up -d --build

compose-down:
	$(COMPOSE) down

compose-logs:
	$(COMPOSE) logs -f

compose-ps:
	$(COMPOSE) ps

docker-build:
	docker build -f services/mirage-api/Dockerfile -t mirage-api:local .
	docker build -f services/mirage-agent-ingestion/Dockerfile -t mirage-agent-ingestion:local .
	docker build -f services/mirage-sandbox-gateway/Dockerfile -t mirage-sandbox-gateway:local .
	docker build -f services/mirage-worker/Dockerfile -t mirage-worker:local .
	docker build -f services/mirage-outbox-relay/Dockerfile -t mirage-outbox-relay:local .
	docker build -f services/mirage-artifact-scanner/Dockerfile -t mirage-artifact-scanner:local .
	docker build -f services/mirage-report-worker/Dockerfile -t mirage-report-worker:local .
	docker build -f dashboard/Dockerfile -t mirage-dashboard:local .

migrate:
	$(PYTHON) scripts/migrate up

migrate-rollback:
	$(PYTHON) scripts/migrate down
