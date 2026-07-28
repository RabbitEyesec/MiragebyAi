# Credential Rotation Report

Date: 2026-07-28
Trigger: the repository was public at `github.com/RabbitEyesec/MiragebyAi` before
final cleanup. Every credential that existed at or before that push is treated
as exposed, regardless of whether it was ever tracked by git.

**No secret values appear in this document.** Only names, rotation status, the
command that regenerates each, where it is stored, and whether that location is
ignored.

---

## 1. What was actually exposed

Two independent scans of the published history (`gitleaks git .` across all
three commits, plus a content search for private-key PEM headers, `AKIA`/`ASIA`
prefixes, bearer tokens and `password=`/`token=` assignments) found:

| Finding | Count | Classification |
| --- | --- | --- |
| Real private keys committed | 0 | — |
| Real `.env` / credential files committed | 0 | — |
| AWS access keys | 0 real | 7 hits, all the same synthetic fixture (below) |
| Cloud / AI provider API keys | 0 | `MIRAGE_AI_API_KEY` shipped empty |

The 7 gitleaks hits were all the literal `AKIA` + sequential alphabet string
used by `tests/unit/test_config_schema.py` to prove the secret scanner
*detects* a planted secret, plus five prose references to it in documentation.
It is structurally AWS-key-shaped and functionally inert. Each occurrence now
carries an inline `gitleaks:allow` marker (inside an HTML comment in the
markdown files, so it stays invisible when rendered), which is why
`.gitleaksignore` no longer needs a fingerprint entry.

**However**, the absence of committed key material is not the whole story. The
real exposure is structural:

`.env.example` is a public template, and `scripts/bootstrap-development`
copied it to `.env` **verbatim**. Every clone on every machine therefore ran
its local stack on the *same published literals* — `mirage_dev_local_only` for
Postgres, NATS, Elasticsearch, Keycloak admin and step-ca; `..._minio` for the
MinIO root password; `..._canary` for the canary ingestion HMAC; and a fixed
dashboard session secret ending `_change_me`. These services bind to
`127.0.0.1` only, so this is a local-development weakness rather than a
production compromise — but a published shared credential is still one nobody
should inherit by default. That is what this rotation fixes.

Production is unaffected: `infra/compose/docker-compose.production.yml`
already requires every credential (`${VAR:?...}`) with no development-shaped
fallback, and `tests/unit/test_production_compose.py` enforces that.

---

## 2. Rotation status

Regenerate everything below with:

```
scripts/rotate-dev-credentials          # rotate .env, discard on-disk key material
scripts/rotate-dev-credentials --check  # fail if any published literal survives
```

`scripts/bootstrap-development` now *generates* `.env` through that script
instead of copying the template, and re-runs `--check` on an existing `.env`,
warning if it still holds a published value.

### Environment credentials — rotated to per-machine randomness

Each is `secrets.token_urlsafe(32)`, generated on this machine, written to
`.env` (mode `0600`).

| Secret | Rotated | Storage | Ignored |
| --- | --- | --- | --- |
| `MIRAGE_SESSION_SECRET` | Yes | `.env` | Yes |
| `MIRAGE_KEYCLOAK_ADMIN_PASSWORD` | Yes | `.env` | Yes |
| `MIRAGE_POSTGRES_PASSWORD` | Yes | `.env` | Yes |
| `MIRAGE_NATS_PASSWORD` | Yes | `.env` | Yes |
| `MIRAGE_ELASTIC_PASSWORD` | Yes | `.env` | Yes |
| `MIRAGE_STEP_CA_PASSWORD` | Yes | `.env` | Yes |
| `MIRAGE_PROXY_SHARED_SECRET` | Yes | `.env` | Yes |
| `MIRAGE_MINIO_SECRET_KEY` | Yes | `.env` | Yes |
| `MIRAGE_CANARY_INGESTION_HMAC` | Yes | `.env` | Yes |

Verified: `scripts/rotate-dev-credentials --check` exits 0 on the generated
file, and exits 1 with the offending variable named when a published literal is
planted back into it.

### Key material — destroyed, re-minted on next bootstrap

None of these existed on disk at cleanup time (all four directories were
absent), and none was ever tracked. They are listed because the rotation script
removes them unconditionally so a stale copy can never survive a rotation.

| Material | Rotated | Regeneration command | Storage | Ignored |
| --- | --- | --- | --- | --- |
| step-ca provisioner keys (5 JWK pairs) | Re-minted | `scripts/bootstrap-step-ca-provisioners` | `infra/step-ca/dev-provisioner-keys/` | Yes |
| step-ca **CA init** password (`MIRAGE_STEP_CA_PASSWORD`) | Yes | `scripts/rotate-dev-credentials` | `.env` | Yes |
| step-ca **JWK encryption** password | **No — see below** | n/a | hardcoded default in two places | n/a |
| Broker (bastion) SSH keypairs | Re-minted | `scripts/bootstrap-broker-keys` | `.broker-keys/` | Yes |
| Dev sandbox SSH keypair | Re-minted | `scripts/bootstrap-dev-sandbox-keys` | `.dev-sandbox-keys/` | Yes |
| Keycloak dev user passwords | Re-minted | `scripts/bootstrap-keycloak-realm` | `.dev-auth-keys/dev-credentials.json` (0600) | Yes |
| Endpoint / sandbox certificates | Re-issued | issued on demand by step-ca after the above | container volume `mirage-stepca-data` | n/a (not on host) |
| Release signing key | Ephemeral | `openssl genpkey` per CI run; never stored | CI runner memory / job workspace | Yes (`*.pem`) |

Keycloak dev user passwords were **already** per-machine random before this
work (`scripts/_lib.py: get_or_create_dev_user_password`) — that is the one
credential in this list that was never a shared published literal.

#### Not rotated, deliberately: the step-ca JWK encryption password

`MIRAGE_STEP_CA_PASSWORD` (rotated) is the CA's own init password, consumed
only by the step-ca container. It is **not** the password that encrypts the
five provisioner JWKs. That one is a hardcoded `"mirage_dev_local_only"`
default paired across two places — `step_ca_admin.add_provisioners` (writes the
encrypted key into `ca.json`) and
`mirage_agent_ingestion.provisioners.DevFileProvisionerSource` (reads it back).
Nothing threads a configured value between them, so rotating it would break
agent enrolment until that wiring exists.

It is left as a known, documented gap rather than silently half-rotated. The
material it protects is re-minted on every bootstrap, exists only inside
gitignored local directories, and was never committed. Closing it properly
means giving `DevFileProvisionerSource` an environment-sourced password and
having the bootstrap script pass the same value — a change to service
configuration, out of scope for this cleanup.

#### Host-side scripts now read `.env`

Rotation exposed a latent coupling: Compose reads `.env` and starts Keycloak
with the rotated `MIRAGE_KEYCLOAK_ADMIN_PASSWORD`, but
`scripts/bootstrap-keycloak-realm` runs on the *host*, read only
`os.environ`, and fell back to the published literal — so admin login would
have failed for anyone who rotated. `scripts/_lib.py: load_env_file()` now
loads `.env` into the environment (without overriding anything already set)
and the Keycloak bootstrap calls it before resolving its defaults.

### Not applicable

| Secret | Status | Reason |
| --- | --- | --- |
| AWS credentials | NOT_PRESENT | No AWS credentials exist in the repo or working tree; `AWS_PROFILE` ships empty and evidence storage runs against local MinIO |
| AI provider keys | NOT_PRESENT | `MIRAGE_AI_API_KEY` ships empty; `AI_ALLOW_EXTERNAL_PROVIDER=false` and the model allowlist is `deterministic-fake` |
| Keycloak client secret | NOT_PRESENT | The dashboard client is configured as a public OIDC client (PKCE), so no client secret exists to rotate |
| `MIRAGE_FLEET_ENROLLMENT_TOKEN` | NOT_PRESENT | Ships empty; minted per enrolment at runtime, never stored in `.env` |
| KMS signing key | NOT_PRESENT | `MIRAGE_KMS_SIGNING_KEY_ARN=LOCAL_DEV_NO_KMS`; no cloud KMS key is provisioned |

---

## 3. Residual risk

The published `.env.example` literals remain readable in the deleted
repository's cached history on third-party mirrors. That is acceptable and
unchanged by this work: they were only ever defaults for `127.0.0.1`-bound
development services, they grant nothing on any deployed system, and after this
rotation they are no longer in use on any machine that runs
`scripts/bootstrap-development`.

The compose files still carry `${VAR:-mirage_dev_local_only}` fallbacks so that
`docker compose config` works without a `.env` (CI's `docker-build-and-boot`
job relies on this for an ephemeral, isolated stack). Anyone bootstrapping
through the supported path gets rotated values; the fallback is reachable only
by invoking compose directly with no `.env` present.
