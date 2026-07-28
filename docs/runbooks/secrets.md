# Secrets Manager Catalogue

Every secret Mirage needs, its AWS Secrets Manager name, its JSON shape, who
reads it, and how it rotates. This is the authoritative catalogue referenced by
`config/schema.json`'s `*_source: secrets_manager` / `secret_name` fields.

## Rules (non-negotiable, enforced by code review + `scripts/validate-config --scan-secrets`)

1. Secret **values** are never committed to git, ever — only secret **names**
   and **schemas** live in this repository.
2. Secret values are never baked into Docker images or MSI/installer packages.
3. Endpoint agents, Spider, and Environment Controller never receive AWS
   Secrets Manager access — they authenticate via mTLS client certificates
   issued by step-ca (Step 3), not AWS credentials.
4. Secrets are never written to application logs. `logging.redact_secrets`
   (config/schema.json) must be `true` outside development, and log formatters
   in `libs/mirage_common/logging.py` redact any field named `*password*`,
   `*secret*`, `*api_key*`, `*token*` regardless of that setting.
5. Control-plane services (`mirage-api`, `mirage-worker`, `mirage-outbox-relay`,
   `mirage-agent-ingestion`, `mirage-sandbox-gateway`) retrieve secrets via
   their EC2/ECS **IAM role** at startup — never long-lived static AWS keys.
6. Every service validates the shape of a secret it reads (Pydantic model,
   matching the JSON Schema below) at startup and refuses to start with a
   missing or malformed secret rather than starting in a half-configured
   state.
7. Secret refresh does not require rebuilding a container: services poll (or
   are signalled, see rotation procedure) and re-resolve the secret without a
   restart wherever the secret is used per-request (DB pool credentials are the
   exception — see rotation procedure below).

## Catalogue

### `mirage/<environment>/postgres`

```json
{
  "type": "object",
  "required": ["username", "password", "host", "port", "database"],
  "properties": {
    "username": {"type": "string"},
    "password": {"type": "string"},
    "host": {"type": "string"},
    "port": {"type": "integer"},
    "database": {"type": "string"}
  }
}
```
Read by: mirage-api, mirage-worker, mirage-outbox-relay, mirage-agent-ingestion.

### `mirage/<environment>/nats`

```json
{
  "type": "object",
  "required": ["username", "password", "url"],
  "properties": {
    "username": {"type": "string"},
    "password": {"type": "string"},
    "url": {"type": "string"}
  }
}
```
Read by: all control-plane services (publishers/consumers).

### `mirage/<environment>/elastic`

```json
{
  "type": "object",
  "required": ["username", "password", "url"],
  "properties": {
    "username": {"type": "string"},
    "password": {"type": "string"},
    "url": {"type": "string"},
    "api_key": {"type": "string", "description": "Optional API-key auth in place of username/password"}
  }
}
```
Read by: mirage-api (dashboard reads), mirage-worker (read-model generation),
mirage-agent-ingestion (rare — health only).

### `mirage/<environment>/keycloak`

```json
{
  "type": "object",
  "required": ["bootstrap_admin_username", "bootstrap_admin_password", "client_secret"],
  "properties": {
    "bootstrap_admin_username": {"type": "string"},
    "bootstrap_admin_password": {"type": "string"},
    "client_secret": {"type": "string", "description": "mirage-dashboard confidential client secret"}
  }
}
```
Read by: mirage-api (OIDC token introspection / realm bootstrap tooling only).

### `mirage/<environment>/step-ca`

Five certificate profiles (infra/step-ca/PROFILES.md), each its own JWK
provisioner with its own encrypted private key — a token minted for one
profile cryptographically cannot be used to obtain a certificate under
another profile. `password` decrypts every `*_encrypted_jwk` below (all five
are encrypted with the same password in this schema; nothing stops rotating
them independently later by giving each its own `..._password` field).

```json
{
  "type": "object",
  "required": ["ca_url", "root_fingerprint", "password",
               "mirage_endpoint_encrypted_jwk", "mirage_endpoint_public_jwk",
               "mirage_spider_encrypted_jwk", "mirage_spider_public_jwk",
               "mirage_env_controller_encrypted_jwk", "mirage_env_controller_public_jwk",
               "mirage_broker_client_encrypted_jwk", "mirage_broker_client_public_jwk",
               "mirage_internal_control_encrypted_jwk", "mirage_internal_control_public_jwk"],
  "properties": {
    "ca_url": {"type": "string"},
    "root_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    "password": {"type": "string"},
    "mirage_endpoint_encrypted_jwk": {"type": "string", "description": "Compact JWE serialization, as produced by `step crypto jwk create`"},
    "mirage_endpoint_public_jwk": {"type": "object"},
    "mirage_spider_encrypted_jwk": {"type": "string"},
    "mirage_spider_public_jwk": {"type": "object"},
    "mirage_env_controller_encrypted_jwk": {"type": "string"},
    "mirage_env_controller_public_jwk": {"type": "object"},
    "mirage_broker_client_encrypted_jwk": {"type": "string"},
    "mirage_broker_client_public_jwk": {"type": "object"},
    "mirage_internal_control_encrypted_jwk": {"type": "string"},
    "mirage_internal_control_public_jwk": {"type": "object"}
  }
}
```

Loaded via `mirage_agent_ingestion.provisioners.SecretsManagerProvisionerSource`
— the interface exists (`libs/mirage_common/step_ca_client.decrypt_provisioner_key`
does the actual JWE decryption, already implemented and tested against a real
step-ca) but the Secrets-Manager-backed loader itself is **not implemented in
Prompt 1** (no AWS account in this environment to test against — see
KNOWN_ISSUES.md). Local development uses
`mirage_agent_ingestion.provisioners.DevFileProvisionerSource`, reading
plaintext-on-disk dev keys from `infra/step-ca/dev-provisioner-keys/`
(gitignored, generated by `scripts/bootstrap-step-ca-provisioners`).

Read by: mirage-agent-ingestion (issues one-time enrollment tokens against
the role-appropriate `mirage-{endpoint,spider,env-controller,broker-client,
internal-control}` JWK provisioner — see infra/step-ca/PROFILES.md).

### `mirage/<environment>/ai-provider`

```json
{
  "type": "object",
  "required": ["provider", "api_key", "model", "base_url"],
  "properties": {
    "provider": {"type": "string", "description": "openai-or-configured-provider"},
    "api_key": {"type": "string"},
    "model": {"type": "string"},
    "base_url": {"type": "string"}
  }
}
```
Read by: mirage-worker only (AI orchestration, Stage 6 — not built in Prompt 1,
catalogued now because the Bootstrap Gate must define it up front).
**Never** reachable from endpoint/spider/controller agents or the sandbox
network (security boundary).

### `mirage/<environment>/installer-signing`

```json
{
  "type": "object",
  "required": ["certificate_thumbprint", "signing_backend"],
  "properties": {
    "certificate_thumbprint": {"type": "string"},
    "signing_backend": {"type": "string", "enum": ["azure_trusted_signing", "aws_kms", "local_pfx"]},
    "pfx_secret_name": {"type": "string", "description": "Only when signing_backend=local_pfx; a second secret holding the PFX bytes+password, restricted to the Windows build host's role only"}
  }
}
```
Read by: the Windows build host performing WiX MSI signing (Step 21 hardening;
Step 4/5/9b dev MSIs in Prompt 1 are unsigned by design — see
`installers/*/README.md`). Never read by any control-plane or agent service.

### `mirage/<environment>/fleet`

```json
{
  "type": "object",
  "required": ["enrollment_token", "fleet_server_url"],
  "properties": {
    "enrollment_token": {"type": "string"},
    "fleet_server_url": {"type": "string"}
  }
}
```
Read by: the installer build/config pipeline that stamps a Fleet enrollment
token into the endpoint MSI config (Step 4) — resolved at package-build time,
not embedded as a long-lived secret in the shipped MSI (Elastic Agent exchanges
it for a runtime credential on first enrollment).

### `mirage/<environment>/canary`

```json
{
  "type": "object",
  "required": ["signing_key", "callback_base_url"],
  "properties": {
    "signing_key": {"type": "string", "description": "HMAC key the serverless collector uses to sign callback evidence records"},
    "callback_base_url": {"type": "string"}
  }
}
```
Read by: mirage-canary-collector (Stage 7 — not built in Prompt 1).

## Rotation procedure (applies to all secrets above)

1. Write the new value as a new version of the same Secrets Manager secret
   (never a new secret name — names are stable, referenced by config).
2. For secrets consumed per-request (NATS/Elastic/Keycloak/step-ca/AI/canary):
   services re-resolve on a TTL (default 5 minutes, `SECRETS_REFRESH_INTERVAL_S`)
   with no restart required.
3. For PostgreSQL (long-lived pooled connections): call the service's
   `POST /internal/reload-credentials` admin endpoint (`platform_admin` role
   only) after the new version is confirmed AWS-side; the connection pool
   drains and re-establishes with the new credentials without dropping
   in-flight transactions.
4. Old secret versions remain retrievable (AWS default) for 30 days in case a
   rotation must be rolled back; `AWSPREVIOUS` stays valid during that window.
5. Certificate-backed identities (step-ca issued, Step 3) rotate independently
   via auto-renewal before 20% lifetime remains — that is a PKI rotation, not
   a Secrets Manager rotation, and is never blocked by this procedure.
6. Every rotation is expected to be logged as an `audit_events` row once
   Stage 2 (Step 6) exists; Bootstrap Gate itself has no audit table yet, so
   for Prompt 1 rotation is a manual, documented AWS Console/CLI action.
