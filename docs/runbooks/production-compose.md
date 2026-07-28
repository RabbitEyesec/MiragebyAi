# Production Compose

Three Compose files now exist under `infra/compose/`, each with a distinct,
enforced purpose:

- `docker-compose.development.yml` — the local dev stack (`make compose-up`).
  Builds images from source, uses dev-convenience default credentials,
  bootstraps a MinIO stand-in for S3.
- `docker-compose.production.yml` — deployed by the Ubuntu server installer
  (`libs/mirage_common/server_installer.py`). Never built from source, never
  has a default credential, never runs a dev-mode service.
- `docker-compose.test.yml` — a Compose **override** layered on top of
  `docker-compose.development.yml` for CI/automated full-stack test runs
  (`docker compose -f docker-compose.development.yml -f docker-compose.test.yml`).
  Not used by `pytest`'s own integration suite, which spins up its own
  ephemeral testcontainers directly.

## What makes the production file actually different

Every one of these is enforced by `scripts/validate-production-compose`
(see `tests/unit/test_production_compose.py` for the automated proof) and by
the file's own required-variable syntax (`${VAR:?message}` — `docker compose`
itself refuses to start if any of these aren't set, independent of the
guard script):

- No credential has a `mirage_dev_local_only`-shaped fallback default —
  every secret is required.
- No MinIO — evidence storage requires a real S3-compatible endpoint.
- No `DOCKER_STEPCA_INIT_*` variables — step-ca is never auto-initialized
  with a throwaway CA; a real CA must already exist in the mounted volume
  (see `docs/runbooks/step-ca-secrets.md`).
- Keycloak runs `start --optimized`, never `start-dev`.
- Application images are pinned digests (`${MIRAGE_API_IMAGE:?...}` etc.,
  supplied by the release manifest), never a `build:` context.
- Every mirage-* application container runs with a read-only root
  filesystem, all Linux capabilities dropped, `no-new-privileges`, and
  explicit CPU/memory limits.
- Named volumes are explicit host-path bind mounts under `/var/lib/mirage/`,
  not anonymous Docker-managed volumes.
- Every port stays bound to `127.0.0.1` — a TLS-terminating reverse proxy in
  front is assumed and out of this file's scope.
- Keycloak's dev test users (`dev-platform-admin` etc.) are never created —
  `scripts/bootstrap-keycloak-realm` checks `MIRAGE_ENV=production` and
  skips that step entirely (`bootstrap_realm(..., create_dev_users=False)`).

## The guard

```sh
.venv/bin/python scripts/validate-production-compose
```

Resolves the FULL merged config via `docker compose config` (env-var
interpolation included, not just the static YAML) and fails if it finds: a
`build:` key, a MinIO image, `start-dev`, any `DOCKER_STEPCA_INIT_*`
variable, any environment value matching a known development-placeholder
substring, or any port published on something other than loopback. The
server installer's `secret-references` step runs this automatically before
`deploy` — a production install cannot proceed with a development setting
still active.

## Exact commands

```sh
make test-production-compose   # static validation, no containers started
scripts/validate-production-compose --env-file .env
```
