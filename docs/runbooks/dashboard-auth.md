# Dashboard authentication

Full flow: landing page → sign in → Keycloak credentials → callback →
session creation → authenticated dashboard → refresh → logout → login
again. See `docs/runbooks/dashboard.md` for general dashboard operations;
this runbook is specifically about the auth path and its local dev setup.

## First-time local setup

```sh
make compose-up
.venv/bin/python scripts/bootstrap-keycloak-realm
make dev-auth-doctor          # confirms everything below before you test by hand
cd dashboard && npm run dev   # if not already running
```

`bootstrap-keycloak-realm` is idempotent — safe to re-run any time the
dashboard's port changes, the Keycloak client config drifts, or you're
unsure of the current state.

## Dev credentials are never a hardcoded shared password

`bootstrap-keycloak-realm` generates a random password on first run and
writes it to `.dev-auth-keys/dev-credentials.json` (gitignored, `chmod 600`).
Re-running the bootstrap script reuses the existing password (won't lock out
an in-progress test session) and — as of this fix — also resets it on any
already-existing dev users, so deleting the credentials file and
re-bootstrapping genuinely rotates the live password rather than silently
leaving the old one active.

```sh
cat .dev-auth-keys/dev-credentials.json   # {"password": "..."}
```

`scripts/dev-auth-doctor` and `dashboard/tests/e2e-auth/real-auth.spec.ts`
both read this same file. Do not add this password back as a literal
anywhere in tracked source — that regression (a single shared password
committed to the repo) is exactly what this mechanism replaced.

## Real local Keycloak login test (no mocks)

```sh
make test-agent-delivery    # unrelated, listed here only to distinguish:
make test-dashboard-auth-e2e
```

This runs `dashboard/tests/e2e-auth/real-auth.spec.ts` against an actually
running Keycloak — no `MIRAGE_E2E_FIXTURE`, no mocked OIDC, no `/test-fixture`
route. It exercises the complete cycle in one browser session: landing →
sign in → real Keycloak credential form → callback → authenticated dashboard
→ page refresh (proves the session cookie survives) → logout (proves the
CSRF-protected logout route and Keycloak end-session redirect) → sign in
again (proves stale-cookie clearing works, not just the first login ever).

## Symptom: redirect loop, wrong port, or FastAPI 404 after login

Run `make dev-auth-doctor` first — it exists specifically because of a real
incident where the dashboard's canonical port (3001) and Keycloak's
registered redirect URI silently drifted apart across several manual fixes,
producing exactly these symptoms in sequence. It checks, in order:

1. `dashboard/.env.local` exists and `MIRAGE_DASHBOARD_URL` matches what the
   dev server is actually bound to, and `MIRAGE_SESSION_SECRET` is long
   enough.
2. The dashboard is actually answering (not some other app squatting the
   port).
3. The generated dev-credentials file exists.
4. Keycloak admin auth succeeds.
5. The Keycloak client's `redirectUris`/`webOrigins`/`rootUrl`/`baseUrl` all
   match the canonical dashboard URL.
6. All 5 dev users exist.

Each failing row names the exact fix (usually: re-run
`scripts/bootstrap-keycloak-realm` after `MIRAGE_DASHBOARD_URL` changes).

## Symptom: Keycloak admin auth fails in dev-auth-doctor

Check `.env`'s `MIRAGE_KEYCLOAK_ADMIN_PASSWORD` matches what the Keycloak
container was actually started with (`infra/compose/docker-compose.development.yml`
passes it through as `KEYCLOAK_ADMIN_PASSWORD`) — this is a separate
credential from the dev test-user password above; it authenticates the
bootstrap script to Keycloak's own admin API, not a human to the dashboard.

## What's still lab work

Production Keycloak (real TLS, a real external issuer, confidential client
authentication, production-grade session cookie settings) is not exercised
by this local flow — see `docs/architecture/signature-trust.md` and
`EXTERNAL_DEPENDENCIES.md` for what remains lab-gated across the whole
platform. The mechanism this runbook covers (PKCE, state/nonce verification,
CSRF-protected logout, encrypted `HttpOnly` session cookie, stale-cookie
clearing) is real and exercised end-to-end against a real local Keycloak,
not a claim of production readiness on its own.
