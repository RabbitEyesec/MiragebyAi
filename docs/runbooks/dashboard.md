# Dashboard runbook

Copy `.env.example` to `.env`, set a random `MIRAGE_SESSION_SECRET` of at least
32 characters, and set the public/internal issuer, dashboard URL, and API URL.
Build contracts before the dashboard when running outside Docker.

```sh
cd contracts/typescript && npm ci && npm run build
cd ../../dashboard && npm ci && npm run build
cd .. && make compose-up
```

Check `/api/auth/session`, then the Operations workspace. A 401 means the OIDC
session is absent/expired; 403 means role/case/CSRF denial; 503/degraded means
an upstream read model is unavailable. Do not bypass the BFF by exposing a
bearer token to the browser.

Before release run `make test-dashboard`, `make test-dashboard-e2e`, and
`npm audit` in `dashboard`. A successful local build does not verify real
Keycloak TLS, production ingress, or Profile B browser latency.
