# Dashboard architecture

The Mirage dashboard is a Next.js 15 application with six workspaces:
Operations, Investigation, Sandbox, AI Interaction, Evidence Board, and
Reporting. It renders canonical PostgreSQL read models; it does not reconstruct
case truth in the browser.

The browser authenticates through the same-origin BFF. The BFF performs OIDC
Authorization Code + PKCE against Keycloak, validates JWKS/issuer/audience, and
stores encrypted tokens only in `HttpOnly`, `Secure` production cookies. It
proxies a fixed `/api/mirage/v1/...` namespace to Mirage API, rejects traversal,
adds the bearer token server-side, and enforces origin plus double-submit CSRF
on mutations. Tokens are never stored in browser storage.

Mirage API enforces roles again and applies case-level access checks. PostgreSQL
migration `0009` owns summaries, timeline items, nodes, edges, offsets,
notifications, saved views, preferences, and grants. The projector records
source IDs, evidence pivots, classification, output tags, confidence, sequence
gaps, and projection versions. SSE carries invalidation/update records; a
reconnect sends `Last-Event-ID` and the client reloads the canonical model.

The 2D Cytoscape and 3D Three.js views consume the same filtered graph object.
Neither renderer has authority to add relationships. Reports are asynchronous
records generated only after a verified evidence export is available.

Build and test:

```sh
make test-dashboard
make test-dashboard-e2e
make test-graph-parity
docker build -f dashboard/Dockerfile -t mirage-dashboard:local .
```
