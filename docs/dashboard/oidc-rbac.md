# Dashboard OIDC and RBAC

Keycloak is the OIDC authority. The public issuer is browser reachable; the
internal issuer is used only for back-channel token/JWKS calls and tokens are
still validated against the public issuer. Production startup rejects a
session secret shorter than 32 characters.

Roles are additive:

| Role | Main access |
|---|---|
| `read_only` | authorised read models |
| `operator` | operations and bounded sandbox operations |
| `investigator` | investigation, directives, evidence work |
| `auditor` | global read/audit |
| `export` | report/export creation and download |
| `direct_intervention` | direct-message preview/create/confirm |
| `emergency_control` | analyst-channel emergency controls |
| `platform_admin` | all platform controls |

The UI hides unavailable controls for usability, but this is not the security
boundary. The API checks roles and case grants. Mutations also require a valid
session, same origin, CSRF token, strict request schema, and an idempotency key
where specified.

Test a role matrix with `make test-security` and test browser denial with
`make test-dashboard-e2e`.
