"""Idempotently provisions the "mirage" Keycloak realm: five RBAC roles
(Step 4b), an OIDC client, and one dev test user per role. Shared by
scripts/bootstrap-keycloak-realm (persistent dev container) and
tests/integration/conftest.py's ephemeral Keycloak fixture — the same
pattern as step_ca_admin.py for step-ca (ADR: one provisioning
implementation, exercised by both the dev workflow and the test suite).
"""
from __future__ import annotations

import httpx

REALM = "mirage"
CLIENT_ID = "mirage-dashboard"
ROLES = [
    "platform_admin",
    "investigator",
    "operator",
    "auditor",
    "read_only",
    "export",
    "direct_intervention",
    "emergency_control",
]


def get_admin_token(client: httpx.Client, keycloak_url: str, admin_user: str, admin_password: str) -> str:
    resp = client.post(
        f"{keycloak_url}/realms/master/protocol/openid-connect/token",
        data={"client_id": "admin-cli", "username": admin_user, "password": admin_password, "grant_type": "password"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def bootstrap_realm(
    keycloak_url: str,
    *,
    admin_user: str = "admin",
    admin_password: str = "mirage_dev_local_only",
    dev_user_password: str = "mirage_dev_local_only",
    allow_http: bool = False,
    dashboard_url: str = "http://localhost:3001",
    create_dev_users: bool = True,
) -> None:
    forwarded_headers = (
        {"X-Forwarded-Proto": "https"}
        if allow_http and keycloak_url.startswith("http://")
        else {}
    )
    with httpx.Client(timeout=15.0, headers=forwarded_headers) as client:
        token = get_admin_token(client, keycloak_url, admin_user, admin_password)
        headers = {"Authorization": f"Bearer {token}"}

        if client.get(f"{keycloak_url}/admin/realms/{REALM}", headers=headers).status_code == 404:
            client.post(
                f"{keycloak_url}/admin/realms", headers=headers,
                json={
                    "realm": REALM,
                    "enabled": True,
                    "accessTokenLifespan": 300,
                    "sslRequired": "none" if allow_http else "external",
                },
            ).raise_for_status()

        for role in ROLES:
            if client.get(f"{keycloak_url}/admin/realms/{REALM}/roles/{role}", headers=headers).status_code == 404:
                client.post(
                    f"{keycloak_url}/admin/realms/{REALM}/roles", headers=headers, json={"name": role}
                ).raise_for_status()

        # Canonical client config, re-applied on every run (not just at
        # creation) — this is the single source of truth for the dashboard's
        # OIDC redirect wiring. A previous version of this function only set
        # these fields when first creating the client, so once a developer's
        # dashboard moved to a different port (e.g. because port 3000 was
        # already taken by something else on their machine), the stale
        # redirectUris/webOrigins in Keycloak silently never got updated and
        # every subsequent login redirected to the wrong place.
        client_payload = {
            "clientId": CLIENT_ID,
            "publicClient": True,
            "directAccessGrantsEnabled": True,
            "standardFlowEnabled": True,
            "redirectUris": [f"{dashboard_url}/*"],
            "webOrigins": [dashboard_url],
            "rootUrl": dashboard_url,
            "baseUrl": dashboard_url,
        }
        existing_clients = client.get(
            f"{keycloak_url}/admin/realms/{REALM}/clients", headers=headers, params={"clientId": CLIENT_ID}
        )
        existing_clients.raise_for_status()
        found = existing_clients.json()
        if not found:
            client.post(
                f"{keycloak_url}/admin/realms/{REALM}/clients", headers=headers, json=client_payload,
            ).raise_for_status()
        else:
            client_uuid = found[0]["id"]
            merged = {**found[0], **client_payload}
            client.put(
                f"{keycloak_url}/admin/realms/{REALM}/clients/{client_uuid}", headers=headers, json=merged,
            ).raise_for_status()

        if not create_dev_users:
            # Production realm bootstrap: the client and roles above are
            # real infrastructure every environment needs; the 5 dev test
            # accounts below are a local/CI convenience that must never
            # exist in a production realm (Priority 9 — no development
            # users in a production deploy).
            return

        for role in ROLES:
            username = f"dev-{role.replace('_', '-')}"
            existing_users = client.get(
                f"{keycloak_url}/admin/realms/{REALM}/users", headers=headers,
                params={"username": username, "exact": "true"},
            )
            existing_users.raise_for_status()
            users = existing_users.json()
            if not users:
                created = client.post(
                    f"{keycloak_url}/admin/realms/{REALM}/users",
                    headers=headers,
                    json={
                        "username": username,
                        "enabled": True,
                        "emailVerified": True,
                        # See ARCHITECTURE_DECISIONS.md / TEST_RESULTS.md
                        # §Step4b: Keycloak's declarative User Profile
                        # silently requires email/name or token issuance
                        # fails with "Account is not fully set up" —
                        # verified empirically, not guessed.
                        "email": f"{username}@mirage.local",
                        "firstName": role.replace("_", " ").title(),
                        "lastName": "Dev",
                        "credentials": [{"type": "password", "value": dev_user_password, "temporary": False}],
                    },
                )
                created.raise_for_status()
                user_id = created.headers["Location"].rsplit("/", 1)[-1]
            else:
                user_id = users[0]["id"]
                # Re-applied on every run, same reasoning as the client
                # config above: dev_user_password is regenerated per machine
                # (scripts/_lib.get_or_create_dev_user_password) and must
                # actually take effect for a user that already existed from
                # a previous bootstrap run — otherwise re-running this
                # script after that credentials file was deleted/rotated
                # would silently leave the OLD password as the only one that
                # works, which defeats the point of generating a new one.
                client.put(
                    f"{keycloak_url}/admin/realms/{REALM}/users/{user_id}/reset-password",
                    headers=headers,
                    json={"type": "password", "value": dev_user_password, "temporary": False},
                ).raise_for_status()

            role_repr = client.get(f"{keycloak_url}/admin/realms/{REALM}/roles/{role}", headers=headers)
            role_repr.raise_for_status()

            current_roles = client.get(
                f"{keycloak_url}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm", headers=headers
            ).json()
            if not any(r["name"] == role for r in current_roles):
                client.post(
                    f"{keycloak_url}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
                    headers=headers,
                    json=[role_repr.json()],
                ).raise_for_status()
