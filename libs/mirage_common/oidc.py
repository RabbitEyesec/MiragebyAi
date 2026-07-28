"""Keycloak OIDC bearer-token verification (Step 4b). JWKS-based signature
verification via PyJWT's PyJWKClient, real roles read from the token's
`realm_access.roles` claim — the exact shape confirmed empirically against a
real Keycloak 25 "mirage" realm (see TEST_RESULTS.md §Step4b;
scripts/bootstrap-keycloak-realm provisions the realm/roles/client this
verifies against).
"""
from __future__ import annotations

from dataclasses import dataclass

import jwt as pyjwt
from jwt import PyJWKClient


class TokenInvalidError(Exception):
    pass


class InsufficientRoleError(Exception):
    def __init__(self, required: set[str], actual: set[str]) -> None:
        super().__init__(f"requires one of {sorted(required)}, token has {sorted(actual)}")
        self.required = required
        self.actual = actual


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject: str
    username: str
    roles: frozenset[str]

    def has_any_role(self, *roles: str) -> bool:
        return bool(self.roles.intersection(roles))


class OidcVerifier:
    """One instance per (issuer, audience) — caches the JWKS client, which
    itself caches keys by kid and only refetches on an unknown kid."""

    def __init__(self, issuer_url: str, *, audience: str | None = None, leeway_seconds: int = 10) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.audience = audience
        self.leeway_seconds = leeway_seconds
        self._jwks_client = PyJWKClient(f"{self.issuer_url}/protocol/openid-connect/certs")

    def verify(self, token: str) -> AuthenticatedPrincipal:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = pyjwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer_url,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"verify_aud": self.audience is not None},
            )
        except pyjwt.PyJWTError as exc:
            raise TokenInvalidError(str(exc)) from exc

        roles = frozenset(claims.get("realm_access", {}).get("roles", []))
        return AuthenticatedPrincipal(subject=claims["sub"], username=claims.get("preferred_username", claims["sub"]), roles=roles)


def require_any_role(principal: AuthenticatedPrincipal, *roles: str) -> None:
    if not principal.has_any_role(*roles):
        raise InsufficientRoleError(set(roles), set(principal.roles))
