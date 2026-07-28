"""Client-identity extraction for mTLS-fronted endpoints — shared by every
service that sits behind the mTLS-terminating Nginx listener
(mirage-agent-ingestion since Step 4b, mirage-api's /route since Step 8a).

Empirically verified (see TEST_RESULTS.md §Step4): uvicorn's default ASGI
transport does NOT expose the TLS peer certificate to application code — the
ASGI `scope` has no `transport`/`extensions.tls` key populated for it,
regardless of `ssl_cert_reqs=CERT_REQUIRED` actually enforcing the handshake
at the socket level. This is a genuine constraint of the stack, not a bug in
this code.

The correct fix — and the one the locked technology list already implies —
is TLS termination at Nginx, which verifies the client certificate against
the step-ca root and forwards the verified serial via a header
(`$ssl_client_serial` -> `X-Mirage-Client-Cert-Serial`), the same pattern
Stage 3's HTTP broker (Step 8b) needs anyway. That Nginx listener config is
built in Step 8b; until then, this module documents and enforces the
CONTRACT (header present + a shared bearer secret so the header cannot be
forged by a client that reaches this service directly, bypassing Nginx) and
is exercised in tests by setting the header directly, matching exactly what
Nginx would inject — see KNOWN_ISSUES.md for the precise scope boundary.
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

CLIENT_SERIAL_HEADER = "X-Mirage-Client-Cert-Serial"
PROXY_SHARED_SECRET_HEADER = "X-Mirage-Proxy-Auth"  # secret-scan: ignore (header name, not a secret value)


class MtlsAuthConfig:
    def __init__(self, proxy_shared_secret: str) -> None:
        self.proxy_shared_secret = proxy_shared_secret


def require_client_certificate_serial(
    proxy_auth: str | None = Header(default=None, alias=PROXY_SHARED_SECRET_HEADER),
    client_serial: str | None = Header(default=None, alias=CLIENT_SERIAL_HEADER),
    *,
    expected_proxy_secret: str,
) -> str:
    """FastAPI dependency: requires the two headers the mTLS-terminating
    Nginx listener injects. Raises 401 if either is missing or the shared
    secret doesn't match (defense against a client reaching this service
    directly, bypassing Nginx's certificate verification).
    """
    if not proxy_auth or not hmac.compare_digest(proxy_auth, expected_proxy_secret):
        raise HTTPException(status_code=401, detail="missing or invalid proxy authentication")
    if not client_serial:
        raise HTTPException(status_code=401, detail="missing client certificate serial")
    return client_serial
