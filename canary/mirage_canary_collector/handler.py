"""AWS Lambda handler: capture minimal callback metadata and forward a signed event.

The collector has no PostgreSQL, sandbox, endpoint, or AI-secret access. Token
validation, replay detection, evidence storage, and classification happen at the
approved ingestion endpoint before any callback becomes displayable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import urllib.request
from datetime import UTC, datetime
from typing import Any

_signing_key: bytes | None = None


def _get_signing_key() -> bytes:
    global _signing_key
    if _signing_key is not None:
        return _signing_key
    secret_arn = os.environ["CANARY_SIGNING_SECRET_ARN"]
    import boto3

    response = boto3.client("secretsmanager").get_secret_value(SecretId=secret_arn)
    raw = json.loads(response["SecretString"])
    _signing_key = base64.b64decode(raw["hmac_key_base64"], validate=True)
    if len(_signing_key) < 32:
        raise ValueError("canary HMAC key must be at least 256 bits")
    return _signing_key


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request_context = event.get("requestContext", {})
    http = request_context.get("http", {})
    headers = {str(key).lower(): str(value)[:2048] for key, value in event.get("headers", {}).items()}
    token = str(event.get("pathParameters", {}).get("token", ""))
    if not 20 <= len(token) <= 256:
        return {"statusCode": 404, "body": ""}
    payload = {
        "public_token": token,
        "callback_time": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_ip": str(http.get("sourceIp", ""))[:64],
        "forwarded_for": headers.get("x-forwarded-for", "")[:2048],
        "user_agent": headers.get("user-agent", "")[:1024],
        "request_path": str(http.get("path", event.get("rawPath", "")))[:2048],
        "referrer": headers.get("referer", "")[:2048],
        "http_method": str(http.get("method", "GET"))[:16],
        "tls_metadata": {
            "protocol": request_context.get("domainPrefix"),
            "source": "API_GATEWAY_V2",
        },
        "collector_request_id": str(request_context.get("requestId", context.aws_request_id)),
    }
    signature = hmac.new(_get_signing_key(), _canonical(payload), hashlib.sha256).hexdigest()
    body = _canonical({"payload": payload, "signature": signature})
    request = urllib.request.Request(
        os.environ["CANARY_INGESTION_URL"],
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Mirage-Canary-Signature": signature},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read(1024)
    except Exception:  # API Gateway retry/DLQ owns durable failure handling
        raise
    return {
        "statusCode": 204,
        "headers": {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }
