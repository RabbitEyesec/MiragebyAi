"""Loads the five step-ca JWK provisioner keys (infra/step-ca/PROFILES.md)
so mirage-agent-ingestion can mint enrollment tokens per role.

Two loaders:
- `DevFileProvisionerSource` — reads the plaintext-on-disk dev keys written
  by scripts/bootstrap-step-ca-provisioners (infra/step-ca/dev-provisioner-keys/,
  gitignored). Development only.
- `SecretsManagerProvisionerSource` — reads `mirage/<environment>/step-ca`
  (docs/runbooks/secrets.md's authoritative schema) from AWS Secrets
  Manager. Unit-tested against `botocore.stub.Stubber` — no AWS account
  required to prove the retrieval/parsing/error-handling logic is correct;
  only the live AWS call itself remains AWS_VERIFICATION_REQUIRED (see
  docs/runbooks/step-ca-secrets.md).

`build_provisioner_source()` is the one place that decides which of the two
to use — production can never silently fall back to the file provider.
"""
from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mirage_common.step_ca_client import DecryptedProvisionerKey, decrypt_provisioner_key

logger = logging.getLogger(__name__)

ROLE_TO_PROVISIONER: dict[str, str] = {
    "ENDPOINT": "mirage-endpoint",
    "SPIDER": "mirage-spider",
    "ENV_CONTROLLER": "mirage-env-controller",
    "BROKER_CLIENT": "mirage-broker-client",
    "INTERNAL_CONTROL": "mirage-internal-control",
}

ROLE_TO_PROFILE: dict[str, str] = {
    "ENDPOINT": "MirageEndpoint",
    "SPIDER": "MirageSpider",
    "ENV_CONTROLLER": "MirageEnvironmentController",
    "BROKER_CLIENT": "BrokerClient",
    "INTERNAL_CONTROL": "InternalControl",
}

# docs/runbooks/secrets.md's mirage/<environment>/step-ca schema, verbatim.
REQUIRED_STEP_CA_SECRET_FIELDS = (
    "ca_url",
    "root_fingerprint",
    "password",
    "mirage_endpoint_encrypted_jwk",
    "mirage_endpoint_public_jwk",
    "mirage_spider_encrypted_jwk",
    "mirage_spider_public_jwk",
    "mirage_env_controller_encrypted_jwk",
    "mirage_env_controller_public_jwk",
    "mirage_broker_client_encrypted_jwk",
    "mirage_broker_client_public_jwk",
    "mirage_internal_control_encrypted_jwk",
    "mirage_internal_control_public_jwk",
)

DEFAULT_REFRESH_INTERVAL_SECONDS = 300.0


class SecretRetrievalError(Exception):
    """Base for every typed secret-loading failure. Messages here name
    fields and error codes only — never a secret VALUE (docs/runbooks/secrets.md
    rule 4: secrets are never written to logs or exceptions that might be
    logged)."""


class SecretAccessDeniedError(SecretRetrievalError):
    """IAM denied access to the secret — wrong role, missing policy, wrong
    account/region. Distinct from the secret simply not existing, so an
    operator can tell "fix my IAM policy" apart from "fix my secret name"."""


class SecretNotFoundError(SecretRetrievalError):
    """The named secret does not exist in this account/region."""


class SecretMalformedError(SecretRetrievalError):
    """The secret was retrieved but its value isn't valid JSON, isn't a JSON
    object, or is missing a required field. Lists missing field NAMES only."""


class ProvisionerSource(ABC):
    @abstractmethod
    def get_key(self, role: str) -> DecryptedProvisionerKey: ...

    @abstractmethod
    def provisioner_name(self, role: str) -> str: ...


@dataclass(frozen=True)
class DevFileProvisionerSource(ProvisionerSource):
    keys_dir: Path
    password: str = "mirage_dev_local_only"

    def get_key(self, role: str) -> DecryptedProvisionerKey:
        provisioner_name = ROLE_TO_PROVISIONER[role]
        pub = json.loads((self.keys_dir / f"{provisioner_name}.pub.json").read_text())
        priv_jwe = (self.keys_dir / f"{provisioner_name}.priv.json").read_text()
        return decrypt_provisioner_key(priv_jwe, pub, self.password)

    def provisioner_name(self, role: str) -> str:
        return ROLE_TO_PROVISIONER[role]


@dataclass
class SecretsManagerProvisionerSource(ProvisionerSource):
    """Reads `mirage/<environment>/step-ca` from AWS Secrets Manager.

    `client` is any object exposing boto3's `get_secret_value(SecretId=...)`
    — production callers pass a real `boto3.client("secretsmanager")`
    (constructed lazily if not supplied); tests pass a `botocore.stub.Stubber`-
    wrapped client, proving the retrieval/parsing/error-handling logic for
    real without ever calling AWS.

    Caches the last successfully parsed secret. A transient AWS-side failure
    (throttling, a momentary network blip, an IAM policy not yet propagated)
    falls back to that cached value with a logged warning rather than
    failing every single enrollment request — but only ever AFTER at least
    one successful fetch. The very first call, with nothing cached yet, always
    raises on failure: "startup fails when a mandatory secret is unavailable"
    is not negotiable just because a later refresh is allowed to be lenient.
    """

    secret_name: str
    client: Any = None
    refresh_interval_seconds: float = DEFAULT_REFRESH_INTERVAL_SECONDS
    _cached_secret: dict[str, Any] | None = field(default=None, init=False, repr=False)
    _cached_at: float = field(default=0.0, init=False, repr=False)

    def _boto_client(self) -> Any:
        if self.client is None:
            import boto3

            self.client = boto3.client("secretsmanager")
        return self.client

    def _fetch(self) -> dict[str, Any]:
        if self._cached_secret is not None and (time.monotonic() - self._cached_at) < self.refresh_interval_seconds:
            return self._cached_secret

        from botocore.exceptions import ClientError

        try:
            response = self._boto_client().get_secret_value(SecretId=self.secret_name)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if self._cached_secret is not None:
                logger.warning(
                    "step_ca_secret_fetch_failed_using_last_known_good",
                    extra={"secret_name": self.secret_name, "error_code": error_code},
                )
                return self._cached_secret
            if error_code in ("AccessDeniedException", "UnrecognizedClientException"):
                raise SecretAccessDeniedError(
                    f"access denied retrieving secret {self.secret_name!r} ({error_code})"
                ) from exc
            if error_code == "ResourceNotFoundException":
                raise SecretNotFoundError(f"secret {self.secret_name!r} does not exist") from exc
            raise SecretRetrievalError(
                f"failed to retrieve secret {self.secret_name!r} ({error_code})"
            ) from exc

        raw = response.get("SecretString")
        if raw is None:
            raise SecretMalformedError(f"secret {self.secret_name!r} has no SecretString value")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SecretMalformedError(f"secret {self.secret_name!r} is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise SecretMalformedError(f"secret {self.secret_name!r} must be a JSON object")
        missing = [name for name in REQUIRED_STEP_CA_SECRET_FIELDS if name not in parsed]
        if missing:
            raise SecretMalformedError(
                f"secret {self.secret_name!r} is missing required fields: {missing}"
            )

        self._cached_secret = parsed
        self._cached_at = time.monotonic()
        return parsed

    def get_key(self, role: str) -> DecryptedProvisionerKey:
        secret = self._fetch()
        key_prefix = ROLE_TO_PROVISIONER[role].replace("-", "_")
        public_jwk = secret[f"{key_prefix}_public_jwk"]
        encrypted_jwk = secret[f"{key_prefix}_encrypted_jwk"]
        return decrypt_provisioner_key(encrypted_jwk, public_jwk, secret["password"])

    def provisioner_name(self, role: str) -> str:
        return ROLE_TO_PROVISIONER[role]

    def invalidate(self) -> None:
        """Forces the next get_key() call to fetch fresh rather than reuse a
        cached value — call after a confirmed rotation instead of waiting
        out refresh_interval_seconds."""
        self._cached_secret = None
        self._cached_at = 0.0


def build_provisioner_source(
    environment: str,
    *,
    keys_dir: Path | None = None,
    secret_name: str | None = None,
    client: Any = None,
) -> ProvisionerSource:
    """The one place that decides DevFileProvisionerSource vs.
    SecretsManagerProvisionerSource — production can never silently fall
    back to the development file provider just because `keys_dir` happens
    to be set (e.g. a stale environment variable left over from copying a
    dev `.env`)."""
    if environment == "production":
        if not secret_name:
            raise ValueError(
                "production environment requires secret_name for "
                "SecretsManagerProvisionerSource — refusing to fall back to "
                "DevFileProvisionerSource"
            )
        return SecretsManagerProvisionerSource(secret_name=secret_name, client=client)
    if secret_name:
        return SecretsManagerProvisionerSource(secret_name=secret_name, client=client)
    if keys_dir is None:
        raise ValueError("non-production environment requires either keys_dir or secret_name")
    return DevFileProvisionerSource(keys_dir=keys_dir)
