"""Unit tests for SecretsManagerProvisionerSource (Priority 4) using
botocore.stub.Stubber — proves the retrieval/parsing/caching/error-handling
logic for real without an AWS account. The only thing this cannot prove is
that a real AWS Secrets Manager call succeeds against a real account; that
remains AWS_VERIFICATION_REQUIRED (see docs/runbooks/step-ca-secrets.md).
"""
from __future__ import annotations

import json

import boto3
import pytest
from botocore.stub import ANY, Stubber
from mirage_agent_ingestion.provisioners import (
    REQUIRED_STEP_CA_SECRET_FIELDS,
    DevFileProvisionerSource,
    SecretAccessDeniedError,
    SecretMalformedError,
    SecretNotFoundError,
    SecretRetrievalError,
    SecretsManagerProvisionerSource,
    build_provisioner_source,
)

pytestmark = pytest.mark.unit


def _valid_secret_payload() -> dict:
    payload = {name: "x" for name in REQUIRED_STEP_CA_SECRET_FIELDS}
    payload["root_fingerprint"] = "a" * 64
    payload["mirage_endpoint_public_jwk"] = {"kid": "endpoint-kid"}
    payload["mirage_spider_public_jwk"] = {"kid": "spider-kid"}
    payload["mirage_env_controller_public_jwk"] = {"kid": "controller-kid"}
    payload["mirage_broker_client_public_jwk"] = {"kid": "broker-kid"}
    payload["mirage_internal_control_public_jwk"] = {"kid": "internal-kid"}
    return payload


def _stubbed_source(**kwargs) -> tuple[SecretsManagerProvisionerSource, Stubber]:
    client = boto3.client("secretsmanager", region_name="us-east-1")
    stubber = Stubber(client)
    source = SecretsManagerProvisionerSource(secret_name="mirage/test/step-ca", client=client, **kwargs)
    return source, stubber


def test_fetches_and_caches_a_valid_secret():
    source, stubber = _stubbed_source()
    payload = _valid_secret_payload()
    stubber.add_response(
        "get_secret_value",
        {"SecretString": json.dumps(payload)},
        {"SecretId": "mirage/test/step-ca"},
    )
    with stubber:
        fetched = source._fetch()
    assert fetched == payload
    # Second call within the refresh interval must NOT hit AWS again — no
    # additional stubbed response was registered, so a second real call
    # would raise inside the `with stubber` block; here it's called outside
    # deliberately to prove the cache path needs no stub at all.
    assert source._fetch() == payload


def test_get_key_decrypts_using_the_role_specific_jwk(monkeypatch: pytest.MonkeyPatch):
    source, stubber = _stubbed_source()
    payload = _valid_secret_payload()
    stubber.add_response(
        "get_secret_value", {"SecretString": json.dumps(payload)}, {"SecretId": "mirage/test/step-ca"}
    )
    calls = []

    def fake_decrypt(encrypted_jwk_json, public_jwk, password):
        calls.append((encrypted_jwk_json, public_jwk, password))
        from mirage_common.step_ca_client import DecryptedProvisionerKey

        return DecryptedProvisionerKey(private_key_pem=b"pem", public_jwk=public_jwk, kid=public_jwk["kid"])

    monkeypatch.setattr("mirage_agent_ingestion.provisioners.decrypt_provisioner_key", fake_decrypt)
    with stubber:
        result = source.get_key("SPIDER")
    assert result.kid == "spider-kid"
    assert calls == [(payload["mirage_spider_encrypted_jwk"], {"kid": "spider-kid"}, payload["password"])]


def test_missing_secret_string_is_malformed():
    source, stubber = _stubbed_source()
    stubber.add_response("get_secret_value", {"Name": "mirage/test/step-ca"}, {"SecretId": ANY})
    with stubber, pytest.raises(SecretMalformedError, match="no SecretString"):
        source._fetch()


def test_invalid_json_is_malformed():
    source, stubber = _stubbed_source()
    stubber.add_response("get_secret_value", {"SecretString": "not json{"}, {"SecretId": ANY})
    with stubber, pytest.raises(SecretMalformedError, match="not valid JSON"):
        source._fetch()


def test_missing_required_fields_are_named_not_silently_accepted():
    source, stubber = _stubbed_source()
    incomplete = {"ca_url": "https://step-ca", "password": "x"}
    stubber.add_response("get_secret_value", {"SecretString": json.dumps(incomplete)}, {"SecretId": ANY})
    with stubber, pytest.raises(SecretMalformedError) as exc_info:
        source._fetch()
    assert "root_fingerprint" in str(exc_info.value)
    assert "x" not in str(exc_info.value).replace("root_fingerprint", "")  # no leaked value, only field names


def test_access_denied_with_no_cache_raises_typed_error():
    source, stubber = _stubbed_source()
    stubber.add_client_error(
        "get_secret_value", service_error_code="AccessDeniedException", service_message="nope"
    )
    with stubber, pytest.raises(SecretAccessDeniedError):
        source._fetch()


def test_resource_not_found_with_no_cache_raises_typed_error():
    source, stubber = _stubbed_source()
    stubber.add_client_error("get_secret_value", service_error_code="ResourceNotFoundException")
    with stubber, pytest.raises(SecretNotFoundError):
        source._fetch()


def test_other_aws_error_with_no_cache_raises_generic_typed_error():
    source, stubber = _stubbed_source()
    stubber.add_client_error("get_secret_value", service_error_code="InternalServiceErrorException")
    with stubber, pytest.raises(SecretRetrievalError):
        source._fetch()


def test_transient_failure_falls_back_to_last_known_good():
    """The core "refresh uses last-known-good value" requirement: a real
    fetch succeeds once, a later transient AWS error must not crash
    subsequent calls — it must transparently reuse the cached value."""
    source, stubber = _stubbed_source(refresh_interval_seconds=0.0)  # force every call to re-hit AWS
    payload = _valid_secret_payload()
    stubber.add_response(
        "get_secret_value", {"SecretString": json.dumps(payload)}, {"SecretId": "mirage/test/step-ca"}
    )
    stubber.add_client_error("get_secret_value", service_error_code="ThrottlingException")
    with stubber:
        first = source._fetch()
        second = source._fetch()  # AWS throttled this one — must fall back, not raise
    assert first == payload
    assert second == payload


def test_invalidate_forces_a_fresh_fetch_even_within_the_refresh_interval():
    source, stubber = _stubbed_source(refresh_interval_seconds=300.0)
    payload = _valid_secret_payload()
    rotated = {**payload, "password": "rotated-password"}
    stubber.add_response(
        "get_secret_value", {"SecretString": json.dumps(payload)}, {"SecretId": "mirage/test/step-ca"}
    )
    stubber.add_response(
        "get_secret_value", {"SecretString": json.dumps(rotated)}, {"SecretId": "mirage/test/step-ca"}
    )
    with stubber:
        first = source._fetch()
        source.invalidate()
        second = source._fetch()
    assert first["password"] == "x"
    assert second["password"] == "rotated-password"


# --- build_provisioner_source production guard -----------------------------


def test_production_without_secret_name_refuses_to_fall_back_to_dev_file(tmp_path):
    with pytest.raises(ValueError, match="production"):
        build_provisioner_source("production", keys_dir=tmp_path)


def test_production_with_secret_name_uses_secrets_manager():
    source = build_provisioner_source("production", secret_name="mirage/production/step-ca")
    assert isinstance(source, SecretsManagerProvisionerSource)
    assert source.secret_name == "mirage/production/step-ca"


def test_development_with_only_keys_dir_uses_dev_file_source(tmp_path):
    source = build_provisioner_source("development", keys_dir=tmp_path)
    assert isinstance(source, DevFileProvisionerSource)


def test_development_with_secret_name_can_still_use_secrets_manager():
    source = build_provisioner_source("development", secret_name="mirage/acceptance/step-ca")
    assert isinstance(source, SecretsManagerProvisionerSource)


def test_non_production_with_neither_argument_is_rejected():
    with pytest.raises(ValueError, match="keys_dir or secret_name"):
        build_provisioner_source("development")
