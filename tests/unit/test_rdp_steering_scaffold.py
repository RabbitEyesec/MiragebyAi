"""Static verification of the RDP steering engineering scaffold (Priority 5).

The plugin itself (infra/broker/rdp/src/*.cs) cannot be built or run in
this environment — no .NET SDK, no Windows host, no access to the real
Terminal Services Gateway Plugin COM type library (see
docs/architecture/rdp-steering.md for the honest accounting of exactly
which part is WINDOWS_VERIFICATION_REQUIRED and why). What CAN be verified
here, and is verified by this file:

- The plugin's own JSON config schema is valid Draft 2020-12 and its
  example config actually validates against it.
- The real, live request contract the plugin is specified to use
  (canonical RDP match_key, header names) is proven correct end to end
  against the actual running mirage-api /route endpoint by
  tests/integration/test_routing_api.py's RDP-protocol tests — this file
  cross-checks that those match_key/header conventions are exactly what
  the C# source (read as plain text, not compiled) declares, so the two
  can't silently drift apart.
- Every required project file exists and cross-references correctly (the
  test project references the main project; the fail_safe_target
  validation never allows "SANDBOX").
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

pytestmark = pytest.mark.unit

RDP_ROOT = Path(__file__).resolve().parents[2] / "infra" / "broker" / "rdp"


def test_config_schema_is_valid_draft_2020_12():
    schema = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.schema.json").read_text())
    Draft202012Validator.check_schema(schema)


def test_example_config_validates_against_the_schema():
    schema = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.schema.json").read_text())
    example = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.example.json").read_text())
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(example))
    assert not errors, [e.message for e in errors]


def test_schema_never_allows_sandbox_as_a_fail_safe_target():
    schema = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.schema.json").read_text())
    assert schema["properties"]["fail_safe_target"]["enum"] == ["ENDPOINT", "DENY"]


@pytest.mark.parametrize(
    "invalid_field,invalid_value",
    [("fail_safe_target", "SANDBOX"), ("timeout_ms", 50), ("timeout_ms", 20000)],
)
def test_schema_rejects_unsafe_or_out_of_range_values(invalid_field, invalid_value):
    schema = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.schema.json").read_text())
    example = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.example.json").read_text())
    example[invalid_field] = invalid_value
    validator = Draft202012Validator(schema)
    assert list(validator.iter_errors(example))


def test_csharp_source_uses_the_exact_match_key_format_the_live_route_endpoint_test_proves():
    """Cross-checks the C# source's match_key format string against the
    literal convention tests/integration/test_routing_api.py's RDP tests
    already prove correct against the real running /route endpoint — the
    two must never silently drift apart."""
    source = (RDP_ROOT / "src" / "MirageRouteDecisionClient.cs").read_text()
    assert 'RDP|{_config.GatewayListenerId}|{clientIp}|{principal}' in source

    live_contract_test = (
        Path(__file__).resolve().parents[2] / "tests" / "integration" / "test_routing_api.py"
    ).read_text()
    assert re.search(r'f"RDP\|rdgw-1\|[^"]+"', live_contract_test), (
        "expected an RDP-protocol match_key test in test_routing_api.py proving the real "
        "/route endpoint accepts this exact convention"
    )


def test_csharp_source_never_treats_a_fail_safe_outcome_as_sandbox():
    source = (RDP_ROOT / "src" / "MirageRouteDecisionClient.cs").read_text()
    # The fail-safe branch must only ever choose between Endpoint and Deny.
    fail_safe_block = source.split('catch (Exception exception)')[1]
    assert "RouteTarget.Sandbox" not in fail_safe_block


def test_csharp_source_sends_the_same_header_contract_the_ssh_broker_uses():
    source = (RDP_ROOT / "src" / "MirageRouteDecisionClient.cs").read_text()
    assert "X-Mirage-Client-Cert-Serial" in source
    assert "X-Mirage-Proxy-Auth" in source
    assert "protocol=RDP" in source


def test_config_never_allows_a_literal_secret_value_field():
    """The config schema must only ever reference an environment-variable
    NAME for the proxy shared secret, never a secret value field."""
    schema = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.schema.json").read_text())
    assert "proxy_shared_secret_env_var" in schema["properties"]
    assert "proxy_shared_secret" not in schema["properties"]
    example = json.loads((RDP_ROOT / "config" / "rdp-plugin-config.example.json").read_text())
    assert "proxy_shared_secret" not in example


@pytest.mark.parametrize(
    "relative_path",
    [
        "README.md",
        "config/rdp-plugin-config.schema.json",
        "config/rdp-plugin-config.example.json",
        "src/MirageRdpPlugin.csproj",
        "src/MirageRouteDecisionClient.cs",
        "src/MirageRdGatewayPlugin.cs",
        "src/MirageRdpPluginConfig.cs",
        "src/RouteDecisionResult.cs",
        "src/MirageDecisionLogger.cs",
        "tests/MirageRdpPlugin.Tests.csproj",
        "tests/MirageRouteDecisionClientTests.cs",
        "scripts/install-mirage-rdp-plugin.ps1",
        "scripts/uninstall-mirage-rdp-plugin.ps1",
    ],
)
def test_every_required_scaffold_file_exists(relative_path):
    assert (RDP_ROOT / relative_path).is_file(), f"missing {relative_path}"


def test_test_project_references_the_main_project():
    test_csproj = (RDP_ROOT / "tests" / "MirageRdpPlugin.Tests.csproj").read_text()
    assert "MirageRdpPlugin.csproj" in test_csproj


def test_install_script_rejects_sandbox_as_fail_safe_target():
    script = (RDP_ROOT / "scripts" / "install-mirage-rdp-plugin.ps1").read_text()
    assert '"ENDPOINT", "DENY"' in script
