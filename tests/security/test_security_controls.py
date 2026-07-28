from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_security_plan_covers_every_required_control() -> None:
    plan = json.loads((ROOT / "security/security-test-plan.json").read_text())
    assert len(plan["tests"]) == 31
    assert len(set(plan["tests"])) == len(plan["tests"])
    assert plan["boundary"] == "Controlled Mirage environments only"


def test_rbac_matrix_is_deny_by_default_and_object_bound() -> None:
    matrix = json.loads((ROOT / "security/rbac-matrix.json").read_text())
    assert matrix["default"] == "DENY"
    assert len(matrix["endpoints"]) >= 12
    assert all(item["roles"] for item in matrix["endpoints"])
    assert all(item["object_check"] for item in matrix["endpoints"])
    report_download = next(
        item for item in matrix["endpoints"] if item["path"].endswith("/download")
    )
    assert "single-use token" in report_download["object_check"]


def test_dashboard_bff_has_fixed_upstream_path_csrf_and_no_local_storage() -> None:
    proxy = (ROOT / "dashboard/app/api/mirage/[...path]/route.ts").read_text()
    session = (ROOT / "dashboard/lib/session.ts").read_text()
    dashboard_sources = "\n".join(
        path.read_text()
        for path in (ROOT / "dashboard").rglob("*.ts*")
        if "node_modules" not in path.parts and ".next" not in path.parts
    )
    assert "serverConfig().apiUrl" in proxy
    assert 'path.includes("..")' in proxy
    assert 'request.headers.get("origin")' in proxy
    assert 'request.headers.get("x-csrf-token")' in proxy
    assert "aes-256-gcm" in session
    assert "createRemoteJWKSet" in session
    assert "localStorage.setItem" not in dashboard_sources
    assert "dangerouslySetInnerHTML" not in dashboard_sources


def test_single_use_download_and_parameterised_sql_are_present() -> None:
    api = (ROOT / "services/mirage-api/mirage_api/prompt3.py").read_text()
    assert "download_token_used_at" in api
    assert "download token is invalid, expired, or already used" in api
    assert "hmac.compare_digest" in api
    assert "single_use" in api
    assert "WHERE r.case_id=%s AND r.report_id=%s" in api
    assert "f\"SELECT" not in api


def test_images_run_non_root_and_windows_tokens_are_not_process_arguments() -> None:
    dockerfiles = list((ROOT / "services").glob("*/Dockerfile")) + [
        ROOT / "dashboard/Dockerfile"
    ]
    assert all("USER " in path.read_text() for path in dockerfiles)
    bundle = (ROOT / "installers/endpoint/Bundle.wxs").read_text()
    assert "FleetEnrollmentToken" not in bundle
    assert "--enrollment-token=" not in bundle
    assert "--protected-input" in bundle
