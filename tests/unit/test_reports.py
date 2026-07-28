from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mirage_common.evidence_export import LocalDevelopmentSigner
from mirage_common.reports import (
    CLASSIFICATIONS,
    REPORT_SECTIONS,
    build_report_model,
    create_report_artifacts,
    create_report_package,
    redact_text,
    report_model_json,
    verify_report_package,
)
from mirage_contracts.envelope import canonical_json_bytes

CASE_ID = "01J00000000000000000000000"
REPORT_ID = "01J00000000000000000000001"
EXPORT_ID = "01J00000000000000000000002"
EVIDENCE_ID = "01J00000000000000000000003"
EVENT_ID = "01J00000000000000000000004"


@pytest.fixture(scope="module")
def signer() -> LocalDevelopmentSigner:
    return LocalDevelopmentSigner(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )


def _data(*, timeline_size: int = 1, malicious: bool = False) -> dict:
    text = (
        "<script>alert('x')</script> password=super-secret"
        if malicious
        else "Observed an interactive shell"
    )
    return {
        "case": {
            "case_id": CASE_ID,
            "state": "ENGAGING",
            "version": 7,
            "severity": "HIGH",
            "owner": "analyst",
        },
        "sessions": [
            {
                "session_id": "01J00000000000000000000005",
                "protocol": "SSH",
                "status": "ACTIVE",
                "created_at": "2026-07-26T10:00:00Z",
            }
        ],
        "timeline": [
            {
                "item_id": f"timeline-{index:05d}",
                "event_time": f"2026-07-26T10:{index // 60:02d}:{index % 60:02d}Z",
                "label": text,
                "description": text,
                "source_event_ids": [EVENT_ID],
                "evidence_references": [EVIDENCE_ID],
                "source_id": "spider",
                "source_sequence": index + 1,
            }
            for index in range(timeline_size)
        ],
        "evidence": [
            {
                "evidence_id": EVIDENCE_ID,
                "evidence_type": "LOG",
                "source_id": "spider",
                "source_sequence": 1,
                "related_event_ids": [EVENT_ID],
                "acquisition_time": "2026-07-26T10:00:00Z",
                "sha256": "a" * 64,
                "s3_version_id": "version-1",
                "verification_status": "VERIFIED",
            }
        ],
        "ai": [
            {
                "proposal_id": "01J00000000000000000000006",
                "rationale": "Likely reconnaissance",
                "action_type": "PLACE_ARTIFACT",
                "confidence": 0.73,
                "supporting_event_ids": [EVENT_ID],
                "contradictory_event_ids": ["01J00000000000000000000007"],
                "uncertainty": "Intent cannot be directly observed.",
                "provider": "fake-provider",
                "model": "fake-model",
            }
        ],
        "policy": [
            {
                "decision_id": "01J00000000000000000000008",
                "decision": "ALLOW",
                "reason_codes": ["APPROVED_INERT"],
            }
        ],
        "directives": [],
        "messages": [],
        "gaps": [],
    }


def _model(**data_options):
    return build_report_model(
        _data(**data_options),
        report_id=REPORT_ID,
        export_id=EXPORT_ID,
        created_by="analyst",
        created_at="2026-07-26T10:10:00Z",
        build_hash="b" * 40,
        source_projection_version=7,
        evidence_manifest_id="01J00000000000000000000009",
    )


def _evidence_manifest() -> dict:
    return {
        "manifest_version": "1.0",
        "evidence_objects": [
            {
                "evidence_id": EVIDENCE_ID,
                "evidence_type": "LOG",
                "source_id": "spider",
                "source_sequence": 1,
                "acquisition_time": "2026-07-26T10:00:00Z",
                "sha256": "a" * 64,
                "s3_version_id": "version-1",
            }
        ],
    }


def _rewrite(package: bytes, *, remove: str | None = None, add: str | None = None) -> bytes:
    output = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(package), "r") as source,
        zipfile.ZipFile(output, "w") as target,
    ):
        for name in source.namelist():
            if name != remove:
                target.writestr(name, source.read(name))
        if add:
            target.writestr(add, b"unexpected")
    return output.getvalue()


def test_all_sections_and_category_separation() -> None:
    model = _model()
    assert tuple(section.title for section in model.sections) == REPORT_SECTIONS
    statements = [item for section in model.sections for item in section.statements]
    assert statements
    assert all(item.category in CLASSIFICATIONS for item in statements)
    assert {item.category for item in statements} >= {
        "OBSERVED_FACT",
        "DETERMINISTIC_CORRELATION",
        "AI_INFERENCE",
    }


def test_fact_and_inference_provenance_are_explicit() -> None:
    model = _model()
    timeline = next(section for section in model.sections if section.title == "Investigation timeline")
    assert timeline.statements[0].provenance.event_ids == (EVENT_ID,)
    assert timeline.statements[0].provenance.evidence_ids == (EVIDENCE_ID,)
    inference = next(section for section in model.sections if section.title == "AI proposals")
    assert inference.statements[0].confidence == 0.73
    assert inference.statements[0].contradictory_event_ids
    assert inference.statements[0].uncertainty
    assert inference.statements[0].provider == "fake-provider"


def test_json_is_deterministic_and_utc_metadata_is_retained() -> None:
    first = report_model_json(_model())
    second = report_model_json(_model())
    assert first == second
    parsed = json.loads(first)
    assert parsed["metadata"]["creation_time"].endswith("Z")


def test_pdf_docx_and_json_are_created() -> None:
    artifacts = create_report_artifacts(_model())
    assert artifacts.pdf.startswith(b"%PDF-")
    assert artifacts.docx.startswith(b"PK")
    assert json.loads(artifacts.case_json)["metadata"]["report_id"] == REPORT_ID
    with zipfile.ZipFile(io.BytesIO(artifacts.docx)) as archive:
        document_xml = archive.read("word/document.xml").decode()
    assert "OBSERVED_FACT" in document_xml
    assert "AI_INFERENCE" in document_xml


def test_long_timeline_long_hash_unicode_and_redaction() -> None:
    data = _data(timeline_size=800, malicious=True)
    data["case"]["owner"] = "分析者–é"
    data["evidence"][0]["sha256"] = "f" * 64
    model = build_report_model(
        data,
        report_id=REPORT_ID,
        export_id=EXPORT_ID,
        created_by="分析者–é",
        created_at=datetime(2026, 7, 26, 10, tzinfo=UTC).isoformat(),
        build_hash="c" * 64,
        source_projection_version=800,
        evidence_manifest_id="manifest",
    )
    assert b"[REDACTED]" in report_model_json(model)
    artifacts = create_report_artifacts(model)
    assert len(artifacts.pdf) > 10_000
    assert len(artifacts.docx) > 10_000


def test_malicious_html_is_data_not_markup() -> None:
    value = redact_text("<script>alert(1)</script> token=do-not-leak")
    assert "<script>" in value
    assert "do-not-leak" not in value
    assert "[REDACTED]" in value


def test_metadata_only_package_independently_verifies(
    signer: LocalDevelopmentSigner,
) -> None:
    package = create_report_package(
        create_report_artifacts(_model()),
        signer=signer,
        export_mode="METADATA_ONLY",
        evidence_manifest=_evidence_manifest(),
    )
    # An externally-trusted key must be supplied — the package's own embedded
    # key is never trusted on its own.
    report = verify_report_package(package.package, public_key_pem=signer.public_key_pem())
    assert report.valid, report.errors
    assert report.manifest_sha256 == package.manifest_sha256
    assert not verify_report_package(package.package).valid


def test_complete_case_requires_and_verifies_evidence(
    signer: LocalDevelopmentSigner,
) -> None:
    package = create_report_package(
        create_report_artifacts(_model()),
        signer=signer,
        export_mode="COMPLETE_CASE",
        evidence_manifest=_evidence_manifest(),
        evidence_objects={EVIDENCE_ID: b"evidence bytes"},
    )
    assert verify_report_package(package.package, public_key_pem=signer.public_key_pem()).valid


def test_missing_evidence_is_blocked_for_complete_case(
    signer: LocalDevelopmentSigner,
) -> None:
    with pytest.raises(ValueError, match="every manifest evidence"):
        create_report_package(
            create_report_artifacts(_model()),
            signer=signer,
            export_mode="COMPLETE_CASE",
            evidence_manifest=_evidence_manifest(),
        )


@pytest.mark.parametrize(
    ("remove", "expected"),
    [
        ("report.pdf", "missing file: report.pdf"),
        ("manifest.sig", "signature or verification key missing"),
    ],
)
def test_missing_file_and_signature_are_detected(
    signer: LocalDevelopmentSigner, remove: str, expected: str
) -> None:
    package = create_report_package(
        create_report_artifacts(_model()),
        signer=signer,
        export_mode="METADATA_ONLY",
        evidence_manifest=_evidence_manifest(),
    )
    result = verify_report_package(_rewrite(package.package, remove=remove))
    assert not result.valid
    assert any(expected in error for error in result.errors)


def test_unexpected_file_is_detected(signer: LocalDevelopmentSigner) -> None:
    package = create_report_package(
        create_report_artifacts(_model()),
        signer=signer,
        export_mode="METADATA_ONLY",
        evidence_manifest=_evidence_manifest(),
    )
    result = verify_report_package(_rewrite(package.package, add="surprise.exe"))
    assert not result.valid
    assert "unexpected file: surprise.exe" in result.errors


def test_modified_report_is_detected(signer: LocalDevelopmentSigner) -> None:
    package = create_report_package(
        create_report_artifacts(_model()),
        signer=signer,
        export_mode="METADATA_ONLY",
        evidence_manifest=_evidence_manifest(),
    )
    output = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(package.package), "r") as source,
        zipfile.ZipFile(output, "w") as target,
    ):
        for name in source.namelist():
            target.writestr(name, b"modified" if name == "report.pdf" else source.read(name))
    result = verify_report_package(output.getvalue())
    assert not result.valid
    assert "hash mismatch: report.pdf" in result.errors


def test_evidence_manifest_mismatch_is_detected(
    signer: LocalDevelopmentSigner,
) -> None:
    manifest = _evidence_manifest()
    package = create_report_package(
        create_report_artifacts(_model()),
        signer=signer,
        export_mode="METADATA_ONLY",
        evidence_manifest=manifest,
    )
    result = verify_report_package(
        package.package,
        expected_evidence_manifest_sha256="0" * 64,
    )
    assert not result.valid
    assert "evidence-manifest mismatch" in result.errors
    assert canonical_json_bytes(manifest)
