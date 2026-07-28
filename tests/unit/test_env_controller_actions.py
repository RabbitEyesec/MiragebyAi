"""Unit tests for the Controller's structured-action executor
(mirage_env_controller.actions) — pure Python, no Docker, no network, no
Windows. Exercises real filesystem mutation + rollback + restricted-path
policy enforcement against a real tmp_path tree standing in for the
sandbox's approved mutation roots.
"""
from __future__ import annotations

import base64
import time

import pytest
from mirage_env_controller.actions import (
    ExecutorContext,
    RestrictedPathError,
    UnknownActionTypeError,
    execute_action,
)
from mirage_env_controller.journal import ActionJournal

pytestmark = pytest.mark.unit


@pytest.fixture
def ctx(tmp_path):
    allowed_root = tmp_path / "DecoyContent"
    allowed_root.mkdir()
    programdata = tmp_path / "ProgramData"
    programdata.mkdir()
    journal = ActionJournal(programdata / "Journal" / "journal.db")
    yield ExecutorContext(allowed_roots=(allowed_root,), programdata=programdata, journal=journal)
    journal.close()


def _run(ctx, action_type, params, action_id="01ARZ3NDEKTSV4RRFFQ69G5FAV"):
    return execute_action(action_type, params, ctx=ctx, action_id=action_id, recorded_at="2026-07-25T00:00:00.000Z")


def test_unknown_action_type_raises():
    ctx_stub = None
    with pytest.raises(UnknownActionTypeError):
        execute_action("DELETE_EVERYTHING", {}, ctx=ctx_stub, action_id="x", recorded_at="x")


def test_test_file_placement_writes_a_real_file(ctx):
    dest = ctx.allowed_roots[0] / "notes.txt"
    outcome = _run(ctx, "TEST_FILE_PLACEMENT", {"destination": str(dest), "content": "hello"})
    assert outcome.status == "SUCCESS"
    assert outcome.output_tag == "REAL_OS_OUTPUT"
    assert dest.read_text() == "hello"
    assert outcome.rollback_definition == {"kind": "delete_file", "path": str(dest)}


def test_test_file_placement_outside_allowed_roots_is_rejected(ctx, tmp_path):
    outside = tmp_path / "OUTSIDE" / "evil.txt"
    outcome = _run(ctx, "TEST_FILE_PLACEMENT", {"destination": str(outside)})
    assert outcome.status == "REJECTED"
    assert not outside.exists()
    assert "outside all approved mutation roots" in outcome.error_detail


def test_path_traversal_via_dotdot_is_rejected(ctx, tmp_path):
    (tmp_path / "OUTSIDE").mkdir()
    traversal = str(ctx.allowed_roots[0] / ".." / "OUTSIDE" / "evil.txt")
    outcome = _run(ctx, "TEST_FILE_PLACEMENT", {"destination": traversal})
    assert outcome.status == "REJECTED"
    assert not (tmp_path / "OUTSIDE" / "evil.txt").exists()


def test_place_artifact_requires_content_in_prompt1(ctx):
    dest = ctx.allowed_roots[0] / "artifact.bin"
    outcome = _run(ctx, "PLACE_ARTIFACT", {"artifact_id": "art-1", "destination": str(dest), "visible_metadata": {}})
    assert outcome.status == "FAILED"
    assert "content_b64" in outcome.error_detail
    assert not dest.exists()


def test_place_artifact_verifies_expected_hash_and_rejects_mismatch(ctx):
    dest = ctx.allowed_roots[0] / "artifact.bin"
    content = base64.b64encode(b"decoy-bytes").decode()
    outcome = _run(ctx, "PLACE_ARTIFACT", {
        "artifact_id": "art-1", "destination": str(dest), "content_b64": content,
        "expected_hash": "0" * 64, "visible_metadata": {},
    })
    assert outcome.status == "FAILED"
    assert "does not match" in outcome.error_detail
    assert not dest.exists()


def test_place_artifact_succeeds_with_correct_hash_and_can_be_rolled_back(ctx):
    import hashlib

    dest = ctx.allowed_roots[0] / "artifact.bin"
    raw = b"decoy-bytes"
    content = base64.b64encode(raw).decode()
    place_outcome = _run(ctx, "PLACE_ARTIFACT", {
        "artifact_id": "art-1", "destination": str(dest), "content_b64": content,
        "expected_hash": hashlib.sha256(raw).hexdigest(),
    }, action_id="ACTION0000000000000000001")
    assert place_outcome.status == "SUCCESS"
    assert place_outcome.output_tag == "REAL_OS_OUTPUT"
    assert dest.read_bytes() == raw

    rollback_outcome = _run(ctx, "ROLLBACK_ACTION", {"target_action_id": "ACTION0000000000000000001"}, action_id="ACTION0000000000000000002")
    assert rollback_outcome.status == "SUCCESS"
    assert not dest.exists()
    assert ctx.journal.get("ACTION0000000000000000001")["status"] == "ROLLED_BACK"


def test_rollback_of_unknown_action_id_is_rejected(ctx):
    outcome = _run(ctx, "ROLLBACK_ACTION", {"target_action_id": "NOPE0000000000000000000001"})
    assert outcome.status == "REJECTED"


def test_move_artifact_moves_a_real_file_and_rolls_back(ctx):
    source = ctx.allowed_roots[0] / "src.txt"
    source.write_text("payload")
    destination = ctx.allowed_roots[0] / "dst.txt"
    outcome = _run(ctx, "MOVE_ARTIFACT", {"artifact_id": "a1", "source": str(source), "destination": str(destination)},
                    action_id="ACTION0000000000000000003")
    assert outcome.status == "SUCCESS"
    assert not source.exists()
    assert destination.read_text() == "payload"

    rollback = _run(ctx, "ROLLBACK_ACTION", {"target_action_id": "ACTION0000000000000000003"}, action_id="ACTION0000000000000000004")
    assert rollback.status == "SUCCESS"
    assert source.read_text() == "payload"
    assert not destination.exists()


def test_create_decoy_directory_and_rollback(ctx):
    target = ctx.allowed_roots[0] / "Documents"
    outcome = _run(ctx, "CREATE_DECOY_DIRECTORY", {"path": str(target), "metadata_profile": {"owner": "j.smith"}},
                    action_id="ACTION0000000000000000005")
    assert outcome.status == "SUCCESS"
    assert target.is_dir()

    rollback = _run(ctx, "ROLLBACK_ACTION", {"target_action_id": "ACTION0000000000000000005"}, action_id="ACTION0000000000000000006")
    assert rollback.status == "SUCCESS"
    assert not target.exists()


def test_change_visible_metadata_updates_and_restores_mtime(ctx):
    target = ctx.allowed_roots[0] / "file.txt"
    target.write_text("x")
    original_mtime = target.stat().st_mtime
    new_mtime = original_mtime - 86400 * 30  # 30 days in the past

    outcome = _run(ctx, "CHANGE_VISIBLE_METADATA", {
        "target": str(target), "approved_fields": {"modified_time": new_mtime},
        "prior_state": {"modified_time": original_mtime},
    }, action_id="ACTION0000000000000000007")
    assert outcome.status == "SUCCESS"
    assert abs(target.stat().st_mtime - new_mtime) < 1.0

    rollback = _run(ctx, "ROLLBACK_ACTION", {"target_action_id": "ACTION0000000000000000007"}, action_id="ACTION0000000000000000008")
    assert rollback.status == "SUCCESS"
    assert abs(target.stat().st_mtime - original_mtime) < 1.0


def test_display_message_requires_a_valid_caller_supplied_output_tag(ctx):
    rejected = _run(ctx, "DISPLAY_MESSAGE", {"surface": "desktop_notification", "content": "hi", "output_tag": "REAL_OS_OUTPUT"})
    assert rejected.status == "FAILED"

    accepted = _run(ctx, "DISPLAY_MESSAGE", {"surface": "desktop_notification", "content": "hi", "output_tag": "AI_GENERATED_INTERACTION"})
    assert accepted.status == "SUCCESS"
    assert accepted.output_tag == "AI_GENERATED_INTERACTION"
    log = (ctx.allowed_roots[0] / "_messages.log").read_text()
    assert "desktop_notification" in log


def test_enable_and_disable_decoy_service_are_tagged_decoy_service_output(ctx):
    enable_outcome = _run(ctx, "ENABLE_DECOY_SERVICE", {"service_id": "decoy-print-spooler", "config_profile": "iis-10"})
    assert enable_outcome.status == "SUCCESS"
    assert enable_outcome.output_tag == "DECOY_SERVICE_OUTPUT"
    marker = ctx.allowed_roots[0] / "_decoy_services" / "decoy-print-spooler.enabled"
    assert marker.exists()

    disable_outcome = _run(ctx, "DISABLE_DECOY_SERVICE", {"service_id": "decoy-print-spooler"})
    assert disable_outcome.status == "SUCCESS"
    assert disable_outcome.output_tag == "DECOY_SERVICE_OUTPUT"
    assert not marker.exists()


def test_decoy_service_action_rejects_an_unregistered_service_id(ctx):
    """Priority 8: only explicitly approved, registered service identifiers
    may ever be targeted — never an arbitrary caller-supplied name."""
    outcome = _run(ctx, "ENABLE_DECOY_SERVICE", {"service_id": "not-a-registered-service"})
    assert outcome.status == "REJECTED"
    assert "not an approved decoy service" in outcome.error_detail
    marker = ctx.allowed_roots[0] / "_decoy_services" / "not-a-registered-service.enabled"
    assert not marker.exists()


def test_disable_decoy_service_rolls_back_to_re_enabled(ctx):
    """Rollback of a DISABLE_DECOY_SERVICE action must re-enable the
    service — proven through the same DecoyServiceController the original
    action used, not a separate/parallel mechanism."""
    marker = ctx.allowed_roots[0] / "_decoy_services" / "decoy-ftp.enabled"
    _run(ctx, "ENABLE_DECOY_SERVICE", {"service_id": "decoy-ftp"}, action_id="ACTION0000000000000000011")
    assert marker.exists()

    disable_outcome = _run(
        ctx, "DISABLE_DECOY_SERVICE", {"service_id": "decoy-ftp"}, action_id="ACTION0000000000000000012"
    )
    assert disable_outcome.status == "SUCCESS"
    assert not marker.exists()

    rollback = _run(
        ctx, "ROLLBACK_ACTION", {"target_action_id": "ACTION0000000000000000012"}, action_id="ACTION0000000000000000013"
    )
    assert rollback.status == "SUCCESS"
    assert marker.exists()  # rolling back the disable re-enabled the service


def test_change_visible_metadata_delegates_windows_fields_to_the_injected_controller(ctx, tmp_path):
    """CHANGE_VISIBLE_METADATA's Windows-specific attribute fields
    (hidden/read_only) must be delegated to ExecutorContext's
    metadata_attribute_controller — proven here with a fake controller
    standing in for WindowsMetadataAttributeController, since pywin32 isn't
    available on this platform."""
    from dataclasses import replace

    from mirage_env_controller.actions import MetadataAttributeController

    calls = []

    class FakeAttributeController(MetadataAttributeController):
        def apply(self, path, fields):
            calls.append((path, dict(fields)))
            return {"hidden": False}

    target = ctx.allowed_roots[0] / "decoy.txt"
    target.write_text("x")
    windows_ctx = replace(ctx, metadata_attribute_controller=FakeAttributeController())

    outcome = execute_action(
        "CHANGE_VISIBLE_METADATA",
        {
            "target": str(target),
            "approved_fields": {"hidden": True, "modified_time": time.time()},
            "prior_state": {"hidden": False},
        },
        ctx=windows_ctx,
        action_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        recorded_at="2026-07-25T00:00:00.000Z",
    )
    assert outcome.status == "SUCCESS"
    assert len(calls) == 1
    assert calls[0][0] == target
    assert calls[0][1]["hidden"] is True


def test_request_snapshot_produces_a_real_tar_archive(ctx):
    (ctx.allowed_roots[0] / "somefile.txt").write_text("content")
    outcome = _run(ctx, "REQUEST_SNAPSHOT", {"reason": "pre-engagement baseline", "retention_class": "standard"})
    assert outcome.status == "SUCCESS"
    snapshot_path = outcome.rollback_definition["path"]
    import tarfile

    assert tarfile.is_tarfile(snapshot_path)


def test_conclude_session_writes_marker(ctx):
    outcome = _run(ctx, "CONCLUDE_SESSION", {"reason": "case moved to CONCLUDING"})
    assert outcome.status == "SUCCESS"
    assert (ctx.programdata / "session_concluded.json").exists()


def test_soft_reset_wipes_and_restores_within_spec_threshold(ctx):
    """Spec: 'soft reset < 3 min.' Proves the LOCAL mechanism executes
    correctly and records its own real elapsed time; the equivalent AWS
    EC2 timing claim is LAB_VERIFICATION_REQUIRED (see KNOWN_ISSUES.md) —
    this assertion is about correctness and about THIS environment's real
    timing, not a substitute for that lab measurement."""
    decoy_file = ctx.allowed_roots[0] / "mutated_by_intruder.txt"
    decoy_file.write_text("attacker was here")
    start = time.monotonic()
    outcome = _run(ctx, "SOFT_RESET", {})
    elapsed = time.monotonic() - start
    assert outcome.status == "SUCCESS"
    assert not decoy_file.exists()
    assert ctx.allowed_roots[0].is_dir()
    assert elapsed < 180


def test_full_rebuild_wipes_deeper_including_session_marker(ctx):
    _run(ctx, "CONCLUDE_SESSION", {"reason": "test"})
    assert (ctx.programdata / "session_concluded.json").exists()
    (ctx.allowed_roots[0] / "leftover.txt").write_text("x")

    start = time.monotonic()
    outcome = _run(ctx, "FULL_REBUILD", {})
    elapsed = time.monotonic() - start
    assert outcome.status == "SUCCESS"
    assert not (ctx.programdata / "session_concluded.json").exists()
    assert not (ctx.allowed_roots[0] / "leftover.txt").exists()
    assert elapsed < 600


def test_clean_shutdown_writes_marker(ctx):
    outcome = _run(ctx, "CLEAN_SHUTDOWN", {"reason": "case exported"})
    assert outcome.status == "SUCCESS"
    assert (ctx.programdata / "shutdown_requested.json").exists()


def test_test_metadata_update_and_rollback(ctx):
    target = ctx.allowed_roots[0] / "f.txt"
    target.write_text("x")
    original_mtime = target.stat().st_mtime
    new_mtime = original_mtime - 3600

    outcome = _run(ctx, "TEST_METADATA_UPDATE", {"target": str(target), "modified_time": new_mtime}, action_id="ACTION0000000000000000009")
    assert outcome.status == "SUCCESS"
    assert abs(target.stat().st_mtime - new_mtime) < 1.0

    rollback = _run(ctx, "ROLLBACK_ACTION", {"target_action_id": "ACTION0000000000000000009"}, action_id="ACTION0000000000000000010")
    assert rollback.status == "SUCCESS"
    assert abs(target.stat().st_mtime - original_mtime) < 1.0


def test_move_artifact_with_missing_source_fails_not_silently(ctx):
    outcome = _run(ctx, "MOVE_ARTIFACT", {
        "artifact_id": "a1", "source": str(ctx.allowed_roots[0] / "missing.txt"),
        "destination": str(ctx.allowed_roots[0] / "dst.txt"),
    })
    assert outcome.status == "FAILED"


def test_restricted_path_error_is_a_subclass_worth_catching():
    assert issubclass(RestrictedPathError, Exception)
