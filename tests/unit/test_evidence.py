from __future__ import annotations

import hashlib
import io

import pytest

from mirage_common.evidence import (
    EvidenceTooLargeError,
    evidence_s3_key,
    sanitise_filename,
    stream_hash,
)
from mirage_contracts.ulid import generate_ulid


def test_stream_hashes_without_changing_bytes() -> None:
    data = b"a" * (2 * 1024 * 1024 + 17)
    spool, size, digest = stream_hash(io.BytesIO(data), max_bytes=len(data))
    try:
        assert size == len(data)
        assert spool.read() == data
        assert digest == hashlib.sha256(data).hexdigest()
    finally:
        spool.close()


def test_stream_hash_enforces_actual_size_not_content_length() -> None:
    with pytest.raises(EvidenceTooLargeError):
        stream_hash(io.BytesIO(b"12345"), max_bytes=4)


@pytest.mark.parametrize(
    ("unsafe", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        (r"C:\Windows\system32\cmd.exe", "cmd.exe"),
        ("..", "unnamed"),
        ("a b?.txt", "a_b_.txt"),
    ],
)
def test_filename_sanitisation(unsafe: str, expected: str) -> None:
    assert sanitise_filename(unsafe) == expected


def test_s3_key_is_deterministic_and_confined() -> None:
    case_id, evidence_id = generate_ulid(), generate_ulid()
    key = evidence_s3_key(
        case_id=case_id,
        category="logs",
        evidence_id=evidence_id,
        original_filename="../../system.log",
    )
    assert key == f"cases/{case_id}/logs/{evidence_id}-system.log"
    assert ".." not in key


def test_evidence_id_prevents_key_collision() -> None:
    case_id = generate_ulid()
    first = evidence_s3_key(
        case_id=case_id,
        category="raw",
        evidence_id=generate_ulid(),
        original_filename="same.bin",
    )
    second = evidence_s3_key(
        case_id=case_id,
        category="raw",
        evidence_id=generate_ulid(),
        original_filename="same.bin",
    )
    assert first != second
