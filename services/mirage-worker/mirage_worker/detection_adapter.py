"""mirage-worker's detection-into-cases adapter (Step 7): consumes
`investigation.detection.raised` via the same durable, dead-letter-aware
NATS consumer pattern every other Mirage consumer uses (Step 1b), and calls
`mirage_common.detection_correlation.correlate_detection` per message.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import psycopg
from nats.aio.msg import Msg

from mirage_common.detection_correlation import correlate_detection
from mirage_common.nats_client import DeadLetterAwareConsumer

logger = logging.getLogger("mirage.detection_adapter")

DETECTION_RAISED_SUBJECT = "investigation.detection.raised"
STREAM_NAME = "MIRAGE_LIFECYCLE"
DURABLE_NAME = "mirage-detection-adapter"


@dataclass
class DetectionAdapter:
    conn: psycopg.AsyncConnection
    consumer: DeadLetterAwareConsumer

    async def handle_message(self, msg: Msg) -> None:
        envelope = json.loads(msg.data)
        payload = envelope["payload"]
        try:
            result = await correlate_detection(
                self.conn,
                detection_event_id=envelope["event_id"],
                detector=payload["detector"],
                signature_id=payload["signature_id"],
                severity=payload["severity"],
                confidence=payload["confidence"],
                correlation_key=payload["correlation_key"],
                source_ref=payload["source_refs"][0] if payload["source_refs"] else "",
            )
        except Exception:
            await self.conn.rollback()
            raise
        await self.conn.commit()
        logger.info(
            "mirage.detection_adapter.processed",
            extra={"case_id": result.case_id, "created": result.created, "detection_event_id": envelope["event_id"]},
        )

    async def run_batch(self, *, batch_size: int = 10, timeout: float = 2.0) -> int:
        """Fetches and processes up to `batch_size` pending detections.
        Returns the number successfully processed (not retried/dead-lettered)."""
        msgs = await self.consumer.fetch(batch_size, timeout=timeout)
        processed = 0
        for msg in msgs:
            outcome = await self.consumer.process(msg, self.handle_message)
            if outcome == "processed":
                processed += 1
        return processed
