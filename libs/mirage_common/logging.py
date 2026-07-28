"""Structured logging with mandatory secret redaction.

Referenced by docs/runbooks/secrets.md rule 4: "log formatters ... redact any
field named *password*, *secret*, *api_key*, *token* regardless of
[configuration]." Also redacts raw untrusted intruder content — never log an
UNTRUSTED_INTRUDER_OUTPUT-classified payload verbatim (security boundary).
"""
from __future__ import annotations

import logging
import re
from collections.abc import MutableMapping
from typing import Any

import structlog

_REDACT_KEY_RE = re.compile(r"(password|secret|api[_-]?key|token)", re.IGNORECASE)
REDACTED = "***REDACTED***"


def _redact_processor(
    logger: object, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    return {k: (REDACTED if _REDACT_KEY_RE.search(k) else v) for k, v in event_dict.items()}


def _truncate_untrusted_content(
    logger: object, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    if event_dict.get("classification") == "UNTRUSTED_INTRUDER_OUTPUT":
        for key in ("payload", "content", "message_body"):
            if key in event_dict:
                event_dict[key] = "<UNTRUSTED_INTRUDER_OUTPUT redacted from logs — see evidence store>"
    return event_dict


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _truncate_untrusted_content,
            _redact_processor,
            structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper(), logging.INFO)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
