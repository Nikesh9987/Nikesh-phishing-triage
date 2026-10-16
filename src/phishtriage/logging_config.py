"""Logging configuration with built-in secret redaction.

Design notes:

* Only the ``phishtriage`` logger hierarchy is configured; the root logger and
  any host application (e.g. uvicorn) are left alone.
* Output goes to **stderr** so CLI JSON/table output on stdout stays clean and
  pipe-friendly.
* Every formatted line passes through a redactor that masks registered secret
  values plus common ``api_key=...`` / ``Authorization: ...`` patterns, so
  API keys cannot leak via exception messages or HTTP debug logs.
* :func:`configure_logging` is idempotent and safe to call repeatedly.
"""

import json
import logging
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import IO, Any, Literal

LOGGER_NAME = "phishtriage"
_HANDLER_TAG = "_phishtriage_handler"
_REDACTED = "***REDACTED***"

_PATTERN_REDACTIONS = (
    re.compile(
        r"(?i)\b(api[-_]?key|auth[-_]?key|x-apikey|key|token|secret|password)"
        r"(\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"',;&]+)"
    ),
    re.compile(r"(?i)\b(authorization)(\s*[\"']?\s*[:=]\s*[\"']?)((?:bearer|basic)\s+[^\s\"',;]+)"),
)

# Third-party libraries that log full request URLs / headers at INFO or DEBUG.
_NOISY_LOGGERS = ("httpx", "httpcore", "hpack", "asyncio", "multipart", "dns")


class Redactor:
    """Masks known secret values and common credential patterns in text."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        self._secrets: set[str] = set()
        self.add(secrets)

    def add(self, secrets: Iterable[str]) -> None:
        """Register additional secret values. Very short values are ignored."""
        for secret in secrets:
            if secret and len(secret) >= 4:
                self._secrets.add(secret)

    def redact(self, text: str) -> str:
        """Return ``text`` with secrets and credential-looking values masked."""
        # Longest first so a secret that contains another is fully masked.
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, _REDACTED)
        for pattern in _PATTERN_REDACTIONS:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", text)
        return text


class _RedactingTextFormatter(logging.Formatter):
    """Human-readable formatter that redacts the final rendered line."""

    def __init__(self, redactor: Redactor) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        return self._redactor.redact(super().format(record))


class _RedactingJsonFormatter(logging.Formatter):
    """Single-line JSON formatter (SIEM/log-shipper friendly) with redaction."""

    _RESERVED = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Include structured ``extra={...}`` fields supplied by callers.
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value
        try:
            line = json.dumps(payload, default=str, ensure_ascii=False)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            line = json.dumps({"level": record.levelname, "message": str(record.msg)})
        return self._redactor.redact(line)


# Shared redactor so secrets registered later (e.g. after settings load) apply
# to handlers that were installed earlier.
_redactor = Redactor()


def register_secrets(secrets: Iterable[str]) -> None:
    """Add secret values that must never appear in log output."""
    _redactor.add(secrets)


def configure_logging(
    level: str = "INFO",
    fmt: Literal["text", "json"] = "text",
    stream: IO[str] | None = None,
    secrets: Iterable[str] = (),
) -> logging.Logger:
    """Configure and return the ``phishtriage`` package logger.

    Args:
        level: Log level name (``DEBUG``, ``INFO``, ``WARNING`` ...). Unknown
            values fall back to ``INFO`` rather than raising.
        fmt: ``"text"`` for humans or ``"json"`` for log aggregation.
        stream: Output stream; defaults to ``sys.stderr``.
        secrets: Plaintext secret values to redact from all output.

    Returns:
        The configured package logger.
    """
    register_secrets(secrets)

    numeric_level = logging.getLevelName(str(level).upper())
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric_level)
    logger.propagate = False  # avoid duplicate lines via the root logger

    # Remove only handlers previously installed by this function (idempotency).
    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_TAG, False):
            logger.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    setattr(handler, _HANDLER_TAG, True)
    handler.setLevel(numeric_level)
    handler.setFormatter(
        _RedactingJsonFormatter(_redactor) if fmt == "json" else _RedactingTextFormatter(_redactor)
    )
    logger.addHandler(handler)

    # Keep chatty dependencies quiet unless we are explicitly debugging, and
    # never below WARNING for HTTP libs, which can log URLs containing keys.
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(
            logging.WARNING if numeric_level > logging.DEBUG or name in ("httpx", "httpcore") else numeric_level
        )

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the ``phishtriage`` namespace.

    ``get_logger("analyzers.auth")`` -> ``phishtriage.analyzers.auth``.
    Passing a ``__name__`` that already starts with the package name is fine.
    """
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")