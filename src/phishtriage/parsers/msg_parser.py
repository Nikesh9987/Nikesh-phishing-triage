"""Parser for Outlook ``.msg`` files (OLE2 / Compound File Binary), via ``extract-msg``.

Key behaviours:

* **Transport headers are the source of truth.** Outlook stores the original
  internet headers (``Received``, ``Authentication-Results`` ...) in a MAPI
  property. When present they are used verbatim, in original order with
  duplicates, so the Received tracer and auth analyzer work exactly as for
  ``.eml``.
* **Graceful degradation.** Items that were drafted or sent from inside
  Exchange often have *no* transport headers. In that case a minimal header set
  is synthesised from MAPI properties and a warning states that Received and
  authentication analysis is unavailable.
* **Embedded Outlook messages** are re-exported as ``.msg`` bytes and returned
  as attachments (hashed later like any other file). They are not flattened
  into the outer body.
* **Exchange X.500 addresses** (``/O=EXCHANGELABS/...``) are flagged because
  they are internal identifiers, not routable SMTP addresses.
* Everything stays in memory. Nothing is executed or written to disk.

``extract_msg`` is imported at module level on purpose: if it is not installed,
``parsers.base`` converts the ``ImportError`` into ``MissingDependencyError``
and only the ``.msg`` format is affected.
"""

import io
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Any, Literal

import extract_msg

from phishtriage.core.exceptions import MalformedMessageError, PhishTriageError
from phishtriage.core.models import HeaderField, ParsedMessage, RawAttachment
from phishtriage.logging_config import get_logger
from phishtriage.parsers.base import (
    clean_body_text,
    clean_header_text,
    decode_bytes,
    decode_header_value,
    parse_addresses,
    parse_date,
    strip_angle_brackets,
)

logger = get_logger(__name__)

_MAX_HEADERS = 5000
_MAX_FILENAME_LEN = 255
_X500_PREFIX = "/o="
_MSG_CONTENT_TYPE = "application/vnd.ms-outlook"
_MISSING = object()


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``obj.name`` without ever raising.

    ``extract_msg`` exposes most data as lazy properties that can raise on
    corrupt streams, so every access goes through this guard.
    """
    try:
        value = getattr(obj, name, _MISSING)
    except Exception:  # noqa: BLE001 - corrupt OLE streams surface as arbitrary errors
        logger.debug("Property %r raised while reading .msg", name, exc_info=True)
        return default
    return default if value is _MISSING or value is None else value


def _as_str(value: Any) -> str:
    """Coerce a MAPI string value (``str``/``bytes``/other) to ``str``."""
    if isinstance(value, (bytes, bytearray)):
        return decode_bytes(bytes(value))
    return value if isinstance(value, str) else ""


def _safe_filename(raw: Any) -> str:
    """Decode an attachment name and keep only its base name (max 255 chars)."""
    text = decode_header_value(_as_str(raw))
    return text.replace("\\", "/").rsplit("/", 1)[-1].strip()[:_MAX_FILENAME_LEN]


class MsgParser:
    """Parse raw ``.msg`` bytes into a :class:`ParsedMessage`."""

    source_format: Literal["msg"] = "msg"

    def __init__(self, max_attachments: int = 100) -> None:
        """Create a parser.

        Args:
            max_attachments: Attachments beyond this count are dropped and a
                warning is recorded.
        """
        self._max_attachments = max(1, max_attachments)

    # ----------------------------------------------------------------- public API
    def parse(self, data: bytes) -> ParsedMessage:
        """Parse ``data``.

        Raises:
            MalformedMessageError: the OLE container cannot be opened, or it
                does not contain an email item.
        """
        try:
            msg = extract_msg.openMsg(io.BytesIO(data), strict=False)
        except Exception as exc:  # noqa: BLE001 - olefile/extract_msg raise many types
            raise MalformedMessageError(
                f"Could not open .msg container: {type(exc).__name__}"
            ) from exc

        try:
            return self._convert(msg)
        except PhishTriageError:
            raise
        except Exception as exc:  # noqa: BLE001 - hostile input
            raise MalformedMessageError(
                f"Could not read .msg contents: {type(exc).__name__}"
            ) from exc
        finally:
            try:
                msg.close()
            except Exception:  # noqa: BLE001
                logger.debug("Error while closing .msg", exc_info=True)

    # ----------------------------------------------------------------- conversion
    def _convert(self, msg: Any) -> ParsedMessage:
        """Map an opened ``extract_msg`` object onto :class:`ParsedMessage`."""
        warnings: list[str] = []

        item_type = type(msg).__name__
        if item_type == "MSGFile" or not hasattr(msg, "subject"):
            raise MalformedMessageError(
                f"The .msg file is not an email item (type: {item_type}).",
                details={"item_type": item_type},
            )
        if item_type not in ("Message", "MessageSigned", "MessageSignedBase", "MessageBase"):
            warnings.append(f"Outlook item type is {item_type!r}, not a plain email.")

        # ---- headers
        headers = self._transport_headers(msg)
        has_transport = bool(headers)
        if not has_transport:
            headers = self._synthesize_headers(msg)
            warnings.append(
                "No transport headers in this .msg (likely drafted or sent inside Exchange). "
                "Received-path and SPF/DKIM/DMARC analysis are unavailable."
            )
        if len(headers) >= _MAX_HEADERS:
            warnings.append(f"Header count capped at {_MAX_HEADERS}.")

        def values(name: str) -> list[str]:
            wanted = name.lower()
            return [h.value for h in headers if h.name.lower() == wanted]

        # ---- addresses
        from_values = values("From")
        if not from_values:
            sender = clean_header_text(_as_str(_attr(msg, "sender", "")))
            from_values = [sender] if sender else []
        from_addresses = parse_addresses(from_values)
        from_address = from_addresses[0] if from_addresses else None
        if from_address is None:
            warnings.append("Message has no sender information.")
        elif from_address.address.lower().startswith(_X500_PREFIX):
            warnings.append(
                "Sender is an Exchange X.500 address (internal identifier), not an SMTP address."
            )
        if len(values("From")) > 1:
            warnings.append(f"Message has {len(values('From'))} From headers (possible spoofing).")

        to_values = values("To") or [_as_str(_attr(msg, "to", ""))]
        cc_values = values("Cc") or [_as_str(_attr(msg, "cc", ""))]

        # ---- subject / ids / date
        subject_values = values("Subject")
        subject = (
            decode_header_value(subject_values[0])
            if subject_values
            else clean_header_text(_as_str(_attr(msg, "subject", "")))
        )
        message_id_values = values("Message-ID")
        message_id = strip_angle_brackets(
            message_id_values[0]
            if message_id_values
            else clean_header_text(_as_str(_attr(msg, "messageId", "")))
        )
        return_path_values = values("Return-Path")
        return_path = strip_angle_brackets(return_path_values[0]) if return_path_values else ""

        date = self._resolve_date(msg, values("Date"))
        if date is None:
            warnings.append("No usable Date could be determined.")

        # ---- bodies
        body_text = clean_body_text(_as_str(_attr(msg, "body", "")))
        body_html = clean_body_text(self._html_body(msg))

        # ---- attachments
        attachments = self._extract_attachments(msg, subject, warnings)

        return ParsedMessage(
            source_format="msg",
            headers=headers,
            subject=subject,
            from_address=from_address,
            to=parse_addresses(to_values),
            cc=parse_addresses(cc_values),
            reply_to=parse_addresses(values("Reply-To")),
            return_path=return_path,
            message_id=message_id,
            date=date,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments,
            parse_warnings=warnings,
        )

    # ------------------------------------------------------------------- headers
    @staticmethod
    def _transport_headers(msg: Any) -> list[HeaderField]:
        """Return the original internet headers in order, duplicates preserved."""
        header = _attr(msg, "header")
        if header is None:
            return []
        try:
            items = list(header.items())
        except Exception:  # noqa: BLE001
            logger.debug("Could not iterate transport headers", exc_info=True)
            return []

        result: list[HeaderField] = []
        for raw_name, raw_value in items:
            name = clean_header_text(raw_name)
            if not name:
                continue
            result.append(HeaderField(name=name, value=clean_header_text(raw_value)))
            if len(result) >= _MAX_HEADERS:
                break
        return result

    @staticmethod
    def _synthesize_headers(msg: Any) -> list[HeaderField]:
        """Build a minimal header set from MAPI properties (no Received chain)."""
        date = MsgParser._raw_date(msg)
        candidates: list[tuple[str, str]] = [
            ("From", _as_str(_attr(msg, "sender", ""))),
            ("To", _as_str(_attr(msg, "to", ""))),
            ("Cc", _as_str(_attr(msg, "cc", ""))),
            ("Subject", _as_str(_attr(msg, "subject", ""))),
            ("Date", format_datetime(date) if date else ""),
            ("Message-ID", _as_str(_attr(msg, "messageId", ""))),
        ]
        return [
            HeaderField(name=name, value=clean_header_text(value))
            for name, value in candidates
            if clean_header_text(value)
        ]

    # ---------------------------------------------------------------------- date
    @staticmethod
    def _raw_date(msg: Any) -> datetime | None:
        """Return ``msg.date`` as an aware datetime (it may be ``str`` or ``datetime``)."""
        value = _attr(msg, "date")
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str):
            return parse_date(value)
        return None

    def _resolve_date(self, msg: Any, date_headers: list[str]) -> datetime | None:
        """Prefer the transport ``Date`` header; fall back to the MAPI date."""
        if date_headers:
            parsed = parse_date(date_headers[0])
            if parsed is not None:
                return parsed
        return self._raw_date(msg)

    # -------------------------------------------------------------------- bodies
    @staticmethod
    def _html_body(msg: Any) -> str:
        """Return the HTML body as text (extract-msg yields bytes, or de-encapsulated RTF)."""
        raw = _attr(msg, "htmlBody")
        if isinstance(raw, (bytes, bytearray)):
            charset = _attr(msg, "stringEncoding")
            return decode_bytes(bytes(raw), charset if isinstance(charset, str) else None)
        return raw if isinstance(raw, str) else ""

    # --------------------------------------------------------------- attachments
    def _extract_attachments(
        self, msg: Any, subject: str, warnings: list[str]
    ) -> list[RawAttachment]:
        """Extract every attachment into memory; one bad attachment never aborts the rest."""
        raw_list = _attr(msg, "attachments", [])
        try:
            items = list(raw_list)
        except TypeError:
            warnings.append("Attachment list could not be read.")
            return []

        result: list[RawAttachment] = []
        for position, att in enumerate(items, start=1):
            if len(result) >= self._max_attachments:
                warnings.append(
                    "Attachment limit reached; additional attachments were not processed."
                )
                break
            try:
                converted = self._convert_attachment(att, position, subject, warnings)
            except Exception:  # noqa: BLE001 - corrupt attachment stream
                logger.debug("Attachment %d failed", position, exc_info=True)
                warnings.append(f"Attachment #{position} could not be read and was skipped.")
                continue
            if converted is not None:
                result.append(converted)
        return result

    @staticmethod
    def _convert_attachment(
        att: Any, position: int, subject: str, warnings: list[str]
    ) -> RawAttachment | None:
        """Convert one ``extract_msg`` attachment to a :class:`RawAttachment`."""
        att_type = _attr(att, "type")
        type_name = str(getattr(att_type, "name", att_type) or "").upper()

        filename = _safe_filename(
            _attr(att, "longFilename") or _attr(att, "shortFilename") or _attr(att, "name")
        )
        content_id = strip_angle_brackets(
            clean_header_text(_as_str(_attr(att, "cid") or _attr(att, "contentId") or ""))
        )
        content_type = clean_header_text(_as_str(_attr(att, "mimetype", ""))).lower()

        payload: bytes = b""
        data = _attr(att, "data")

        if type_name == "MSG":
            # Embedded Outlook message: re-export its bytes.
            content_type = _MSG_CONTENT_TYPE
            try:
                payload = bytes(data.exportBytes()) if data is not None else b""
            except Exception:  # noqa: BLE001
                logger.debug("Could not export embedded .msg", exc_info=True)
                warnings.append(f"Embedded message #{position} could not be exported.")
            if not filename:
                safe = "".join(c for c in subject if c.isalnum() or c in " ._-").strip()
                filename = f"{safe[:60] or 'embedded_message'}.msg"
        elif type_name == "WEB":
            warnings.append(
                f"Attachment #{position} is a web/cloud reference, not an embedded file "
                "(no payload to hash)."
            )
            if not filename:
                filename = f"web_attachment_{position}.url"
        elif isinstance(data, (bytes, bytearray)):
            payload = bytes(data)
        elif isinstance(data, str):
            payload = data.encode("utf-8", "replace")
        elif data is not None:
            warnings.append(f"Attachment #{position} has an unsupported payload type.")

        if not filename:
            filename = f"unnamed_attachment_{position}.bin"

        return RawAttachment(
            filename=filename,
            declared_content_type=content_type,
            content_id=content_id,
            is_inline=bool(content_id) or bool(_attr(att, "hidden", False)),
            data=payload,
        )
