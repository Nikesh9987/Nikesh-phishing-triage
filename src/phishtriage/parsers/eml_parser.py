"""Parser for RFC 5322 ``.eml`` files, built on the standard library.

Choices made for hostile input:

* ``policy.compat32`` is used because it is the most forgiving: malformed
  messages parse with recorded *defects* instead of raising.
* Raw headers are preserved in original order, with duplicates, **unfolded
  but not RFC 2047-decoded**. Authentication and ``Received`` analyzers need
  the raw text. Decoded values appear only in the summary fields.
* The MIME tree is walked iteratively-bounded: depth and total part count are
  capped to defeat MIME-bomb messages.
* ``message/rfc822`` parts (forwarded or attached emails, a common phishing
  carrier) are returned as attachments and are **not** flattened into the
  outer body. Their bytes are a re-serialisation of the inner message, so the
  hash may differ from the original source bytes.
* Nothing is executed or written to disk. Everything stays in memory.
"""

import email
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from typing import Literal

from phishtriage.core.exceptions import MalformedMessageError
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
    to_text,
)

logger = get_logger(__name__)

_MAX_MIME_DEPTH = 25
_MAX_MIME_PARTS = 2000
_MAX_HEADERS = 5000
_MAX_FILENAME_LEN = 255
_MAX_DEFECT_NAMES = 10

# compat32 mangles body lines starting with "From " by default; disable that
# when re-serialising an attached message.
_SERIALIZE_POLICY = policy.compat32.clone(mangle_from_=False)


@dataclass
class _WalkState:
    """Mutable accumulator for one MIME-tree traversal."""

    text_parts: list[str] = field(default_factory=list)
    html_parts: list[str] = field(default_factory=list)
    attachments: list[RawAttachment] = field(default_factory=list)
    defects: set[str] = field(default_factory=set)
    parts_seen: int = 0
    parts_truncated: bool = False
    depth_exceeded: bool = False
    attachments_truncated: bool = False


class EmlParser:
    """Parse raw ``.eml`` bytes into a :class:`ParsedMessage`."""

    source_format: Literal["eml"] = "eml"

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
            MalformedMessageError: no RFC 5322 headers could be extracted.
        """
        try:
            msg = email.message_from_bytes(data, policy=policy.compat32)
        except Exception as exc:  # noqa: BLE001 - stdlib parser on hostile bytes
            raise MalformedMessageError(
                f"Could not parse message: {type(exc).__name__}"
            ) from exc

        headers = self._extract_headers(msg)
        if not headers:
            raise MalformedMessageError("No RFC 5322 headers could be parsed from the file.")

        warnings: list[str] = []
        if len(headers) >= _MAX_HEADERS:
            warnings.append(f"Header count capped at {_MAX_HEADERS}.")

        state = _WalkState()
        self._walk(msg, 0, state)
        warnings.extend(self._walk_warnings(state))

        def values(name: str) -> list[str]:
            wanted = name.lower()
            return [h.value for h in headers if h.name.lower() == wanted]

        # ---- From
        from_values = values("From")
        from_addresses = parse_addresses(from_values)
        from_address = from_addresses[0] if from_addresses else None
        if not from_values:
            warnings.append("Message has no From header.")
        elif from_address is None or not from_address.address:
            warnings.append("From header present but no valid address could be parsed.")
        if len(from_values) > 1:
            warnings.append(f"Message has {len(from_values)} From headers (possible spoofing).")

        # ---- Date
        date_values = values("Date")
        date = parse_date(date_values[0]) if date_values else None
        if date_values and date is None:
            warnings.append("Date header could not be parsed.")

        return ParsedMessage(
            source_format="eml",
            headers=headers,
            subject=decode_header_value(values("Subject")[0]) if values("Subject") else "",
            from_address=from_address,
            to=parse_addresses(values("To")),
            cc=parse_addresses(values("Cc")),
            reply_to=parse_addresses(values("Reply-To")),
            return_path=strip_angle_brackets(values("Return-Path")[0])
            if values("Return-Path")
            else "",
            message_id=strip_angle_brackets(values("Message-ID")[0])
            if values("Message-ID")
            else "",
            date=date,
            body_text="\n\n".join(state.text_parts),
            body_html="\n".join(state.html_parts),
            attachments=state.attachments,
            parse_warnings=warnings,
        )

    # ------------------------------------------------------------------- headers
    @staticmethod
    def _extract_headers(msg: Message) -> list[HeaderField]:
        """Return top-level headers in original order, unfolded and sanitised."""
        headers: list[HeaderField] = []
        for raw_name, raw_value in msg.items():
            name = clean_header_text(raw_name)
            if not name:
                continue
            headers.append(HeaderField(name=name, value=clean_header_text(raw_value)))
            if len(headers) >= _MAX_HEADERS:
                break
        return headers

    # ----------------------------------------------------------------- MIME walk
    def _walk(self, part: Message, depth: int, state: _WalkState) -> None:
        """Depth-first traversal that stops at ``message/rfc822`` boundaries."""
        state.parts_seen += 1
        if state.parts_seen > _MAX_MIME_PARTS:
            state.parts_truncated = True
            return
        if depth > _MAX_MIME_DEPTH:
            state.depth_exceeded = True
            return

        for defect in part.defects:
            if len(state.defects) < _MAX_DEFECT_NAMES:
                state.defects.add(type(defect).__name__)

        if part.get_content_type() == "message/rfc822":
            self._handle_attached_message(part, state)
            return

        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                for child in payload:
                    if isinstance(child, Message):
                        self._walk(child, depth + 1, state)
            return

        self._handle_leaf(part, state)

    def _handle_leaf(self, part: Message, state: _WalkState) -> None:
        """Classify a non-multipart part as body text, body HTML, or attachment."""
        content_type = part.get_content_type()
        maintype = part.get_content_maintype()
        disposition = part.get_content_disposition() or ""
        filename = self._get_filename(part)

        is_body_candidate = (
            disposition != "attachment"
            and not filename
            and (content_type in ("text/plain", "text/html") or maintype == "multipart")
        )
        # A "multipart/*" leaf is a multipart with a broken boundary; its
        # payload is raw text, so treat it as a plain-text body.

        payload = part.get_payload(decode=True)
        raw = payload if isinstance(payload, bytes) else b""

        if is_body_candidate:
            text = clean_body_text(decode_bytes(raw, part.get_content_charset()))
            if content_type == "text/html":
                state.html_parts.append(text)
            else:
                state.text_parts.append(text)
            return

        if not filename:
            extension = content_type.split("/", 1)[-1].split("+", 1)[0] or "bin"
            filename = f"unnamed_attachment.{extension}"[:_MAX_FILENAME_LEN]

        content_id = strip_angle_brackets(clean_header_text(part.get("Content-ID", "")))
        self._add_attachment(
            state,
            RawAttachment(
                filename=filename,
                declared_content_type=content_type,
                content_id=content_id,
                is_inline=disposition == "inline" or bool(content_id),
                data=raw,
            ),
        )

    def _handle_attached_message(self, part: Message, state: _WalkState) -> None:
        """Record an embedded ``message/rfc822`` part as an attachment."""
        data = b""
        inner_subject = ""
        payload = part.get_payload()
        if isinstance(payload, list) and payload and isinstance(payload[0], Message):
            inner = payload[0]
            inner_subject = decode_header_value(inner.get("Subject", ""))
            try:
                data = inner.as_bytes(policy=_SERIALIZE_POLICY)
            except Exception:  # noqa: BLE001 - re-serialising damaged messages can fail
                logger.debug("Could not re-serialise attached message", exc_info=True)
                state.defects.add("AttachedMessageSerialisationError")

        filename = self._get_filename(part)
        if not filename:
            safe_subject = "".join(c for c in inner_subject if c.isalnum() or c in " ._-").strip()
            filename = f"{safe_subject[:60] or 'attached_message'}.eml"

        self._add_attachment(
            state,
            RawAttachment(
                filename=filename,
                declared_content_type="message/rfc822",
                content_id=strip_angle_brackets(clean_header_text(part.get("Content-ID", ""))),
                is_inline=False,
                data=data,
            ),
        )

    def _add_attachment(self, state: _WalkState, attachment: RawAttachment) -> None:
        """Append an attachment unless the configured cap has been reached."""
        if len(state.attachments) >= self._max_attachments:
            state.attachments_truncated = True
            return
        state.attachments.append(attachment)

    @staticmethod
    def _get_filename(part: Message) -> str:
        """Return a decoded, path-stripped attachment name ('' if none).

        Handles RFC 2231 parameters (via the stdlib) and RFC 2047 encoded-words.
        Only the base name is kept so a name like ``../../x`` cannot be misused
        by downstream consumers. Other characters, including bidi overrides,
        are left intact for the attachment analyzer to flag.
        """
        try:
            raw = part.get_filename()
        except Exception:  # noqa: BLE001 - malformed parameter syntax
            return ""
        if not raw:
            return ""
        name = decode_header_value(to_text(raw))
        name = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
        return name[:_MAX_FILENAME_LEN]

    # ------------------------------------------------------------------ warnings
    @staticmethod
    def _walk_warnings(state: _WalkState) -> list[str]:
        """Convert traversal limits and parser defects into analyst warnings."""
        warnings: list[str] = []
        if state.parts_truncated:
            warnings.append(f"MIME part count exceeded {_MAX_MIME_PARTS}; remaining parts ignored.")
        if state.depth_exceeded:
            warnings.append(f"MIME nesting exceeded {_MAX_MIME_DEPTH} levels; deeper parts ignored.")
        if state.attachments_truncated:
            warnings.append("Attachment limit reached; additional attachments were not processed.")
        if state.defects:
            warnings.append("MIME parser defects: " + ", ".join(sorted(state.defects)) + ".")
        return warnings