"""Parser interface, input validation, format sniffing, and shared helpers.

Public entry point: :func:`parse_message`. It validates the raw bytes, detects
whether they are an ``.eml`` or ``.msg`` file from the **content** (never the
file name alone, since attackers control names), and dispatches to the right
parser. Parsers are imported lazily, so a missing optional dependency only
affects the format that needs it.

The helper functions at the bottom are shared by all parsers and are written to
never raise on malformed input: they return a best-effort value instead.
"""

import importlib
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from email.errors import HeaderParseError
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import PurePath
from typing import Any, Literal, Protocol, runtime_checkable

from phishtriage.config import Settings, get_settings
from phishtriage.core.exceptions import (
    EmptyInputError,
    FileTooLargeError,
    InputError,
    MalformedMessageError,
    MissingDependencyError,
    ParserError,
    PhishTriageError,
    UnsupportedFormatError,
)
from phishtriage.core.models import ParsedAddress, ParsedMessage
from phishtriage.logging_config import get_logger

__all__ = [
    "OLE_MAGIC",
    "MessageParser",
    "SourceFormat",
    "clean_body_text",
    "clean_header_text",
    "decode_bytes",
    "decode_header_value",
    "detect_format",
    "looks_like_eml",
    "parse_addresses",
    "parse_date",
    "parse_message",
    "strip_angle_brackets",
    "to_text",
    "validate_input",
]

logger = get_logger(__name__)

SourceFormat = Literal["eml", "msg"]

#: Magic bytes of an OLE2 / Compound File Binary container (Outlook ``.msg``).
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

_SNIFF_BYTES = 16 * 1024
_MAX_ADDRESSES_PER_HEADER = 500

_HEADER_LINE_RE = re.compile(r"^[!-9;-~]+:")  # RFC 5322 field-name chars, then ":"
_MBOX_FROM_RE = re.compile(r"^From \S+")
_KNOWN_HEADERS = frozenset(
    {
        "received", "from", "to", "cc", "bcc", "subject", "date", "message-id",
        "mime-version", "content-type", "content-transfer-encoding", "return-path",
        "delivered-to", "reply-to", "sender", "authentication-results", "received-spf",
        "dkim-signature", "arc-seal", "arc-message-signature", "arc-authentication-results",
        "list-id", "in-reply-to", "references", "thread-topic", "thread-index",
    }
)  # fmt: skip

_UNFOLD_RE = re.compile(r"\r?\n(?=[ \t])")
_LINEBREAK_RE = re.compile(r"[\r\n]+")
_CTRL_HEADER_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CTRL_BODY_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ======================================================================== interface
@runtime_checkable
class MessageParser(Protocol):
    """Contract every format-specific parser implements."""

    source_format: SourceFormat

    def parse(self, data: bytes) -> ParsedMessage:
        """Parse ``data`` into a :class:`ParsedMessage`.

        Implementations must degrade gracefully (record problems in
        ``parse_warnings``) and raise :class:`ParserError` only when nothing
        useful can be extracted.
        """
        ...


# ============================================================ validation / sniffing
def validate_input(data: bytes, max_bytes: int) -> None:
    """Reject empty or oversized input.

    Raises:
        InputError: ``data`` is not bytes.
        EmptyInputError: ``data`` is empty or whitespace only.
        FileTooLargeError: ``data`` exceeds ``max_bytes``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise InputError("Input must be raw bytes.")
    if not data or not bytes(data[:4096]).strip():
        raise EmptyInputError()
    if len(data) > max_bytes:
        raise FileTooLargeError(len(data), max_bytes)


def looks_like_eml(data: bytes) -> bool:
    """Heuristically decide whether ``data`` starts like an RFC 5322 message.

    The first header block must consist of valid ``Name:`` lines (an mbox
    ``From `` line is tolerated first) and contain at least one well-known
    header or an ``X-`` header. Binary data (NUL bytes) is rejected.
    """
    head = bytes(data[:_SNIFF_BYTES])
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    if b"\x00" in head:
        return False

    text = head.decode("latin-1").lstrip()
    seen_known = False
    first_line = True
    for line in text.splitlines():
        if not line.strip():
            break  # blank line terminates the header block
        if line[0] in " \t":
            continue  # folded continuation of the previous header
        if first_line and _MBOX_FROM_RE.match(line):
            first_line = False
            continue
        first_line = False
        if not _HEADER_LINE_RE.match(line):
            break
        name = line.split(":", 1)[0].lower()
        if name in _KNOWN_HEADERS or name.startswith("x-"):
            seen_known = True
    return seen_known


def detect_format(data: bytes, filename: str | None = None) -> SourceFormat:
    """Detect ``eml`` or ``msg`` from content, using ``filename`` only as a hint.

    A mismatch between the extension and the real content is logged, and the
    content wins.

    Raises:
        UnsupportedFormatError: the data is neither an OLE container nor
            text that looks like an RFC 5322 message.
    """
    ext = PurePath(filename).suffix.lower() if filename else ""

    if bytes(data[: len(OLE_MAGIC)]) == OLE_MAGIC:
        if ext == ".eml":
            logger.warning("File named %r is an OLE container, not an .eml", filename)
        return "msg"

    if looks_like_eml(data):
        if ext == ".msg":
            logger.warning("File named %r is plain text, not an Outlook .msg", filename)
        return "eml"

    raise UnsupportedFormatError(
        "File is not a recognised .eml or .msg message.",
        details={"filename": filename or "", "extension": ext},
    )


# ============================================================================ dispatch
_PARSER_REGISTRY: dict[SourceFormat, tuple[str, str]] = {
    "eml": ("phishtriage.parsers.eml_parser", "EmlParser"),
    "msg": ("phishtriage.parsers.msg_parser", "MsgParser"),
}


def _load_parser(fmt: SourceFormat, settings: Settings) -> MessageParser:
    """Import and instantiate the parser for ``fmt`` (lazy, dependency-safe)."""
    module_name, class_name = _PARSER_REGISTRY[fmt]
    try:
        module = importlib.import_module(module_name)
        parser_cls: Any = getattr(module, class_name)
    except (ImportError, AttributeError) as exc:
        raise MissingDependencyError(
            f"The {fmt!r} parser is unavailable: {exc}",
            details={"format": fmt},
        ) from exc
    parser: MessageParser = parser_cls(max_attachments=settings.max_attachments)
    return parser


def parse_message(
    data: bytes,
    filename: str | None = None,
    *,
    settings: Settings | None = None,
) -> ParsedMessage:
    """Validate, sniff, and parse raw message bytes.

    Args:
        data: Raw ``.eml`` or ``.msg`` file contents.
        filename: Original file name; a hint only, never trusted.
        settings: Override settings (defaults to the process singleton).

    Raises:
        InputError: empty, oversized, or unrecognised input.
        ParserError: the message is too damaged to parse.
    """
    cfg = settings or get_settings()
    validate_input(data, cfg.max_upload_bytes)
    fmt = detect_format(data, filename)
    parser = _load_parser(fmt, cfg)
    try:
        message = parser.parse(bytes(data))
    except PhishTriageError:
        raise
    except Exception as exc:  # parsers face hostile input; never leak raw crashes
        logger.exception("Unexpected %s parser failure", fmt)
        raise MalformedMessageError(
            f"Failed to parse {fmt} message: {type(exc).__name__}",
            details={"format": fmt},
        ) from exc
    logger.debug(
        "Parsed %s: %d headers, %d attachments, %d warnings",
        fmt, len(message.headers), len(message.attachments), len(message.parse_warnings),
    )  # fmt: skip
    return message


# ============================================================== shared text helpers
def to_text(value: object) -> str:
    """Convert a header value (``str``, ``Header``, bytes, ...) to clean ``str``.

    Lone surrogate escapes produced by the stdlib for undecodable 8-bit input
    are converted to U+FFFD instead of raising later during serialisation.
    """
    try:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("utf-8", "replace")
        text = value if isinstance(value, str) else str(value)
    except Exception:  # noqa: BLE001 - exotic Header objects can fail in str()
        return ""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8", "replace")


def clean_header_text(value: object) -> str:
    """Unfold a header into one line and strip control characters."""
    text = _UNFOLD_RE.sub("", to_text(value))
    text = _LINEBREAK_RE.sub(" ", text)
    return _CTRL_HEADER_RE.sub("", text).strip()


def clean_body_text(value: str) -> str:
    """Remove control characters from a body but keep newlines and tabs."""
    return _CTRL_BODY_RE.sub("", value)


def strip_angle_brackets(value: str) -> str:
    """Return ``value`` without surrounding whitespace and ``<>``."""
    return value.strip().strip("<>").strip()


def decode_bytes(data: bytes, charset: str | None = None) -> str:
    """Decode bytes using ``charset`` with robust fallbacks; never raises."""
    declared = (charset or "").strip().strip("\"'").lower()
    for encoding in ([declared] if declared else []) + ["utf-8"]:
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    if declared:
        try:
            return data.decode(declared, "replace")
        except LookupError:
            pass
    return data.decode("utf-8", "replace")


def decode_header_value(value: object) -> str:
    """Decode RFC 2047 encoded-words (``=?UTF-8?B?...?=``) in a header value."""
    text = clean_header_text(value)
    if "=?" not in text:
        return text
    try:
        chunks = decode_header(text)
    except (HeaderParseError, ValueError, LookupError):
        return text
    decoded = [
        decode_bytes(chunk, charset) if isinstance(chunk, bytes) else chunk
        for chunk, charset in chunks
    ]
    return clean_header_text("".join(decoded))


def parse_addresses(values: Iterable[str]) -> list[ParsedAddress]:
    """Parse one or more address-list header values into mailboxes.

    Entries with neither a name nor an address are dropped. Unparseable
    fragments are kept as an address-less display name so analysts can still
    see them. At most 500 addresses are returned per call.
    """
    cleaned = [clean_header_text(v) for v in values]
    try:
        pairs = getaddresses([c for c in cleaned if c])
    except Exception:  # noqa: BLE001 - stdlib can raise on pathological input
        return [ParsedAddress(display_name=c) for c in cleaned[:1] if c]

    result: list[ParsedAddress] = []
    for name, address in pairs:
        display = decode_header_value(name)
        addr = clean_header_text(strip_angle_brackets(address))
        if not display and not addr:
            continue
        result.append(ParsedAddress(display_name=display, address=addr))
        if len(result) >= _MAX_ADDRESSES_PER_HEADER:
            break
    return result


def parse_date(value: str | None) -> datetime | None:
    """Parse an RFC 5322 date into a timezone-aware datetime, or ``None``.

    Naive results (``-0000`` zones) are interpreted as UTC.
    """
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(clean_header_text(value))
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)