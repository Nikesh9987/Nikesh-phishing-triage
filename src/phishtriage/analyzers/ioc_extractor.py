"""Extract indicators of compromise (IOCs) from a parsed message.

Extracted types: URLs, e-mail addresses, domains (derived from URL hosts and
e-mail addresses), and public IPv4/IPv6 addresses.

Sources scanned:

* **Headers.** ``Received``/``X-Received`` yield *IP addresses only*. Recipient
  headers (``To``, ``Cc``, ``Delivered-To`` ...), ``Message-ID``-style
  identifiers and signature blobs are skipped, because they would only add
  noise (victim addresses, ``abc@host`` message IDs). The decoded subject is
  scanned instead of the raw, RFC 2047-encoded ``Subject`` header.
* **Plain-text body.**
* **HTML body**, parsed properly: ``href``/``src``/``action``/... attributes,
  ``mailto:`` links, meta-refresh targets, ``<script>``/``<style>`` content,
  comments (conditional ``<!--[if mso]>`` blocks) and visible text.

Behaviours worth knowing:

* Input is **refanged** first, so ``hxxp[://]evil[.]com`` is found as a live
  indicator. ``IOC.value`` is the live form (for lookups) and ``IOC.defanged``
  is the safe form (for display and copying).
* Indicators are de-duplicated; ``count`` and ``sources`` record every sighting.
* IPs are reported only if globally routable (or in documentation ranges, so
  samples and tests work). Pass ``include_non_public_ips=True`` to keep
  private/loopback/link-local addresses.
* Single-integer URL hosts (``http://3405803781/``) are decoded to their IPv4.
* All regexes use bounded quantifiers or anchored starts, so hostile
  megabyte-long inputs cannot cause catastrophic backtracking. Each scanned
  text blob is capped at 5,000,000 characters.
* Never raises: a failing stage becomes a warning.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from phishtriage.config import Settings, get_settings
from phishtriage.core.defang import defang_ioc, refang
from phishtriage.core.models import IOC, IOCSource, IOCType, ParsedMessage
from phishtriage.logging_config import get_logger

__all__ = ["ExtractionResult", "IOCExtractor", "extract_iocs"]

logger = get_logger(__name__)

_MAX_SCAN_CHARS = 5_000_000
_MAX_URL_LEN = 4096
_MAX_LOCAL_PART = 64

_TYPE_ORDER = (IOCType.URL, IOCType.EMAIL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6, IOCType.HASH)

# Headers that carry no useful indicators (or only noise).
_SKIP_HEADERS = frozenset(
    {
        "dkim-signature", "domainkey-signature", "arc-seal", "arc-message-signature",
        "message-id", "in-reply-to", "references", "thread-index",
        "to", "cc", "bcc", "delivered-to", "x-original-to", "envelope-to", "x-forwarded-to",
    }
)  # fmt: skip
_RECEIVED_HEADERS = frozenset({"received", "x-received"})

# HTML attributes that may hold a URL.
_URL_ATTRS = frozenset(
    {"href", "src", "action", "background", "data", "poster", "formaction", "cite",
     "longdesc", "xlink:href", "codebase", "usemap"}
)  # fmt: skip

# ------------------------------------------------------------------------- patterns
_URL_RE = re.compile(r"""(?i)\b(?:https?|ftps?)://[^\s<>"'`\\^{}|\x00-\x1f\x7f]+""")
_WWW_RE = re.compile(
    r"""(?i)(?<![\w@/.\-])www\.[a-z0-9\-]{1,63}(?:\.[a-z0-9\-]{1,63}){1,8}"""
    r"""(?:[/?#][^\s<>"'`\\^{}|\x00-\x1f\x7f]*)?"""
)
# The look-behind restricts matches to the start of an address-like run, which
# keeps scanning linear on long runs of local-part characters.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@"
    r"[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,8}"
)
_IPV6_TAG_RE = re.compile(r"(?i)\bipv6:")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")

_URL_PARTS_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(.*)$", re.DOTALL)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$")
_DEC_HOST_RE = re.compile(r"^\d{1,10}$")
_HEX_HOST_RE = re.compile(r"^0x[0-9a-f]{1,8}$")
_ATTR_WS_RE = re.compile(r"[\t\r\n]")
_META_URL_RE = re.compile(r"(?i)url\s*=\s*['\"]?([^'\";\s]+)")

_TRAILING_PUNCT = ".,;:!?'\"*"
_CLOSERS = {")": "(", "]": "["}

# Documentation ranges are never routable, but they appear in every sample and
# test message, so they are reported like public addresses.
_DOC_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


# ===================================================================== result type
@dataclass
class ExtractionResult:
    """IOCs plus non-fatal warnings produced during extraction."""

    iocs: list[IOC] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================ normalisation helpers
def _trim_url(url: str) -> str:
    """Strip trailing punctuation and unbalanced closing brackets from a URL."""
    url = url.strip()
    while url:
        last = url[-1]
        if (
            last in _TRAILING_PUNCT
            or last in _CLOSERS
            and url.count(last) > url.count(_CLOSERS[last])
        ):
            url = url[:-1]
        else:
            break
    return url


def _normalize_hostname(host: str) -> str | None:
    """Return a lower-cased, punycode-encoded hostname, or ``None`` if not a valid domain.

    Requires at least two labels and an alphabetic (or ``xn--``) TLD, which
    rejects file names, versions, and Outlook ``cid:`` identifiers.
    """
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return None
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    return host if _TLD_RE.match(labels[-1]) else None


def _decode_numeric_host(host: str) -> ipaddress.IPv4Address | None:
    """Decode obfuscated single-number hosts (decimal or ``0x`` hex) to IPv4."""
    try:
        if _HEX_HOST_RE.match(host):
            number = int(host, 16)
        elif _DEC_HOST_RE.match(host):
            number = int(host)
        else:
            return None
        return ipaddress.IPv4Address(number)
    except (ValueError, ipaddress.AddressValueError):
        return None


def _normalize_url(raw: str) -> tuple[str, str] | None:
    """Return ``(normalised_url, host)`` or ``None`` if ``raw`` is not a usable URL.

    The scheme and host are lower-cased; user-info, path and query keep their case.
    """
    url = _trim_url(raw)
    if len(url) > _MAX_URL_LEN:
        return None
    match = _URL_PARTS_RE.match(url)
    if match is None:
        return None
    scheme, authority, rest = match.groups()
    userinfo, at_sign, hostport = authority.rpartition("@")
    hostport = hostport.lower()
    if not hostport:
        return None
    rebuilt = f"{scheme.lower()}://{userinfo}{at_sign}{hostport}{rest}"
    try:
        host = urlsplit(rebuilt).hostname or ""
    except ValueError:
        return None
    return (rebuilt, host) if host else None


def _normalize_email(raw: str) -> str | None:
    """Return a lower-cased e-mail address with a valid domain, or ``None``."""
    local, sep, domain = raw.strip().strip("<>").rpartition("@")
    if not sep or not local or len(local) > _MAX_LOCAL_PART:
        return None
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    normalized = _normalize_hostname(domain)
    return f"{local.lower()}@{normalized}" if normalized else None


def _is_reportable_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, include_non_public: bool
) -> bool:
    """Decide whether an IP is worth listing as an IOC."""
    if ip.is_unspecified or ip.is_multicast:
        return False
    if include_non_public or ip.is_global:
        return True
    return any(ip.version == net.version and ip in net for net in _DOC_NETWORKS)


# ====================================================================== accumulator
@dataclass
class _Sighting:
    count: int = 0
    sources: list[IOCSource] = field(default_factory=list)


class _Collector:
    """De-duplicating, size-capped store of indicators in first-seen order."""

    def __init__(self, max_per_type: int) -> None:
        self._cap = max_per_type
        self._items: dict[tuple[IOCType, str], _Sighting] = {}
        self._per_type: dict[IOCType, int] = {}
        self._warned: set[str] = set()
        self.warnings: list[str] = []

    def warn_once(self, key: str, message: str) -> None:
        """Record ``message`` once per ``key``."""
        if key not in self._warned:
            self._warned.add(key)
            self.warnings.append(message)

    def add(self, ioc_type: IOCType, value: str, source: IOCSource) -> None:
        """Record one sighting of an indicator."""
        key = (ioc_type, value)
        sighting = self._items.get(key)
        if sighting is None:
            if self._per_type.get(ioc_type, 0) >= self._cap:
                self.warn_once(
                    f"cap:{ioc_type.value}",
                    f"IOC limit ({self._cap}) reached for {ioc_type.value}; "
                    "additional indicators of that type were dropped.",
                )
                return
            sighting = self._items[key] = _Sighting()
            self._per_type[ioc_type] = self._per_type.get(ioc_type, 0) + 1
        sighting.count += 1
        if source not in sighting.sources:
            sighting.sources.append(source)

    def build(self) -> list[IOC]:
        """Return IOCs grouped by type, first-seen order within each type."""
        rank = {t: i for i, t in enumerate(_TYPE_ORDER)}
        ordered = sorted(self._items.items(), key=lambda kv: rank[kv[0][0]])
        return [
            IOC(
                type=ioc_type,
                value=value,
                defanged=defang_ioc(ioc_type, value),
                sources=list(sighting.sources),
                count=sighting.count,
            )
            for (ioc_type, value), sighting in ordered
        ]


# ================================================================== HTML collection
class _HtmlCollector(HTMLParser):
    """Collects URL-bearing attributes, code blocks, comments, and visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_values: list[str] = []
        self.code: list[str] = []
        self.text: list[str] = []
        self._code_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._code_depth += 1
        attr_map = {name.lower(): value for name, value in attrs if value}
        for name, value in attr_map.items():
            if name in _URL_ATTRS:
                self.attr_values.append(value)
            elif name == "style":
                self.code.append(value)
        if tag == "meta" and attr_map.get("http-equiv", "").lower() == "refresh":
            found = _META_URL_RE.search(attr_map.get("content", ""))
            if found:
                self.attr_values.append(found.group(1))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._code_depth > 0:
            self._code_depth -= 1

    def handle_data(self, data: str) -> None:
        (self.code if self._code_depth else self.text).append(data)

    def handle_comment(self, data: str) -> None:
        self.code.append(data)


# ======================================================================== scanner
class _Scanner:
    """One extraction run. Holds all mutable state, so extractors are thread-safe."""

    def __init__(self, max_per_type: int, include_non_public_ips: bool) -> None:
        self.collector = _Collector(max_per_type)
        self._include_non_public = include_non_public_ips

    # ---------------------------------------------------------------- primitives
    def _truncate(self, text: str, label: str) -> str:
        if len(text) > _MAX_SCAN_CHARS:
            self.collector.warn_once(
                f"trunc:{label}",
                f"{label} exceeds {_MAX_SCAN_CHARS:,} characters; only the start was scanned for IOCs.",
            )
            return text[:_MAX_SCAN_CHARS]
        return text

    def _add_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, source: IOCSource) -> None:
        if _is_reportable_ip(ip, self._include_non_public):
            ioc_type = IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
            self.collector.add(ioc_type, str(ip), source)

    def _add_host(self, host: str, source: IOCSource) -> None:
        try:
            self._add_ip(ipaddress.ip_address(host), source)
            return
        except ValueError:
            pass
        numeric = _decode_numeric_host(host)
        if numeric is not None:
            self._add_ip(numeric, source)
            return
        domain = _normalize_hostname(host)
        if domain:
            self.collector.add(IOCType.DOMAIN, domain, source)

    def _add_url(self, raw: str, source: IOCSource) -> None:
        normalized = _normalize_url(raw)
        if normalized is None:
            return
        url, host = normalized
        self.collector.add(IOCType.URL, url, source)
        self._add_host(host, source)

    def _add_email(self, raw: str, source: IOCSource) -> None:
        address = _normalize_email(raw)
        if address is None:
            return
        self.collector.add(IOCType.EMAIL, address, source)
        self.collector.add(IOCType.DOMAIN, address.rpartition("@")[2], source)

    # ------------------------------------------------------------------ scanners
    def scan_ips(self, text: str, source: IOCSource) -> None:
        """Find IPv4 and IPv6 literals in ``text`` (already refanged)."""
        text = _IPV6_TAG_RE.sub(" ", text)
        for match in _IPV4_RE.finditer(text):
            try:
                self._add_ip(ipaddress.IPv4Address(match.group(0)), source)
            except ValueError:
                continue
        for match in _IPV6_RE.finditer(text):
            try:
                self._add_ip(ipaddress.IPv6Address(match.group(0)), source)
            except ValueError:
                continue

    def _scan_urls_only(self, text: str, source: IOCSource) -> None:
        for match in _URL_RE.finditer(refang(text)):
            self._add_url(match.group(0), source)

    def scan_text(self, text: str, source: IOCSource, label: str) -> None:
        """Scan free text for URLs, e-mails and IPs."""
        if not isinstance(text, str) or not text:
            return
        refanged = refang(self._truncate(text, label))

        def take_url(match: re.Match[str]) -> str:
            self._add_url(match.group(0), source)
            return " "

        def take_www(match: re.Match[str]) -> str:
            self._add_url(f"http://{match.group(0)}", source)
            return " "

        # URLs are blanked out before e-mail scanning so that user-info
        # (``http://a@b``) and query parameters are not reported as addresses.
        masked = _URL_RE.sub(take_url, refanged)
        masked = _WWW_RE.sub(take_www, masked)
        for match in _EMAIL_RE.finditer(masked):
            self._add_email(match.group(0), source)
        self.scan_ips(refanged, source)

    def scan_html(self, html: str) -> None:
        """Parse an HTML body and scan attributes, code, comments, and text."""
        if not isinstance(html, str) or not html:
            return
        html = self._truncate(html, "HTML body")
        parser = _HtmlCollector()
        try:
            parser.feed(html)
            parser.close()
        except Exception:  # noqa: BLE001 - html.parser can fail on hostile markup
            logger.debug("HTML parsing failed; falling back to raw scan", exc_info=True)
            self.collector.warn_once(
                "html-parse",
                "HTML body could not be fully parsed; the raw markup was scanned as text as well.",
            )
            self.scan_text(html, IOCSource.BODY_HTML, "HTML body")

        for value in parser.attr_values:
            self._scan_attribute(value)
        for chunk in parser.code:
            self._scan_urls_only(chunk, IOCSource.BODY_HTML)
        self.scan_text("\n".join(parser.text), IOCSource.BODY_HTML, "HTML text")

    def _scan_attribute(self, value: str) -> None:
        """Handle one URL-bearing HTML attribute value."""
        cleaned = _ATTR_WS_RE.sub("", value).strip()
        if not cleaned:
            return
        if cleaned.lower().startswith("mailto:"):
            for part in cleaned[7:].split("?", 1)[0].split(","):
                self._add_email(unquote(part.strip()), IOCSource.BODY_HTML)
            return
        if cleaned.startswith("//") and len(cleaned) > 2:
            cleaned = f"http:{cleaned}"  # protocol-relative URL
        self._scan_urls_only(cleaned, IOCSource.BODY_HTML)

    def scan_message(self, message: ParsedMessage) -> None:
        """Scan headers, then text body, then HTML body; one failing stage never stops the rest."""
        stages = (
            ("headers", lambda: self._scan_headers(message)),
            (
                "text body",
                lambda: self.scan_text(message.body_text, IOCSource.BODY_TEXT, "Text body"),
            ),
            ("HTML body", lambda: self.scan_html(message.body_html)),
        )
        for label, stage in stages:
            try:
                stage()
            except Exception:  # noqa: BLE001 - degrade gracefully
                logger.exception("IOC extraction failed for %s", label)
                self.collector.warnings.append(
                    f"IOC extraction from the {label} failed; results may be incomplete."
                )

    def _scan_headers(self, message: ParsedMessage) -> None:
        for header in message.headers:
            name = header.name.strip().lower()
            if name in _SKIP_HEADERS:
                continue
            if name in _RECEIVED_HEADERS:
                self.scan_ips(
                    refang(self._truncate(header.value, "Received header")), IOCSource.RECEIVED
                )
                continue
            value = message.subject if name == "subject" and message.subject else header.value
            self.scan_text(value, IOCSource.HEADERS, f"Header {header.name}")


# ===================================================================== public API
class IOCExtractor:
    """Extract IOCs from parsed messages or raw text."""

    def __init__(self, max_per_type: int = 500, include_non_public_ips: bool = False) -> None:
        """Create an extractor.

        Args:
            max_per_type: Maximum distinct IOCs kept per type; extra ones are
                dropped with a warning (sightings of kept IOCs still count).
            include_non_public_ips: Also report private, loopback and
                link-local addresses.
        """
        self._max_per_type = max(1, max_per_type)
        self._include_non_public = include_non_public_ips

    def extract(self, message: ParsedMessage) -> ExtractionResult:
        """Extract IOCs from a :class:`ParsedMessage`."""
        scanner = _Scanner(self._max_per_type, self._include_non_public)
        scanner.scan_message(message)
        return ExtractionResult(iocs=scanner.collector.build(), warnings=scanner.collector.warnings)

    def extract_text(self, text: str, source: IOCSource = IOCSource.BODY_TEXT) -> ExtractionResult:
        """Extract IOCs from arbitrary text (used by the CLI ``--ioc-text`` style helpers)."""
        scanner = _Scanner(self._max_per_type, self._include_non_public)
        try:
            scanner.scan_text(text, source, "Text")
        except Exception:  # noqa: BLE001
            logger.exception("IOC extraction from text failed")
            scanner.collector.warnings.append(
                "IOC extraction from text failed; results may be incomplete."
            )
        return ExtractionResult(iocs=scanner.collector.build(), warnings=scanner.collector.warnings)


def extract_iocs(message: ParsedMessage, settings: Settings | None = None) -> ExtractionResult:
    """Extract IOCs from ``message`` using limits from ``settings``."""
    cfg = settings or get_settings()
    return IOCExtractor(max_per_type=cfg.max_iocs_per_type).extract(message)
