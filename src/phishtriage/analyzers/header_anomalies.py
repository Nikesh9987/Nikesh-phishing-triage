"""Heuristic header, content and link anomaly detection -> scored findings.

Inputs: the parsed message, plus (all optional) the extracted IOCs, the
:class:`AuthReport` and the :class:`ReceivedTrace`. Output: de-duplicated
:class:`Finding` objects, one per ``code``, sorted most severe first.

Checks
------
* **Header consistency:** missing/multiple/unparseable ``From``; ``Reply-To``,
  ``Return-Path``, ``Sender`` and ``Message-ID`` domains that differ from the
  From domain; missing/future ``Date``; a fake ``Re:``/``Fwd:`` thread.
* **Display-name spoofing:** an e-mail address or domain in the display name
  that differs from the real sender, hidden characters, and brand names used
  from an unrelated (especially free-mail) domain.
* **Lookalike domains:** confusable characters (``paypa1``, ``rnicrosoft``,
  Cyrillic/Greek lookalikes), one-edit typosquats, brand-plus-lure names
  (``paypal-secure``) and brands used as subdomains (``paypal.com.evil.example``),
  for the sender, Reply-To and domains found in the content. IDN/punycode
  hosts are assessed for mixed scripts.
* **HTML body:** anchors whose visible text shows one site but link to another,
  forms, and password fields.
* **URLs:** user-info tricks (``http://paypal.com@evil.example``), IP and
  numeric hosts, IDN hosts, link shorteners.
* **Language:** urgency, credential, financial and BEC-style phrases.
* **Authentication / Received trace:** converts SPF/DKIM/DMARC results and hop
  anomalies into findings.

Limits, stated plainly:

* These are *heuristics*. Each finding is a prompt for an analyst, not a
  verdict; legitimate bulk mail often trips LOW findings. Step 15 decides
  weighting.
* The built-in brand list is small (see :data:`DEFAULT_BRANDS`); pass your own
  ``brands`` mapping to extend it. A brand name registered under a different
  TLD with the *same* label (``paypal.net``) is deliberately not flagged,
  because it cannot be distinguished from legitimate regional domains here.
* Language matching is English only.
* Trace findings match the anomaly wording produced by ``received_tracer.py``.

Every string placed in a finding is defanged and stripped of control/bidi
characters, so reports and ticket copy are safe to paste. Each stage is
isolated: a failure becomes a warning and the other stages still run.
"""

import ipaddress
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from typing import Final
from urllib.parse import urlsplit

from phishtriage.core.defang import defang_text, refang
from phishtriage.core.models import (
    IOC,
    SEVERITY_WEIGHT,
    AuthReport,
    AuthSource,
    AuthStatus,
    Finding,
    IOCType,
    ParsedMessage,
    ReceivedTrace,
    Severity,
)
from phishtriage.core.utils import org_domain
from phishtriage.logging_config import get_logger
from phishtriage.parsers.base import parse_addresses

__all__ = ["DEFAULT_BRANDS", "AnomalyAnalyzer", "AnomalyResult", "analyze_anomalies"]

logger = get_logger(__name__)

_S = Severity
_MAX_EVIDENCE: Final = 10
_MAX_TEXT: Final = 300
_MAX_HTML: Final = 2_000_000
_MAX_LANG_CHARS: Final = 100_000
_MAX_ANCHORS: Final = 2000
_MAX_FORMS: Final = 20
_MAX_URLS: Final = 500
_MAX_CONTENT_DOMAINS: Final = 100
_FUTURE_TOLERANCE: Final = timedelta(days=1)
_DATE_SKEW: Final = timedelta(days=3)


# ============================================================== reference data
def _brands(**mapping: str) -> dict[str, frozenset[str]]:
    return {name: frozenset(domains.split()) for name, domains in mapping.items()}


#: Brand label -> registrable domains that legitimately use it. Extend freely.
DEFAULT_BRANDS: Final[dict[str, frozenset[str]]] = _brands(
    paypal="paypal.com paypal.me paypal.co.uk paypalobjects.com",
    microsoft=(
        "microsoft.com office.com office365.com outlook.com live.com hotmail.com msn.com "
        "microsoftonline.com sharepoint.com onedrive.com windows.com xbox.com skype.com "
        "azure.com bing.com"
    ),
    apple="apple.com icloud.com me.com",
    google="google.com gmail.com googlemail.com youtube.com goo.gl withgoogle.com",
    amazon="amazon.com amazon.co.uk amazon.de amazon.in amazon.ca amazon.fr amazonaws.com",
    netflix="netflix.com nflxext.com",
    facebook="facebook.com facebookmail.com fb.com meta.com",
    instagram="instagram.com",
    linkedin="linkedin.com",
    dropbox="dropbox.com dropboxmail.com",
    docusign="docusign.com docusign.net",
    adobe="adobe.com adobesign.com",
    dhl="dhl.com dhl.de",
    fedex="fedex.com",
    ups="ups.com",
    chase="chase.com jpmorgan.com",
    wellsfargo="wellsfargo.com",
    bankofamerica="bankofamerica.com bofa.com",
    citibank="citibank.com citi.com",
    americanexpress="americanexpress.com aexp.com",
    coinbase="coinbase.com",
    binance="binance.com",
    whatsapp="whatsapp.com whatsapp.net",
)

_FREEMAIL: Final = frozenset(
    {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
     "ymail.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com",
     "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "msn.com"}
)  # fmt: skip
_SHORTENERS: Final = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
     "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in"}
)  # fmt: skip
_LURE_WORDS: Final = frozenset(
    {"secure", "security", "support", "login", "signin", "verify", "verification", "account",
     "service", "services", "update", "billing", "alert", "alerts", "help", "team", "online",
     "pay", "payment", "mail", "notice", "center", "portal", "customer", "care", "official"}
)  # fmt: skip

_CONFUSABLES: Final = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "5": "s",
     "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
     "ј": "j", "ѕ": "s", "ӏ": "l", "ο": "o", "α": "a", "ρ": "p", "ν": "v", "τ": "t", "ι": "i"}
)  # fmt: skip

# ================================================================== patterns
_EMAIL_RE: Final = re.compile(
    r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,8}"
)
_DOMAINISH_RE: Final = re.compile(
    r"(?i)(?<![\w.\-])(?:[a-z0-9\-]{1,63}\.){1,6}[a-z]{2,24}(?![\w\-])"
)
_BARE_DOMAIN_RE: Final = re.compile(r"(?<![\w\[.])[\w\-]+(?:\.[\w\-]+)+(?![\w\]])")
_TEXT_URL_RE: Final = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']{3,300}""")
_BARE_HOST_RE: Final = re.compile(
    r"(?i)[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,62}[a-z0-9])?){0,6}\.[a-z]{2,24}(?:[/:?#]\S{0,300})?"
)
_NUMERIC_HOST_RE: Final = re.compile(r"(?i)^(?:\d{1,10}|0x[0-9a-f]{1,8})$")
_WS_RE: Final = re.compile(r"[\t\r\n]")
_REPLY_SUBJECT_RE: Final = re.compile(r"(?i)^\s*(?:re|fwd?)\s*:")


def _rx(*phrases: str) -> re.Pattern[str]:
    return re.compile(r"(?i)\b(?:" + "|".join(phrases) + r")\b")


_LANGUAGE: Final[dict[str, re.Pattern[str]]] = {
    "urgency": _rx(
        r"urgent(?:ly)?", r"immediate(?:ly)?", r"act\s+now", r"action\s+required",
        r"final\s+(?:notice|warning|reminder)", r"within\s+\d{1,3}\s+(?:hours?|days?)",
        r"expires?\s+(?:today|soon|in)",
        r"(?:will|may)\s+be\s+(?:suspended|closed|locked|terminated|disabled|deactivated)",
        r"failure\s+to\s+(?:respond|comply|verify|act)",
    ),
    "credentials": _rx(
        r"verify\s+your\s+(?:account|identity|email|password|information)",
        r"confirm\s+your\s+(?:account|identity|password|details)",
        r"(?:reset|update)\s+your\s+password", r"log\s?in\s+(?:to|now|here)",
        r"sign\s?in\s+(?:to|now|here)", r"security\s+alert",
        r"unusual\s+(?:sign-?in|activity|login)", r"password\s+(?:expires?|expired|expiry)",
        r"unauthori[sz]ed\s+(?:access|login|activity|transaction)",
    ),
    "financial": _rx(
        r"wire\s+transfer", r"gift\s+cards?", r"bank\s+(?:details|account)", r"invoice",
        r"overdue\s+payment", r"payment\s+(?:failed|declined|pending|required)", r"refund",
        r"direct\s+deposit", r"payroll",
    ),
    "secrecy_or_bec": _rx(
        r"keep\s+(?:this\s+)?(?:confidential|private|between\s+us)",
        r"are\s+you\s+(?:available|at\s+your\s+desk)", r"i\s+need\s+(?:a\s+)?favou?r",
        r"do\s+not\s+(?:call|discuss)", r"(?:quick|urgent)\s+task",
    ),
}  # fmt: skip


# ================================================================ small helpers
def _safe(value: object) -> str:
    """Render text for reports: collapse whitespace, escape control/bidi chars, defang."""
    text = " ".join(str(value)[:_MAX_TEXT].split())
    text = "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf") else c for c in text
    )
    text = defang_text(text)
    return _BARE_DOMAIN_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)


class _Findings:
    """Collects findings, merging evidence and keeping the highest severity per code."""

    def __init__(self) -> None:
        self._items: dict[str, Finding] = {}

    def add(
        self,
        code: str,
        severity: Severity,
        title: str,
        detail: str = "",
        evidence: Iterable[object] = (),
    ) -> None:
        shown = [e for e in (_safe(x) for x in evidence) if e]
        existing = self._items.get(code)
        if existing is None:
            self._items[code] = Finding(
                code=code,
                severity=severity,
                title=title[:200],
                detail=detail[:600],
                evidence=list(dict.fromkeys(shown))[:_MAX_EVIDENCE],
            )
            return
        existing.evidence = list(dict.fromkeys([*existing.evidence, *shown]))[:_MAX_EVIDENCE]
        if SEVERITY_WEIGHT[severity] > SEVERITY_WEIGHT[existing.severity]:
            existing.severity = severity

    def build(self) -> list[Finding]:
        return sorted(self._items.values(), key=lambda f: -SEVERITY_WEIGHT[f.severity])


def _idn_view(domain: str) -> tuple[str, str]:
    """Return ``(ascii_form, unicode_form)`` of a domain; never raises."""
    d = domain.strip().rstrip(".").lower()
    if not d:
        return "", ""
    if d.isascii():
        if "xn--" not in d:
            return d, d
        try:
            return d, d.encode("ascii").decode("idna")
        except UnicodeError:
            return d, d
    try:
        return d.encode("idna").decode("ascii"), d
    except UnicodeError:
        return d, d


def _org(domain: str) -> str:
    """Organizational domain of ``domain`` ('' if empty)."""
    ascii_d = _idn_view(domain)[0]
    return org_domain(ascii_d) if ascii_d else ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _host_of(url: str) -> str:
    candidate = url if "://" in url else f"http://{url}"
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def _same_site(a: str, b: str) -> bool:
    if a == b:
        return True
    if _is_ip(a) or _is_ip(b):
        return False
    return org_domain(_idn_view(a)[0]) == org_domain(_idn_view(b)[0])


def _scripts(label: str) -> set[str]:
    found: set[str] = set()
    for char in label:
        if char.isalpha():
            try:
                found.add(unicodedata.name(char).split(" ", 1)[0])
            except ValueError:
                continue
    return found


def _idn_assess(domain: str) -> tuple[Severity, str] | None:
    """Assess an internationalized domain; ``None`` for plain ASCII."""
    ascii_d, uni = _idn_view(domain)
    if "xn--" not in ascii_d and uni.isascii():
        return None
    all_scripts: set[str] = set()
    for label in uni.split("."):
        scripts = _scripts(label)
        if len(scripts) > 1:
            return _S.HIGH, f"a label mixes writing systems ({', '.join(sorted(scripts))})"
        all_scripts |= scripts
    if all_scripts - {"LATIN"}:
        return _S.MEDIUM, f"non-Latin internationalized domain ({', '.join(sorted(all_scripts))})"
    return _S.LOW, "internationalized domain with accented Latin characters"


def _skeleton(label: str) -> str:
    return label.lower().translate(_CONFUSABLES).replace("vv", "w").replace("rn", "m")


def _osa(a: str, b: str, limit: int = 2) -> int:
    """Optimal-string-alignment distance (adjacent swaps cost 1); ``limit + 1`` if farther."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            value = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                value = min(value, prev2[j - 2] + 1)
            cur[j] = value
        prev2, prev = prev, cur
    return prev[-1]


def _lookalike(
    domain: str, brands: Mapping[str, frozenset[str]]
) -> tuple[str, str, Severity] | None:
    """Return ``(brand, reason, severity)`` if ``domain`` imitates a known brand."""
    ascii_d, _ = _idn_view(domain)
    if not ascii_d:
        return None
    org = org_domain(ascii_d)
    if not org or "." not in org:
        return None
    label = _idn_view(org)[1].split(".")[0]
    skeleton = _skeleton(label)
    sub = ascii_d[: -len(org)].rstrip(".") if ascii_d.endswith(org) else ""
    sub_tokens = {t for part in sub.split(".") for t in part.split("-") if t}
    tokens = [t for t in skeleton.split("-") if t]

    for brand, legit in brands.items():
        if org in legit or label == brand:
            continue
        if skeleton == brand:
            return brand, f"imitates '{brand}' with look-alike characters", _S.HIGH
        if len(brand) >= 6 and _osa(skeleton, brand) == 1:
            return brand, f"is one character away from '{brand}'", _S.HIGH
        if len(tokens) > 1 and brand in tokens:
            return brand, f"embeds the brand name '{brand}'", _S.MEDIUM
        if len(brand) >= 6 and brand in skeleton:
            rest = [t for t in re.split(r"[-_\d]+", skeleton.replace(brand, "", 1)) if t]
            if rest and all(t in _LURE_WORDS for t in rest):
                return brand, f"combines '{brand}' with a lure word", _S.MEDIUM
        if brand in sub_tokens:
            severity = _S.HIGH if any(d in sub for d in legit) else _S.MEDIUM
            return brand, f"uses '{brand}' as a subdomain of an unrelated domain", severity
    return None


def _mentions_brand(name: str, brand: str) -> bool:
    words = re.findall(r"[a-z0-9]+", name.lower())
    return brand in words or (len(brand) >= 8 and brand in "".join(words))


# =============================================================== HTML collection
class _HtmlProbe(HTMLParser):
    """Collects anchors (href + visible text), visible text, forms and password inputs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.text: list[str] = []
        self.form_actions: list[str] = []
        self.password_inputs = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0

    def _close_anchor(self) -> None:
        if self._href is not None and len(self.anchors) < _MAX_ANCHORS:
            self.anchors.append((self._href, " ".join("".join(self._anchor_text).split())))
        self._href = None
        self._anchor_text = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._close_anchor()
            if "href" in attr:
                self._href = attr["href"]
        elif tag == "form" and len(self.form_actions) < _MAX_FORMS:
            self.form_actions.append(attr.get("action", ""))
        elif tag == "input" and attr.get("type", "").strip().lower() == "password":
            self.password_inputs += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)

    def close(self) -> None:
        super().close()
        self._close_anchor()


def _clean_href(href: str) -> str:
    cleaned = _WS_RE.sub("", href).strip()
    if cleaned.startswith("//"):
        cleaned = f"http:{cleaned}"
    return cleaned if cleaned.lower().startswith(("http://", "https://")) else ""


#: Last labels that are file extensions, not top-level domains ("invoice.pdf" is a file name).
_FILE_EXTENSIONS: Final = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rar", "png", "jpg",
     "jpeg", "gif", "exe", "html", "htm", "rtf", "eml", "msg", "dll", "js", "bat", "iso"}
)  # fmt: skip


def _visible_host(text: str) -> str:
    """Host that the visible link text *claims* to point at ('' if it shows none)."""
    shown = refang(text)[:400].strip()
    match = _TEXT_URL_RE.search(shown)
    if match:
        return _host_of(match.group(0))
    if _BARE_HOST_RE.fullmatch(shown):
        host = _host_of(shown)
        return "" if host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS else host
    return ""


# ===================================================================== analyzer
@dataclass
class AnomalyResult:
    """Findings plus non-fatal warnings from the analysis stages."""

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class AnomalyAnalyzer:
    """Run all anomaly checks for one message."""

    def __init__(self, brands: Mapping[str, Iterable[str]] | None = None) -> None:
        """Create an analyzer.

        Args:
            brands: Brand label -> legitimate registrable domains. Defaults to
                :data:`DEFAULT_BRANDS`. Labels and domains are lower-cased.
        """
        source = DEFAULT_BRANDS if brands is None else brands
        self._brands: dict[str, frozenset[str]] = {
            str(name).strip().lower(): frozenset(d.strip().lower() for d in domains)
            for name, domains in source.items()
            if str(name).strip()
        }

    # ----------------------------------------------------------------- public API
    def analyze(
        self,
        message: ParsedMessage,
        *,
        iocs: Sequence[IOC] = (),
        auth: AuthReport | None = None,
        trace: ReceivedTrace | None = None,
    ) -> AnomalyResult:
        """Analyze ``message``. Stages for omitted inputs are skipped."""
        findings = _Findings()
        warnings: list[str] = []
        visible: list[str] = []

        stages: list[tuple[str, Callable[[], None]]] = [
            ("header consistency", lambda: self._header_checks(message, findings)),
            ("display name", lambda: self._display_name_checks(message, findings)),
            ("lookalike domain", lambda: self._lookalike_checks(message, iocs, findings)),
            ("HTML body", lambda: visible.append(self._html_checks(message, findings))),
            ("URL", lambda: self._url_checks(iocs, findings)),
            (
                "language",
                lambda: self._language_checks(message, visible[-1] if visible else "", findings),
            ),
        ]
        if auth is not None:
            stages.append(("authentication", lambda: self._auth_checks(auth, findings)))
        if trace is not None:
            stages.append(("received-trace", lambda: self._trace_checks(message, trace, findings)))

        for label, stage in stages:
            try:
                stage()
            except Exception:  # noqa: BLE001 - one failing heuristic must not hide the others
                logger.exception("Anomaly stage %r failed", label)
                warnings.append(f"The {label} checks failed; findings may be incomplete.")
        return AnomalyResult(findings=findings.build(), warnings=warnings)

    # ------------------------------------------------------- header consistency
    def _header_checks(self, msg: ParsedMessage, f: _Findings) -> None:
        values = msg.get_headers("From")
        sender = msg.from_address
        if not values:
            f.add("missing_from", _S.MEDIUM, "Message has no From header")
        elif len(values) > 1:
            f.add(
                "multiple_from", _S.HIGH, "Message has multiple From headers",
                "Clients may display a different sender than the one that was authenticated.",
                values,
            )  # fmt: skip
        if values and (sender is None or not sender.address):
            f.add(
                "unparseable_from",
                _S.MEDIUM,
                "From header has no valid address",
                evidence=values[:1],
            )
        elif sender is not None and sender.address.lower().startswith("/o="):
            f.add(
                "exchange_x500_sender", _S.LOW, "Sender is an Exchange X.500 address",
                "Internal identifier, not a routable SMTP address (typical of .msg exports).",
                [sender.address],
            )  # fmt: skip

        from_domain = sender.domain if sender else ""
        from_org = _org(from_domain)

        if from_org:
            self._reply_to(msg, from_domain, from_org, f)
            self._return_path(msg, from_org, f)
            for sender_hdr in parse_addresses(msg.get_headers("Sender"))[:1]:
                if sender_hdr.domain and _org(sender_hdr.domain) != from_org:
                    f.add(
                        "sender_header_mismatch", _S.LOW,
                        "Sender header domain differs from From",
                        evidence=[f"From {from_domain} / Sender {sender_hdr.address}"],
                    )  # fmt: skip
            mid_domain = msg.message_id.rpartition("@")[2]
            if mid_domain and _org(mid_domain) != from_org:
                f.add(
                    "message_id_domain_mismatch", _S.INFO,
                    "Message-ID domain differs from the From domain",
                    "Common with ESPs; notable when combined with other findings.",
                    [f"From {from_domain} / Message-ID {msg.message_id}"],
                )  # fmt: skip

        if not msg.message_id:
            f.add("missing_message_id", _S.LOW, "Message has no Message-ID")
        date_header = msg.get_header("Date")
        if date_header is None:
            f.add("missing_date", _S.LOW, "Message has no Date header")
        elif msg.date is None:
            f.add(
                "unparseable_date",
                _S.LOW,
                "Date header could not be parsed",
                evidence=[date_header],
            )
        elif msg.date > datetime.now(UTC) + _FUTURE_TOLERANCE:
            f.add("date_in_future", _S.LOW, "Date header is in the future", evidence=[date_header])

        if (
            _REPLY_SUBJECT_RE.match(msg.subject)
            and msg.get_header("In-Reply-To") is None
            and msg.get_header("References") is None
        ):
            f.add(
                "fake_reply_thread", _S.LOW, "Subject claims a reply or forward, but no thread exists",
                "Re:/Fwd: with no In-Reply-To or References is a common trust trick.",
                [msg.subject],
            )  # fmt: skip

    @staticmethod
    def _reply_to(msg: ParsedMessage, from_domain: str, from_org: str, f: _Findings) -> None:
        for reply in msg.reply_to:
            if not reply.domain or _org(reply.domain) == from_org:
                continue
            freemail = reply.domain in _FREEMAIL and from_domain not in _FREEMAIL
            f.add(
                "reply_to_mismatch",
                _S.HIGH if freemail else _S.MEDIUM,
                "Reply-To domain differs from the From domain",
                "Replies would go to a different party than the apparent sender"
                + (" (a free-mail account)." if freemail else "."),
                [f"From {from_domain} / Reply-To {reply.address}"],
            )

    @staticmethod
    def _return_path(msg: ParsedMessage, from_org: str, f: _Findings) -> None:
        path = msg.return_path.strip()
        domain = path.rpartition("@")[2] if "@" in path else ""
        if domain and _org(domain) != from_org:
            f.add(
                "return_path_mismatch", _S.LOW, "Return-Path domain differs from the From domain",
                "Normal for bulk senders and mailing lists; suspicious when combined with SPF/DMARC failures.",
                [f"Return-Path {path} / From domain {from_org}"],
            )  # fmt: skip

    # ------------------------------------------------------------- display name
    def _display_name_checks(self, msg: ParsedMessage, f: _Findings) -> None:
        sender = msg.from_address
        if sender is None or not sender.display_name:
            return
        name = sender.display_name[:500]
        from_org = _org(sender.domain)

        if any(unicodedata.category(c) in ("Cc", "Cf") for c in name):
            f.add(
                "display_name_hidden_characters", _S.MEDIUM,
                "Display name contains invisible or direction-control characters",
                evidence=[name],
            )  # fmt: skip

        refanged = refang(name)
        for address in _EMAIL_RE.findall(refanged)[:3]:
            domain = address.rpartition("@")[2].lower()
            if address.lower() != sender.address.lower() and _org(domain) != from_org:
                f.add(
                    "display_name_address_spoof", _S.HIGH,
                    "Display name shows a different e-mail address than the real sender",
                    "Many mail clients show only the display name.",
                    [f"Display name '{name}' / actual sender {sender.address}"],
                )  # fmt: skip
        without_emails = _EMAIL_RE.sub(" ", refanged)
        for domain in _DOMAINISH_RE.findall(without_emails)[:3]:
            if from_org and _org(domain) != from_org:
                f.add(
                    "display_name_domain_mismatch", _S.MEDIUM,
                    "Display name names a domain that is not the sender's domain",
                    evidence=[f"Display name '{name}' / sender domain {sender.domain}"],
                )  # fmt: skip

        from_label = from_org.split(".")[0]
        if not from_org:
            return
        for brand, legit in self._brands.items():
            if not _mentions_brand(name, brand) or from_org in legit or from_label == brand:
                continue
            freemail = from_org in _FREEMAIL
            f.add(
                "display_name_brand_impersonation",
                _S.HIGH if freemail else _S.MEDIUM,
                "Display name uses a brand name from an unrelated sender domain",
                f"'{brand}' is not associated with the sender domain"
                + (", which is a free-mail provider." if freemail else "."),
                [f"Display name '{name}' / sender {sender.address}"],
            )

    # ----------------------------------------------------------- lookalike domains
    def _lookalike_checks(self, msg: ParsedMessage, iocs: Sequence[IOC], f: _Findings) -> None:
        own: list[str] = []
        if msg.from_address and msg.from_address.domain:
            own.append(msg.from_address.domain)
        own.extend(r.domain for r in msg.reply_to if r.domain)

        for domain in dict.fromkeys(own):
            idn = _idn_assess(domain)
            if idn is not None:
                f.add(
                    "idn_sender_domain", idn[0], "Sender uses an internationalized domain name",
                    f"The domain is {idn[1]}.", [domain],
                )  # fmt: skip
            hit = _lookalike(domain, self._brands)
            if hit is not None:
                f.add(
                    "lookalike_sender_domain", hit[2], "Sender domain imitates a known brand",
                    f"The domain {hit[1]}.", [domain],
                )  # fmt: skip

        sender_orgs = {_org(d) for d in own}
        seen: set[str] = set()
        for ioc in iocs:
            if ioc.type is not IOCType.DOMAIN or len(seen) >= _MAX_CONTENT_DOMAINS:
                continue
            org = _org(ioc.value)
            if not org or org in seen or org in sender_orgs:
                continue
            seen.add(org)
            hit = _lookalike(ioc.value, self._brands)
            if hit is not None:
                f.add(
                    "lookalike_domain_in_content", hit[2],
                    "Message links to or mentions a domain imitating a known brand",
                    f"The domain {hit[1]}.", [ioc.value],
                )  # fmt: skip

    # ------------------------------------------------------------------ HTML body
    def _html_checks(self, msg: ParsedMessage, f: _Findings) -> str:
        """Check anchors/forms; returns the visible HTML text for language analysis."""
        html = msg.body_html
        if not html:
            return ""
        probe = _HtmlProbe()
        try:
            probe.feed(html[:_MAX_HTML])
            probe.close()
        except Exception:  # noqa: BLE001 - html.parser can fail on hostile markup
            logger.debug("HTML parsing stopped early", exc_info=True)

        for href, text in probe.anchors:
            url = _clean_href(href)
            shown = _visible_host(text) if url and text else ""
            target = _host_of(url) if url else ""
            if shown and target and not _same_site(shown, target):
                f.add(
                    "link_text_mismatch", _S.HIGH,
                    "Link text shows one website but the link goes to another",
                    "Classic phishing disguise: the visible address is not where the link leads.",
                    [f"text '{text[:80]}' links to {url[:120]}"],
                )  # fmt: skip
        if probe.form_actions:
            f.add(
                "html_form_in_body", _S.MEDIUM, "Message body contains an HTML form",
                "Legitimate mail rarely embeds forms; they are used to harvest input directly.",
                [a or "(no action)" for a in probe.form_actions],
            )  # fmt: skip
        if probe.password_inputs:
            f.add(
                "html_password_field", _S.HIGH, "Message body contains a password field",
                f"{probe.password_inputs} password input(s) found in the HTML body.",
            )  # fmt: skip
        return " ".join(probe.text)

    # ----------------------------------------------------------------------- URLs
    @staticmethod
    def _url_checks(iocs: Sequence[IOC], f: _Findings) -> None:
        checked = 0
        for ioc in iocs:
            if ioc.type is not IOCType.URL:
                continue
            checked += 1
            if checked > _MAX_URLS:
                break
            try:
                parts = urlsplit(ioc.value)
                host = (parts.hostname or "").rstrip(".").lower()
                user = parts.username
            except ValueError:
                continue
            if user and host:
                f.add(
                    "url_userinfo", _S.HIGH if "." in user else _S.MEDIUM,
                    "URL contains credentials-style user info before the real host",
                    "In http://trusted.example@evil.example the real host is after the '@'.",
                    [ioc.value],
                )  # fmt: skip
            if host and (_is_ip(host) or _NUMERIC_HOST_RE.match(host)):
                f.add(
                    "url_ip_host", _S.MEDIUM, "URL points to an IP address instead of a domain",
                    evidence=[ioc.value],
                )  # fmt: skip
            elif host:
                idn = _idn_assess(host)
                if idn is not None:
                    f.add(
                        "url_idn_host", idn[0], "URL host is an internationalized domain name",
                        f"The host is {idn[1]}.", [ioc.value],
                    )  # fmt: skip
                if org_domain(_idn_view(host)[0]) in _SHORTENERS:
                    f.add(
                        "url_shortener", _S.LOW, "URL uses a link shortener that hides its destination",
                        evidence=[ioc.value],
                    )  # fmt: skip

    # ------------------------------------------------------------------- language
    @staticmethod
    def _language_checks(msg: ParsedMessage, visible_html: str, f: _Findings) -> None:
        half = _MAX_LANG_CHARS // 2
        text = "\n".join((msg.subject, msg.body_text[:half], visible_html[:half]))
        hits: dict[str, list[str]] = {}
        for category, pattern in _LANGUAGE.items():
            phrases: list[str] = []
            for match in pattern.finditer(text):
                phrase = " ".join(match.group(0).lower().split())
                if phrase not in phrases:
                    phrases.append(phrase)
                if len(phrases) >= 5:
                    break
            if phrases:
                hits[category] = phrases

        total = sum(len(v) for v in hits.values())
        if len(hits) >= 3 or (len(hits) == 2 and total >= 4):
            severity = _S.MEDIUM
        elif total >= 2:
            severity = _S.LOW
        else:
            return
        f.add(
            "social_engineering_language", severity,
            "Message uses pressure, credential or payment language",
            f"Matched {total} phrase(s) across {len(hits)} categor{'y' if len(hits) == 1 else 'ies'}. "
            "Language alone is weak evidence; weigh it with the other findings.",
            [f"{cat}: {phrase}" for cat, phrases in hits.items() for phrase in phrases],
        )  # fmt: skip

    # ---------------------------------------------------------------------- auth
    @staticmethod
    def _auth_checks(auth: AuthReport, f: _Findings) -> None:
        spf, dmarc = auth.spf, auth.dmarc
        policy = auth.dmarc_policy

        if spf.source is AuthSource.ABSENT and not auth.dkim and dmarc.source is AuthSource.ABSENT:
            f.add(
                "authentication_unavailable", _S.LOW, "No SPF, DKIM or DMARC results are available",
                "The sender could not be authenticated from the headers.",
            )  # fmt: skip
        else:
            if not auth.dkim:
                f.add("dkim_absent", _S.LOW, "Message carries no DKIM signature")
        if dmarc.status is AuthStatus.FAIL:
            f.add(
                "dmarc_fail", _S.HIGH, "DMARC failed",
                "Neither SPF nor DKIM passed with an aligned domain.",
                [f"DMARC policy p={policy.policy or 'unspecified'}" if policy else dmarc.detail],
            )  # fmt: skip
        elif dmarc.status is AuthStatus.NONE:
            f.add(
                "dmarc_missing", _S.LOW, "The From domain publishes no DMARC policy",
                "Anyone can spoof this domain without DMARC enforcement.",
                [auth.from_domain],
            )  # fmt: skip

        if spf.status is AuthStatus.FAIL:
            f.add("spf_fail", _S.HIGH, "SPF failed", "The sending server is not authorised for the envelope domain.", [spf.detail])  # fmt: skip
        elif spf.status is AuthStatus.SOFTFAIL:
            f.add("spf_softfail", _S.MEDIUM, "SPF soft-failed", "The sending server is probably not authorised.", [spf.detail])  # fmt: skip
        elif spf.status is AuthStatus.PASS and spf.aligned is False:
            f.add(
                "spf_not_aligned", _S.MEDIUM, "SPF passed for a domain that is not the From domain",
                "A spoofed From address can still pass SPF for the attacker's own envelope domain.",
                [f"SPF domain {spf.domain} / From domain {auth.from_domain}"],
            )  # fmt: skip

        overall = auth.dkim_overall
        if overall in (AuthStatus.FAIL, AuthStatus.PERMERROR):
            f.add("dkim_fail", _S.MEDIUM, "DKIM verification failed", evidence=[r.detail for r in auth.dkim if r.status is overall])  # fmt: skip
        elif overall is AuthStatus.PASS and not any(
            r.status is AuthStatus.PASS and r.aligned is True for r in auth.dkim
        ):
            f.add(
                "dkim_not_aligned", _S.LOW, "DKIM passed, but not for the From domain",
                evidence=[f"d={r.domain}" for r in auth.dkim if r.status is AuthStatus.PASS],
            )  # fmt: skip

    # ---------------------------------------------------------------- trace
    _TRACE_MARKERS: Final = (
        ("earlier than the previous hop", "received_clock_skew", _S.MEDIUM, "Received timestamps run backwards (clock skew or forged hop)"),
        ("more than a day in the future", "received_future_timestamp", _S.MEDIUM, "A Received hop is timestamped in the future"),
        ("does not match reverse dns", "received_rdns_mismatch", _S.LOW, "A hop's claimed host does not match its reverse DNS"),
        ("unparseable timestamp", "received_no_timestamp", _S.LOW, "A Received hop has no usable timestamp"),
        ("structure could not be parsed", "received_unparseable", _S.LOW, "A Received header could not be parsed"),
    )  # fmt: skip

    def _trace_checks(self, msg: ParsedMessage, trace: ReceivedTrace, f: _Findings) -> None:
        if not trace.hops:
            f.add(
                "no_received_headers", _S.LOW, "No Received headers; the delivery path is unknown",
                "Headers may have been stripped, or the item was never delivered over SMTP.",
            )  # fmt: skip
            return
        for hop in trace.hops:
            for anomaly in hop.anomalies:
                lowered = anomaly.lower()
                for needle, code, severity, title in self._TRACE_MARKERS:
                    if needle in lowered:
                        f.add(code, severity, title, evidence=[f"hop #{hop.index + 1}: {anomaly}"])
                        break

        origin = trace.originating_mta
        if origin is not None and origin.rdns is None and 0 <= origin.hop_index < len(trace.hops):
            hop = trace.hops[origin.hop_index]
            if any(i.address == origin.ip and i.rdns_error for i in hop.ips):
                f.add(
                    "origin_no_rdns", _S.LOW, "The originating server has no reverse DNS",
                    "Legitimate mail servers almost always publish a PTR record.",
                    [origin.ip],
                )  # fmt: skip

        first = trace.hops[0].timestamp
        if msg.date is not None and first is not None and abs(msg.date - first) > _DATE_SKEW:
            f.add(
                "date_received_skew", _S.LOW, "Date header differs greatly from the first hop's time",
                evidence=[f"Date {msg.date.isoformat()} / first hop {first.isoformat()}"],
            )  # fmt: skip


def analyze_anomalies(
    message: ParsedMessage,
    *,
    iocs: Sequence[IOC] = (),
    auth: AuthReport | None = None,
    trace: ReceivedTrace | None = None,
    brands: Mapping[str, Iterable[str]] | None = None,
) -> AnomalyResult:
    """Convenience wrapper around :class:`AnomalyAnalyzer`. Pure CPU, no network access."""
    return AnomalyAnalyzer(brands).analyze(message, iocs=iocs, auth=auth, trace=trace)
