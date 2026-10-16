"""Typed data models shared by every layer (parsers, analyzers, CLI, API).

Pipeline data flow::

    bytes --parser--> ParsedMessage --analyzers--> pieces --pipeline--> Report

* :class:`ParsedMessage` is the *normalised* handoff from the ``.eml`` and
  ``.msg`` parsers, so analyzers never care about the source format.
* :class:`Report` is the final, JSON-serialisable result returned by the CLI
  (``--json``) and the API.
* Raw attachment bytes live only on :class:`RawAttachment` and are excluded from
  serialisation, so they can never leak into a report or API response.
"""

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

TOOL_VERSION = "1.0.0"


class _Model(BaseModel):
    """Base model: validates on assignment so analyzers can mutate safely."""

    model_config = ConfigDict(validate_assignment=True, extra="forbid")


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ======================================================================== enums
class Severity(StrEnum):
    """Severity of a finding. Ordered by :data:`SEVERITY_WEIGHT`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Verdict(StrEnum):
    """Overall triage verdict for a message."""

    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class AuthMethod(StrEnum):
    """Email authentication mechanism."""

    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"


class AuthStatus(StrEnum):
    """Normalised result of an authentication check (RFC 8601 vocabulary)."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"
    UNKNOWN = "unknown"


class AuthSource(StrEnum):
    """Where an authentication result came from."""

    HEADER = "header"  # Authentication-Results / Received-SPF
    DNS = "dns"  # derived by this tool from live DNS records
    ABSENT = "absent"  # nothing available


class IPScope(StrEnum):
    """Routing scope of an IP address."""

    PUBLIC = "public"
    PRIVATE = "private"  # RFC 1918 (IPv4)
    UNIQUE_LOCAL = "unique_local"  # fc00::/7 (IPv6)
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CGNAT = "cgnat"  # 100.64.0.0/10 (RFC 6598)
    MULTICAST = "multicast"
    RESERVED = "reserved"  # documentation, unspecified, other non-routable


class IOCType(StrEnum):
    """Kind of indicator of compromise."""

    URL = "url"
    EMAIL = "email"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HASH = "hash"


class IOCSource(StrEnum):
    """Where an IOC was found."""

    HEADERS = "headers"
    BODY_TEXT = "body_text"
    BODY_HTML = "body_html"
    ATTACHMENT = "attachment"
    RECEIVED = "received"


class IntelVerdict(StrEnum):
    """Verdict from a single threat-intel provider for a single indicator."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"  # provider has no data
    ERROR = "error"  # lookup failed (timeout, rate limit, auth)
    SKIPPED = "skipped"  # provider disabled / offline


# ============================================================ normalised message
class HeaderField(_Model):
    """One raw header, in original order (duplicates preserved)."""

    name: str
    value: str


class ParsedAddress(_Model):
    """An RFC 5322 mailbox: optional display name plus address."""

    display_name: str = ""
    address: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def domain(self) -> str:
        """Lower-cased domain part of the address, or ``""`` if absent."""
        _, sep, domain = self.address.rpartition("@")
        return domain.strip().lower() if sep else ""


class RawAttachment(_Model):
    """An attachment held in memory. ``data`` is never serialised."""

    filename: str = ""
    declared_content_type: str = ""
    content_id: str = ""
    is_inline: bool = False
    data: bytes = Field(default=b"", exclude=True, repr=False)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def size(self) -> int:
        """Size of the attachment payload in bytes."""
        return len(self.data)


class ParsedMessage(_Model):
    """Format-independent view of an email produced by the parsers."""

    source_format: Literal["eml", "msg"]
    headers: list[HeaderField] = Field(default_factory=list)
    subject: str = ""
    from_address: ParsedAddress | None = None
    to: list[ParsedAddress] = Field(default_factory=list)
    cc: list[ParsedAddress] = Field(default_factory=list)
    reply_to: list[ParsedAddress] = Field(default_factory=list)
    return_path: str = ""
    message_id: str = ""
    date: datetime | None = None
    body_text: str = ""
    body_html: str = ""
    attachments: list[RawAttachment] = Field(default_factory=list, exclude=True)
    parse_warnings: list[str] = Field(default_factory=list)

    def get_headers(self, name: str) -> list[str]:
        """Return every value of header ``name`` (case-insensitive), in order."""
        wanted = name.lower()
        return [h.value for h in self.headers if h.name.lower() == wanted]

    def get_header(self, name: str) -> str | None:
        """Return the first value of header ``name``, or ``None``."""
        values = self.get_headers(name)
        return values[0] if values else None


# ================================================================ Received trace
class HopIP(_Model):
    """An IP address observed in a ``Received`` hop."""

    address: str
    version: Literal[4, 6]
    scope: IPScope
    rdns: str | None = None
    rdns_error: str | None = None

    @field_validator("address")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))  # raises ValueError if invalid

    @property
    def is_public(self) -> bool:
        """True if the address is globally routable."""
        return self.scope is IPScope.PUBLIC


class Hop(_Model):
    """One parsed ``Received:`` header."""

    index: int = Field(ge=0, description="0 = first hop (oldest, closest to the sender).")
    raw: str
    from_host: str = ""
    by_host: str = ""
    protocol: str = ""
    envelope_for: str = ""
    queue_id: str = ""
    timestamp: datetime | None = None
    delay_seconds: float | None = Field(
        default=None, description="Seconds since the previous (older) hop; may be negative."
    )
    ips: list[HopIP] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)


class OriginatingMTA(_Model):
    """The best estimate of the first external (public) sending server."""

    ip: str
    hostname: str | None = None
    rdns: str | None = None
    hop_index: int
    reason: str = Field(description="Why this hop was selected as the origin.")


class ReceivedTrace(_Model):
    """Result of tracing the ``Received`` chain (hops sorted oldest -> newest)."""

    hops: list[Hop] = Field(default_factory=list)
    originating_mta: OriginatingMTA | None = None
    total_delay_seconds: float | None = None
    warnings: list[str] = Field(default_factory=list)


# ================================================================= authentication
class AuthResult(_Model):
    """A single SPF, DKIM, or DMARC result."""

    method: AuthMethod
    status: AuthStatus = AuthStatus.UNKNOWN
    source: AuthSource = AuthSource.ABSENT
    domain: str = Field(default="", description="Domain that was authenticated.")
    aligned: bool | None = Field(
        default=None, description="Identifier alignment with the From domain; None if unknown."
    )
    selector: str = Field(default="", description="DKIM selector (DKIM only).")
    detail: str = ""
    raw: str = Field(default="", description="Raw header fragment this was derived from.")


class DmarcPolicy(_Model):
    """Published DMARC policy for the From domain (from DNS)."""

    domain: str = ""
    record: str = ""
    policy: str = ""
    subdomain_policy: str = ""
    percentage: int = 100
    spf_alignment: Literal["relaxed", "strict"] = "relaxed"
    dkim_alignment: Literal["relaxed", "strict"] = "relaxed"


class AuthReport(_Model):
    """Combined authentication assessment for the message."""

    from_domain: str = ""
    spf: AuthResult = Field(default_factory=lambda: AuthResult(method=AuthMethod.SPF))
    dkim: list[AuthResult] = Field(default_factory=list)
    dmarc: AuthResult = Field(default_factory=lambda: AuthResult(method=AuthMethod.DMARC))
    dmarc_policy: DmarcPolicy | None = None
    warnings: list[str] = Field(default_factory=list)

    @property
    def dkim_overall(self) -> AuthStatus:
        """``PASS`` if any DKIM signature passed, else the worst/only result."""
        if not self.dkim:
            return AuthStatus.NONE
        if any(r.status is AuthStatus.PASS for r in self.dkim):
            return AuthStatus.PASS
        for status in (AuthStatus.FAIL, AuthStatus.PERMERROR, AuthStatus.TEMPERROR):
            if any(r.status is status for r in self.dkim):
                return status
        return self.dkim[0].status


# ===================================================================== threat intel
class IntelResult(_Model):
    """One provider's verdict on one indicator."""

    provider: str
    indicator: str = Field(description="The *refanged* value that was queried.")
    indicator_type: IOCType
    verdict: IntelVerdict = IntelVerdict.UNKNOWN
    score: int | None = Field(default=None, ge=0, le=100, description="Provider risk score 0-100.")
    detail: str = ""
    reference_url: str = ""
    from_cache: bool = False
    queried_at: datetime = Field(default_factory=_utcnow)


# ====================================================================== IOCs / files
class IOC(_Model):
    """An extracted indicator of compromise."""

    type: IOCType
    value: str = Field(description="Original (refanged / normalised) value.")
    defanged: str = Field(description="Safe-to-share form, e.g. hxxp[://]evil[.]com.")
    sources: list[IOCSource] = Field(default_factory=list)
    count: int = Field(default=1, ge=1)
    intel: list[IntelResult] = Field(default_factory=list)

    @property
    def worst_intel_verdict(self) -> IntelVerdict:
        """The most severe verdict across all providers."""
        order = (IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS, IntelVerdict.CLEAN)
        for verdict in order:
            if any(r.verdict is verdict for r in self.intel):
                return verdict
        return IntelVerdict.UNKNOWN


class AttachmentFlag(_Model):
    """A suspicious characteristic detected on an attachment."""

    code: str
    severity: Severity
    description: str


class Attachment(_Model):
    """Analysis result for one attachment (no payload bytes)."""

    filename: str
    size: int = Field(ge=0)
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    declared_content_type: str = ""
    detected_mime: str = ""
    detected_extension: str = ""
    is_inline: bool = False
    skipped: bool = Field(default=False, description="True if too large to inspect.")
    flags: list[AttachmentFlag] = Field(default_factory=list)
    intel: list[IntelResult] = Field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        """True if any flag is MEDIUM or above, or intel marks it malicious."""
        flagged = any(
            SEVERITY_WEIGHT[f.severity] >= SEVERITY_WEIGHT[Severity.MEDIUM] for f in self.flags
        )
        return flagged or any(r.verdict is IntelVerdict.MALICIOUS for r in self.intel)


# ===================================================================== report
class Finding(_Model):
    """A discrete, analyst-readable observation that contributes to the verdict."""

    code: str = Field(description="Stable machine-readable id, e.g. 'spf_fail'.")
    severity: Severity
    title: str
    detail: str = ""
    evidence: list[str] = Field(default_factory=list)


class MessageSummary(_Model):
    """Headline fields displayed at the top of a report."""

    source_format: Literal["eml", "msg"]
    subject: str = ""
    from_address: ParsedAddress | None = None
    to: list[ParsedAddress] = Field(default_factory=list)
    reply_to: list[ParsedAddress] = Field(default_factory=list)
    return_path: str = ""
    message_id: str = ""
    date: datetime | None = None


class Report(_Model):
    """The complete triage result. This is what the CLI and API emit."""

    report_id: str = Field(default_factory=lambda: uuid4().hex)
    generated_at: datetime = Field(default_factory=_utcnow)
    tool_version: str = TOOL_VERSION
    filename: str = ""
    file_size: int = 0
    file_sha256: str = ""
    offline: bool = False

    message: MessageSummary
    headers: list[HeaderField] = Field(default_factory=list)
    received: ReceivedTrace = Field(default_factory=ReceivedTrace)
    authentication: AuthReport = Field(default_factory=AuthReport)
    iocs: list[IOC] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    risk_score: int = Field(default=0, ge=0, le=100)
    verdict: Verdict = Verdict.CLEAN
    intel_providers_used: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def iocs_of(self, ioc_type: IOCType) -> list[IOC]:
        """Return all IOCs of a single type."""
        return [i for i in self.iocs if i.type is ioc_type]

    def export_defanged(self) -> list[str]:
        """Flat list of defanged IOCs and attachment SHA-256 hashes for ticketing."""
        lines = [ioc.defanged for ioc in self.iocs]
        lines.extend(a.sha256 for a in self.attachments if a.sha256)
        return lines

    def to_json_dict(self) -> dict[str, Any]:
        """JSON-safe dict (enums -> strings, datetimes -> ISO 8601)."""
        return self.model_dump(mode="json")
