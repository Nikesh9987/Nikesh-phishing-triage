"""Response models for the web API.

* :class:`ErrorResponse`: uniform error body for every failure.
* :class:`HealthResponse`: liveness plus threat-intel provider state.
* :class:`ReportSummary`: a slim digest of a report for dashboards and lists.
* :class:`AnalyzeResponse`: the summary plus the full :class:`Report`.
* :class:`IocExport`: defanged indicators and attachment hashes for tickets,
  with plain-text and CSV renderings.

Safety rules:

* Exports contain **defanged** values only. Live (refanged) indicators never
  leave through the export endpoints.
* Control and direction-override characters in file names are escaped as
  ``\\uXXXX`` and CSV cells starting with ``= + - @`` are neutralised, so
  pasted or opened exports cannot mislead an analyst or run a spreadsheet formula.
* Error ``details`` are sanitised, because some echo attacker-chosen text such
  as a file name.

Pure data shaping: no I/O, never raises on well-typed input.
"""

import csv
import io
import unicodedata
from collections import Counter
from collections.abc import Collection
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Self

from pydantic import BaseModel, ConfigDict

from phishtriage.core.exceptions import PhishTriageError
from phishtriage.core.models import (
    SEVERITY_WEIGHT,
    AuthStatus,
    Report,
    Severity,
    Verdict,
)
from phishtriage.core.utils import clean_text

__all__ = [
    "AnalyzeResponse",
    "AuthSummary",
    "ErrorResponse",
    "FindingBrief",
    "HashExportItem",
    "HealthResponse",
    "IocExport",
    "IocExportFormat",
    "IocExportItem",
    "ProviderInfo",
    "ReportSummary",
]

_TOP_FINDINGS: Final = 5
_CSV_DANGEROUS_PREFIXES: Final = ("=", "+", "-", "@", "\t", "\r")
_CSV_COLUMNS: Final = ("kind", "type", "value", "count", "sources", "intel_verdict", "filename")


def _escape(value: str, limit: int = 255) -> str:
    """Show control and format (bidi, zero-width) characters as ``\\uXXXX``."""
    text = "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf") else c for c in value
    )
    return text[:limit]


def _csv_cell(value: object) -> str:
    """Neutralise spreadsheet formula injection."""
    text = str(value)
    return f"'{text}" if text.startswith(_CSV_DANGEROUS_PREFIXES) else text


class _Schema(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ===================================================================== errors
def _safe_details(details: dict[str, Any]) -> dict[str, Any]:
    """Sanitise string values in error details (they can echo hostile input)."""
    return {k: clean_text(v, 200) if isinstance(v, str) else v for k, v in details.items()}


class ErrorResponse(_Schema):
    """Body of every error response."""

    error: str
    message: str
    details: dict[str, Any] | None = None

    @classmethod
    def from_exception(cls, exc: PhishTriageError) -> Self:
        """Build from an application exception."""
        return cls(
            error=exc.code,
            message=clean_text(exc.message, 500),
            details=_safe_details(exc.details) if exc.details else None,
        )

    @classmethod
    def generic(cls, code: str, message: str) -> Self:
        """Build from a code and message (framework errors, unexpected failures)."""
        return cls(error=code, message=clean_text(message, 500))


# ===================================================================== health
class ProviderInfo(_Schema):
    """State of one threat-intel provider."""

    name: str
    enabled: bool
    reason: str = ""


class HealthResponse(_Schema):
    """Liveness and configuration highlights. Never includes secrets."""

    status: str = "ok"
    version: str
    environment: str
    offline: bool
    providers: list[ProviderInfo]
    stored_reports: int = 0


# ==================================================================== summary
class AuthSummary(_Schema):
    """One authentication mechanism, condensed."""

    status: AuthStatus
    aligned: bool | None = None
    domain: str = ""


class FindingBrief(_Schema):
    """A finding without its evidence."""

    code: str
    severity: Severity
    title: str


class ReportSummary(_Schema):
    """A slim digest of a :class:`Report`."""

    report_id: str
    generated_at: datetime
    filename: str
    file_size: int
    file_sha256: str
    offline: bool
    verdict: Verdict
    risk_score: int
    subject: str
    from_display: str
    from_domain: str
    reply_to: list[str]
    spf: AuthSummary
    dkim: AuthSummary
    dmarc: AuthSummary
    hop_count: int
    origin_ip: str | None
    ioc_counts: dict[str, int]
    attachment_count: int
    suspicious_attachment_count: int
    finding_counts: dict[str, int]
    top_findings: list[FindingBrief]
    warning_count: int
    intel_providers_used: list[str]

    @classmethod
    def from_report(cls, report: Report) -> Self:
        """Condense ``report``."""
        auth = report.authentication
        msg = report.message
        sender = msg.from_address
        if sender is None:
            from_display = ""
        elif sender.display_name and sender.address:
            from_display = f"{sender.display_name} <{sender.address}>"
        else:
            from_display = sender.display_name or sender.address

        dkim_domain = next(
            (r.domain for r in auth.dkim if r.status is AuthStatus.PASS and r.domain),
            auth.dkim[0].domain if auth.dkim else "",
        )
        if not auth.dkim:
            dkim_aligned: bool | None = None
        elif any(r.aligned is True for r in auth.dkim if r.status is AuthStatus.PASS):
            dkim_aligned = True
        elif any(r.aligned is False for r in auth.dkim):
            dkim_aligned = False
        else:
            dkim_aligned = None

        severities = Counter(f.severity.value for f in report.findings)
        top = sorted(report.findings, key=lambda f: -SEVERITY_WEIGHT[f.severity])[:_TOP_FINDINGS]
        origin = report.received.originating_mta

        return cls(
            report_id=report.report_id,
            generated_at=report.generated_at,
            filename=report.filename,
            file_size=report.file_size,
            file_sha256=report.file_sha256,
            offline=report.offline,
            verdict=report.verdict,
            risk_score=report.risk_score,
            subject=msg.subject,
            from_display=from_display,
            from_domain=auth.from_domain or (sender.domain if sender else ""),
            reply_to=[r.address for r in msg.reply_to if r.address],
            spf=AuthSummary(status=auth.spf.status, aligned=auth.spf.aligned, domain=auth.spf.domain),
            dkim=AuthSummary(status=auth.dkim_overall, aligned=dkim_aligned, domain=dkim_domain),
            dmarc=AuthSummary(
                status=auth.dmarc.status, aligned=auth.dmarc.aligned, domain=auth.dmarc.domain
            ),
            hop_count=len(report.received.hops),
            origin_ip=origin.ip if origin else None,
            ioc_counts=dict(Counter(i.type.value for i in report.iocs)),
            attachment_count=len(report.attachments),
            suspicious_attachment_count=sum(1 for a in report.attachments if a.is_suspicious),
            finding_counts={s.value: severities[s.value] for s in Severity if severities[s.value]},
            top_findings=[FindingBrief(code=f.code, severity=f.severity, title=f.title) for f in top],
            warning_count=len(report.warnings)
            + len(report.received.warnings)
            + len(auth.warnings),
            intel_providers_used=list(report.intel_providers_used),
        )


class AnalyzeResponse(_Schema):
    """Result of ``POST /api/analyze``."""

    summary: ReportSummary
    report: Report
    retention_seconds: int


# ===================================================================== exports
class IocExportFormat(StrEnum):
    """Formats offered by the IOC export endpoint."""

    JSON = "json"
    TEXT = "text"
    CSV = "csv"


class IocExportItem(_Schema):
    """One defanged indicator."""

    type: str
    defanged: str
    count: int
    sources: list[str]
    intel_verdict: str


class HashExportItem(_Schema):
    """One attachment's hashes."""

    filename: str
    size: int
    sha256: str
    sha1: str
    md5: str


class IocExport(_Schema):
    """Defanged indicators and attachment hashes, ready for a ticket."""

    report_id: str
    filename: str
    verdict: Verdict
    risk_score: int
    iocs: list[IocExportItem]
    attachments: list[HashExportItem]

    @classmethod
    def from_report(
        cls,
        report: Report,
        types: Collection[str] | None = None,
        include_hashes: bool = True,
    ) -> Self:
        """Select indicators of ``types`` (``None`` = all); ``"hash"`` selects attachment hashes."""
        wanted_hashes = include_hashes and (types is None or "hash" in types)
        return cls(
            report_id=report.report_id,
            filename=_escape(report.filename),
            verdict=report.verdict,
            risk_score=report.risk_score,
            iocs=[
                IocExportItem(
                    type=i.type.value,
                    defanged=_escape(i.defanged, 2000),
                    count=i.count,
                    sources=[s.value for s in i.sources],
                    intel_verdict=i.worst_intel_verdict.value,
                )
                for i in report.iocs
                if types is None or i.type.value in types
            ],
            attachments=[
                HashExportItem(
                    filename=_escape(a.filename),
                    size=a.size,
                    sha256=a.sha256,
                    sha1=a.sha1,
                    md5=a.md5,
                )
                for a in report.attachments
                if wanted_hashes and a.sha256
            ],
        )

    def text_lines(self) -> list[str]:
        """Defanged values then attachment SHA-256 hashes, one per line, de-duplicated."""
        lines = [i.defanged for i in self.iocs] + [a.sha256 for a in self.attachments]
        return list(dict.fromkeys(line for line in lines if line))

    def to_csv(self) -> str:
        """CSV with a header row; cells that could run as spreadsheet formulas are neutralised."""
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(_CSV_COLUMNS)
        for ioc in self.iocs:
            writer.writerow(
                [
                    "indicator",
                    ioc.type,
                    _csv_cell(ioc.defanged),
                    ioc.count,
                    " ".join(ioc.sources),
                    ioc.intel_verdict,
                    "",
                ]
            )
        for att in self.attachments:
            writer.writerow(
                ["attachment", "sha256", att.sha256, 1, "attachment", "", _csv_cell(att.filename)]
            )
        return buffer.getvalue()