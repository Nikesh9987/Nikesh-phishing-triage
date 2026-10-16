"""The triage orchestrator: raw bytes in, :class:`Report` out.

Stages and their dependencies::

    parse (+ file SHA-256)                                   fatal on failure
      +-- IOC extraction  --+
      +-- Received trace  --+--> (parallel)
      +-- attachments     --+
            |
            +-- auth (needs trace for the SPF client IP) --> anomalies
            +-- threat-intel enrichment (needs IOCs and attachment hashes)
                                   (these two branches run in parallel)
      findings merge --> scoring --> Report

Behaviour:

* **Parsing is the only fatal stage.** Empty, oversized, unrecognised or
  corrupt input raises a typed :class:`PhishTriageError` subclass (see
  ``core/exceptions.py``) carrying ``http_status`` and ``exit_code``. Every
  later stage that fails is turned into a warning, and the report is still
  produced.
* **Blocking work runs in threads** (``asyncio.to_thread``): parsing, DNS
  (reverse DNS, SPF/DKIM/DMARC fallback), macro scanning and the regex-heavy
  analyzers never block the event loop. Threat-intel I/O is natively async.
* **Offline mode** (``PHISHTRIAGE_OFFLINE=true``): no DNS and no HTTP at all.
  The report says so in its warnings.
* **Trust inputs.** ``trusted_hops`` and ``trusted_authserv_ids`` are passed
  through to the tracer and the authentication analyzer (see those modules for
  what they protect against).
* **Long-lived services keep one pipeline.** Its aggregator owns the rate
  limiters, and the shared cache de-duplicates across requests. Use
  :func:`analyze_bytes` only for one-off runs (CLI, scripts).

Warnings: the report's ``warnings`` collect parse, extraction, attachment,
anomaly, threat-intel and stage-failure notes. Tracer and authentication notes
stay on ``report.received.warnings`` and ``report.authentication.warnings``.

Nothing in the message is executed or written to disk. Only indicators (hashes,
URLs, IPs, domains) ever leave the machine, and only to enabled providers.
"""

import asyncio
import hashlib
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from types import TracebackType
from typing import Any, Final, TypeVar

from phishtriage.analyzers.attachment_analyzer import AttachmentAnalysis, analyze_attachments
from phishtriage.analyzers.auth_analyzer import analyze_auth
from phishtriage.analyzers.header_anomalies import AnomalyResult, analyze_anomalies
from phishtriage.analyzers.ioc_extractor import ExtractionResult, extract_iocs
from phishtriage.analyzers.received_tracer import trace_received
from phishtriage.config import Settings, get_settings
from phishtriage.core.exceptions import InputError
from phishtriage.core.models import (
    IOC,
    Attachment,
    AuthReport,
    Finding,
    MessageSummary,
    ParsedMessage,
    ReceivedTrace,
    Report,
    Severity,
)
from phishtriage.core.scoring import (
    FLOORS,
    attachment_findings,
    intel_findings,
    merge_findings,
    score_findings,
)
from phishtriage.intel.aggregator import IntelAggregator
from phishtriage.intel.base import ProviderStatus
from phishtriage.logging_config import get_logger, register_secrets
from phishtriage.parsers.base import parse_message

__all__ = ["TriagePipeline", "analyze_bytes", "analyze_bytes_sync"]

logger = get_logger(__name__)

T = TypeVar("T")

_MAX_FILENAME: Final = 255
_OFFLINE_NOTE: Final = (
    "Offline mode: reverse DNS, SPF/DKIM/DMARC DNS fallbacks and threat-intelligence "
    "lookups were skipped."
)


# ================================================================== helpers
def _parse_and_hash(data: bytes, filename: str | None, cfg: Settings) -> tuple[ParsedMessage, str]:
    """Parse ``data`` and fingerprint the original file (runs in a worker thread)."""
    message = parse_message(data, filename, settings=cfg)
    return message, hashlib.sha256(data).hexdigest()


def _display_filename(filename: str | None) -> str:
    """Base name only, control and direction characters removed, at most 255 chars."""
    if not filename:
        return ""
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if unicodedata.category(c) not in ("Cc", "Cf"))
    return name.strip()[:_MAX_FILENAME]


async def _blocking(
    label: str,
    warnings: list[str],
    default: T,
    func: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run ``func`` in a thread; on failure record a warning and return ``default``."""
    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except Exception:  # noqa: BLE001 - one broken stage must not lose the whole report
        logger.exception("%s stage failed", label)
        warnings.append(f"{label} failed unexpectedly; its results are missing or incomplete.")
        return default


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


# ================================================================== pipeline
class TriagePipeline:
    """Analyze messages end to end. Safe to share between concurrent requests."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        aggregator: IntelAggregator | None = None,
        brands: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        """Create a pipeline.

        Args:
            settings: Application settings (defaults to the process singleton).
            aggregator: A shared threat-intel aggregator. If omitted, one is
                created lazily from ``settings`` and closed by :meth:`aclose`.
                A supplied aggregator is *not* closed by this pipeline.
            brands: Brand label -> legitimate domains for lookalike detection
                (see ``header_anomalies.DEFAULT_BRANDS``). Add your own company's
                domains here to detect spoofs of your organisation.
        """
        self._settings = settings or get_settings()
        register_secrets(self._settings.secret_values())
        self._aggregator = aggregator
        self._owns_aggregator = aggregator is None
        self._brands = brands

    # ----------------------------------------------------------------- lifecycle
    def _get_aggregator(self) -> IntelAggregator:
        if self._aggregator is None:
            self._aggregator = IntelAggregator.from_settings(self._settings)
        return self._aggregator

    def provider_statuses(self) -> list[ProviderStatus]:
        """Enabled/disabled state (with reasons) of every threat-intel provider."""
        return self._get_aggregator().provider_statuses()

    async def aclose(self) -> None:
        """Release network resources owned by this pipeline."""
        aggregator, self._aggregator = self._aggregator, None
        if aggregator is not None and self._owns_aggregator:
            await aggregator.aclose()

    async def __aenter__(self) -> "TriagePipeline":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ analysis
    async def analyze(
        self,
        data: bytes,
        filename: str | None = None,
        *,
        trusted_hops: int | None = None,
        trusted_authserv_ids: Sequence[str] | None = None,
        enrich: bool = True,
        scan_macros: bool = True,
    ) -> Report:
        """Analyze one ``.eml`` or ``.msg`` file.

        Args:
            data: Raw file contents.
            filename: Original file name (a hint only; never trusted).
            trusted_hops: Number of *newest* Received hops operated by your own
                infrastructure; the originating MTA is then taken from your
                server's observation (see ``received_tracer``).
            trusted_authserv_ids: Only ``Authentication-Results`` from these
                servers are believed (default: the topmost header's server).
            enrich: Query threat-intelligence providers.
            scan_macros: Run the CPU-heavy oletools macro scan.

        Raises:
            InputError: bad arguments, or empty/oversized/unrecognised input.
            ParserError: the message is too damaged to parse.
        """
        cfg = self._settings
        if trusted_hops is not None and trusted_hops < 1:
            raise InputError("trusted_hops must be at least 1.")

        message, file_sha256 = await asyncio.to_thread(_parse_and_hash, data, filename, cfg)
        warnings: list[str] = list(message.parse_warnings)

        # ---- stage A: independent analyses in parallel
        extraction, trace, attachment_result = await asyncio.gather(
            _blocking("IOC extraction", warnings, ExtractionResult(), extract_iocs, message, cfg),
            _blocking(
                "Received-path analysis", warnings, ReceivedTrace(),
                trace_received, message, cfg, trusted_hops=trusted_hops,
            ),
            _blocking(
                "Attachment analysis", warnings, AttachmentAnalysis(),
                analyze_attachments, message, cfg, scan_macros=scan_macros,
            ),
        )  # fmt: skip
        iocs: list[IOC] = extraction.iocs
        attachments: list[Attachment] = attachment_result.attachments
        warnings.extend(extraction.warnings)
        warnings.extend(attachment_result.warnings)

        # ---- stage B: (auth -> anomalies) in parallel with threat-intel enrichment
        async def auth_then_anomalies() -> tuple[AuthReport, AnomalyResult]:
            origin = trace.originating_mta
            helo = None
            if origin is not None and 0 <= origin.hop_index < len(trace.hops):
                helo = trace.hops[origin.hop_index].from_host or None
            auth = await _blocking(
                "Authentication analysis", warnings, AuthReport(),
                analyze_auth, message, cfg,
                client_ip=origin.ip if origin is not None else None,
                helo=helo,
                trusted_authserv_ids=list(trusted_authserv_ids) if trusted_authserv_ids else None,
            )  # fmt: skip
            anomalies = await _blocking(
                "Anomaly analysis", warnings, AnomalyResult(),
                analyze_anomalies, message,
                iocs=iocs, auth=auth, trace=trace, brands=self._brands,
            )  # fmt: skip
            return auth, anomalies

        (auth, anomalies), providers_used = await asyncio.gather(
            auth_then_anomalies(), self._enrich(iocs, attachments, enrich, warnings)
        )
        warnings.extend(anomalies.warnings)

        # ---- findings, score, verdict
        findings = merge_findings(
            anomalies.findings,
            attachment_findings(attachments),
            intel_findings(iocs, attachments),
        )
        scored = score_findings(findings)
        if scored.floors_applied:
            findings.append(
                Finding(
                    code="score_floor_applied",
                    severity=Severity.INFO,
                    title="Risk score raised by a high-confidence finding",
                    detail=(
                        f"Weighted evidence alone scored {scored.raw_score}; the findings "
                        f"below set a higher minimum of {scored.score}."
                    ),
                    evidence=[
                        f"{code} -> minimum score {FLOORS[code]}"
                        for code, _ in scored.floors_applied
                    ],
                )
            )

        report = Report(
            filename=_display_filename(filename),
            file_size=len(data),
            file_sha256=file_sha256,
            offline=cfg.offline,
            message=MessageSummary(
                source_format=message.source_format,
                subject=message.subject,
                from_address=message.from_address,
                to=message.to,
                reply_to=message.reply_to,
                return_path=message.return_path,
                message_id=message.message_id,
                date=message.date,
            ),
            headers=message.headers,
            received=trace,
            authentication=auth,
            iocs=iocs,
            attachments=attachments,
            findings=findings,
            risk_score=scored.score,
            verdict=scored.verdict,
            intel_providers_used=providers_used,
            warnings=_unique(warnings),
        )
        logger.info(
            "Triage complete: verdict=%s score=%d findings=%d iocs=%d attachments=%d",
            report.verdict.value, report.risk_score, len(findings), len(iocs), len(attachments),
        )  # fmt: skip
        return report

    # ---------------------------------------------------------------- enrichment
    async def _enrich(
        self,
        iocs: list[IOC],
        attachments: list[Attachment],
        enabled: bool,
        warnings: list[str],
    ) -> list[str]:
        """Run threat-intel lookups; returns the providers that produced answers."""
        if not enabled:
            warnings.append("Threat-intelligence enrichment was disabled for this run.")
            return []
        if self._settings.offline:
            warnings.append(_OFFLINE_NOTE)
            return []
        try:
            result = await self._get_aggregator().enrich(iocs, attachments)
        except Exception:  # noqa: BLE001 - the aggregator already guards itself; belt and braces
            logger.exception("Threat-intel stage failed")
            warnings.append("Threat-intelligence enrichment failed unexpectedly.")
            return []
        warnings.extend(result.warnings)
        return result.providers_used


# ================================================================ one-shot helpers
async def analyze_bytes(
    data: bytes,
    filename: str | None = None,
    settings: Settings | None = None,
    *,
    aggregator: IntelAggregator | None = None,
    trusted_hops: int | None = None,
    trusted_authserv_ids: Sequence[str] | None = None,
    enrich: bool = True,
    scan_macros: bool = True,
) -> Report:
    """Analyze one message with a throw-away pipeline (opened and closed here).

    Long-lived services should keep a :class:`TriagePipeline` instead, so rate
    limiters and the intel cache persist between requests.
    """
    async with TriagePipeline(settings, aggregator=aggregator) as pipeline:
        return await pipeline.analyze(
            data,
            filename,
            trusted_hops=trusted_hops,
            trusted_authserv_ids=trusted_authserv_ids,
            enrich=enrich,
            scan_macros=scan_macros,
        )


def analyze_bytes_sync(
    data: bytes,
    filename: str | None = None,
    settings: Settings | None = None,
    **options: Any,
) -> Report:
    """Blocking wrapper around :func:`analyze_bytes` for scripts and the CLI.

    Must not be called from inside a running event loop.
    """
    return asyncio.run(analyze_bytes(data, filename, settings, **options))
