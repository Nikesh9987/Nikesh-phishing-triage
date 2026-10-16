"""HTTP endpoints.

====================  ==================================================  =========
Endpoint              Purpose                                             Limited?
====================  ==================================================  =========
GET  /                dashboard page                                      no
GET  /health          liveness, version, provider state                   no
POST /api/analyze     upload a .eml/.msg, get summary + full report       yes
GET  /api/report/id   fetch a stored report (``?download=true`` = file)   no
GET  /api/export/iocs/id   defanged IOCs + hashes (json | text | csv)     no
DELETE /api/report/id delete a stored report                              no
====================  ==================================================  =========

Report ids are 128-bit random values and act as bearer links for the retention
period, so put the service behind authentication if it is reachable beyond
your SOC network.

``/api/analyze`` and ``/api/report`` build their JSON directly from the models
instead of using FastAPI's ``response_model``: the models contain computed
fields and forbid extras, so FastAPI's dump-and-revalidate step would reject
valid output. The schema is still documented through ``responses=``.
"""

import asyncio
from typing import Annotated, Any, Final

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import TemplateNotFound
from pydantic import BaseModel

from phishtriage.api.dependencies import (
    OptionsDep,
    PipelineDep,
    RateLimitDep,
    ServiceNotReadyError,
    SettingsDep,
    StoreDep,
    UploadDep,
)
from phishtriage.api.schemas import (
    AnalyzeResponse,
    ErrorResponse,
    HealthResponse,
    IocExport,
    IocExportFormat,
    ProviderInfo,
    ReportSummary,
)
from phishtriage.core.exceptions import InputError, PhishTriageError
from phishtriage.core.models import TOOL_VERSION, Report
from phishtriage.core.utils import clean_text
from phishtriage.logging_config import get_logger

__all__ = ["AnalysisTimeoutError", "router"]

logger = get_logger(__name__)

router = APIRouter()

_ANALYZE_TIMEOUT_SECONDS: Final = 150.0
_IOC_TYPES: Final = frozenset({"url", "email", "ipv4", "ipv6", "domain", "hash"})
_ERROR_DOCS: Final[dict[int | str, dict[str, Any]]] = {
    code: {"model": ErrorResponse, "description": text}
    for code, text in {
        400: "Invalid input or options",
        413: "File too large",
        415: "Unsupported file type or content",
        422: "Unparseable message or invalid request",
        429: "Rate limit exceeded",
        504: "Analysis timed out",
    }.items()
}
_FALLBACK_PAGE: Final = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Phishing Triage</title></head><body style=\"font-family:sans-serif;margin:2rem\">"
    "<h1>Phishing Triage API</h1><p>The dashboard template is not installed. "
    "The API is running: see <a href=\"/docs\">/docs</a> (if enabled) or "
    "<a href=\"/health\">/health</a>.</p></body></html>"
)


class AnalysisTimeoutError(PhishTriageError):
    """The analysis did not finish within the request time budget."""

    http_status = 504
    code = "analysis_timeout"


# ================================================================== helpers
def _json(model: BaseModel, *, headers: dict[str, str] | None = None) -> Response:
    """Serialize a model straight to a JSON response (see module docstring)."""
    return Response(model.model_dump_json(), media_type="application/json", headers=headers)


def _attachment(filename: str) -> dict[str, str]:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


def _gate(request: Request) -> asyncio.Semaphore:
    gate = getattr(request.app.state, "analysis_gate", None)
    if not isinstance(gate, asyncio.Semaphore):
        raise ServiceNotReadyError("The service is not ready ('analysis_gate' is not initialised).")
    return gate


def _bundle(report: Report, retention_seconds: int) -> AnalyzeResponse:
    return AnalyzeResponse(
        summary=ReportSummary.from_report(report), report=report, retention_seconds=retention_seconds
    )


# =================================================================== system
@router.get("/health", response_model=HealthResponse, tags=["system"], summary="Liveness and provider state")
async def health(settings: SettingsDep, pipeline: PipelineDep, store: StoreDep) -> HealthResponse:
    """Version, offline flag and which threat-intel providers can run. Never returns secrets."""
    return HealthResponse(
        version=TOOL_VERSION,
        environment=settings.environment,
        offline=settings.offline,
        providers=[
            ProviderInfo(name=s.name, enabled=s.enabled, reason=s.reason)
            for s in pipeline.provider_statuses()
        ],
        stored_reports=len(store),
    )


@router.get("/", include_in_schema=False, response_class=HTMLResponse)
async def dashboard(request: Request, settings: SettingsDep, pipeline: PipelineDep) -> Response:
    """The single-page dashboard (falls back to a stub until the template exists)."""
    templates: Jinja2Templates = request.app.state.templates
    context = {
        "version": TOOL_VERSION,
        "offline": settings.offline,
        "max_upload_bytes": settings.max_upload_bytes,
        "max_upload_mb": max(1, round(settings.max_upload_bytes / (1024 * 1024))),
        "allowed_extensions": list(settings.api_allowed_extensions),
        "providers": [
            {"name": s.name, "enabled": s.enabled, "reason": s.reason}
            for s in pipeline.provider_statuses()
        ],
    }
    try:
        return templates.TemplateResponse(request, "index.html", context)
    except TemplateNotFound:
        return HTMLResponse(_FALLBACK_PAGE)


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    """No favicon; answer quietly so browsers stop asking."""
    return Response(status_code=204)


# ================================================================== analysis
@router.post(
    "/api/analyze",
    response_model=None,
    tags=["analysis"],
    summary="Analyze an uploaded .eml or .msg file",
    responses={200: {"model": AnalyzeResponse, "description": "Summary and full report"}, **_ERROR_DOCS},
)
async def analyze(
    _rate: RateLimitDep,
    upload: UploadDep,
    options: OptionsDep,
    request: Request,
    pipeline: PipelineDep,
    store: StoreDep,
) -> Response:
    """Upload one message (multipart field ``file``) and receive its triage report.

    Optional form fields: ``trusted_hops``, ``trusted_authserv``, ``enrich``,
    ``scan_macros``. The report is kept in memory for ``retention_seconds`` and
    can be fetched again by its id.
    """
    gate = _gate(request)
    try:
        async with asyncio.timeout(_ANALYZE_TIMEOUT_SECONDS):
            async with gate:
                report = await pipeline.analyze(
                    upload.data,
                    upload.filename,
                    trusted_hops=options.trusted_hops,
                    trusted_authserv_ids=options.trusted_authserv_ids or None,
                    enrich=options.enrich,
                    scan_macros=options.scan_macros,
                )
    except TimeoutError:
        raise AnalysisTimeoutError(
            f"The analysis did not finish within {_ANALYZE_TIMEOUT_SECONDS:g} seconds."
        ) from None

    store.put(report)
    return _json(_bundle(report, store.ttl_seconds))


@router.get(
    "/api/report/{report_id}",
    response_model=None,
    tags=["analysis"],
    summary="Fetch a stored report",
    responses={200: {"model": AnalyzeResponse}, 404: {"model": ErrorResponse}},
)
async def get_report(
    report_id: str,
    store: StoreDep,
    download: Annotated[bool, Query(description="Send as a file download.")] = False,
) -> Response:
    """Return a report analysed within the retention window (``retention_seconds`` is the maximum)."""
    report = store.get(report_id)
    headers = _attachment(f"report-{report.report_id}.json") if download else None
    return _json(_bundle(report, store.ttl_seconds), headers=headers)


@router.delete(
    "/api/report/{report_id}",
    status_code=204,
    response_class=Response,
    tags=["analysis"],
    summary="Delete a stored report",
    responses={404: {"model": ErrorResponse}},
)
async def delete_report(report_id: str, store: StoreDep) -> Response:
    """Remove a report from memory immediately."""
    store.get(report_id)  # validates the id format and raises 404 when unknown
    store.delete(report_id)
    return Response(status_code=204)


@router.get(
    "/api/export/iocs/{report_id}",
    response_model=None,
    tags=["analysis"],
    summary="Export defanged indicators and attachment hashes",
    responses={200: {"model": IocExport}, 400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def export_iocs(
    report_id: str,
    store: StoreDep,
    fmt: Annotated[
        IocExportFormat, Query(alias="format", description="json, text (one per line) or csv.")
    ] = IocExportFormat.JSON,
    types: Annotated[
        list[str] | None,
        Query(max_length=6, description="Only these types: url, email, ipv4, ipv6, domain, hash."),
    ] = None,
    include_hashes: Annotated[bool, Query(description="Include attachment hashes.")] = True,
    download: Annotated[bool, Query(description="Send as a file download.")] = False,
) -> Response:
    """Defanged values only: live indicators never leave through this endpoint."""
    wanted = {t.strip().lower() for t in types or [] if t.strip()}
    unknown = sorted(wanted - _IOC_TYPES)
    if unknown:
        raise InputError(
            "Unknown indicator type(s): " + ", ".join(clean_text(u, 20) for u in unknown[:5]) + ".",
            details={"allowed": sorted(_IOC_TYPES)},
        )

    report = store.get(report_id)
    export = IocExport.from_report(report, types=wanted or None, include_hashes=include_hashes)

    if fmt is IocExportFormat.TEXT:
        body = "\n".join(export.text_lines())
        return PlainTextResponse(
            body + "\n" if body else "",
            headers=_attachment(f"iocs-{report.report_id}.txt") if download else None,
        )
    if fmt is IocExportFormat.CSV:
        return Response(
            export.to_csv(),
            media_type="text/csv; charset=utf-8",
            headers=_attachment(f"iocs-{report.report_id}.csv") if download else None,
        )
    return _json(export, headers=_attachment(f"iocs-{report.report_id}.json") if download else None)