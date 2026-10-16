"""FastAPI application factory.

Run it with::

    uvicorn phishtriage.api.app:create_app --factory --host 127.0.0.1 --port 8000
    # or:  python -m phishtriage.api.app      (uses PHISHTRIAGE_API_HOST / _PORT)

Behind a reverse proxy add ``--proxy-headers --forwarded-allow-ips=<proxy ip>``
so per-client rate limiting sees real client addresses.

Run **one worker**: the report store, rate limiter and intel cache live in
process memory, so several workers would each hold their own copy (a report
created on one would return 404 on another). The pipeline is asynchronous, so
one worker serves concurrent uploads.

Layers, outermost first:

1. CORS (only if ``PHISHTRIAGE_API_CORS_ORIGINS`` is set; the bundled
   dashboard is same-origin and needs none)
2. :class:`SecurityHeadersMiddleware`: CSP and friends, ``no-store`` for API
   responses, and the last-resort JSON 500 handler
3. :class:`BodySizeLimitMiddleware`: hard cap on request size
4. exception handlers, then routes

Nothing about a message is logged here; the pipeline logs only verdicts and
counts. Note: Starlette spools multipart uploads larger than 1 MiB to a
temporary file until the request ends. If that matters for your samples, point
``TMPDIR`` at a RAM-backed directory (the Docker setup does this).
"""

import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

import asyncio

from phishtriage.api.dependencies import ReportStore, SlidingWindowRateLimiter
from phishtriage.api.routes import router
from phishtriage.api.schemas import ErrorResponse
from phishtriage.config import Settings, get_settings
from phishtriage.core.exceptions import ConfigurationError, PhishTriageError, RateLimitExceeded
from phishtriage.core.models import TOOL_VERSION
from phishtriage.core.pipeline import TriagePipeline
from phishtriage.core.utils import clean_text
from phishtriage.logging_config import configure_logging, get_logger, register_secrets

__all__ = ["BodySizeLimitMiddleware", "SecurityHeadersMiddleware", "create_app", "run"]

logger = get_logger(__name__)

_HERE: Final = Path(__file__).resolve().parent
_TEMPLATES_DIR: Final = _HERE / "templates"
_STATIC_DIR: Final = _HERE / "static"

_MIB: Final = 1024 * 1024
_MULTIPART_OVERHEAD: Final = 1 * _MIB  # form fields, boundaries, headers on top of the file
_REPORT_TTL_SECONDS: Final = 3600.0
_MAX_STORED_REPORTS: Final = 200
_MAX_CONCURRENT_ANALYSES: Final = 4
_MAX_VALIDATION_ERRORS: Final = 10

# Dashboard policy: same-origin everything except the Tailwind CDN script.
# Inline styles are needed because the Tailwind CDN injects a <style> element.
_APP_CSP: Final = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
# Swagger UI and ReDoc load assets from jsDelivr and need inline scripts.
_DOCS_CSP: Final = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "connect-src 'self'; worker-src blob:; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)
_BASE_HEADERS: Final[dict[str, str]] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
_HSTS: Final = "max-age=31536000; includeSubDomains"

_STATUS_CODES: Final[dict[int, str]] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    413: "file_too_large",
    415: "unsupported_format",
    429: "rate_limit_exceeded",
}


# ================================================================== middleware
class _BodyTooLargeError(Exception):
    """Raised inside the receive channel once the request body exceeds the cap."""


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes`` (pure ASGI, streaming-aware).

    * A ``Content-Length`` over the cap is rejected before any byte is read.
    * Otherwise bytes are counted as they arrive, which also covers chunked
      uploads and a lying ``Content-Length``.
    * FastAPI turns any exception raised while reading a form into a generic
      400, so the middleware remembers the overflow and replaces whatever the
      application answers with a proper 413.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self._max = max(1, int(max_bytes))

    async def _reject(self, send: Send) -> None:
        body = (
            ErrorResponse.generic(
                "file_too_large", f"The request body exceeds the {self._max:,}-byte limit."
            )
            .model_dump_json(exclude_none=True)
            .encode()
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    def _declared_length(scope: Scope) -> int | None:
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = self._declared_length(scope)
        if declared is not None and declared > self._max:
            await self._reject(send)
            return

        received = 0
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max:
                    exceeded = True
                    raise _BodyTooLargeError
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if exceeded:
                if not started:  # replace the application's own (400) answer
                    started = True
                    await self._reject(send)
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except _BodyTooLargeError:
            if not started:
                started = True
                await self._reject(send)


class SecurityHeadersMiddleware:
    """Add security headers to every response and answer crashes with a JSON 500."""

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self._hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        csp = _DOCS_CSP if path.startswith(("/docs", "/redoc")) else _APP_CSP
        no_store = path.startswith("/api/") or path == "/health"
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                for name, value in _BASE_HEADERS.items():
                    headers.setdefault(name, value)
                headers.setdefault("Content-Security-Policy", csp)
                if no_store:
                    headers.setdefault("Cache-Control", "no-store")
                if self._hsts:
                    headers.setdefault("Strict-Transport-Security", _HSTS)
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:  # noqa: BLE001 - last line of defence; details stay in the log
            logger.exception("Unhandled error while serving %s", clean_text(path, 120))
            if started:
                raise
            response = JSONResponse(
                ErrorResponse.generic(
                    "internal_error", "An unexpected error occurred."
                ).model_dump(exclude_none=True),
                status_code=500,
            )
            await response(scope, receive, send_with_headers)


# ================================================================ error handlers
def _error_response(
    body: ErrorResponse, status: int, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(body.model_dump(exclude_none=True), status_code=status, headers=headers)


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(PhishTriageError)
    async def _application_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, PhishTriageError)  # noqa: S101 - narrowing for type checkers
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimitExceeded):
            headers["Retry-After"] = str(max(1, math.ceil(exc.retry_after)))
        if exc.http_status >= 500:
            logger.warning("Request failed: %s (%s)", exc.code, clean_text(exc.message, 200))
        return _error_response(ErrorResponse.from_exception(exc), exc.http_status, headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, StarletteHTTPException)  # noqa: S101
        try:
            phrase = HTTPStatus(exc.status_code).phrase
        except ValueError:
            phrase = "Error"
        message = exc.detail if isinstance(exc.detail, str) and exc.detail else phrase
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        headers = dict(exc.headers) if exc.headers else None
        return _error_response(ErrorResponse.generic(code, message), exc.status_code, headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, RequestValidationError)  # noqa: S101
        problems = [
            {
                "field": ".".join(str(part) for part in err.get("loc", ())),
                "problem": clean_text(err.get("msg", "invalid"), 200),
            }
            for err in exc.errors()[:_MAX_VALIDATION_ERRORS]
        ]
        body = ErrorResponse(
            error="validation_error",
            message="The request is missing required data or contains invalid values.",
            details={"errors": problems},
        )
        return _error_response(body, 422)


# ===================================================================== factory
def _load_settings(settings: Settings | None) -> Settings:
    if settings is not None:
        return settings
    try:
        return get_settings()
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'settings'}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigurationError(f"Invalid configuration: {problems}") from None


def create_app(settings: Settings | None = None, *, pipeline: TriagePipeline | None = None) -> FastAPI:
    """Build the application.

    Args:
        settings: Settings to use (defaults to the process singleton).
        pipeline: A ready pipeline (tests). It is not closed at shutdown; a
            pipeline created here is.

    Raises:
        ConfigurationError: the environment holds invalid settings.
    """
    cfg = _load_settings(settings)
    register_secrets(cfg.secret_values())
    owns_pipeline = pipeline is None
    pipe = pipeline or TriagePipeline(cfg)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        configure_logging(cfg.log_level, cfg.log_format, secrets=cfg.secret_values())
        enabled = ", ".join(s.name for s in pipe.provider_statuses() if s.enabled) or "none"
        logger.info(
            "Phishing Triage API %s started (environment=%s, offline=%s, intel providers: %s)",
            TOOL_VERSION, cfg.environment, cfg.offline, enabled,
        )  # fmt: skip
        try:
            yield
        finally:
            if owns_pipeline:
                await pipe.aclose()
            logger.info("Phishing Triage API stopped")

    docs = cfg.enable_api_docs
    app = FastAPI(
        title="Phishing Triage & Header Parser",
        version=TOOL_VERSION,
        description="Upload a suspicious .eml or .msg file and receive a triage report.",
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )

    app.state.settings = cfg
    app.state.pipeline = pipe
    app.state.report_store = ReportStore(_REPORT_TTL_SECONDS, _MAX_STORED_REPORTS)
    app.state.rate_limiter = SlidingWindowRateLimiter(cfg.api_rate_limit_per_minute, 60.0)
    app.state.analysis_gate = asyncio.Semaphore(_MAX_CONCURRENT_ANALYSES)
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # The last middleware added is the outermost one.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=cfg.max_upload_bytes + _MULTIPART_OVERHEAD)
    app.add_middleware(SecurityHeadersMiddleware, hsts=cfg.is_production)
    if cfg.api_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cfg.api_cors_origins),
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Content-Type"],
            allow_credentials=False,
            expose_headers=["Retry-After", "Content-Disposition"],
        )

    _register_error_handlers(app)
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR), check_dir=False), name="static")
    return app


def run() -> None:
    """Start uvicorn with host and port from the settings (single worker)."""
    import uvicorn  # noqa: PLC0415 - only needed when launched this way

    cfg = _load_settings(None)
    uvicorn.run(
        "phishtriage.api.app:create_app",
        factory=True,
        host=cfg.api_host,
        port=cfg.api_port,
        workers=1,
        log_level=cfg.log_level.lower(),
    )


if __name__ == "__main__":
    run()