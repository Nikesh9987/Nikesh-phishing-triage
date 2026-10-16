"""FastAPI dependencies: shared services, upload validation, rate limiting.

Services created once at start-up (Step 20's lifespan) live on ``app.state``:
``settings``, ``pipeline`` (:class:`TriagePipeline`), ``report_store``
(:class:`ReportStore`) and ``rate_limiter`` (:class:`SlidingWindowRateLimiter`).
The ``get_*`` functions fetch them, and ``Annotated`` aliases
(``PipelineDep`` ...) keep route signatures short.

Upload validation order (cheapest first), all before any parsing:

1. file name has an allowed extension (the name is only a hint, never trusted);
2. the body is read in chunks and rejected as soon as it exceeds the limit;
3. empty / whitespace-only bodies are rejected;
4. the **content** must be an OLE container (.msg) or look like an RFC 5322
   message (.eml). A text file renamed ``x.eml`` is rejected with HTTP 415.

Size limits: Starlette parses the multipart body before dependencies run, so the
hard cap on request size is enforced by the body-size middleware in ``app.py``.
Step 2 here is defense in depth.

Rate limiting: sliding window, in memory, per client address. It counts every
request that reaches the dependency, including ones later rejected as invalid.
Behind a reverse proxy, run uvicorn with ``--proxy-headers`` and
``--forwarded-allow-ips`` so ``request.client`` is the real client; this module
never parses ``X-Forwarded-For`` itself (it is spoofable).

Report store: bounded, TTL-limited, in memory only. Reports contain headers and
addresses; nothing is persisted.
"""

import re
import time
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePath
from typing import Annotated, Any, Final

from fastapi import Depends, File, Form, Request, UploadFile

from phishtriage.config import Settings
from phishtriage.core.exceptions import (
    FileTooLargeError,
    InputError,
    PhishTriageError,
    RateLimitExceeded,
    UnsupportedFormatError,
)
from phishtriage.core.models import Report
from phishtriage.core.pipeline import TriagePipeline
from phishtriage.parsers.base import SourceFormat, detect_format, validate_input

__all__ = [
    "AnalyzeOptions",
    "OptionsDep",
    "PipelineDep",
    "RateLimitDep",
    "ReportNotFoundError",
    "ReportStore",
    "ServiceNotReadyError",
    "SettingsDep",
    "SlidingWindowRateLimiter",
    "StoreDep",
    "UploadDep",
    "ValidatedUpload",
    "analyze_options",
    "client_key",
    "enforce_rate_limit",
    "get_pipeline",
    "get_report_store",
    "get_settings_dep",
    "read_upload",
    "sanitize_filename",
    "validated_upload",
]

_CHUNK: Final = 64 * 1024
_MAX_FILENAME: Final = 255
_MAX_TRUSTED_HOPS: Final = 100
_MAX_AUTHSERV_IDS: Final = 10
_MAX_AUTHSERV_LEN: Final = 253
_REPORT_ID_RE: Final = re.compile(r"^[0-9a-f]{32}$")


# ================================================================== exceptions
class ReportNotFoundError(PhishTriageError):
    """No stored report has this id (never existed, expired, or evicted)."""

    http_status = 404
    code = "report_not_found"

    def __init__(self) -> None:
        super().__init__("Report not found. It may have expired; upload the message again.")


class ServiceNotReadyError(PhishTriageError):
    """A shared service is missing from ``app.state`` (start-up did not complete)."""

    http_status = 503
    code = "service_unavailable"


# ================================================================== rate limiter
class SlidingWindowRateLimiter:
    """Per-key sliding-window request limiter (in memory, single event loop).

    Memory is bounded: when more than ``max_clients`` keys are tracked, idle ones
    are purged and, if still over the cap, the least recently seen are dropped.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        *,
        max_clients: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a limiter allowing ``limit`` requests per ``window_seconds`` per key."""
        self._limit = max(1, int(limit))
        self._window = max(0.001, float(window_seconds))
        self._max_clients = max(1, int(max_clients))
        self._clock = clock
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _purge(self, now: float) -> None:
        cutoff = now - self._window
        for key in [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]:
            del self._hits[key]
        while len(self._hits) > self._max_clients:
            self._hits.popitem(last=False)

    def check(self, key: str) -> None:
        """Record a request for ``key``.

        Raises:
            RateLimitExceeded: the key already made ``limit`` requests in the window.
                Rejected requests are not recorded, so a client recovers on time.
        """
        now = self._clock()
        cutoff = now - self._window
        hits = self._hits.get(key)
        if hits is None:
            hits = self._hits[key] = deque()
            if len(self._hits) > self._max_clients:
                self._purge(now)
        else:
            self._hits.move_to_end(key)
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self._limit:
            raise RateLimitExceeded(max(0.0, self._window - (now - hits[0])))
        hits.append(now)


# ================================================================== report store
class ReportStore:
    """Bounded in-memory store of recent reports (uniform TTL, FIFO eviction)."""

    def __init__(
        self,
        ttl_seconds: float = 3600.0,
        max_reports: int = 200,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a store keeping at most ``max_reports`` reports for ``ttl_seconds`` each."""
        self._ttl = max(1.0, float(ttl_seconds))
        self._max = max(1, int(max_reports))
        self._clock = clock
        self._items: OrderedDict[str, tuple[float, Report]] = OrderedDict()

    @property
    def ttl_seconds(self) -> int:
        """Retention time in seconds."""
        return int(self._ttl)

    def _purge(self) -> None:
        now = self._clock()
        while self._items:
            key = next(iter(self._items))
            if self._items[key][0] > now:
                break
            del self._items[key]

    def put(self, report: Report) -> None:
        """Store ``report`` (treat stored reports as read-only)."""
        self._purge()
        self._items.pop(report.report_id, None)
        self._items[report.report_id] = (self._clock() + self._ttl, report)
        while len(self._items) > self._max:
            self._items.popitem(last=False)

    def get(self, report_id: str) -> Report:
        """Return a stored report.

        Raises:
            ReportNotFoundError: unknown, malformed, expired or evicted id.
        """
        self._purge()
        if not _REPORT_ID_RE.match(report_id):
            raise ReportNotFoundError()
        entry = self._items.get(report_id)
        if entry is None:
            raise ReportNotFoundError()
        return entry[1]

    def delete(self, report_id: str) -> bool:
        """Remove a report; returns whether it existed."""
        self._purge()
        return self._items.pop(report_id, None) is not None

    def __len__(self) -> int:
        self._purge()
        return len(self._items)


# ================================================================== service access
def _state(request: Request, name: str) -> Any:
    value = getattr(request.app.state, name, None)
    if value is None:
        raise ServiceNotReadyError(f"The service is not ready ('{name}' is not initialised).")
    return value


def get_settings_dep(request: Request) -> Settings:
    """The application settings."""
    settings: Settings = _state(request, "settings")
    return settings


def get_pipeline(request: Request) -> TriagePipeline:
    """The shared triage pipeline."""
    pipeline: TriagePipeline = _state(request, "pipeline")
    return pipeline


def get_report_store(request: Request) -> ReportStore:
    """The shared in-memory report store."""
    store: ReportStore = _state(request, "report_store")
    return store


def client_key(request: Request) -> str:
    """Identify the client for rate limiting (``request.client.host``)."""
    client = request.client
    return client.host if client is not None and client.host else "unknown"


async def enforce_rate_limit(request: Request) -> None:
    """Dependency: apply the shared rate limiter to this request."""
    limiter: SlidingWindowRateLimiter = _state(request, "rate_limiter")
    limiter.check(client_key(request))


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
PipelineDep = Annotated[TriagePipeline, Depends(get_pipeline)]
StoreDep = Annotated[ReportStore, Depends(get_report_store)]
RateLimitDep = Annotated[None, Depends(enforce_rate_limit)]


# ================================================================== upload
def sanitize_filename(raw: str | None) -> str:
    """Base name only, control and direction characters removed, at most 255 chars."""
    if not raw:
        return ""
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if unicodedata.category(c) not in ("Cc", "Cf"))
    return name.strip()[:_MAX_FILENAME]


async def read_upload(file: UploadFile, max_bytes: int) -> bytes:
    """Read ``file`` in chunks, failing as soon as it exceeds ``max_bytes``."""
    buffer = bytearray()
    while True:
        chunk = await file.read(_CHUNK)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise FileTooLargeError(len(buffer), max_bytes)
    return bytes(buffer)


@dataclass(frozen=True)
class ValidatedUpload:
    """An upload that passed every check and is safe to hand to the pipeline."""

    data: bytes
    filename: str
    source_format: SourceFormat


async def validated_upload(
    file: Annotated[UploadFile, File(description="The .eml or .msg file to analyze.")],
    settings: SettingsDep,
) -> ValidatedUpload:
    """Dependency: read and validate the uploaded message file.

    Raises:
        UnsupportedFormatError: HTTP 415, bad extension or content.
        EmptyInputError: HTTP 400.
        FileTooLargeError: HTTP 413.
    """
    try:
        name = sanitize_filename(file.filename)
        extension = PurePath(name).suffix.lower()
        if extension not in settings.api_allowed_extensions:
            raise UnsupportedFormatError(
                f"Only {', '.join(settings.api_allowed_extensions)} files are accepted.",
                details={"extension": extension},
            )
        data = await read_upload(file, settings.max_upload_bytes)
    finally:
        await file.close()
    validate_input(data, settings.max_upload_bytes)
    return ValidatedUpload(data=data, filename=name, source_format=detect_format(data, name))


# ================================================================== options
@dataclass(frozen=True)
class AnalyzeOptions:
    """Optional analysis parameters from the upload form."""

    trusted_hops: int | None
    trusted_authserv_ids: tuple[str, ...]
    enrich: bool
    scan_macros: bool


def analyze_options(
    trusted_hops: Annotated[str, Form(max_length=10)] = "",
    trusted_authserv: Annotated[str, Form(max_length=2000)] = "",
    enrich: Annotated[bool, Form()] = True,
    scan_macros: Annotated[bool, Form()] = True,
) -> AnalyzeOptions:
    """Dependency: parse and validate the optional form fields.

    ``trusted_hops`` and ``trusted_authserv`` arrive as text so that an empty HTML
    form field means "not set" instead of a validation error.

    Raises:
        InputError: HTTP 400, a value is malformed or out of range.
    """
    hops: int | None = None
    text = trusted_hops.strip()
    if text:
        try:
            hops = int(text)
        except ValueError:
            raise InputError("trusted_hops must be a whole number.") from None
        if not 1 <= hops <= _MAX_TRUSTED_HOPS:
            raise InputError(f"trusted_hops must be between 1 and {_MAX_TRUSTED_HOPS}.")

    ids = [p.strip() for p in trusted_authserv.split(",") if p.strip()]
    if len(ids) > _MAX_AUTHSERV_IDS or any(len(i) > _MAX_AUTHSERV_LEN for i in ids):
        raise InputError(
            f"trusted_authserv accepts at most {_MAX_AUTHSERV_IDS} ids of {_MAX_AUTHSERV_LEN} characters."
        )
    return AnalyzeOptions(
        trusted_hops=hops,
        trusted_authserv_ids=tuple(dict.fromkeys(ids)),
        enrich=enrich,
        scan_macros=scan_macros,
    )


UploadDep = Annotated[ValidatedUpload, Depends(validated_upload)]
OptionsDep = Annotated[AnalyzeOptions, Depends(analyze_options)]