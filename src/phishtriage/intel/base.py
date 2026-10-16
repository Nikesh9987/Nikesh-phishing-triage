"""Threat-intel provider interface and the shared, hardened HTTP client.

Two building blocks:

* :class:`IntelHttpClient`: an async JSON-over-HTTPS helper that every
  provider uses. It enforces:
    - a total per-request deadline plus per-phase httpx timeouts;
    - retries with exponential backoff and jitter on timeouts, connection
      errors, HTTP 5xx and 408 (lookups are read-only, so retrying is safe);
    - ``429`` handling that honours ``Retry-After``, feeds it into the rate
      limiter, and fails fast instead of sleeping for minutes;
    - a response-size cap enforced while streaming (a hostile or broken API
      cannot exhaust memory, including via compression bombs);
    - **no redirects** (API endpoints should not redirect, and following them
      could leak the API-key header to another host);
    - strict error mapping onto :mod:`phishtriage.core.exceptions`.
* :class:`IntelProvider`: the abstract base class. Its public
  :meth:`~IntelProvider.lookup` **never raises**: disabled, unsupported,
  invalid and failing lookups all come back as an :class:`IntelResult` with a
  ``SKIPPED`` or ``ERROR`` verdict, so one provider outage can never abort a
  triage. Subclasses implement only :meth:`~IntelProvider._lookup`.

Secrets: API keys are sent in request headers (never in URLs), error messages
never include request URLs or headers, and configured secrets are registered
with the log redactor.

Indicators passed to providers must be the *refanged* live value (``IOC.value``)
and only that value is ever sent, never email content or attachments.
"""

import asyncio
import json
import math
import random
import re
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from types import TracebackType
from typing import Any, ClassVar, Final
from urllib.parse import urlsplit

import httpx

from phishtriage.config import Settings, get_settings
from phishtriage.core.exceptions import (
    IntelAuthError,
    IntelProviderError,
    IntelRateLimitError,
    IntelTimeoutError,
    IntelUnavailableError,
)
from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.intel.rate_limiter import AsyncRateLimiter
from phishtriage.logging_config import get_logger, register_secrets

__all__ = [
    "IntelHttpClient",
    "IntelProvider",
    "JsonResponse",
    "ProviderStatus",
    "expect_mapping",
    "parse_retry_after",
]

logger = get_logger(__name__)

_MIB: Final = 1024 * 1024
_MAX_RETRY_SLEEP: Final = 10.0  # never sleep longer than this inside a retry
_BACKOFF_BASE: Final = 0.5
_MAX_INDICATOR_LEN: Final = 2048
_MAX_DETAIL_LEN: Final = 500
_BAD_INDICATOR_RE: Final = re.compile(r"[\s\x00-\x1f\x7f]")

Sleeper = Callable[[float], Awaitable[None]]


# ================================================================== helpers
def parse_retry_after(value: str | None) -> float | None:
    """Parse a ``Retry-After`` header (delta-seconds or HTTP-date) into seconds.

    Returns ``None`` if absent or unparseable. Past dates yield ``0.0``.
    """
    if not value or not value.strip():
        return None
    text = value.strip()
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return max(0.0, seconds)


def expect_mapping(data: Any, *, provider: str, what: str = "response") -> dict[str, Any]:
    """Return ``data`` if it is a JSON object, else raise a provider error."""
    if not isinstance(data, dict):
        raise IntelProviderError(
            f"{provider} returned an unexpected {what} format.", provider=provider
        )
    return data


@dataclass(frozen=True)
class JsonResponse:
    """A completed HTTP exchange. ``data`` is ``None`` for empty/non-JSON bodies
    of statuses the caller explicitly allowed.
    """

    status: int
    data: Any
    headers: dict[str, str] = field(default_factory=dict)


# ================================================================= HTTP client
class IntelHttpClient:
    """Async JSON HTTP client with retries, rate limiting, and error mapping."""

    def __init__(
        self,
        *,
        provider: str,
        timeout: float = 10.0,
        max_retries: int = 2,
        user_agent: str = "phishing-triage",
        headers: Mapping[str, str] | None = None,
        limiter: AsyncRateLimiter | None = None,
        max_response_bytes: int = 2 * _MIB,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        """Create a client (the underlying connection pool is opened lazily).

        Args:
            provider: Provider name used in errors and logs.
            timeout: Total seconds allowed per attempt, and per httpx phase.
            max_retries: Extra attempts after the first (0 disables retries).
            user_agent: ``User-Agent`` header.
            headers: Extra default headers. May contain secrets and is never logged.
            limiter: Rate limiter applied before every attempt.
            max_response_bytes: Responses larger than this are rejected.
            transport: Custom httpx transport (used by tests).
            sleep: Async sleep used for backoff (injectable for tests).
        """
        self._provider = provider
        self._timeout = max(0.1, float(timeout))
        self._max_retries = max(0, int(max_retries))
        self._limiter = limiter
        self._max_bytes = max(1024, int(max_response_bytes))
        self._transport = transport
        self._sleep = sleep
        self._headers: dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "application/json",
            **(dict(headers) if headers else {}),
        }
        self._client: httpx.AsyncClient | None = None

    def __repr__(self) -> str:  # never include headers (they may hold API keys)
        return f"IntelHttpClient(provider={self._provider!r})"

    @property
    def limiter(self) -> AsyncRateLimiter | None:
        """The rate limiter in use, if any."""
        return self._limiter

    # ------------------------------------------------------------------ lifecycle
    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                headers=self._headers,
                follow_redirects=False,
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                transport=self._transport,
            )
        return self._client

    async def aclose(self) -> None:
        """Close the connection pool. Safe to call more than once."""
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def __aenter__(self) -> "IntelHttpClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --------------------------------------------------------------- one attempt
    async def _send_once(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None,
        data: Mapping[str, Any] | None,
        json_body: Any,
        headers: Mapping[str, str] | None,
    ) -> tuple[int, dict[str, str], bytes]:
        client = self._get_client()
        try:
            async with asyncio.timeout(self._timeout):
                async with client.stream(
                    method, url, params=params, data=data, json=json_body, headers=headers
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self._max_bytes:
                            raise IntelProviderError(
                                f"{self._provider} response exceeded {self._max_bytes:,} bytes.",
                                provider=self._provider,
                            )
                    resp_headers = {k.lower(): v for k, v in response.headers.items()}
                    return response.status_code, resp_headers, bytes(body)
        except (TimeoutError, httpx.TimeoutException):
            raise IntelTimeoutError(
                f"{self._provider} did not respond within {self._timeout:g}s.",
                provider=self._provider,
            ) from None
        except httpx.TransportError as exc:
            raise IntelUnavailableError(
                f"{self._provider} is unreachable ({type(exc).__name__}).",
                provider=self._provider,
            ) from None
        except httpx.InvalidURL:
            raise IntelProviderError(
                f"{self._provider} request URL is invalid.", provider=self._provider
            ) from None
        except httpx.HTTPError as exc:
            raise IntelProviderError(
                f"{self._provider} request failed ({type(exc).__name__}).",
                provider=self._provider,
            ) from None

    # ----------------------------------------------------------------- backoff
    @staticmethod
    def _backoff_delay(attempt: int) -> float:
        base = min(_BACKOFF_BASE * (2**attempt), _MAX_RETRY_SLEEP)
        return base + random.uniform(0.0, 0.25)  # noqa: S311 - jitter, not security

    # -------------------------------------------------------------- JSON decoding
    def _decode(self, status: int, body: bytes, *, strict: bool) -> Any:
        """Parse a JSON body. ``strict`` (2xx) raises on invalid JSON; otherwise ``None``."""
        if not body.strip():
            return None
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except (ValueError, RecursionError):
            if strict:
                raise IntelProviderError(
                    f"{self._provider} returned invalid JSON (HTTP {status}).",
                    provider=self._provider,
                ) from None
            return None

    # ------------------------------------------------------------------ public API
    async def request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        allow_statuses: Collection[int] = (),
    ) -> JsonResponse:
        """Send a request and return the decoded JSON response.

        Args:
            method: HTTP method.
            url: Absolute ``https://`` URL.
            params: Query parameters.
            data: Form-encoded body.
            json_body: JSON body.
            headers: Extra per-request headers.
            allow_statuses: Non-2xx statuses returned normally instead of
                raising (e.g. ``{404}`` for "not found" lookups).

        Raises:
            IntelRateLimitError: local limiter or server (429) says wait too long.
            IntelAuthError: HTTP 401/403.
            IntelTimeoutError: every attempt timed out.
            IntelUnavailableError: connection failure or persistent 5xx.
            IntelProviderError: any other failure (4xx, invalid JSON, oversize).
        """
        attempts = self._max_retries + 1
        provider = self._provider
        target = urlsplit(url)
        label = f"{target.netloc}{target.path}"  # no query string: keep logs clean

        for attempt in range(attempts):
            last = attempt == attempts - 1
            if self._limiter is not None:
                await self._limiter.acquire()  # may raise IntelRateLimitError

            try:
                status, resp_headers, body = await self._send_once(
                    method, url, params=params, data=data, json_body=json_body, headers=headers
                )
            except (IntelTimeoutError, IntelUnavailableError) as exc:
                logger.debug(
                    "%s attempt %d/%d failed: %s", label, attempt + 1, attempts, exc.message
                )
                if last:
                    raise
                await self._sleep(self._backoff_delay(attempt))
                continue

            logger.debug(
                "%s %s -> HTTP %d (attempt %d/%d)", method, label, status, attempt + 1, attempts
            )

            if 200 <= status < 300:
                return JsonResponse(status, self._decode(status, body, strict=True), resp_headers)
            if status in allow_statuses:
                return JsonResponse(status, self._decode(status, body, strict=False), resp_headers)

            if status in (401, 403):
                raise IntelAuthError(
                    f"{provider} rejected the API key or access (HTTP {status}).", provider=provider
                )

            if status == 429:
                retry_after = parse_retry_after(resp_headers.get("retry-after"))
                delay = retry_after if retry_after is not None else self._backoff_delay(attempt)
                if self._limiter is not None:
                    self._limiter.defer(delay)
                if last or delay > _MAX_RETRY_SLEEP:
                    raise IntelRateLimitError(
                        f"{provider} rate limit reached (HTTP 429).",
                        provider=provider,
                        retry_after=delay,
                    )
                await self._sleep(delay)
                continue

            if status >= 500 or status == 408:
                if last:
                    raise IntelUnavailableError(
                        f"{provider} is unavailable (HTTP {status}).", provider=provider
                    )
                retry_after = parse_retry_after(resp_headers.get("retry-after"))
                delay = retry_after if retry_after is not None else self._backoff_delay(attempt)
                await self._sleep(min(delay, _MAX_RETRY_SLEEP))
                continue

            raise IntelProviderError(f"{provider} returned HTTP {status}.", provider=provider)

        # Unreachable: the final attempt either returns or raises above.
        raise IntelUnavailableError(f"{provider} request failed.", provider=provider)


# ============================================================== provider base
@dataclass(frozen=True)
class ProviderStatus:
    """Whether a provider can run, and why not if it cannot."""

    name: str
    enabled: bool
    reason: str = ""


def _indicator_problem(value: str) -> str | None:
    if not value:
        return "empty indicator"
    if len(value) > _MAX_INDICATOR_LEN:
        return f"indicator longer than {_MAX_INDICATOR_LEN} characters"
    if _BAD_INDICATOR_RE.search(value):
        return "indicator contains whitespace or control characters"
    return None


class IntelProvider(ABC):
    """Base class for threat-intelligence providers.

    Subclasses must set :attr:`name` and :attr:`supported_types`, and implement
    :meth:`_requests_per_minute` and :meth:`_lookup`. They may override
    :meth:`_default_headers` (to add an API-key header) and :meth:`_config_problem`
    (to report a missing key).
    """

    name: ClassVar[str]
    supported_types: ClassVar[frozenset[IOCType]]

    def __init__(
        self, settings: Settings | None = None, *, http: IntelHttpClient | None = None
    ) -> None:
        """Create a provider.

        Args:
            settings: Application settings (defaults to the process singleton).
            http: A pre-built HTTP client (used by tests); one is created otherwise.
        """
        self._settings = settings or get_settings()
        register_secrets(self._settings.secret_values())
        if http is None:
            limiter = AsyncRateLimiter(self._requests_per_minute(), name=self.name)
            http = IntelHttpClient(
                provider=self.name,
                timeout=self._settings.http_timeout_seconds,
                max_retries=self._settings.http_max_retries,
                user_agent=self._settings.http_user_agent,
                headers=self._default_headers(),
                limiter=limiter,
            )
        self._http = http

    # ------------------------------------------------------------- subclass hooks
    @abstractmethod
    def _requests_per_minute(self) -> float:
        """Sustained request rate for this provider's rate limiter."""

    @abstractmethod
    async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        """Query the provider. May raise :class:`IntelProviderError` subclasses."""

    def _default_headers(self) -> Mapping[str, str]:
        """Headers sent with every request (e.g. the API key). Never logged."""
        return {}

    def _config_problem(self) -> str | None:
        """Return a reason string if the provider is not configured, else ``None``."""
        return None

    # -------------------------------------------------------------------- status
    def disabled_reason(self) -> str | None:
        """Why this provider cannot run, or ``None`` if it can."""
        if self._settings.offline:
            return "offline mode"
        return self._config_problem()

    @property
    def enabled(self) -> bool:
        """True if the provider is configured and the network is allowed."""
        return self.disabled_reason() is None

    def status(self) -> ProviderStatus:
        """Return a :class:`ProviderStatus` for reports and the CLI."""
        reason = self.disabled_reason()
        return ProviderStatus(name=self.name, enabled=reason is None, reason=reason or "")

    def supports(self, indicator_type: IOCType) -> bool:
        """True if this provider can look up ``indicator_type``."""
        return indicator_type in self.supported_types

    # ------------------------------------------------------------ result helpers
    def _result(
        self,
        indicator: str,
        indicator_type: IOCType,
        verdict: IntelVerdict,
        *,
        score: int | None = None,
        detail: str = "",
        reference_url: str = "",
    ) -> IntelResult:
        """Build an :class:`IntelResult` with clamped score and bounded text."""
        return IntelResult(
            provider=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            score=None if score is None else max(0, min(100, int(score))),
            detail=detail[:_MAX_DETAIL_LEN],
            reference_url=reference_url[:_MAX_DETAIL_LEN],
        )

    # -------------------------------------------------------------- public lookup
    async def lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        """Look up one indicator. **Never raises** (except task cancellation).

        Args:
            indicator: The refanged, live indicator value (``IOC.value``).
            indicator_type: What kind of indicator it is.

        Returns:
            An :class:`IntelResult`. ``SKIPPED`` if the type is unsupported or
            the provider is disabled; ``ERROR`` if the lookup failed.
        """
        value = indicator.strip() if isinstance(indicator, str) else ""
        if not self.supports(indicator_type):
            return self._result(
                value, indicator_type, IntelVerdict.SKIPPED,
                detail=f"{self.name} does not support {indicator_type.value} indicators.",
            )  # fmt: skip
        reason = self.disabled_reason()
        if reason is not None:
            return self._result(
                value,
                indicator_type,
                IntelVerdict.SKIPPED,
                detail=f"{self.name} disabled: {reason}.",
            )
        problem = _indicator_problem(value)
        if problem is not None:
            return self._result(
                value[:100], indicator_type, IntelVerdict.ERROR, detail=f"Not queried: {problem}."
            )

        try:
            return await self._lookup(value, indicator_type)
        except IntelRateLimitError as exc:
            wait = f" Retry in about {exc.retry_after:.0f}s." if exc.retry_after else ""
            return self._result(
                value, indicator_type, IntelVerdict.ERROR, detail=f"{exc.message}{wait}"
            )
        except IntelProviderError as exc:
            return self._result(value, indicator_type, IntelVerdict.ERROR, detail=exc.message)
        except Exception:  # noqa: BLE001 - a provider bug must never abort a triage
            logger.exception("Unexpected error in provider %s", self.name)
            return self._result(
                value,
                indicator_type,
                IntelVerdict.ERROR,
                detail=f"{self.name} lookup failed unexpectedly.",
            )

    # ----------------------------------------------------------------- lifecycle
    async def aclose(self) -> None:
        """Release network resources."""
        await self._http.aclose()

    async def __aenter__(self) -> "IntelProvider":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
