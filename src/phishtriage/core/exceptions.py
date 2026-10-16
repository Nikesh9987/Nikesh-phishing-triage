"""Exception hierarchy for Phishing Triage.

Every error raised deliberately by this package derives from
:class:`PhishTriageError`, so interface layers can catch one base class.
Each exception carries:

* ``http_status``: the status code the FastAPI layer should return.
* ``exit_code``: the process exit code the CLI should use.
* ``details``: optional structured, JSON-safe context (never secrets).

Analyzers should prefer *degrading gracefully* (append a warning to the report)
over raising. Exceptions are reserved for conditions where no meaningful
report can be produced, such as an unreadable file or an oversized upload.
"""

from typing import Any


class PhishTriageError(Exception):
    """Base class for all application errors."""

    http_status: int = 500
    exit_code: int = 1
    code: str = "internal_error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation for API error responses."""
        payload: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload

    def __str__(self) -> str:
        return self.message


# --------------------------------------------------------------------- input errors
class InputError(PhishTriageError):
    """The caller supplied unusable input."""

    http_status = 400
    exit_code = 2
    code = "invalid_input"


class FileTooLargeError(InputError):
    """The input exceeds the configured size limit."""

    http_status = 413
    code = "file_too_large"

    def __init__(self, size: int, limit: int) -> None:
        super().__init__(
            f"Input is {size} bytes; the limit is {limit} bytes.",
            details={"size": size, "limit": limit},
        )


class EmptyInputError(InputError):
    """The input contained no data."""

    code = "empty_input"

    def __init__(self) -> None:
        super().__init__("The supplied file is empty.")


class UnsupportedFormatError(InputError):
    """The input is not a recognised .eml or .msg file."""

    http_status = 415
    code = "unsupported_format"


# ------------------------------------------------------------------- parsing errors
class ParserError(PhishTriageError):
    """A message could not be parsed into a usable structure."""

    http_status = 422
    exit_code = 3
    code = "parse_error"


class MalformedMessageError(ParserError):
    """The message is too damaged to extract any meaningful data."""

    code = "malformed_message"


class MissingDependencyError(ParserError):
    """An optional parsing dependency (e.g. ``extract-msg``) is unavailable."""

    http_status = 501
    code = "missing_dependency"


# ------------------------------------------------------------------ analysis errors
class AnalysisError(PhishTriageError):
    """An analyzer failed in a way that could not be degraded gracefully."""

    exit_code = 4
    code = "analysis_error"


class DNSLookupError(AnalysisError):
    """A DNS query failed (timeout, SERVFAIL, resolver unreachable)."""

    http_status = 502
    code = "dns_lookup_error"


# ------------------------------------------------------------ threat-intel errors
class IntelProviderError(PhishTriageError):
    """Base class for threat-intelligence provider failures."""

    http_status = 502
    exit_code = 5
    code = "intel_provider_error"

    def __init__(
        self,
        message: str,
        *,
        provider: str = "unknown",
        details: dict[str, Any] | None = None,
    ) -> None:
        merged = {"provider": provider, **(details or {})}
        super().__init__(message, details=merged)
        self.provider = provider


class IntelTimeoutError(IntelProviderError):
    """The provider did not respond within the configured timeout."""

    http_status = 504
    code = "intel_timeout"


class IntelAuthError(IntelProviderError):
    """The provider rejected the API key (HTTP 401/403)."""

    code = "intel_auth_error"


class IntelRateLimitError(IntelProviderError):
    """The provider (or local limiter) refused the request due to rate limits."""

    http_status = 429
    code = "intel_rate_limited"

    def __init__(
        self,
        message: str,
        *,
        provider: str = "unknown",
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, provider=provider, details={"retry_after": retry_after})
        self.retry_after = retry_after


class IntelUnavailableError(IntelProviderError):
    """The provider is disabled, unconfigured, or unreachable."""

    http_status = 503
    code = "intel_unavailable"


# -------------------------------------------------------------- operational errors
class ConfigurationError(PhishTriageError):
    """The application is misconfigured."""

    exit_code = 78  # EX_CONFIG
    code = "configuration_error"


class RateLimitExceeded(PhishTriageError):
    """A client exceeded the API request rate limit."""

    http_status = 429
    code = "rate_limit_exceeded"

    def __init__(self, retry_after: float) -> None:
        super().__init__(
            "Too many requests. Please retry later.",
            details={"retry_after_seconds": round(retry_after, 1)},
        )
        self.retry_after = retry_after
