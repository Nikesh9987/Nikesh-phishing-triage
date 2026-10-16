"""Application configuration.

All settings are environment-driven (12-factor style) and validated at start-up.
Values are read from process environment variables and, optionally, a local
``.env`` file. Most settings use the ``PHISHTRIAGE_`` prefix, e.g.
``PHISHTRIAGE_LOG_LEVEL=DEBUG``. Third-party API keys additionally accept their
conventional unprefixed names (``ABUSEIPDB_API_KEY``, ``VT_API_KEY`` ...).

Secrets are held as :class:`pydantic.SecretStr` so they never appear in
``repr()``, tracebacks, or accidental ``print(settings)`` calls.
"""

import ipaddress
import json
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_MIB = 1024 * 1024

Environment = Literal["development", "production", "testing"]
LogFormat = Literal["text", "json"]
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _split_list(value: Any) -> Any:
    """Coerce a comma-separated string or JSON array string into a list of str.

    Non-string inputs are returned untouched so pydantic can validate them.
    """
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON list: {exc}") from exc
            if not isinstance(parsed, list):
                raise ValueError("Expected a JSON array")
            return [str(item).strip() for item in parsed if str(item).strip()]
        return [part.strip() for part in text.split(",") if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return value


def _api_key_alias(*names: str) -> AliasChoices:
    """Build an alias set accepting the prefixed and conventional env names."""
    return AliasChoices(*names)


class Settings(BaseSettings):
    """Validated, immutable runtime settings for the whole application."""

    model_config = SettingsConfigDict(
        env_prefix="PHISHTRIAGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
        frozen=True,
    )

    # ------------------------------------------------------------------ general
    environment: Environment = "development"
    log_level: str = "INFO"
    log_format: LogFormat = "text"
    offline: bool = Field(
        default=False,
        description=(
            "When true, NO network activity is performed: threat-intel lookups, "
            "reverse DNS, and SPF/DKIM/DMARC DNS fallbacks are all skipped."
        ),
    )

    # ------------------------------------------------------------ analysis limits
    max_upload_bytes: int = Field(default=25 * _MIB, ge=1024, le=512 * _MIB)
    max_attachment_bytes: int = Field(
        default=50 * _MIB,
        ge=1024,
        le=1024 * _MIB,
        description="Attachments larger than this are listed but not hashed/inspected.",
    )
    max_attachments: int = Field(default=100, ge=1, le=10_000)
    max_received_hops: int = Field(default=40, ge=1, le=500)
    max_iocs_per_type: int = Field(default=500, ge=1, le=100_000)

    # ---------------------------------------------------------------------- network
    http_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    http_max_retries: int = Field(default=2, ge=0, le=10)
    http_user_agent: str = "phishing-triage/1.0 (+SOC analysis tool)"

    dns_timeout_seconds: float = Field(default=3.0, gt=0, le=60)
    dns_lifetime_seconds: float = Field(default=6.0, gt=0, le=120)
    dns_nameservers: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Custom resolvers (IPs). Empty means use the system resolver.",
    )

    # ----------------------------------------------------------------- threat intel
    urlhaus_auth_key: SecretStr | None = Field(
        default=None,
        validation_alias=_api_key_alias("PHISHTRIAGE_URLHAUS_AUTH_KEY", "URLHAUS_AUTH_KEY"),
    )
    abuseipdb_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=_api_key_alias("PHISHTRIAGE_ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY"),
    )
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=_api_key_alias(
            "PHISHTRIAGE_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY"
        ),
    )

    # Requests per minute. The VirusTotal default matches the public free tier.
    urlhaus_requests_per_minute: int = Field(default=30, ge=1, le=10_000)
    abuseipdb_requests_per_minute: int = Field(default=30, ge=1, le=10_000)
    virustotal_requests_per_minute: int = Field(default=4, ge=1, le=10_000)

    dnsbl_concurrency: int = Field(default=10, ge=1, le=100)
    dnsbl_ip_zones: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl-1.uceprotect.net"]
    )
    dnsbl_domain_zones: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["dbl.spamhaus.org", "multi.uribl.com"]
    )

    cache_ttl_seconds: int = Field(default=3600, ge=0, le=7 * 24 * 3600)
    cache_max_entries: int = Field(default=10_000, ge=1, le=1_000_000)

    # -------------------------------------------------------------------------- API
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_rate_limit_per_minute: int = Field(
        default=30, ge=1, le=100_000, description="Per-client limit on /api/analyze."
    )
    api_allowed_extensions: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [".eml", ".msg"]
    )
    api_cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    enable_api_docs: bool = True

    # ------------------------------------------------------------------- validators
    @field_validator(
        "dns_nameservers",
        "dnsbl_ip_zones",
        "dnsbl_domain_zones",
        "api_allowed_extensions",
        "api_cors_origins",
        mode="before",
    )
    @classmethod
    def _parse_list_fields(cls, value: Any) -> Any:
        return _split_list(value)

    @field_validator("urlhaus_auth_key", "abuseipdb_api_key", "virustotal_api_key", mode="before")
    @classmethod
    def _blank_secret_is_none(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if isinstance(value, str) and not value.strip():
            return None
        return value.strip() if isinstance(value, str) else value

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: Any) -> str:
        level = str(value).strip().upper()
        if level == "WARN":
            level = "WARNING"
        if level not in _VALID_LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_VALID_LOG_LEVELS)}")
        return level

    @field_validator("dns_nameservers")
    @classmethod
    def _validate_nameservers(cls, value: list[str]) -> list[str]:
        for server in value:
            try:
                ipaddress.ip_address(server)
            except ValueError as exc:
                raise ValueError(f"Invalid nameserver IP address: {server!r}") from exc
        return value

    @field_validator("dnsbl_ip_zones", "dnsbl_domain_zones")
    @classmethod
    def _normalise_zones(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for zone in value:
            zone = zone.strip().strip(".").lower()
            if zone and zone not in cleaned:
                cleaned.append(zone)
        return cleaned

    @field_validator("api_allowed_extensions")
    @classmethod
    def _normalise_extensions(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for ext in value:
            ext = ext.strip().lower()
            if not ext:
                continue
            if not ext.startswith("."):
                ext = f".{ext}"
            if ext not in cleaned:
                cleaned.append(ext)
        if not cleaned:
            raise ValueError("api_allowed_extensions must contain at least one extension")
        return cleaned

    # ------------------------------------------------------------------ convenience
    @property
    def is_production(self) -> bool:
        """True when running with ``PHISHTRIAGE_ENVIRONMENT=production``."""
        return self.environment == "production"

    @property
    def network_enabled(self) -> bool:
        """True unless offline mode is active."""
        return not self.offline

    @property
    def intel_providers_available(self) -> dict[str, bool]:
        """Which threat-intel providers can actually run with the current settings.

        DNSBL needs no key but does need network access, so offline mode
        disables every provider.
        """
        online = self.network_enabled
        return {
            "urlhaus": online and self.urlhaus_auth_key is not None,
            "abuseipdb": online and self.abuseipdb_api_key is not None,
            "virustotal": online and self.virustotal_api_key is not None,
            "dnsbl": online and bool(self.dnsbl_ip_zones or self.dnsbl_domain_zones),
        }

    def secret_values(self) -> list[str]:
        """Return the plaintext of every configured secret (for log redaction)."""
        secrets = (self.urlhaus_auth_key, self.abuseipdb_api_key, self.virustotal_api_key)
        return [s.get_secret_value() for s in secrets if s is not None]

    def redacted_dump(self) -> dict[str, Any]:
        """Return all settings as a dict that is safe to log or display."""
        data = self.model_dump()
        for key, value in data.items():
            if isinstance(value, SecretStr):
                data[key] = "***set***"
        return data


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings` singleton."""
    return Settings()


def reload_settings() -> Settings:
    """Discard the cached settings and re-read the environment (used by tests)."""
    get_settings.cache_clear()
    return get_settings()
