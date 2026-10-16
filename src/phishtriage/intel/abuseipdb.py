"""AbuseIPDB provider: crowd-sourced IP abuse reports.

Endpoint: ``GET https://api.abuseipdb.com/api/v2/check`` with the API key in
the ``Key`` header. Supports IPv4 and IPv6.

Verdict mapping uses AbuseIPDB's *abuse confidence score* (0 to 100). That score
is a confidence that the IP is abusive, **not** a severity rating:

* score >= 75                      -> ``MALICIOUS``
* 25 <= score < 75                 -> ``SUSPICIOUS``
* score < 25 with reports on file  -> ``CLEAN``
* score < 25 and zero reports      -> ``UNKNOWN`` (AbuseIPDB has no data; this
  is not evidence of safety)
* whitelisted by AbuseIPDB         -> ``CLEAN``

Only globally routable addresses are sent. Private, loopback, link-local and
documentation-range IPs (``203.0.113.0/24`` etc.) return ``SKIPPED`` locally,
which also saves free-tier quota.

Quota: the free tier allows about 1,000 checks per day. The per-minute limiter
cannot see that daily total. When AbuseIPDB answers HTTP 429 the shared HTTP
client honours ``Retry-After`` and fails fast, so the indicator gets an
``ERROR`` result saying so and the triage continues.
"""

import ipaddress
from collections.abc import Mapping
from typing import ClassVar, Final

from phishtriage.core.exceptions import IntelProviderError
from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.core.utils import clean_text, safe_int
from phishtriage.intel.base import IntelProvider, expect_mapping

__all__ = ["AbuseIPDBProvider"]

_ENDPOINT: Final = "https://api.abuseipdb.com/api/v2/check"
_REFERENCE: Final = "https://www.abuseipdb.com/check/"
_MAX_AGE_DAYS: Final = 90
_MALICIOUS_AT: Final = 75
_SUSPICIOUS_AT: Final = 25


class AbuseIPDBProvider(IntelProvider):
    """Look up IP addresses in AbuseIPDB."""

    name: ClassVar[str] = "abuseipdb"
    supported_types: ClassVar[frozenset[IOCType]] = frozenset({IOCType.IPV4, IOCType.IPV6})

    # ------------------------------------------------------------------ hooks
    def _requests_per_minute(self) -> float:
        return float(self._settings.abuseipdb_requests_per_minute)

    def _default_headers(self) -> Mapping[str, str]:
        key = self._settings.abuseipdb_api_key
        return {"Key": key.get_secret_value()} if key is not None else {}

    def _config_problem(self) -> str | None:
        if self._settings.abuseipdb_api_key is None:
            return "no API key configured (set ABUSEIPDB_API_KEY)"
        return None

    # ----------------------------------------------------------------- lookup
    async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        try:
            ip = ipaddress.ip_address(indicator.strip().strip("[]"))
        except ValueError:
            raise IntelProviderError(
                "AbuseIPDB: not a valid IP address.", provider=self.name
            ) from None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        address = str(ip)

        if not ip.is_global:
            return self._result(
                address, indicator_type, IntelVerdict.SKIPPED,
                detail="Not queried: address is private, reserved or not publicly routable.",
            )  # fmt: skip

        response = await self._http.request_json(
            "GET",
            _ENDPOINT,
            params={"ipAddress": address, "maxAgeInDays": _MAX_AGE_DAYS},
            allow_statuses={422},
        )
        if response.status == 422:
            raise IntelProviderError(
                "AbuseIPDB rejected the IP address as invalid.", provider=self.name
            )

        body = expect_mapping(response.data, provider=self.name)
        data = expect_mapping(body.get("data"), provider=self.name, what="data block")

        score = min(100, safe_int(data.get("abuseConfidenceScore")))
        reports = safe_int(data.get("totalReports"))
        users = safe_int(data.get("numDistinctUsers"))
        whitelisted = data.get("isWhitelisted") is True

        parts = [f"Abuse confidence {score}%"]
        parts.append(f"{reports} report(s) from {users} user(s) in the last {_MAX_AGE_DAYS} days")
        if data.get("isp"):
            parts.append(f"ISP: {clean_text(data['isp'], 60)}")
        if data.get("countryCode"):
            parts.append(f"country: {clean_text(data['countryCode'], 4)}")
        if data.get("usageType"):
            parts.append(f"usage: {clean_text(data['usageType'], 40)}")
        if data.get("isTor") is True:
            parts.append("Tor exit node")
        if data.get("lastReportedAt"):
            parts.append(f"last reported: {clean_text(data['lastReportedAt'], 10)}")
        if whitelisted:
            parts.append("whitelisted by AbuseIPDB")

        if whitelisted:
            verdict, score = IntelVerdict.CLEAN, 0
        elif score >= _MALICIOUS_AT:
            verdict = IntelVerdict.MALICIOUS
        elif score >= _SUSPICIOUS_AT:
            verdict = IntelVerdict.SUSPICIOUS
        elif reports == 0:
            verdict = IntelVerdict.UNKNOWN
        else:
            verdict = IntelVerdict.CLEAN

        return self._result(
            address, indicator_type, verdict,
            score=score,
            detail=" | ".join(parts),
            reference_url=f"{_REFERENCE}{address}",
        )  # fmt: skip
