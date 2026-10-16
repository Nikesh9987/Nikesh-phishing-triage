"""VirusTotal (API v3) provider: files, URLs, domains and IP addresses.

Endpoints (all ``GET``, read-only, API key in the ``x-apikey`` header):

* ``/files/{md5|sha1|sha256}``  indicator type HASH
* ``/urls/{id}``                indicator type URL (id = unpadded URL-safe base64)
* ``/domains/{domain}``         indicator type DOMAIN
* ``/ip_addresses/{ip}``        indicator types IPV4 and IPV6

This provider **never submits** anything for scanning. Submitting would upload
the indicator for active analysis and cost extra quota. Indicators VirusTotal
has not seen (HTTP 404) come back ``UNKNOWN``.

Verdict mapping, from ``last_analysis_stats`` (engines that actually voted,
i.e. malicious + suspicious + harmless + undetected; timeouts excluded):

* >= 3 malicious engines                  -> ``MALICIOUS``
* 1-2 malicious, or >= 2 suspicious       -> ``SUSPICIOUS`` (a lone detection is
  frequently a false positive)
* otherwise                               -> ``CLEAN``
* no engine results yet                   -> ``UNKNOWN``

``score`` blends the verdict with the detection ratio so it never contradicts
the verdict: MALICIOUS 70-100, SUSPICIOUS 30-100 scale from 30, CLEAN 0.
A ``CLEAN`` result means "no engine objected today", not "safe".

Quota: the free tier allows 4 requests/minute and about 500/day. The
per-minute limiter is enforced locally; the daily quota is not visible and shows
up as an HTTP 429 -> ``ERROR`` result.

All text echoed from the API is sanitised (control and bidi characters removed,
length bounded). Reference links are built locally, never taken from the API.
"""

import base64
import hashlib
import ipaddress
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar, Final
from urllib.parse import urlsplit

from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.core.utils import clean_text, safe_int
from phishtriage.intel.base import IntelProvider, expect_mapping

__all__ = ["VirusTotalProvider"]

_API: Final = "https://www.virustotal.com/api/v3"
_GUI: Final = "https://www.virustotal.com/gui"
_MALICIOUS_AT: Final = 3
_SUSPICIOUS_FLOOR: Final = 30
_MALICIOUS_FLOOR: Final = 70

_HEX_RE: Final = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_DOMAIN_RE: Final = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?"
    r"(?:\.[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?)+$"
)
_INTERNAL_TLDS: Final = frozenset(
    {"local", "localhost", "internal", "lan", "home", "corp", "intranet", "localdomain",
     "invalid", "arpa"}
)  # fmt: skip


# ================================================================== helpers
def _signed_int(value: object) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _date(value: object) -> str:
    """Epoch seconds -> ``YYYY-MM-DD`` ('' if unusable)."""
    try:
        return datetime.fromtimestamp(int(str(value)), tz=UTC).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _normalize_domain(value: str) -> str | None:
    """Lower-cased ASCII (punycode) hostname with at least two labels, else ``None``."""
    host = value.strip().strip("[]").rstrip(".").lower()
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host if _DOMAIN_RE.match(host) else None


def _is_public_host(host: str) -> bool:
    """True for globally routable IPs and dotted, non-internal domain names."""
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_global
    except ValueError:
        pass
    domain = _normalize_domain(host)
    return domain is not None and domain.rsplit(".", 1)[-1] not in _INTERNAL_TLDS


def _url_id(url: str) -> str:
    """VirusTotal URL identifier: URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8", "replace")).decode("ascii").rstrip("=")


# ================================================================= provider
class VirusTotalProvider(IntelProvider):
    """Look up hashes, URLs, domains and IPs in VirusTotal."""

    name: ClassVar[str] = "virustotal"
    supported_types: ClassVar[frozenset[IOCType]] = frozenset(
        {IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6, IOCType.HASH}
    )

    # ------------------------------------------------------------------ hooks
    def _requests_per_minute(self) -> float:
        return float(self._settings.virustotal_requests_per_minute)

    def _default_headers(self) -> Mapping[str, str]:
        key = self._settings.virustotal_api_key
        return {"x-apikey": key.get_secret_value()} if key is not None else {}

    def _config_problem(self) -> str | None:
        if self._settings.virustotal_api_key is None:
            return "no API key configured (set VIRUSTOTAL_API_KEY)"
        return None

    # --------------------------------------------------------------- targeting
    def _target(
        self, indicator: str, indicator_type: IOCType
    ) -> tuple[str, str, str] | IntelResult:
        """Return ``(display, api_path, gui_url)`` or a ``SKIPPED`` result."""

        def skip(shown: str, why: str) -> IntelResult:
            return self._result(shown[:100], indicator_type, IntelVerdict.SKIPPED, detail=why)

        if indicator_type is IOCType.HASH:
            digest = indicator.strip().lower()
            if not _HEX_RE.match(digest):
                return skip(digest, "Not queried: not an MD5, SHA-1 or SHA-256 hash.")
            return digest, f"files/{digest}", f"{_GUI}/file/{digest}"

        if indicator_type is IOCType.URL:
            try:
                host = urlsplit(indicator).hostname or ""
            except ValueError:
                host = ""
            if not _is_public_host(host):
                return skip(
                    indicator, "Not queried: URL host is internal or not publicly routable."
                )
            sha = hashlib.sha256(indicator.encode("utf-8", "replace")).hexdigest()
            return indicator, f"urls/{_url_id(indicator)}", f"{_GUI}/url/{sha}"

        if indicator_type is IOCType.DOMAIN:
            domain = _normalize_domain(indicator)
            if domain is None or not _is_public_host(domain):
                return skip(indicator, "Not queried: not a public domain name.")
            return domain, f"domains/{domain}", f"{_GUI}/domain/{domain}"

        try:
            ip = ipaddress.ip_address(indicator.strip().strip("[]"))
        except ValueError:
            return skip(indicator, "Not queried: not a valid IP address.")
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return skip(
                str(ip), "Not queried: address is private, reserved or not publicly routable."
            )
        return str(ip), f"ip_addresses/{ip}", f"{_GUI}/ip-address/{ip}"

    # ------------------------------------------------------------------ lookup
    async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        target = self._target(indicator, indicator_type)
        if isinstance(target, IntelResult):
            return target
        shown, path, gui = target

        response = await self._http.request_json("GET", f"{_API}/{path}", allow_statuses={404})
        if response.status == 404:
            return self._result(
                shown, indicator_type, IntelVerdict.UNKNOWN,
                detail="Not found in VirusTotal (never analysed).",
            )  # fmt: skip

        body = expect_mapping(response.data, provider=self.name)
        data = expect_mapping(body.get("data"), provider=self.name, what="data block")
        attrs = data.get("attributes")
        attributes: Mapping[str, Any] = attrs if isinstance(attrs, Mapping) else {}
        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, Mapping) else {}

        mal, sus = safe_int(stats.get("malicious")), safe_int(stats.get("suspicious"))
        harmless, undetected = safe_int(stats.get("harmless")), safe_int(stats.get("undetected"))
        total = mal + sus + harmless + undetected
        if total == 0:
            return self._result(
                shown, indicator_type, IntelVerdict.UNKNOWN,
                detail="VirusTotal has no analysis results for this indicator yet.",
                reference_url=gui,
            )  # fmt: skip

        if mal >= _MALICIOUS_AT:
            verdict, floor = IntelVerdict.MALICIOUS, _MALICIOUS_FLOOR
        elif mal >= 1 or sus >= 2:
            verdict, floor = IntelVerdict.SUSPICIOUS, _SUSPICIOUS_FLOOR
        else:
            verdict, floor = IntelVerdict.CLEAN, 0
        ratio = min(1.0, (mal + 0.5 * sus) / total)
        score = 0 if verdict is IntelVerdict.CLEAN else floor + round((100 - floor) * ratio)

        parts = [f"{mal}/{total} engines flag it malicious"]
        if sus:
            parts.append(f"{sus} suspicious")
        threat = attributes.get("popular_threat_classification")
        if isinstance(threat, Mapping) and threat.get("suggested_threat_label"):
            parts.append(f"threat: {clean_text(threat['suggested_threat_label'], 50)}")
        if attributes.get("meaningful_name"):
            parts.append(f"name: {clean_text(attributes['meaningful_name'], 60)}")
        if attributes.get("type_description"):
            parts.append(f"type: {clean_text(attributes['type_description'], 40)}")
        if attributes.get("as_owner"):
            parts.append(f"owner: {clean_text(attributes['as_owner'], 60)}")
        if attributes.get("country"):
            parts.append(f"country: {clean_text(attributes['country'], 4)}")
        reputation = _signed_int(attributes.get("reputation"))
        if reputation:
            parts.append(f"community reputation: {reputation}")
        analysed = _date(attributes.get("last_analysis_date"))
        if analysed:
            parts.append(f"analysed: {analysed}")

        return self._result(
            shown, indicator_type, verdict, score=score,
            detail=" | ".join(parts), reference_url=gui,
        )  # fmt: skip
