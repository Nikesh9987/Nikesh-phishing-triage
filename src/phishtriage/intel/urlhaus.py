"""URLhaus (abuse.ch) provider: malware-distribution URLs, hosts and payload hashes.

Endpoints used (all ``POST``, form-encoded, read-only):

* ``/v1/url/``     indicator type URL
* ``/v1/host/``    indicator types DOMAIN and IPV4
* ``/v1/payload/`` indicator type HASH (MD5 or SHA-256; SHA-1 is not supported)

Authentication: abuse.ch requires a free ``Auth-Key`` (https://auth.abuse.ch/),
sent in the ``Auth-Key`` header. Without a key the provider reports itself
disabled and every lookup is ``SKIPPED``.

Verdict mapping (URLhaus only lists confirmed malware distribution):

* URL listed                  -> ``MALICIOUS`` (score 95 online, 75 offline, 60 unknown).
  An offline URL was still used to distribute malware; the detail says so.
* Host with online URLs       -> ``MALICIOUS`` (score 90).
* Host with only past URLs    -> ``SUSPICIOUS`` (score 55). Shared hosting and
  compromised legitimate sites appear here, so this is deliberately softer.
* Payload hash known          -> ``MALICIOUS`` (score 100).
* ``no_results``              -> ``UNKNOWN``. Absence from URLhaus is **not** a
  clean verdict; it only means URLhaus has never seen the indicator.

All text echoed from the API is sanitised (control and bidi characters removed,
length bounded), and reference links are only kept when they point at
``https://urlhaus.abuse.ch/``.
"""

import ipaddress
import re
from collections.abc import Mapping
from typing import Any, ClassVar, Final
from urllib.parse import urlsplit

from phishtriage.core.exceptions import IntelProviderError
from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.core.utils import clean_text, safe_int
from phishtriage.intel.base import IntelProvider, expect_mapping

__all__ = ["URLhausProvider"]

_API_BASE: Final = "https://urlhaus-api.abuse.ch/v1"
_REFERENCE_PREFIX: Final = "https://urlhaus.abuse.ch/"
_BROWSE_URL: Final = "https://urlhaus.abuse.ch/browse.php?search="

_MD5_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")


# ================================================================== helpers
def _reference(value: object, fallback: str = "") -> str:
    """Keep an API-supplied link only if it points at urlhaus.abuse.ch."""
    if (
        isinstance(value, str)
        and value.startswith(_REFERENCE_PREFIX)
        and not any(c.isspace() for c in value)
    ):
        return value[:500]
    return fallback


def _is_external_host(host: str) -> bool:
    """True if ``host`` is a publicly routable IP or a dotted domain name."""
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return "." in host


def _blacklist_note(data: Mapping[str, Any]) -> str:
    """Summarise third-party blocklist listings reported alongside a hit."""
    raw = data.get("blacklists")
    if not isinstance(raw, Mapping):
        return ""
    listed = [
        f"{clean_text(name, 30)}={clean_text(value, 30)}"
        for name, value in raw.items()
        if str(value).strip().lower() not in ("", "not listed")
    ]
    return f"; blocklists: {', '.join(listed[:4])}" if listed else ""


# ================================================================= provider
class URLhausProvider(IntelProvider):
    """Look up URLs, hosts and payload hashes in URLhaus."""

    name: ClassVar[str] = "urlhaus"
    supported_types: ClassVar[frozenset[IOCType]] = frozenset(
        {IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.HASH}
    )

    # ------------------------------------------------------------------ hooks
    def _requests_per_minute(self) -> float:
        return float(self._settings.urlhaus_requests_per_minute)

    def _default_headers(self) -> Mapping[str, str]:
        key = self._settings.urlhaus_auth_key
        return {"Auth-Key": key.get_secret_value()} if key is not None else {}

    def _config_problem(self) -> str | None:
        if self._settings.urlhaus_auth_key is None:
            return "no Auth-Key configured (set URLHAUS_AUTH_KEY)"
        return None

    # ---------------------------------------------------------------- dispatch
    async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        if indicator_type is IOCType.URL:
            return await self._lookup_url(indicator)
        if indicator_type is IOCType.HASH:
            return await self._lookup_hash(indicator)
        return await self._lookup_host(indicator, indicator_type)

    # --------------------------------------------------------------- transport
    async def _query(self, path: str, form: Mapping[str, str]) -> tuple[str, dict[str, Any]]:
        """POST a query and return ``(query_status, body)`` for a usable response."""
        response = await self._http.request_json("POST", f"{_API_BASE}/{path}/", data=form)
        body = expect_mapping(response.data, provider=self.name)
        status = str(body.get("query_status", "")).strip().lower()
        if status in ("ok", "no_results"):
            return status, body
        if status.startswith("invalid"):
            raise IntelProviderError(
                f"URLhaus rejected the query ({clean_text(status, 40)}).", provider=self.name
            )
        raise IntelProviderError(
            f"URLhaus returned an unexpected status ({clean_text(status or 'none', 40)}).",
            provider=self.name,
        )

    # --------------------------------------------------------------------- URL
    async def _lookup_url(self, url: str) -> IntelResult:
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = ""
        if not _is_external_host(host):
            return self._result(
                url, IOCType.URL, IntelVerdict.SKIPPED,
                detail="Not queried: URL host is internal or not publicly routable.",
            )  # fmt: skip

        status, body = await self._query("url", {"url": url})
        if status == "no_results":
            return self._result(
                url, IOCType.URL, IntelVerdict.UNKNOWN, detail="Not listed in URLhaus."
            )

        url_status = clean_text(body.get("url_status") or "unknown", 20).lower()
        score = {"online": 95, "offline": 75}.get(url_status, 60)
        parts = [f"status: {url_status}"]
        if body.get("threat"):
            parts.append(f"threat: {clean_text(body['threat'], 40)}")
        tags = body.get("tags")
        if isinstance(tags, list) and tags:
            parts.append("tags: " + ", ".join(clean_text(t, 30) for t in tags[:6]))
        if body.get("date_added"):
            parts.append(f"added: {clean_text(body['date_added'], 25)}")
        note = " (no longer serving, but it distributed malware)" if url_status == "offline" else ""
        return self._result(
            url, IOCType.URL, IntelVerdict.MALICIOUS, score=score,
            detail=f"Listed in URLhaus ({'; '.join(parts)}){note}{_blacklist_note(body)}",
            reference_url=_reference(body.get("urlhaus_reference")),
        )  # fmt: skip

    # -------------------------------------------------------------------- host
    async def _lookup_host(self, host: str, indicator_type: IOCType) -> IntelResult:
        target = host.strip().rstrip(".").lower()
        if not _is_external_host(target):
            return self._result(
                target, indicator_type, IntelVerdict.SKIPPED,
                detail="Not queried: host is internal or not publicly routable.",
            )  # fmt: skip

        status, body = await self._query("host", {"host": target})
        urls = body.get("urls")
        listed = [u for u in urls if isinstance(u, Mapping)] if isinstance(urls, list) else []
        count = max(safe_int(body.get("url_count")), len(listed))
        if status == "no_results" or count == 0:
            return self._result(
                target, indicator_type, IntelVerdict.UNKNOWN,
                detail="No malware URLs recorded for this host in URLhaus.",
            )  # fmt: skip

        online = sum(1 for u in listed if str(u.get("url_status", "")).lower() == "online")
        reference = _reference(body.get("urlhaus_reference"))
        if online:
            return self._result(
                target, indicator_type, IntelVerdict.MALICIOUS, score=90,
                detail=f"{count} malware URL(s) recorded on this host, {online} currently online"
                f"{_blacklist_note(body)}.",
                reference_url=reference,
            )  # fmt: skip
        return self._result(
            target, indicator_type, IntelVerdict.SUSPICIOUS, score=55,
            detail=f"{count} past malware URL(s) recorded on this host, none currently online "
            f"(shared or compromised hosts also appear here){_blacklist_note(body)}.",
            reference_url=reference,
        )  # fmt: skip

    # -------------------------------------------------------------------- hash
    async def _lookup_hash(self, value: str) -> IntelResult:
        digest = value.strip().lower()
        if _SHA256_RE.match(digest):
            field = "sha256_hash"
        elif _MD5_RE.match(digest):
            field = "md5_hash"
        else:
            return self._result(
                digest[:100], IOCType.HASH, IntelVerdict.SKIPPED,
                detail="URLhaus supports only MD5 and SHA-256 hashes.",
            )  # fmt: skip

        status, body = await self._query("payload", {field: digest})
        if status == "no_results":
            return self._result(
                digest, IOCType.HASH, IntelVerdict.UNKNOWN, detail="Payload not known to URLhaus."
            )

        parts = ["Known malware payload in URLhaus"]
        if body.get("signature"):
            parts.append(f"signature: {clean_text(body['signature'], 50)}")
        if body.get("file_type"):
            parts.append(f"type: {clean_text(body['file_type'], 20)}")
        distribution = safe_int(body.get("url_count"))
        if distribution:
            parts.append(f"seen on {distribution} URL(s)")
        return self._result(
            digest, IOCType.HASH, IntelVerdict.MALICIOUS, score=100,
            detail="; ".join(parts) + ".",
            reference_url=f"{_BROWSE_URL}{digest}",
        )  # fmt: skip
