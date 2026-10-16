"""Keyless DNS blocklist (DNSBL / URIBL / DBL) provider.

Supports IPv4, IPv6 and DOMAIN indicators. Zones come from settings:
``PHISHTRIAGE_DNSBL_IP_ZONES`` and ``PHISHTRIAGE_DNSBL_DOMAIN_ZONES``.

How a lookup works:

* IPs: the reversed address (octets, or nibbles for IPv6) is prepended to each
  zone, e.g. ``5.113.0.203.zen.spamhaus.org``.
* Domains: the host name and, when different, its organizational domain are
  both queried against each zone (URIBL lists registered domains).
* An ``A`` answer inside ``127.0.0.0/8`` means *listed*; ``NXDOMAIN`` means
  *not listed*. The exact code is interpreted per zone (Spamhaus ZEN/DBL,
  URIBL, SpamCop, UCEPROTECT). Unknown zones: any ``127.x.x.x`` answer is a
  generic listing.

Things that must not be mistaken for a verdict:

* ``127.255.255.252/254/255`` (Spamhaus) and ``127.0.0.1`` (URIBL) mean "query
  refused": you are using a public/open resolver or exceeded a free quota.
  These are reported as **errors**, never as clean.
* A *non-127* answer usually means the resolver rewrites NXDOMAIN (ISP
  search pages). Also an error.
* Spamhaus PBL (``127.0.0.10/11``) says an IP belongs to an end-user range
  that should not send mail directly. That is informational, not abuse.

Verdicts: listed on a malware/phishing/exploit list -> ``MALICIOUS``; listed on
spam lists -> ``SUSPICIOUS``; no listing -> ``UNKNOWN`` (never ``CLEAN``;
absence from a blocklist is weak evidence); no zone could answer -> ``ERROR``.
Each extra listing zone adds 5 to the score (capped at 100).

Privacy: only the IP or domain is placed in DNS queries, and internal, private,
documentation or non-routable indicators are skipped locally. Note that DNS
queries reveal the looked-up name to your resolver and the blocklist operator.

Concurrency: a semaphore sized ``dnsbl_concurrency`` bounds the queries of one
lookup. Callers (the aggregator) bound how many lookups run at once.
"""

import asyncio
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final

import dns.asyncresolver
import dns.exception
import dns.resolver

from phishtriage.core.exceptions import IntelProviderError, IntelUnavailableError
from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.core.utils import org_domain
from phishtriage.intel.base import IntelHttpClient, IntelProvider

__all__ = ["DNSBLProvider"]

_S: Final = IntelVerdict
_SCORE_PER_EXTRA_ZONE: Final = 5
_DOMAIN_RE: Final = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?"
    r"(?:\.[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?)+$"
)
_INTERNAL_TLDS: Final = frozenset(
    {"local", "localhost", "internal", "lan", "home", "corp", "intranet", "localdomain",
     "invalid", "arpa"}
)  # fmt: skip
_BLOCKED: Final = "query refused (public/open resolver or quota exceeded); use your own resolver"


# ============================================================ code interpretation
@dataclass(frozen=True)
class _Hit:
    """Meaning of one A-record answer. ``kind``: listed | info | blocked."""

    kind: str
    verdict: IntelVerdict
    score: int
    label: str


def _listed(verdict: IntelVerdict, score: int, label: str) -> _Hit:
    return _Hit("listed", verdict, score, label)


_ZEN: Final[dict[int, _Hit]] = {
    2: _listed(_S.MALICIOUS, 85, "SBL: spam or malware infrastructure"),
    3: _listed(_S.SUSPICIOUS, 70, "SBL CSS: snowshoe spam operation"),
    4: _listed(_S.MALICIOUS, 85, "XBL: compromised or infected host"),
    5: _listed(_S.MALICIOUS, 85, "XBL: compromised or infected host"),
    6: _listed(_S.MALICIOUS, 85, "XBL: compromised or infected host"),
    7: _listed(_S.MALICIOUS, 85, "XBL: compromised or infected host"),
    9: _listed(_S.MALICIOUS, 95, "DROP: hijacked or criminal netblock"),
    10: _Hit("info", _S.UNKNOWN, 0, "PBL: end-user range that should not send mail directly"),
    11: _Hit("info", _S.UNKNOWN, 0, "PBL: end-user range that should not send mail directly"),
}
_DBL: Final[dict[int, _Hit]] = {
    2: _listed(_S.SUSPICIOUS, 70, "DBL: spam domain"),
    4: _listed(_S.MALICIOUS, 95, "DBL: phishing domain"),
    5: _listed(_S.MALICIOUS, 95, "DBL: malware domain"),
    6: _listed(_S.MALICIOUS, 95, "DBL: botnet C&C domain"),
    102: _listed(_S.SUSPICIOUS, 60, "DBL: abused legitimate domain (spam)"),
    103: _listed(_S.SUSPICIOUS, 60, "DBL: abused redirector domain"),
    104: _listed(_S.MALICIOUS, 85, "DBL: abused legitimate domain (phishing)"),
    105: _listed(_S.MALICIOUS, 85, "DBL: abused legitimate domain (malware)"),
    106: _listed(_S.MALICIOUS, 85, "DBL: abused legitimate domain (botnet C&C)"),
}


def _spamhaus_zen(o: tuple[int, ...]) -> _Hit | None:
    return _ZEN.get(o[3]) if o[:3] == (127, 0, 0) else None


def _spamhaus_dbl(o: tuple[int, ...]) -> _Hit | None:
    if o[:3] == (127, 0, 1):
        if o[3] == 255:
            return _Hit("blocked", _S.UNKNOWN, 0, "DBL does not support IP queries")
        return _DBL.get(o[3])
    return None


def _uribl(o: tuple[int, ...]) -> _Hit | None:
    if o[:3] != (127, 0, 0):
        return None
    bits = o[3]
    if bits == 1:
        return _Hit("blocked", _S.UNKNOWN, 0, _BLOCKED)
    if bits & 2:
        return _listed(_S.MALICIOUS, 80, "URIBL black: domain used in spam or abuse")
    if bits & 8:
        return _listed(_S.SUSPICIOUS, 65, "URIBL red: domain seen in spam")
    if bits & 4:
        return _listed(_S.SUSPICIOUS, 40, "URIBL grey: possibly abusive domain")
    return None


def _simple(
    verdict: IntelVerdict, score: int, label: str
) -> Callable[[tuple[int, ...]], _Hit | None]:
    def rule(o: tuple[int, ...]) -> _Hit | None:
        return _listed(verdict, score, label) if o[:3] == (127, 0, 0) and o[3] == 2 else None

    return rule


# (zone suffix, rule). The first matching suffix wins; DBL must precede the general Spamhaus rule.
_RULES: Final[tuple[tuple[str, Callable[[tuple[int, ...]], _Hit | None]], ...]] = (
    ("dbl.spamhaus.org", _spamhaus_dbl),
    ("spamhaus.org", _spamhaus_zen),
    ("uribl.com", _uribl),
    ("spamcop.net", _simple(_S.SUSPICIOUS, 55, "SpamCop: recent spam source")),
    ("uceprotect.net", _simple(_S.SUSPICIOUS, 45, "UCEPROTECT level 1: individual spam source")),
)


def _interpret(zone: str, code: str) -> _Hit:
    """Translate one A-record answer from ``zone`` into a :class:`_Hit`."""
    try:
        octets = tuple(int(b) for b in ipaddress.IPv4Address(code).packed)
    except ValueError:
        octets = ()
    if not octets or octets[0] != 127:
        return _Hit(
            "blocked", _S.UNKNOWN, 0,
            f"unexpected answer {code[:40]!r} (the resolver may rewrite NXDOMAIN)",
        )  # fmt: skip
    if octets[:3] == (127, 255, 255):
        return _Hit("blocked", _S.UNKNOWN, 0, _BLOCKED)
    for suffix, rule in _RULES:
        if zone == suffix or zone.endswith(f".{suffix}"):
            hit = rule(octets)
            if hit is not None:
                return hit
            break
    return _listed(_S.SUSPICIOUS, 50, f"listed (return code {code})")


# ================================================================ aggregation
@dataclass
class _ZoneState:
    """Outcome for one zone. ``state``: listed | info | clear | error."""

    zone: str
    state: str
    hit: _Hit | None = None
    notes: list[str] = field(default_factory=list)


def _summarize_zone(zone: str, outcomes: list[tuple[str, list[str]]]) -> _ZoneState:
    """Merge the answers of every name queried against one zone."""
    listed: list[_Hit] = []
    infos: list[_Hit] = []
    problems: list[str] = []
    for state, codes in outcomes:
        if state == "error":
            problems.append(codes[0] if codes else "lookup failed")
        elif state == "listed":
            for code in codes:
                hit = _interpret(zone, code)
                if hit.kind == "listed":
                    listed.append(hit)
                elif hit.kind == "info":
                    infos.append(hit)
                else:
                    problems.append(hit.label)
    if listed:
        best = max(listed, key=lambda h: (h.verdict is _S.MALICIOUS, h.score))
        return _ZoneState(zone, "listed", best, [h.label for h in infos])
    if infos:
        return _ZoneState(zone, "info", infos[0], [])
    if problems:
        return _ZoneState(zone, "error", None, list(dict.fromkeys(problems)))
    return _ZoneState(zone, "clear")


# ================================================================== provider
class DNSBLProvider(IntelProvider):
    """Check IPs and domains against DNS blocklists."""

    name: ClassVar[str] = "dnsbl"
    supported_types: ClassVar[frozenset[IOCType]] = frozenset(
        {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN}
    )

    def __init__(
        self,
        settings: Any = None,
        *,
        http: IntelHttpClient | None = None,
        resolver: Any = None,
    ) -> None:
        """Create the provider.

        Args:
            settings: Application settings (defaults to the process singleton).
            http: Unused by this provider; accepted for interface symmetry.
            resolver: Object with ``async resolve(name, "A")`` (tests); a
                ``dns.asyncresolver.Resolver`` is built from settings otherwise.
        """
        self._resolver: Any = resolver
        super().__init__(settings, http=http)

    # ------------------------------------------------------------------ hooks
    def _requests_per_minute(self) -> float:
        return 6000.0  # unused: DNS lookups do not go through the HTTP limiter

    def _config_problem(self) -> str | None:
        if not (self._settings.dnsbl_ip_zones or self._settings.dnsbl_domain_zones):
            return "no DNSBL zones configured"
        return None

    def _get_resolver(self) -> Any:
        if self._resolver is None:
            servers = list(self._settings.dns_nameservers)
            try:
                resolver = dns.asyncresolver.Resolver(configure=not servers)
            except dns.resolver.NoResolverConfiguration:
                raise IntelUnavailableError(
                    "No DNS resolver is configured for DNSBL lookups.", provider=self.name
                ) from None
            if servers:
                resolver.nameservers = servers
            resolver.timeout = self._settings.dns_timeout_seconds
            resolver.lifetime = self._settings.dns_lifetime_seconds
            self._resolver = resolver
        return self._resolver

    # --------------------------------------------------------------- targeting
    @staticmethod
    def _ip_labels(indicator: str) -> tuple[str, list[str]] | str:
        """Return ``(display, [label])`` or a skip reason; raises on invalid input."""
        try:
            ip = ipaddress.ip_address(indicator.strip().strip("[]"))
        except ValueError:
            raise IntelProviderError("DNSBL: not a valid IP address.", provider="dnsbl") from None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return "Not queried: address is private, reserved or not publicly routable."
        label = ip.reverse_pointer.removesuffix(".in-addr.arpa").removesuffix(".ip6.arpa")
        return str(ip), [label]

    @staticmethod
    def _domain_labels(indicator: str) -> tuple[str, list[str]] | str:
        host = indicator.strip().rstrip(".").lower()
        if not host.isascii():
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                raise IntelProviderError("DNSBL: invalid domain name.", provider="dnsbl") from None
        if not _DOMAIN_RE.match(host):
            raise IntelProviderError("DNSBL: invalid domain name.", provider="dnsbl")
        if host.rsplit(".", 1)[-1] in _INTERNAL_TLDS:
            return "Not queried: internal or non-public domain."
        names = [host]
        org = org_domain(host)
        if org and "." in org and org != host:
            names.append(org)
        return host, names

    # ------------------------------------------------------------------- query
    async def _query(self, resolver: Any, name: str) -> tuple[str, list[str]]:
        """Return ``(state, codes)``: clear, listed (A answers) or error (message)."""
        try:
            answer = await resolver.resolve(name, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return "clear", []
        except dns.exception.Timeout:
            return "error", ["timeout"]
        except dns.resolver.NoNameservers:
            return "error", ["resolver refused or failed (SERVFAIL)"]
        except dns.exception.DNSException:
            return "error", ["lookup failed"]
        codes = [str(getattr(r, "address", "")) for r in answer]
        return ("listed", codes) if codes else ("clear", [])

    # ------------------------------------------------------------------ lookup
    async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        is_ip = indicator_type in (IOCType.IPV4, IOCType.IPV6)
        zones = list(self._settings.dnsbl_ip_zones if is_ip else self._settings.dnsbl_domain_zones)
        kind = "IP" if is_ip else "domain"
        if not zones:
            return self._result(
                indicator[:100], indicator_type, IntelVerdict.SKIPPED,
                detail=f"No DNSBL zones are configured for {kind} indicators.",
            )  # fmt: skip

        prepared = self._ip_labels(indicator) if is_ip else self._domain_labels(indicator)
        if isinstance(prepared, str):
            return self._result(
                indicator[:100], indicator_type, IntelVerdict.SKIPPED, detail=prepared
            )
        shown, labels = prepared

        resolver = self._get_resolver()
        semaphore = asyncio.Semaphore(self._settings.dnsbl_concurrency)

        async def one(zone: str, label: str) -> tuple[str, tuple[str, list[str]]]:
            async with semaphore:
                return zone, await self._query(resolver, f"{label}.{zone}")

        results = await asyncio.gather(*(one(z, label) for z in zones for label in labels))
        grouped: dict[str, list[tuple[str, list[str]]]] = {z: [] for z in zones}
        for zone, outcome in results:
            grouped[zone].append(outcome)
        states = [_summarize_zone(zone, grouped[zone]) for zone in zones]

        listed = [s for s in states if s.state == "listed" and s.hit is not None]
        notes = [f"{s.zone}: {n}" for s in states for n in s.notes]
        notes += [f"{s.zone}: {s.hit.label}" for s in states if s.state == "info" and s.hit]
        answered = sum(1 for s in states if s.state != "error")

        if listed:
            verdict = (
                IntelVerdict.MALICIOUS
                if any(s.hit and s.hit.verdict is IntelVerdict.MALICIOUS for s in listed)
                else IntelVerdict.SUSPICIOUS
            )
            top = max(s.hit.score for s in listed if s.hit)
            score = min(100, top + _SCORE_PER_EXTRA_ZONE * (len(listed) - 1))
            where = "; ".join(f"{s.zone} ({s.hit.label})" for s in listed if s.hit)
            detail = f"Listed on {len(listed)} of {len(zones)} {kind} blocklists: {where}"
            if notes:
                detail += " | " + "; ".join(notes)
            return self._result(shown, indicator_type, verdict, score=score, detail=detail)

        if answered == 0:
            return self._result(
                shown, indicator_type, IntelVerdict.ERROR,
                detail="No blocklist could answer: " + "; ".join(notes or ["lookup failed"]),
            )  # fmt: skip
        detail = f"Not listed on {answered} of {len(zones)} {kind} blocklists."
        if notes:
            detail += " | " + "; ".join(notes)
        return self._result(shown, indicator_type, IntelVerdict.UNKNOWN, detail=detail)
