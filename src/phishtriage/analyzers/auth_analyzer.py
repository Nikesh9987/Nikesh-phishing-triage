"""SPF / DKIM / DMARC assessment with identifier alignment.

Sources, in order of preference, for every mechanism:

1. ``Authentication-Results`` (RFC 8601), written by the receiving server.
2. ``Received-SPF`` (SPF only).
3. DNS fallback, only when the network is enabled (never in offline mode).

Trust model (important):

* Anyone can *forge* an ``Authentication-Results`` header and plant it below
  the real one. By default only headers carrying the **same authserv-id as the
  topmost** ``Authentication-Results`` are used (the topmost is the one your
  receiving server prepended). Headers from other servers are ignored and
  reported as a warning. Pass ``trusted_authserv_ids`` to pin the exact
  server(s) you trust.

Alignment (RFC 7489):

* SPF identifier = ``smtp.mailfrom`` domain (HELO if the sender is empty).
* DKIM identifier = the signature's ``d=`` domain.
* *Relaxed* alignment compares organizational domains, *strict* requires an
  exact match. The mode comes from the published DMARC record (``aspf`` /
  ``adkim``), defaulting to relaxed. Organizational domains use the
  ``tldextract`` bundled snapshot, so no network fetch is made.
* ``aligned`` is reported independently of pass/fail; DMARC needs both.

DNS fallback limits, stated plainly:

* **SPF** is evaluated by a compact built-in evaluator (``ip4``, ``ip6``,
  ``a``, ``mx``, ``include``, ``exists``, ``redirect``, ``all``) with the
  RFC 7208 limit of 10 DNS-querying terms and 2 void lookups. Records using
  macros (``%{i}``) or ``ptr`` are **not evaluated** (status ``unknown``).
  It needs the IP that connected to the first trusted server. If you pass the
  originating-MTA estimate from the Received tracer, the result is an
  estimate, and a warning says so.
* **DKIM** signatures are *not* cryptographically verified (message bytes are
  not retained). Without a header result the status is ``unknown`` when the
  key record exists, ``permerror`` when it does not, and ``fail`` when the
  key is revoked.
* **DMARC** is computed from the SPF/DKIM results plus the DNS policy when
  the headers carry no DMARC verdict.

DNS work shares a total time budget and a per-analysis cache. Every name
queried is validated first, because selectors and domains come from
attacker-controlled headers. Never raises: failures become warnings.
"""

import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Final

import dns.exception
import dns.rdata
import dns.resolver
import tldextract

from phishtriage.config import Settings, get_settings
from phishtriage.core.models import (
    AuthMethod,
    AuthReport,
    AuthResult,
    AuthSource,
    AuthStatus,
    DmarcPolicy,
    ParsedMessage,
)
from phishtriage.logging_config import get_logger
from phishtriage.parsers.base import clean_header_text

__all__ = ["AuthAnalyzer", "analyze_auth"]

logger = get_logger(__name__)

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_MAX_AR_HEADERS: Final = 20
_MAX_DKIM_SIGS: Final = 10
_SPF_MAX_LOOKUPS: Final = 10
_SPF_MAX_VOID: Final = 2
_SPF_MAX_MX: Final = 10
_DNS_BUDGET_SECONDS: Final = 15.0

_STATUS_MAP: Final[dict[str, AuthStatus]] = {
    "pass": AuthStatus.PASS,
    "fail": AuthStatus.FAIL,
    "hardfail": AuthStatus.FAIL,
    "softfail": AuthStatus.SOFTFAIL,
    "neutral": AuthStatus.NEUTRAL,
    "none": AuthStatus.NONE,
    "temperror": AuthStatus.TEMPERROR,
    "permerror": AuthStatus.PERMERROR,
    "policy": AuthStatus.POLICY,
    "unknown": AuthStatus.UNKNOWN,
    "error": AuthStatus.TEMPERROR,
}
_INCONCLUSIVE: Final = frozenset({AuthStatus.UNKNOWN, AuthStatus.TEMPERROR})
_QUALIFIER_STATUS: Final[dict[str, AuthStatus]] = {
    "+": AuthStatus.PASS,
    "-": AuthStatus.FAIL,
    "~": AuthStatus.SOFTFAIL,
    "?": AuthStatus.NEUTRAL,
}

_DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.\-]{0,251}[a-z0-9_])?$")
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")
_RESINFO_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_\-]*)(?:/\d+)?=(.*)$")
_KV_RE = re.compile(r'([A-Za-z][A-Za-z0-9\-]*)\s*=\s*("[^"]*"|[^;\s]+)')
_SPF_PREFIX_RE = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)
_SPF_MODIFIER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]*)=(\S*)$")
_SPF_TERM_RE = re.compile(r"^([A-Za-z0-9]+)(.*)$")
_DMARC_PREFIX_RE = re.compile(r"^\s*v\s*=\s*DMARC1\s*(?:;|$)", re.IGNORECASE)


# ============================================================== text helpers
def _strip_comments(text: str) -> str:
    """Remove RFC 5322 ``(comments)`` (nestable, quote-aware); each becomes one space."""
    out: list[str] = []
    depth = 0
    in_quote = False
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text) and (in_quote or depth):
            if not depth:
                out.append(text[i : i + 2])
            i += 2
            continue
        if in_quote:
            out.append(char)
            in_quote = char != '"'
        elif depth:
            depth += 1 if char == "(" else -1 if char == ")" else 0
        elif char == '"':
            in_quote = True
            out.append(char)
        elif char == "(":
            depth = 1
            out.append(" ")
        else:
            out.append(char)
        i += 1
    return "".join(out)


def _split_unquoted(text: str, separator: str) -> list[str]:
    """Split on ``separator`` outside double quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    for char in text:
        if char == '"':
            in_quote = not in_quote
        if char == separator and not in_quote:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _ws_tokens(text: str) -> list[str]:
    """Split on whitespace outside double quotes."""
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    for char in text:
        if char == '"':
            in_quote = not in_quote
        if char.isspace() and not in_quote:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(char)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _tag_list(text: str) -> dict[str, str]:
    """Parse ``k=v; k=v`` tag lists (DKIM-Signature, DKIM key, DMARC). First tag wins."""
    tags: dict[str, str] = {}
    for part in text.split(";"):
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if sep and key:
            tags.setdefault(key, value.strip())
    return tags


def _to_status(value: str) -> AuthStatus:
    return _STATUS_MAP.get(value.strip().strip('"').lower(), AuthStatus.UNKNOWN)


def _domain_of(value: str) -> str:
    """Return a lower-cased, validated domain from a domain or ``user@domain``; else ``""``."""
    text = value.strip().strip("<>\"' ").lower()
    if "@" in text:
        text = text.rpartition("@")[2]
    text = text.strip().rstrip(".")
    if text and not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    return text if _DOMAIN_RE.match(text) else ""


def _normalize_ip(value: str | None) -> _IPAddress | None:
    if not value:
        return None
    try:
        ip: _IPAddress = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


@lru_cache(maxsize=1)
def _extractor() -> "tldextract.TLDExtract | None":
    """tldextract using only its bundled suffix snapshot (no network, no disk cache)."""
    try:
        return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    except Exception:  # noqa: BLE001
        logger.debug("tldextract unavailable; using two-label fallback", exc_info=True)
        return None


@lru_cache(maxsize=2048)
def _org_domain(domain: str) -> str:
    """Organizational domain (registrable domain); falls back to the last two labels."""
    extractor = _extractor()
    if extractor is not None:
        try:
            parts = extractor(domain)
            registered = getattr(parts, "top_domain_under_public_suffix", "") or getattr(
                parts, "registered_domain", ""
            )
            if registered:
                return str(registered).lower()
        except Exception:  # noqa: BLE001
            logger.debug("tldextract failed for %r", domain, exc_info=True)
    return ".".join(domain.lower().rstrip(".").split(".")[-2:])


def _aligned(identifier: str, from_domain: str, *, strict: bool) -> bool | None:
    """DMARC identifier alignment; ``None`` when either side is unknown."""
    if not identifier or not from_domain:
        return None
    if strict:
        return identifier == from_domain
    return _org_domain(identifier) == _org_domain(from_domain)


# ====================================================== header parsing (RFC 8601)
@dataclass(frozen=True)
class _ArResult:
    authserv_id: str
    method: str
    result: str
    props: dict[str, str]
    raw: str


@dataclass(frozen=True)
class _ArHeader:
    authserv_id: str
    results: list[_ArResult]


def _parse_authentication_results(value: str) -> _ArHeader | None:
    """Parse one ``Authentication-Results`` header; ``None`` if unusable."""
    text = _strip_comments(clean_header_text(value))
    segments = _split_unquoted(text, ";")
    head = _ws_tokens(segments[0]) if segments else []
    if not head:
        return None
    if "=" in head[0]:  # malformed: authserv-id missing, results start immediately
        authserv_id, result_segments = "unknown", segments
    else:
        authserv_id, result_segments = head[0].strip('"').lower(), segments[1:]

    results: list[_ArResult] = []
    for segment in result_segments:
        segment = re.sub(r"\s*=\s*", "=", segment.strip())
        if not segment or segment.lower() == "none":
            continue
        tokens = _ws_tokens(segment)
        match = _RESINFO_RE.match(tokens[0]) if tokens else None
        if match is None:
            continue
        props: dict[str, str] = {}
        for token in tokens[1:]:
            key, sep, val = token.partition("=")
            if sep:
                props.setdefault(key.lower(), val.strip('"'))
        results.append(
            _ArResult(
                authserv_id=authserv_id,
                method=match.group(1).lower(),
                result=match.group(2).strip('"').lower(),
                props=props,
                raw=segment[:500],
            )
        )
    return _ArHeader(authserv_id=authserv_id, results=results)


@dataclass(frozen=True)
class _ReceivedSpf:
    status: AuthStatus
    domain: str
    client_ip: str
    raw: str


def _parse_received_spf(value: str) -> _ReceivedSpf | None:
    """Parse a ``Received-SPF`` header (result word first, then ``key=value`` pairs)."""
    text = _strip_comments(clean_header_text(value)).strip()
    pieces = text.split(None, 1)
    if not pieces:
        return None
    word = pieces[0].rstrip(";").lower()
    if word not in _STATUS_MAP:
        return None
    pairs: dict[str, str] = {}
    for key, val in _KV_RE.findall(pieces[1] if len(pieces) > 1 else ""):
        pairs.setdefault(key.lower(), val.strip('"'))
    domain = _domain_of(pairs.get("envelope-from", "")) or _domain_of(pairs.get("helo", ""))
    return _ReceivedSpf(
        status=_STATUS_MAP[word], domain=domain, client_ip=pairs.get("client-ip", ""), raw=text[:500]
    )


@dataclass(frozen=True)
class _DkimSig:
    domain: str
    selector: str
    algorithm: str
    signed_headers: tuple[str, ...]
    expires: int | None
    has_body_length: bool
    malformed: bool
    raw: str


def _parse_dkim_signature(value: str) -> _DkimSig:
    """Parse the tags of one ``DKIM-Signature`` header (no cryptography)."""
    tags = {k: re.sub(r"\s+", "", v) for k, v in _tag_list(clean_header_text(value)).items()}
    domain = _domain_of(tags.get("d", ""))
    selector = tags.get("s", "")
    if not _SELECTOR_RE.match(selector):
        selector = ""
    expires: int | None = None
    if tags.get("x", "").isdigit():
        expires = int(tags["x"])
    return _DkimSig(
        domain=domain,
        selector=selector,
        algorithm=tags.get("a", "").lower(),
        signed_headers=tuple(h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()),
        expires=expires,
        has_body_length="l" in tags,
        malformed=not domain or not selector,
        raw=f"d={tags.get('d', '')}; s={tags.get('s', '')}; a={tags.get('a', '')}"[:300],
    )


# ============================================================================ DNS
class _DnsTemp(Exception):
    """A DNS query could not be completed (timeout, SERVFAIL, budget exhausted)."""


class _Dns:
    """Small caching resolver wrapper with a shared time budget."""

    def __init__(self, nameservers: list[str], timeout: float, lifetime: float, budget: float) -> None:
        self._deadline = time.monotonic() + budget
        self._cache: dict[tuple[str, str], list[dns.rdata.Rdata]] = {}
        self._resolver: dns.resolver.Resolver | None
        try:
            self._resolver = dns.resolver.Resolver(configure=not nameservers)
        except dns.resolver.NoResolverConfiguration:
            self._resolver = None
            return
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    def _query(self, name: str, rdtype: str) -> list[dns.rdata.Rdata]:
        key = (name.lower().rstrip("."), rdtype)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if self._resolver is None:
            raise _DnsTemp("no DNS resolver is configured")
        if time.monotonic() > self._deadline:
            raise _DnsTemp("DNS time budget exhausted")
        try:
            records = list(self._resolver.resolve(key[0], rdtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            records = []
        except (dns.exception.SyntaxError, dns.exception.FormError):
            records = []  # syntactically invalid name: treat as nonexistent
        except dns.exception.Timeout:
            raise _DnsTemp("timeout") from None
        except dns.resolver.NoNameservers:
            raise _DnsTemp("no nameserver answered") from None
        except dns.exception.DNSException:
            raise _DnsTemp("lookup failed") from None
        self._cache[key] = records
        return records

    def txt(self, name: str) -> list[str]:
        """TXT records with multi-string chunks joined, as strings."""
        return [
            b"".join(getattr(r, "strings", ())).decode("utf-8", "replace")
            for r in self._query(name, "TXT")
        ]

    def addresses(self, name: str, version: int) -> list[_IPAddress]:
        """A (``version=4``) or AAAA (``version=6``) addresses."""
        found: list[_IPAddress] = []
        for rdata in self._query(name, "A" if version == 4 else "AAAA"):
            try:
                found.append(ipaddress.ip_address(getattr(rdata, "address", "")))
            except ValueError:
                continue
        return found

    def mx(self, name: str) -> list[str]:
        """MX exchange host names ordered by preference (null MX excluded)."""
        records = sorted(self._query(name, "MX"), key=lambda r: getattr(r, "preference", 0))
        hosts = (str(getattr(r, "exchange", "")).rstrip(".") for r in records)
        return [h for h in hosts if h]


# ================================================================ SPF evaluator
class _SpfAbort(Exception):
    """Evaluation ends with a definitive error status."""

    def __init__(self, status: AuthStatus, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class _SpfUnsupported(Exception):
    """The record uses a feature this evaluator deliberately does not implement."""


def _split_domain_cidr(rest: str, default: str) -> tuple[str, int, int]:
    """Parse ``[:domain][/v4cidr][//v6cidr]`` for the ``a`` and ``mx`` mechanisms."""
    spec = rest[1:] if rest.startswith(":") else rest
    v4, v6 = 32, 128
    try:
        if "//" in spec:
            spec, _, tail = spec.partition("//")
            v6 = int(tail)
        if "/" in spec:
            spec, _, tail = spec.partition("/")
            v4 = int(tail)
    except ValueError:
        raise _SpfAbort(AuthStatus.PERMERROR, "Invalid CIDR length in SPF record.") from None
    if not 0 <= v4 <= 32 or not 0 <= v6 <= 128:
        raise _SpfAbort(AuthStatus.PERMERROR, "CIDR length out of range in SPF record.")
    return (spec or default).lower().rstrip("."), v4, v6


class _SpfEvaluator:
    """Compact RFC 7208 ``check_host`` for one client IP (see module docstring)."""

    def __init__(self, resolver: _Dns, client_ip: _IPAddress) -> None:
        self._dns = resolver
        self._ip = client_ip
        self._lookups = 0
        self._voids = 0
        self.matched = ""
        self.record = ""

    def evaluate(self, domain: str) -> tuple[AuthStatus, str]:
        """Return ``(status, detail)`` for ``domain``; never raises."""
        try:
            status = self._check(domain, top=True)
        except _SpfAbort as exc:
            return exc.status, exc.detail
        except _SpfUnsupported as exc:
            return AuthStatus.UNKNOWN, str(exc)
        except _DnsTemp as exc:
            return AuthStatus.TEMPERROR, f"DNS error during SPF evaluation: {exc}."
        if status is AuthStatus.NONE:
            return status, f"No SPF record published for {domain}."
        return status, f"'{self.matched}' evaluated for {domain} against {self._ip}."

    def _count_lookup(self) -> None:
        self._lookups += 1
        if self._lookups > _SPF_MAX_LOOKUPS:
            raise _SpfAbort(
                AuthStatus.PERMERROR, f"SPF record exceeds the {_SPF_MAX_LOOKUPS}-lookup limit."
            )

    def _void(self) -> None:
        self._voids += 1
        if self._voids > _SPF_MAX_VOID:
            raise _SpfAbort(AuthStatus.PERMERROR, "SPF evaluation hit too many void DNS lookups.")

    def _check(self, domain: str, *, top: bool = False) -> AuthStatus:
        records = [r for r in self._dns.txt(domain) if _SPF_PREFIX_RE.match(r)]
        if not records:
            return AuthStatus.NONE
        if len(records) > 1:
            raise _SpfAbort(AuthStatus.PERMERROR, f"Multiple SPF records published for {domain}.")
        if top:
            self.record = records[0]

        redirect = ""
        for term in records[0].split()[1:]:
            modifier = _SPF_MODIFIER_RE.match(term)
            if modifier:
                name, value = modifier.group(1).lower(), modifier.group(2)
                if name == "exp":
                    continue
                if "%" in value:
                    raise _SpfUnsupported("SPF record uses macros, which are not evaluated.")
                if name == "redirect":
                    if redirect:
                        raise _SpfAbort(AuthStatus.PERMERROR, "Duplicate redirect modifier.")
                    redirect = value.lower().rstrip(".")
                continue
            if "%" in term:
                raise _SpfUnsupported("SPF record uses macros, which are not evaluated.")
            qualifier, body = ("+", term)
            if term[0] in _QUALIFIER_STATUS:
                qualifier, body = term[0], term[1:]
            if self._matches(body, domain):
                self.matched = term
                return _QUALIFIER_STATUS[qualifier]

        if redirect:
            self._count_lookup()
            sub = self._check(redirect)
            if sub is AuthStatus.NONE:
                raise _SpfAbort(AuthStatus.PERMERROR, f"Redirect target {redirect} has no SPF record.")
            return sub
        self.matched = "(no mechanism matched)"
        return AuthStatus.NEUTRAL

    def _matches(self, body: str, domain: str) -> bool:
        parsed = _SPF_TERM_RE.match(body)
        if parsed is None:
            raise _SpfAbort(AuthStatus.PERMERROR, f"Invalid SPF term {body!r}.")
        mech, rest = parsed.group(1).lower(), parsed.group(2)

        if mech == "all":
            return not rest
        if mech in ("ip4", "ip6"):
            return self._match_ip(mech, rest[1:] if rest.startswith(":") else "")
        if mech in ("a", "mx"):
            target, v4, v6 = _split_domain_cidr(rest, domain)
            self._count_lookup()
            return self._match_a(target, v4, v6) if mech == "a" else self._match_mx(target, v4, v6)
        if mech in ("include", "exists"):
            target = rest[1:].lower().rstrip(".") if rest.startswith(":") else ""
            if not target:
                raise _SpfAbort(AuthStatus.PERMERROR, f"'{mech}' requires a domain argument.")
            self._count_lookup()
            if mech == "exists":
                found = bool(self._dns.addresses(target, 4))
                if not found:
                    self._void()
                return found
            sub = self._check(target)
            if sub is AuthStatus.NONE:
                raise _SpfAbort(AuthStatus.PERMERROR, f"Included domain {target} has no SPF record.")
            return sub is AuthStatus.PASS
        if mech == "ptr":
            raise _SpfUnsupported("SPF record uses the deprecated 'ptr' mechanism, which is not evaluated.")
        raise _SpfAbort(AuthStatus.PERMERROR, f"Unknown SPF mechanism {mech!r}.")

    def _match_ip(self, mech: str, value: str) -> bool:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise _SpfAbort(AuthStatus.PERMERROR, f"Invalid {mech} range {value!r}.") from None
        if (mech == "ip4") != (network.version == 4):
            raise _SpfAbort(AuthStatus.PERMERROR, f"{mech} term holds a v{network.version} range.")
        return network.version == self._ip.version and self._ip in network

    def _match_a(self, host: str, v4: int, v6: int) -> bool:
        addresses = self._dns.addresses(host, self._ip.version)
        if not addresses:
            self._void()
            return False
        prefix = v4 if self._ip.version == 4 else v6
        return any(self._ip in ipaddress.ip_network(f"{a}/{prefix}", strict=False) for a in addresses)

    def _match_mx(self, domain: str, v4: int, v6: int) -> bool:
        hosts = self._dns.mx(domain)
        if not hosts:
            self._void()
            return False
        return any(self._match_a(host, v4, v6) for host in hosts[:_SPF_MAX_MX])


# ================================================================= DMARC helpers
def _parse_dmarc_record(domain: str, record: str) -> DmarcPolicy:
    tags = _tag_list(record)
    try:
        percentage = int(tags.get("pct", "100"))
    except ValueError:
        percentage = 100
    return DmarcPolicy(
        domain=domain,
        record=record[:1000],
        policy=tags.get("p", "").lower(),
        subdomain_policy=tags.get("sp", "").lower(),
        percentage=max(0, min(100, percentage)),
        spf_alignment="strict" if tags.get("aspf", "").lower() == "s" else "relaxed",
        dkim_alignment="strict" if tags.get("adkim", "").lower() == "s" else "relaxed",
    )


def _policy_summary(policy: DmarcPolicy | None) -> str:
    if policy is None:
        return ""
    parts = [f"p={policy.policy or 'unspecified'}"]
    if policy.subdomain_policy:
        parts.append(f"sp={policy.subdomain_policy}")
    parts += [
        f"pct={policy.percentage}",
        f"aspf={policy.spf_alignment}",
        f"adkim={policy.dkim_alignment}",
    ]
    return f"Published DMARC policy at {policy.domain}: {', '.join(parts)}."


def _fetch_dmarc(
    resolver: _Dns, from_domain: str, warnings: list[str]
) -> tuple[DmarcPolicy | None, bool]:
    """Return ``(policy, lookup_ok)``. ``(None, True)`` means no record exists."""
    candidates = [from_domain]
    org = _org_domain(from_domain)
    if org and org != from_domain:
        candidates.append(org)
    for domain in candidates:
        try:
            records = resolver.txt(f"_dmarc.{domain}")
        except _DnsTemp as exc:
            warnings.append(f"DMARC lookup for _dmarc.{domain} failed: {exc}.")
            return None, False
        found = [r for r in records if _DMARC_PREFIX_RE.match(r)]
        if len(found) > 1:
            warnings.append(f"Multiple DMARC records at _dmarc.{domain}; they are ignored (RFC 7489).")
            continue
        if found:
            return _parse_dmarc_record(domain, found[0]), True
    return None, True


# ===================================================================== analyzer
class AuthAnalyzer:
    """Assess SPF, DKIM and DMARC for a :class:`ParsedMessage`."""

    def __init__(
        self,
        *,
        network: bool = True,
        nameservers: list[str] | None = None,
        dns_timeout: float = 3.0,
        dns_lifetime: float = 6.0,
        dns_budget: float = _DNS_BUDGET_SECONDS,
        trusted_authserv_ids: list[str] | None = None,
    ) -> None:
        """Create an analyzer.

        Args:
            network: Allow DNS fallbacks. ``False`` produces zero DNS traffic.
            nameservers: Custom resolver IPs; empty/None uses the system resolver.
            dns_timeout: Per-attempt DNS timeout (seconds).
            dns_lifetime: Total time per DNS lookup (seconds).
            dns_budget: Total DNS time allowed for one analysis (seconds).
            trusted_authserv_ids: Only ``Authentication-Results`` headers whose
                authserv-id is in this list are used. Default: the topmost.
        """
        self._network = network
        self._nameservers = list(nameservers or [])
        self._dns_timeout = dns_timeout
        self._dns_lifetime = dns_lifetime
        self._dns_budget = dns_budget
        self._trusted_ids = {t.strip().lower() for t in (trusted_authserv_ids or []) if t.strip()}

    @classmethod
    def from_settings(
        cls, settings: Settings, *, trusted_authserv_ids: list[str] | None = None
    ) -> "AuthAnalyzer":
        """Build an analyzer from application settings (honours offline mode)."""
        return cls(
            network=settings.network_enabled,
            nameservers=settings.dns_nameservers,
            dns_timeout=settings.dns_timeout_seconds,
            dns_lifetime=settings.dns_lifetime_seconds,
            trusted_authserv_ids=trusted_authserv_ids,
        )

    # ----------------------------------------------------------------- public API
    def analyze(
        self,
        message: ParsedMessage,
        *,
        client_ip: str | None = None,
        helo: str | None = None,
    ) -> AuthReport:
        """Analyze ``message``.

        Args:
            message: The parsed message.
            client_ip: IP that connected to the first server you trust. Used only
                for the SPF DNS fallback. If you pass the originating-MTA
                estimate, the SPF result is an estimate (a warning says so).
            helo: HELO/EHLO name of that client; used when Return-Path is empty.
        """
        try:
            return self._analyze(message, client_ip, helo)
        except Exception:  # noqa: BLE001 - never abort a triage on auth analysis
            logger.exception("Authentication analysis failed")
            return AuthReport(warnings=["Authentication analysis failed unexpectedly."])

    # ------------------------------------------------------------------ pipeline
    def _make_dns(self) -> _Dns | None:
        if not self._network:
            return None
        return _Dns(self._nameservers, self._dns_timeout, self._dns_lifetime, self._dns_budget)

    def _analyze(self, message: ParsedMessage, client_ip: str | None, helo: str | None) -> AuthReport:
        warnings: list[str] = []
        from_domain = _domain_of(message.from_address.domain) if message.from_address else ""
        if not from_domain:
            warnings.append("No usable From domain; alignment and DMARC cannot be evaluated.")

        resolver = self._make_dns()
        policy: DmarcPolicy | None = None
        policy_checked = False
        if resolver is not None and from_domain:
            policy, policy_checked = _fetch_dmarc(resolver, from_domain, warnings)
        spf_strict = policy is not None and policy.spf_alignment == "strict"
        dkim_strict = policy is not None and policy.dkim_alignment == "strict"

        ar_results = self._trusted_ar_results(message, warnings)
        spf = self._resolve_spf(
            message, ar_results, from_domain, spf_strict, resolver, client_ip, helo, warnings
        )
        dkim = self._resolve_dkim(message, ar_results, from_domain, dkim_strict, resolver, warnings)
        dmarc = self._resolve_dmarc(
            ar_results, spf, dkim, from_domain, policy, policy_checked, warnings
        )

        if spf.source is AuthSource.ABSENT and not dkim and dmarc.source is AuthSource.ABSENT:
            warnings.append("No SPF, DKIM or DMARC information was found in the message headers.")

        return AuthReport(
            from_domain=from_domain,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            dmarc_policy=policy,
            warnings=warnings,
        )

    # --------------------------------------------------- Authentication-Results
    def _trusted_ar_results(self, message: ParsedMessage, warnings: list[str]) -> list[_ArResult]:
        raw_headers = message.get_headers("Authentication-Results")
        if not raw_headers:
            return []
        if len(raw_headers) > _MAX_AR_HEADERS:
            warnings.append(
                f"{len(raw_headers)} Authentication-Results headers; only the first "
                f"{_MAX_AR_HEADERS} were examined."
            )
        parsed = [
            h
            for h in (_parse_authentication_results(v) for v in raw_headers[:_MAX_AR_HEADERS])
            if h is not None
        ]
        if not parsed:
            warnings.append("Authentication-Results header present but could not be parsed.")
            return []

        if self._trusted_ids:
            chosen = [h for h in parsed if h.authserv_id in self._trusted_ids]
            if not chosen:
                warnings.append(
                    "No Authentication-Results header comes from a trusted authserv-id "
                    f"({', '.join(sorted(self._trusted_ids))})."
                )
                return []
        else:
            top = parsed[0].authserv_id
            chosen = [h for h in parsed if h.authserv_id == top]

        used = {h.authserv_id for h in chosen}
        ignored = sorted({h.authserv_id for h in parsed} - used)
        if ignored:
            warnings.append(
                f"Ignored Authentication-Results from other server(s) ({', '.join(ignored)}); "
                f"using '{', '.join(sorted(used))}' only. Headers added below your own "
                "server can be forged."
            )
        return [r for h in chosen for r in h.results]

    # ----------------------------------------------------------------------- SPF
    def _resolve_spf(
        self,
        message: ParsedMessage,
        ar_results: list[_ArResult],
        from_domain: str,
        strict: bool,
        resolver: _Dns | None,
        client_ip: str | None,
        helo: str | None,
        warnings: list[str],
    ) -> AuthResult:
        ar = next((r for r in ar_results if r.method == "spf"), None)
        received_spf = next(
            (p for p in map(_parse_received_spf, message.get_headers("Received-SPF")) if p), None
        )

        if ar is not None:
            identity = _domain_of(ar.props.get("smtp.mailfrom", "")) or _domain_of(
                ar.props.get("smtp.helo", "")
            )
            result = AuthResult(
                method=AuthMethod.SPF,
                status=_to_status(ar.result),
                source=AuthSource.HEADER,
                domain=identity,
                aligned=_aligned(identity, from_domain, strict=strict),
                detail=ar.props.get("reason", "") or f"Reported by {ar.authserv_id}.",
                raw=ar.raw,
            )
            if received_spf is not None and received_spf.status is not result.status:
                warnings.append(
                    f"SPF conflict: Authentication-Results says {result.status.value}, "
                    f"Received-SPF says {received_spf.status.value}."
                )
            return result

        if received_spf is not None:
            return AuthResult(
                method=AuthMethod.SPF,
                status=received_spf.status,
                source=AuthSource.HEADER,
                domain=received_spf.domain,
                aligned=_aligned(received_spf.domain, from_domain, strict=strict),
                detail="Taken from the Received-SPF header.",
                raw=received_spf.raw,
            )

        return self._spf_via_dns(message, from_domain, strict, resolver, client_ip, helo, warnings)

    def _spf_via_dns(
        self,
        message: ParsedMessage,
        from_domain: str,
        strict: bool,
        resolver: _Dns | None,
        client_ip: str | None,
        helo: str | None,
        warnings: list[str],
    ) -> AuthResult:
        domain = _domain_of(message.return_path) or _domain_of(helo or "")
        aligned = _aligned(domain, from_domain, strict=strict)

        def result(status: AuthStatus, source: AuthSource, detail: str, raw: str = "") -> AuthResult:
            return AuthResult(
                method=AuthMethod.SPF,
                status=status,
                source=source,
                domain=domain,
                aligned=aligned,
                detail=detail,
                raw=raw[:500],
            )

        if resolver is None:
            return result(
                AuthStatus.UNKNOWN,
                AuthSource.ABSENT,
                "No SPF result in the headers; DNS fallback skipped (offline mode).",
            )
        if not domain:
            return result(
                AuthStatus.UNKNOWN,
                AuthSource.ABSENT,
                "No SPF result in the headers and no Return-Path/HELO domain to evaluate.",
            )

        ip = _normalize_ip(client_ip)
        if ip is None:
            try:
                records = [r for r in resolver.txt(domain) if _SPF_PREFIX_RE.match(r)]
            except _DnsTemp as exc:
                return result(AuthStatus.TEMPERROR, AuthSource.DNS, f"SPF lookup failed: {exc}.")
            if not records:
                return result(AuthStatus.NONE, AuthSource.DNS, f"No SPF record published for {domain}.")
            return result(
                AuthStatus.UNKNOWN,
                AuthSource.DNS,
                "SPF record is published but the sending IP is unknown, so it was not evaluated.",
                records[0],
            )

        evaluator = _SpfEvaluator(resolver, ip)
        status, detail = evaluator.evaluate(domain)
        warnings.append(
            f"SPF was evaluated by this tool for {domain} against {ip}, not reported by your mail "
            "server. If that IP is an estimate of the origin, it may differ from the host that "
            "actually connected, and forwarded mail will be misjudged."
        )
        return result(status, AuthSource.DNS, detail, evaluator.record)

    # ---------------------------------------------------------------------- DKIM
    def _resolve_dkim(
        self,
        message: ParsedMessage,
        ar_results: list[_ArResult],
        from_domain: str,
        strict: bool,
        resolver: _Dns | None,
        warnings: list[str],
    ) -> list[AuthResult]:
        raw_sigs = message.get_headers("DKIM-Signature")
        if len(raw_sigs) > _MAX_DKIM_SIGS:
            warnings.append(
                f"{len(raw_sigs)} DKIM signatures; only the first {_MAX_DKIM_SIGS} were examined."
            )
        sigs = [_parse_dkim_signature(v) for v in raw_sigs[:_MAX_DKIM_SIGS]]
        for sig in sigs:
            self._signature_warnings(sig, warnings)

        results: list[AuthResult] = []
        used: set[int] = set()
        for ar in [r for r in ar_results if r.method == "dkim"][: _MAX_DKIM_SIGS * 2]:
            domain = _domain_of(ar.props.get("header.d", "")) or _domain_of(
                ar.props.get("header.i", "")
            )
            selector = ar.props.get("header.s", "")
            for index, sig in enumerate(sigs):
                if (
                    index not in used
                    and sig.domain == domain
                    and (not selector or sig.selector.lower() == selector.lower())
                ):
                    used.add(index)
                    break
            results.append(
                AuthResult(
                    method=AuthMethod.DKIM,
                    status=_to_status(ar.result),
                    source=AuthSource.HEADER,
                    domain=domain,
                    aligned=_aligned(domain, from_domain, strict=strict),
                    selector=selector,
                    detail=ar.props.get("reason", "") or f"Reported by {ar.authserv_id}.",
                    raw=ar.raw,
                )
            )

        for index, sig in enumerate(sigs):
            if index not in used:
                results.append(self._dkim_via_dns(sig, from_domain, strict, resolver))
        return results

    @staticmethod
    def _signature_warnings(sig: _DkimSig, warnings: list[str]) -> None:
        label = f"DKIM signature (d={sig.domain or '?'}, s={sig.selector or '?'})"
        if sig.malformed:
            warnings.append(f"{label} is malformed (missing or invalid d=/s=).")
            return
        if sig.expires is not None and sig.expires < int(datetime.now(UTC).timestamp()):
            warnings.append(f"{label} has expired (x= is in the past).")
        if sig.algorithm.startswith("rsa-sha1"):
            warnings.append(f"{label} uses the deprecated rsa-sha1 algorithm.")
        if sig.has_body_length:
            warnings.append(f"{label} uses l=, so content may have been appended after signing.")
        if sig.signed_headers and "from" not in sig.signed_headers:
            warnings.append(f"{label} does not sign the From header.")

    @staticmethod
    def _dkim_via_dns(
        sig: _DkimSig, from_domain: str, strict: bool, resolver: _Dns | None
    ) -> AuthResult:
        aligned = _aligned(sig.domain, from_domain, strict=strict)

        def result(status: AuthStatus, source: AuthSource, detail: str) -> AuthResult:
            return AuthResult(
                method=AuthMethod.DKIM,
                status=status,
                source=source,
                domain=sig.domain,
                aligned=aligned,
                selector=sig.selector,
                detail=detail,
                raw=sig.raw,
            )

        if sig.malformed:
            return result(
                AuthStatus.PERMERROR, AuthSource.HEADER, "Malformed DKIM-Signature (missing d= or s=)."
            )
        if resolver is None:
            return result(
                AuthStatus.UNKNOWN,
                AuthSource.ABSENT,
                "Signature present but no verification result in the headers; not verified (offline).",
            )
        name = f"{sig.selector}._domainkey.{sig.domain}"
        try:
            records = [r for r in resolver.txt(name) if "p=" in r.lower()]
        except _DnsTemp as exc:
            return result(AuthStatus.TEMPERROR, AuthSource.DNS, f"Key lookup for {name} failed: {exc}.")
        if not records:
            return result(
                AuthStatus.PERMERROR,
                AuthSource.DNS,
                f"No DKIM key record at {name}; the signature cannot be verified.",
            )
        tags = _tag_list(records[0])
        if not tags.get("p", "").strip():
            return result(AuthStatus.FAIL, AuthSource.DNS, f"DKIM key at {name} is revoked (empty p=).")
        note = " The key is in test mode (t=y)." if "y" in tags.get("t", "").lower().split(":") else ""
        return result(
            AuthStatus.UNKNOWN,
            AuthSource.DNS,
            f"Key record found at {name}, but this tool does not cryptographically verify "
            f"signatures and the headers carry no verdict.{note}",
        )

    # --------------------------------------------------------------------- DMARC
    def _resolve_dmarc(
        self,
        ar_results: list[_ArResult],
        spf: AuthResult,
        dkim: list[AuthResult],
        from_domain: str,
        policy: DmarcPolicy | None,
        policy_checked: bool,
        warnings: list[str],
    ) -> AuthResult:
        summary = _policy_summary(policy)

        ar = next((r for r in ar_results if r.method == "dmarc"), None)
        if ar is not None:
            status = _to_status(ar.result)
            header_from = _domain_of(ar.props.get("header.from", ""))
            if header_from and from_domain and header_from != from_domain:
                warnings.append(
                    f"DMARC was evaluated for header.from={header_from} but the message From "
                    f"domain is {from_domain}."
                )
            return AuthResult(
                method=AuthMethod.DMARC,
                status=status,
                source=AuthSource.HEADER,
                domain=header_from or from_domain,
                aligned=True if status is AuthStatus.PASS else False if status is AuthStatus.FAIL else None,
                detail=f"Reported by {ar.authserv_id}. {summary}".strip(),
                raw=ar.raw,
            )

        def result(
            status: AuthStatus, source: AuthSource, aligned: bool | None, detail: str
        ) -> AuthResult:
            return AuthResult(
                method=AuthMethod.DMARC,
                status=status,
                source=source,
                domain=from_domain,
                aligned=aligned,
                detail=detail.strip(),
            )

        if not from_domain:
            return result(AuthStatus.UNKNOWN, AuthSource.ABSENT, None, "No From domain to evaluate.")
        if policy_checked and policy is None:
            return result(
                AuthStatus.NONE,
                AuthSource.DNS,
                None,
                f"No DMARC record published for {from_domain} or its organizational domain.",
            )

        spf_ok = spf.status is AuthStatus.PASS and spf.aligned is True
        dkim_ok = any(r.status is AuthStatus.PASS and r.aligned is True for r in dkim)
        if spf_ok or dkim_ok:
            via = " and ".join(n for n, ok in (("SPF", spf_ok), ("DKIM", dkim_ok)) if ok)
            suffix = "" if policy_checked else " (DMARC record not checked.)"
            return result(
                AuthStatus.PASS,
                AuthSource.DNS if policy else AuthSource.HEADER,
                True,
                f"Computed locally: aligned {via} pass. {summary}{suffix}",
            )

        inconclusive = spf.status in _INCONCLUSIVE or any(r.status in _INCONCLUSIVE for r in dkim)
        if inconclusive or policy is None:
            return result(
                AuthStatus.UNKNOWN,
                AuthSource.ABSENT,
                None,
                "No aligned SPF/DKIM pass, but some results were unavailable or the DMARC policy "
                "could not be checked.",
            )
        return result(
            AuthStatus.FAIL,
            AuthSource.DNS,
            False,
            f"Computed locally: no aligned SPF or DKIM pass. {summary}",
        )


def analyze_auth(
    message: ParsedMessage,
    settings: Settings | None = None,
    *,
    client_ip: str | None = None,
    helo: str | None = None,
    trusted_authserv_ids: list[str] | None = None,
) -> AuthReport:
    """Analyze ``message`` using DNS and offline settings from ``settings``.

    Synchronous (DNS is blocking). Async callers should wrap it in
    ``asyncio.to_thread``.
    """
    cfg = settings or get_settings()
    analyzer = AuthAnalyzer.from_settings(cfg, trusted_authserv_ids=trusted_authserv_ids)
    return analyzer.analyze(message, client_ip=client_ip, helo=helo)