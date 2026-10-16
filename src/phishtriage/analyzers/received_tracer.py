"""Trace the ``Received:`` chain of a message and estimate its originating MTA.

Each mail server *prepends* a ``Received`` header, so the first header in the
file is the newest hop. This module reverses them: **hop index 0 is the oldest
hop** (closest to the sender) and the last hop is the final delivery server.

What is extracted per hop: ``from``/``by`` hosts, protocol (``with``), queue id
(``id``), envelope recipient (``for``), timestamp, delay since the previous hop,
and every IP literal in the ``from`` clause (IPv4, IPv6, IPv4-mapped IPv6), each
classified by scope (public, RFC 1918, CGNAT, loopback, ...). Only the ``from``
clause is scanned for IPs, because the ``by`` clause describes the *receiving*
server (Gmail even writes IPv6-looking tokens there).

Reverse DNS is performed for **public** IPs only, concurrently, with bounded
time. Private and reserved addresses are never sent to a resolver. With
``resolve_rdns=False`` (offline mode) no DNS traffic occurs at all.

Trust model for the originating MTA (important):

* The sender controls every header **below** the first one added by a server
  you trust, and can forge those lines. By default the "originating MTA" is
  therefore the *oldest hop with a public IP*, labelled as an estimate.
* If you know how many of the newest hops belong to your own infrastructure,
  pass ``trusted_hops=N``. The origin is then taken from the oldest of those N
  hops, i.e. the connecting IP that **your** server actually observed. That
  value cannot be forged by the sender.
* RFC 5737 / RFC 3849 documentation addresses (``203.0.113.0/24`` etc.) are
  accepted as origin candidates so that samples and test fixtures work.

Never raises: any failure becomes a warning on the returned trace.
"""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime, timedelta
from typing import Final

import dns.exception
import dns.resolver
import dns.reversename

from phishtriage.config import Settings, get_settings
from phishtriage.core.models import (
    Hop,
    HopIP,
    IPScope,
    OriginatingMTA,
    ParsedMessage,
    ReceivedTrace,
)
from phishtriage.logging_config import get_logger
from phishtriage.parsers.base import clean_header_text, parse_date

__all__ = ["ReceivedTracer", "classify_ip", "trace_received"]

logger = get_logger(__name__)

_MAX_RECEIVED_LEN: Final = 8192
_MAX_RAW_KEPT: Final = 4096
_MAX_TOKEN_LEN: Final = 255
_MAX_RDNS_LOOKUPS: Final = 64
_CLOCK_SKEW_SECONDS: Final = 120.0
_LARGE_DELAY_SECONDS: Final = 3600.0
_FUTURE_TOLERANCE: Final = timedelta(days=1)

_KEYWORDS: Final = frozenset({"from", "by", "with", "id", "for", "via"})

_COMMENT_RE = re.compile(r"\([^)]*\)")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:]|\.\d)")
_IPV6_TAG_RE = re.compile(r"(?i)\bipv6:")
_MAPPED_RE = re.compile(r"(?i)::ffff:(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")

_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_UNIQUE_LOCAL = ipaddress.ip_network("fc00::/7")
_DOC_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# ==================================================================== IP helpers
def _is_documentation(ip: _IPAddress) -> bool:
    return any(ip.version == net.version and ip in net for net in _DOC_NETWORKS)


def classify_ip(address: str) -> IPScope:
    """Classify an IP address string by routing scope.

    Raises:
        ValueError: ``address`` is not a valid IPv4/IPv6 address.
    """
    ip: _IPAddress = ipaddress.ip_address(address.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return IPScope.RESERVED
    if ip.is_loopback:
        return IPScope.LOOPBACK
    if ip.is_link_local:
        return IPScope.LINK_LOCAL
    if ip.is_multicast:
        return IPScope.MULTICAST
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CGNAT:
            return IPScope.CGNAT
        if _is_documentation(ip):
            return IPScope.RESERVED
        if any(ip in net for net in _RFC1918):
            return IPScope.PRIVATE
    else:
        if ip in _UNIQUE_LOCAL:
            return IPScope.UNIQUE_LOCAL
        if _is_documentation(ip):
            return IPScope.RESERVED
    return IPScope.PUBLIC if ip.is_global else IPScope.RESERVED


def _extract_ips(text: str) -> list[HopIP]:
    """Return unique, valid IPs found in ``text`` in order of appearance."""
    text = _IPV6_TAG_RE.sub(" ", text)  # "[IPv6:2001:db8::1]" -> bare literal
    found: list[tuple[int, _IPAddress]] = []

    for match in _MAPPED_RE.finditer(text):
        try:
            found.append((match.start(), ipaddress.IPv4Address(match.group(1))))
        except ValueError:
            continue
    for match in _IPV4_RE.finditer(text):
        try:
            found.append((match.start(), ipaddress.IPv4Address(match.group(0))))
        except ValueError:
            continue
    for match in _IPV6_RE.finditer(text):
        try:
            v6 = ipaddress.IPv6Address(match.group(0))
        except ValueError:
            continue
        if v6.ipv4_mapped is None:
            found.append((match.start(), v6))

    result: list[HopIP] = []
    seen: set[str] = set()
    for _, ip in sorted(found, key=lambda item: item[0]):
        address = str(ip)
        if address in seen:
            continue
        seen.add(address)
        result.append(HopIP(address=address, version=ip.version, scope=classify_ip(address)))
    return result


def _is_origin_candidate(hop_ip: HopIP) -> bool:
    """Public addresses, or documentation ranges (so samples and tests work)."""
    if hop_ip.scope is IPScope.PUBLIC:
        return True
    return hop_ip.scope is IPScope.RESERVED and _is_documentation(
        ipaddress.ip_address(hop_ip.address)
    )


# ================================================================== text helpers
def _tokenize(text: str) -> list[str]:
    """Split on whitespace at bracket depth 0, keeping ``(...)`` and ``[...]`` whole."""
    tokens: list[str] = []
    buf: list[str] = []
    depth = 0
    for char in text:
        if char in "([":
            depth += 1
        elif char in ")]" and depth > 0:
            depth -= 1
        if char.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(char)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _split_clauses(body: str) -> dict[str, list[str]]:
    """Group tokens under their first-seen keyword (``from``, ``by``, ``with`` ...)."""
    clauses: dict[str, list[str]] = {}
    current: str | None = None
    for token in _tokenize(body):
        low = token.lower()
        if low in _KEYWORDS and low not in clauses:
            clauses[low] = []
            current = low
        elif current is not None:
            clauses[current].append(token)
    return clauses


def _first_value(tokens: list[str] | None) -> str:
    """First non-comment token, stripped of ``[]<>;`` and an ``IPv6:`` prefix."""
    for token in tokens or []:
        if token.startswith("("):
            continue
        value = token.strip("[]<>;, ")
        if value.lower().startswith("ipv6:"):
            value = value[5:]
        if value:
            return value[:_MAX_TOKEN_LEN]
    return ""


def _joined_value(tokens: list[str] | None, limit: int = 64) -> str:
    parts = [t.strip(";") for t in (tokens or []) if not t.startswith("(")]
    return " ".join(p for p in parts if p)[:limit]


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _format_duration(seconds: float) -> str:
    total = int(abs(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


def _base_domain(host: str) -> str:
    """Last two labels. Deliberately crude: avoids the network-fetched public-suffix list."""
    return ".".join(host.lower().rstrip(".").split(".")[-2:])


# ==================================================================== reverse DNS
def _reverse_lookup(resolver: dns.resolver.Resolver, address: str) -> tuple[str | None, str | None]:
    """Return ``(ptr_name, error)`` for ``address``; exactly one is ``None``."""
    try:
        answer = resolver.resolve(dns.reversename.from_address(address), "PTR")
        names = sorted(str(rdata.target).rstrip(".").lower() for rdata in answer)
        return (names[0], None) if names else (None, "no PTR record")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None, "no PTR record"
    except dns.exception.Timeout:
        return None, "timeout"
    except dns.resolver.NoNameservers:
        return None, "resolver unavailable"
    except Exception:  # noqa: BLE001 - dnspython raises many types on odd network states
        logger.debug("Reverse lookup failed for %s", address, exc_info=True)
        return None, "lookup failed"


# ========================================================================= tracer
class ReceivedTracer:
    """Parse and analyse the ``Received`` chain of a :class:`ParsedMessage`."""

    def __init__(
        self,
        *,
        resolve_rdns: bool = True,
        nameservers: list[str] | None = None,
        dns_timeout: float = 3.0,
        dns_lifetime: float = 6.0,
        max_hops: int = 40,
        max_workers: int = 8,
    ) -> None:
        """Create a tracer.

        Args:
            resolve_rdns: Perform reverse DNS for public IPs. ``False`` means
                zero network traffic.
            nameservers: Custom resolver IPs; empty/None uses the system resolver.
            dns_timeout: Per-attempt DNS timeout in seconds.
            dns_lifetime: Total time budget per DNS lookup in seconds.
            max_hops: Maximum hops analysed. If exceeded, the *oldest* are
                kept, since they matter most for finding the origin.
            max_workers: Concurrent reverse-DNS lookups.
        """
        self._resolve_rdns = resolve_rdns
        self._nameservers = list(nameservers or [])
        self._dns_timeout = dns_timeout
        self._dns_lifetime = dns_lifetime
        self._max_hops = max(1, max_hops)
        self._max_workers = max(1, max_workers)

    @classmethod
    def from_settings(cls, settings: Settings) -> "ReceivedTracer":
        """Build a tracer from application settings (honours offline mode)."""
        return cls(
            resolve_rdns=settings.network_enabled,
            nameservers=settings.dns_nameservers,
            dns_timeout=settings.dns_timeout_seconds,
            dns_lifetime=settings.dns_lifetime_seconds,
            max_hops=settings.max_received_hops,
        )

    # ----------------------------------------------------------------- public API
    def trace(self, message: ParsedMessage, *, trusted_hops: int | None = None) -> ReceivedTrace:
        """Trace the Received chain.

        Args:
            message: The parsed message.
            trusted_hops: Number of *newest* hops operated by infrastructure
                you trust. When set, the originating MTA is taken from the
                oldest of those hops (see module docstring).
        """
        try:
            return self._trace(message, trusted_hops)
        except Exception:  # noqa: BLE001 - never let hop analysis abort a triage
            logger.exception("Received-chain analysis failed")
            return ReceivedTrace(warnings=["Received-chain analysis failed unexpectedly."])

    # ------------------------------------------------------------------ internals
    def _trace(self, message: ParsedMessage, trusted_hops: int | None) -> ReceivedTrace:
        warnings: list[str] = []
        self._note_originating_ip_header(message, warnings)

        raw_headers = message.get_headers("Received")
        if not raw_headers:
            warnings.append("No Received headers found; the message path cannot be traced.")
            return ReceivedTrace(warnings=warnings)

        chronological = raw_headers[::-1]
        if len(chronological) > self._max_hops:
            warnings.append(
                f"{len(chronological)} Received headers found; only the oldest "
                f"{self._max_hops} were analysed."
            )
            chronological = chronological[: self._max_hops]

        hops = [self._parse_hop(i, raw) for i, raw in enumerate(chronological)]
        total_delay = self._apply_timing(hops, warnings)

        if self._resolve_rdns:
            self._apply_rdns(hops, warnings)
            self._flag_rdns_mismatch(hops)

        if trusted_hops is not None and trusted_hops > len(hops):
            warnings.append(
                f"trusted_hops={trusted_hops} exceeds the {len(hops)} hop(s) present; "
                "all hops are treated as trusted."
            )

        origin = self._select_origin(hops, trusted_hops)
        if origin is None:
            warnings.append(
                "No public sending IP found in the Received chain; the message may be "
                "internal, or the headers were stripped or rewritten."
            )
        elif not any(ip.address for hop in hops for ip in hop.ips):  # pragma: no cover
            warnings.append("No IP addresses found in Received headers.")

        return ReceivedTrace(
            hops=hops,
            originating_mta=origin,
            total_delay_seconds=total_delay,
            warnings=warnings,
        )

    @staticmethod
    def _note_originating_ip_header(message: ParsedMessage, warnings: list[str]) -> None:
        """Mention ``X-Originating-IP`` (webmail client address) as an unverified hint."""
        for value in message.get_headers("X-Originating-IP")[:1]:
            for hop_ip in _extract_ips(value):
                warnings.append(
                    f"X-Originating-IP reports {hop_ip.address} ({hop_ip.scope.value}); "
                    "this header is added by the first server and is not authenticated."
                )

    # --------------------------------------------------------------- hop parsing
    def _parse_hop(self, index: int, raw: str) -> Hop:
        text = clean_header_text(raw)[:_MAX_RECEIVED_LEN]
        anomalies: list[str] = []

        if ";" in text:
            body, _, tail = text.rpartition(";")
        else:
            body, tail = text, ""
        tail = _COMMENT_RE.sub("", tail).strip()
        timestamp = parse_date(tail) if tail else None
        if timestamp is None:
            anomalies.append("Missing or unparseable timestamp.")

        clauses = _split_clauses(body)
        if "from" not in clauses and "by" not in clauses:
            anomalies.append("Received header structure could not be parsed.")

        from_tokens = clauses.get("from", [])
        ips = _extract_ips(" ".join(from_tokens)) if from_tokens else []

        return Hop(
            index=index,
            raw=text[:_MAX_RAW_KEPT],
            from_host=_first_value(from_tokens),
            by_host=_first_value(clauses.get("by")),
            protocol=_joined_value(clauses.get("with")),
            envelope_for=_first_value(clauses.get("for")),
            queue_id=_first_value(clauses.get("id")),
            timestamp=timestamp,
            ips=ips,
            anomalies=anomalies,
        )

    # -------------------------------------------------------------------- timing
    @staticmethod
    def _apply_timing(hops: list[Hop], warnings: list[str]) -> float | None:
        """Fill ``delay_seconds``, flag timing anomalies, return total transit time."""
        now = datetime.now(UTC)
        previous: Hop | None = None
        first: Hop | None = None
        for hop in hops:
            if hop.timestamp is None:
                continue
            if hop.timestamp > now + _FUTURE_TOLERANCE:
                hop.anomalies.append("Timestamp is more than a day in the future.")
            if previous is not None and previous.timestamp is not None:
                delta = (hop.timestamp - previous.timestamp).total_seconds()
                hop.delay_seconds = delta
                if delta < -_CLOCK_SKEW_SECONDS:
                    hop.anomalies.append(
                        f"Timestamp is {_format_duration(delta)} earlier than the previous hop "
                        "(clock skew or forged header)."
                    )
                elif delta > _LARGE_DELAY_SECONDS:
                    hop.anomalies.append(
                        f"Delay of {_format_duration(delta)} since the previous hop."
                    )
            first = first or hop
            previous = hop

        if first is None or previous is None or first is previous:
            return None
        assert first.timestamp is not None and previous.timestamp is not None  # noqa: S101
        total = (previous.timestamp - first.timestamp).total_seconds()
        if any("earlier than the previous hop" in a for h in hops for a in h.anomalies):
            warnings.append("Received timestamps are not monotonic; timing data is unreliable.")
        return total

    # --------------------------------------------------------------- reverse DNS
    def _build_resolver(self) -> dns.resolver.Resolver | None:
        try:
            resolver = dns.resolver.Resolver(configure=not self._nameservers)
        except dns.resolver.NoResolverConfiguration:
            return None
        if self._nameservers:
            resolver.nameservers = list(self._nameservers)
        resolver.timeout = self._dns_timeout
        resolver.lifetime = self._dns_lifetime
        return resolver

    def _apply_rdns(self, hops: list[Hop], warnings: list[str]) -> None:
        """Resolve PTR records for every distinct public IP, concurrently."""
        targets: list[str] = []
        for hop in hops:
            for hop_ip in hop.ips:
                if hop_ip.scope is IPScope.PUBLIC and hop_ip.address not in targets:
                    targets.append(hop_ip.address)
        if not targets:
            return
        if len(targets) > _MAX_RDNS_LOOKUPS:
            warnings.append(
                f"Reverse DNS limited to the first {_MAX_RDNS_LOOKUPS} of {len(targets)} public IPs."
            )
            targets = targets[:_MAX_RDNS_LOOKUPS]

        resolver = self._build_resolver()
        if resolver is None:
            warnings.append("No DNS resolver is configured; reverse DNS was skipped.")
            return

        results: dict[str, tuple[str | None, str | None]] = {}
        with ThreadPoolExecutor(
            max_workers=min(self._max_workers, len(targets)), thread_name_prefix="rdns"
        ) as pool:
            futures = {pool.submit(_reverse_lookup, resolver, ip): ip for ip in targets}
            for future, address in futures.items():
                try:
                    results[address] = future.result(timeout=self._dns_lifetime + 2.0)
                except FutureTimeoutError:
                    results[address] = (None, "timeout")
                except Exception:  # noqa: BLE001
                    results[address] = (None, "lookup failed")

        for hop in hops:
            for hop_ip in hop.ips:
                if hop_ip.address in results:
                    hop_ip.rdns, hop_ip.rdns_error = results[hop_ip.address]

    @staticmethod
    def _flag_rdns_mismatch(hops: list[Hop]) -> None:
        """Flag hops whose claimed ``from`` hostname disagrees with the IP's PTR record."""
        for hop in hops:
            claimed = hop.from_host.lower().rstrip(".")
            if "." not in claimed or _is_ip_literal(claimed):
                continue
            for hop_ip in hop.ips:
                if hop_ip.rdns and _base_domain(hop_ip.rdns) != _base_domain(claimed):
                    hop.anomalies.append(
                        f"Claimed host '{hop.from_host}' does not match reverse DNS "
                        f"'{hop_ip.rdns}' of {hop_ip.address}."
                    )
                    break

    # ------------------------------------------------------------- origin choice
    @staticmethod
    def _select_origin(hops: list[Hop], trusted_hops: int | None) -> OriginatingMTA | None:
        """Pick the first externally routable sending IP (see module docstring)."""
        trusted = trusted_hops is not None and trusted_hops > 0
        start = max(0, len(hops) - trusted_hops) if trusted and trusted_hops else 0

        for hop in hops[start:]:
            for hop_ip in hop.ips:
                if not _is_origin_candidate(hop_ip):
                    continue
                if trusted:
                    reason = (
                        f"Connecting IP recorded by the oldest of your {len(hops) - start} "
                        f"trusted hop(s) (hop #{hop.index + 1}); earlier hops are ignored."
                    )
                else:
                    reason = (
                        f"Oldest Received hop with a public sending IP (hop #{hop.index + 1} "
                        f"of {len(hops)}). Hops below it are unverifiable and may be forged."
                    )
                    if hop.index > 0:
                        reason += f" Preceded by {hop.index} hop(s) with no public IP."
                hostname = (
                    hop.from_host if hop.from_host and not _is_ip_literal(hop.from_host) else None
                )
                return OriginatingMTA(
                    ip=hop_ip.address,
                    hostname=hostname,
                    rdns=hop_ip.rdns,
                    hop_index=hop.index,
                    reason=reason,
                )
        return None


def trace_received(
    message: ParsedMessage,
    settings: Settings | None = None,
    *,
    trusted_hops: int | None = None,
) -> ReceivedTrace:
    """Trace ``message`` using limits and offline mode from ``settings``.

    This function is synchronous (reverse DNS uses a thread pool internally).
    Async callers such as FastAPI should wrap it in ``asyncio.to_thread``.
    """
    cfg = settings or get_settings()
    return ReceivedTracer.from_settings(cfg).trace(message, trusted_hops=trusted_hops)
