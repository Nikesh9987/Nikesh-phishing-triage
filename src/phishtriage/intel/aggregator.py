"""Fan-out of indicators across threat-intel providers.

What it does, in order:

1. **Collect targets.** IOCs (URL, DOMAIN, IPV4, IPV6) and attachment SHA-256
   hashes are de-duplicated into one target per distinct indicator. Several
   holders (two attachments with the same hash, a URL repeated across IOCs)
   share a single set of lookups. E-mail addresses have no provider; their
   domains are already separate DOMAIN IOCs.
2. **Prioritise.** Targets are processed hashes -> URLs -> IPs -> domains, so
   the scarcest quota (VirusTotal) is spent on the most valuable indicators.
   At most ``max_indicators`` targets are looked up.
3. **Route.** Each type has an ordered provider list (see ``_DEFAULT_ROUTES``).
   Only enabled providers that support the type are used.
4. **Budget.** Each rate-limited provider may serve a limited number of
   *network* lookups per run. The default is what its token bucket can serve
   within the limiter's wait budget, so lookups are skipped up front instead
   of failing with "rate limited" errors. Cache hits and lookups that end up
   ``SKIPPED`` locally (internal addresses) do not consume budget.
5. **Look up** through the shared :class:`IntelCache` (single-flight,
   TTL), with a global concurrency cap and an overall deadline.
6. **Write back** to ``IOC.intel`` / ``Attachment.intel`` (replacing any
   previous list) and build an :class:`AggregationResult` with provider status,
   statistics and analyst-readable warnings.

DNSBL: keyless, so it is the natural fallback. With ``dnsbl_always=True``
(default) it runs next to the keyed providers. With ``False`` it runs only if
no other provider returned a definitive answer (MALICIOUS, SUSPICIOUS, CLEAN
or UNKNOWN) for that indicator.

Semantics worth remembering:

* ``UNKNOWN`` means "provider has no data", never "safe".
* ``ERROR`` results are kept on the indicator (so the dashboard can show
  "VirusTotal: rate limited") and summarised per provider in the warnings.
* The budget is per run, but rate limiters live as long as the providers. In a
  long-lived API process, back-to-back runs can therefore still hit a limiter
  that is "in debt" from the previous run; those lookups come back as ``ERROR``.
* The aggregator never raises (task cancellation excepted): failures become
  warnings and partial results.

Use one aggregator and one cache for the life of the process, and call
:meth:`IntelAggregator.aclose` (or use ``async with``) at shutdown.
"""

import asyncio
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final

from phishtriage.config import Settings, get_settings
from phishtriage.core.models import IOC, Attachment, IntelResult, IntelVerdict, IOCType
from phishtriage.intel.abuseipdb import AbuseIPDBProvider
from phishtriage.intel.base import IntelProvider, ProviderStatus
from phishtriage.intel.cache import IntelCache
from phishtriage.intel.dnsbl import DNSBLProvider
from phishtriage.intel.urlhaus import URLhausProvider
from phishtriage.intel.virustotal import VirusTotalProvider
from phishtriage.logging_config import get_logger

__all__ = [
    "AggregationResult",
    "AggregationStats",
    "IntelAggregator",
    "default_budgets",
    "run_enrichment",
    "worst_verdict",
]

logger = get_logger(__name__)

_V = IntelVerdict
_DEFINITIVE: Final = frozenset({_V.MALICIOUS, _V.SUSPICIOUS, _V.CLEAN, _V.UNKNOWN})

#: Lower rank = looked up first.
_TYPE_RANK: Final[dict[IOCType, int]] = {
    IOCType.HASH: 0,
    IOCType.URL: 1,
    IOCType.IPV4: 2,
    IOCType.IPV6: 2,
    IOCType.DOMAIN: 3,
}

#: Ordered primary providers per indicator type. The fallback (DNSBL) is added
#: separately. Providers that do not support the type are skipped automatically.
_DEFAULT_ROUTES: Final[dict[IOCType, tuple[str, ...]]] = {
    IOCType.HASH: ("virustotal", "urlhaus"),
    IOCType.URL: ("urlhaus", "virustotal"),
    IOCType.DOMAIN: ("urlhaus", "virustotal"),
    IOCType.IPV4: ("abuseipdb", "virustotal", "urlhaus"),
    IOCType.IPV6: ("abuseipdb", "virustotal"),
}
_FALLBACK: Final = "dnsbl"

# Matches the default wait budget of AsyncRateLimiter (30 s). One second is
# held back so float rounding can never push the last lookup over the limit.
_LIMITER_WAIT_SECONDS: Final = 30.0
_MAX_ERROR_EXAMPLE: Final = 200

Target = tuple[str, str]


# ================================================================== public types
def worst_verdict(results: Iterable[IntelResult]) -> IntelVerdict:
    """Most severe verdict in ``results``; ``UNKNOWN`` if none is MALICIOUS/SUSPICIOUS/CLEAN."""
    seen = {r.verdict for r in results}
    for verdict in (_V.MALICIOUS, _V.SUSPICIOUS, _V.CLEAN):
        if verdict in seen:
            return verdict
    return _V.UNKNOWN


def default_budgets(settings: Settings) -> dict[str, int]:
    """Network lookups per run that each keyed provider's limiter can serve in time.

    Burst capacity plus what refills during the limiter's wait budget. For the
    VirusTotal free tier (4 per minute) that is 2 lookups; for 30 per minute, 19.
    """
    budgets: dict[str, int] = {}
    for name in ("urlhaus", "abuseipdb", "virustotal"):
        rpm = float(getattr(settings, f"{name}_requests_per_minute"))
        burst = max(1, int(rpm // 6))
        budgets[name] = burst + int(rpm * (_LIMITER_WAIT_SECONDS - 2.0) / 60.0)
    return budgets


@dataclass
class AggregationStats:
    """Counters for one enrichment run."""

    indicators: int = 0  # distinct targets looked up
    queried: int = 0  # results that came from a live provider query
    cache_hits: int = 0
    errors: int = 0
    local_skipped: int = 0  # provider declined locally (e.g. internal address)
    budget_skipped: int = 0  # lookups not attempted because a provider budget ran out
    unfinished: int = 0  # targets cut off by the deadline


@dataclass
class AggregationResult:
    """Outcome of :meth:`IntelAggregator.enrich`."""

    providers: list[ProviderStatus] = field(default_factory=list)
    providers_used: list[str] = field(default_factory=list)
    stats: AggregationStats = field(default_factory=AggregationStats)
    warnings: list[str] = field(default_factory=list)


# ================================================================== internals
@dataclass
class _Target:
    ioc_type: IOCType
    value: str
    holders: list[IOC | Attachment] = field(default_factory=list)
    results: list[tuple[int, IntelResult]] = field(default_factory=list)


class _Budget:
    """Per-run lookup allowance per provider. Providers without a limit are unlimited."""

    def __init__(self, limits: Mapping[str, int]) -> None:
        self._left = dict(limits)

    def take(self, name: str) -> bool:
        left = self._left.get(name)
        if left is None:
            return True
        if left <= 0:
            return False
        self._left[name] = left - 1
        return True

    def refund(self, name: str) -> None:
        if name in self._left:
            self._left[name] += 1


@dataclass
class _Run:
    semaphore: asyncio.Semaphore
    budget: _Budget
    budget_skipped: Counter[str] = field(default_factory=Counter)


# ================================================================== aggregator
class IntelAggregator:
    """Run threat-intel lookups for a set of IOCs and attachments."""

    def __init__(
        self,
        providers: Sequence[IntelProvider],
        *,
        cache: IntelCache | None = None,
        max_concurrency: int = 8,
        budgets: Mapping[str, int] | None = None,
        routes: Mapping[IOCType, Sequence[str]] | None = None,
        fallback: str = _FALLBACK,
        dnsbl_always: bool = True,
        max_indicators: int = 150,
        deadline_seconds: float = 60.0,
    ) -> None:
        """Create an aggregator.

        Args:
            providers: Providers in display order (also the result order).
            cache: Shared :class:`IntelCache`; a private one is created if omitted.
            max_concurrency: Maximum provider calls in flight at once.
            budgets: Provider name -> max network lookups per run. Missing
                names are unlimited. Use :func:`default_budgets` for the
                rate-limit-derived defaults.
            routes: Override the type -> ordered provider names table.
            fallback: Name of the keyless fallback provider.
            dnsbl_always: Run the fallback next to the others (``True``) or
                only when nothing else answered (``False``).
            max_indicators: Cap on distinct indicators looked up per run.
            deadline_seconds: Overall time limit for one run.
        """
        self._providers = list(providers)
        self._by_name = {p.name: p for p in self._providers}
        self._order = {p.name: i for i, p in enumerate(self._providers)}
        self._cache = cache if cache is not None else IntelCache()
        self._max_concurrency = max(1, int(max_concurrency))
        self._budgets = {k: max(0, int(v)) for k, v in (budgets or {}).items()}
        self._routes = {t: tuple(names) for t, names in (routes or _DEFAULT_ROUTES).items()}
        self._fallback = fallback
        self._dnsbl_always = dnsbl_always
        self._max_indicators = max(1, int(max_indicators))
        self._deadline = max(0.1, float(deadline_seconds))

    @classmethod
    def from_settings(
        cls,
        settings: Settings | None = None,
        *,
        cache: IntelCache | None = None,
        budgets: Mapping[str, int] | None = None,
        **options: object,
    ) -> "IntelAggregator":
        """Build the standard four providers, cache and budgets from settings.

        ``budgets`` entries override the computed defaults. Remaining keyword
        options are passed to the constructor (``dnsbl_always``, ``max_concurrency`` ...).
        """
        cfg = settings or get_settings()
        providers: list[IntelProvider] = [
            AbuseIPDBProvider(cfg),
            URLhausProvider(cfg),
            VirusTotalProvider(cfg),
            DNSBLProvider(cfg),
        ]
        merged = {**default_budgets(cfg), **(dict(budgets) if budgets else {})}
        shared = cache if cache is not None else IntelCache.from_settings(cfg)
        return cls(providers, cache=shared, budgets=merged, **options)  # type: ignore[arg-type]

    # ----------------------------------------------------------------- lifecycle
    async def aclose(self) -> None:
        """Close every provider's network resources."""
        await asyncio.gather(*(p.aclose() for p in self._providers), return_exceptions=True)

    async def __aenter__(self) -> "IntelAggregator":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ status
    def provider_statuses(self) -> list[ProviderStatus]:
        """Status (enabled / reason) of every provider."""
        return [p.status() for p in self._providers]

    @property
    def cache(self) -> IntelCache:
        """The cache in use (for statistics)."""
        return self._cache

    # ------------------------------------------------------------------ planning
    def _plan(self, ioc_type: IOCType) -> tuple[list[IntelProvider], IntelProvider | None]:
        """Return ``(primary providers in route order, fallback or None)`` that can run."""
        primaries = [
            p
            for name in self._routes.get(ioc_type, ())
            if (p := self._by_name.get(name)) is not None and p.enabled and p.supports(ioc_type)
        ]
        backup = self._by_name.get(self._fallback)
        fallback = (
            backup
            if backup is not None
            and backup.enabled
            and backup.supports(ioc_type)
            and backup not in primaries
            else None
        )
        return primaries, fallback

    def _collect(
        self, iocs: Sequence[IOC], attachments: Sequence[Attachment], warnings: list[str]
    ) -> list[_Target]:
        targets: dict[Target, _Target] = {}

        def add(ioc_type: IOCType, value: str, holder: IOC | Attachment) -> None:
            value = value.strip()
            if not value:
                return
            primaries, fallback = self._plan(ioc_type)
            if not primaries and fallback is None:
                return
            key = IntelCache.make_key("", ioc_type, value)[1:]
            target = targets.get(key)
            if target is None:
                target = targets[key] = _Target(ioc_type, value)
            if not any(h is holder for h in target.holders):
                target.holders.append(holder)

        for attachment in attachments:
            if attachment.sha256 and not attachment.skipped:
                add(IOCType.HASH, attachment.sha256, attachment)
        for ioc in iocs:
            if ioc.type in _TYPE_RANK:
                add(ioc.type, ioc.value, ioc)

        ordered = sorted(targets.values(), key=lambda t: _TYPE_RANK[t.ioc_type])  # stable
        if len(ordered) > self._max_indicators:
            warnings.append(
                f"{len(ordered)} indicators found; only the {self._max_indicators} highest-priority "
                "(hashes, URLs, IPs, then domains) were looked up."
            )
            ordered = ordered[: self._max_indicators]
        return ordered

    # ------------------------------------------------------------------ execution
    async def _call(self, provider: IntelProvider, target: _Target, run: _Run) -> None:
        """One provider lookup for one target; appends its result to ``target.results``."""
        order = self._order[provider.name]
        try:
            async with run.semaphore:
                cached = self._cache.get(provider.name, target.ioc_type, target.value)
                if cached is not None:
                    target.results.append((order, cached))
                    return
                if not run.budget.take(provider.name):
                    run.budget_skipped[provider.name] += 1
                    return
                result = await self._cache.lookup(provider, target.value, target.ioc_type)
                if result.verdict is _V.SKIPPED:
                    run.budget.refund(provider.name)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one lookup must never abort the run
            logger.exception("Lookup via %s failed", provider.name)
            result = IntelResult(
                provider=provider.name,
                indicator=target.value,
                indicator_type=target.ioc_type,
                verdict=_V.ERROR,
                detail=f"{provider.name} lookup failed unexpectedly.",
            )
        target.results.append((order, result))

    async def _investigate(self, target: _Target, run: _Run) -> None:
        primaries, fallback = self._plan(target.ioc_type)
        calls = list(primaries)
        if fallback is not None and self._dnsbl_always:
            calls.append(fallback)
        await asyncio.gather(*(self._call(p, target, run) for p in calls))
        if (
            fallback is not None
            and not self._dnsbl_always
            and not any(r.verdict in _DEFINITIVE for _, r in target.results)
        ):
            await self._call(fallback, target, run)

    # ------------------------------------------------------------------ public API
    async def enrich(
        self,
        iocs: Sequence[IOC] = (),
        attachments: Sequence[Attachment] = (),
    ) -> AggregationResult:
        """Look up ``iocs`` and attachment hashes; results are written onto the models.

        Existing ``intel`` lists of the models that were looked up are replaced.
        """
        statuses = self.provider_statuses()
        try:
            return await self._enrich(statuses, iocs, attachments)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - never abort a triage on enrichment failure
            logger.exception("Threat-intel enrichment failed")
            return AggregationResult(
                providers=statuses, warnings=["Threat-intel enrichment failed unexpectedly."]
            )

    async def _enrich(
        self,
        statuses: list[ProviderStatus],
        iocs: Sequence[IOC],
        attachments: Sequence[Attachment],
    ) -> AggregationResult:
        warnings: list[str] = []
        stats = AggregationStats()

        if not any(s.enabled for s in statuses):
            reasons = {s.reason for s in statuses}
            warnings.append(
                "Offline mode: threat-intelligence lookups were skipped."
                if reasons == {"offline mode"}
                else "No threat-intelligence provider is enabled; lookups were skipped. "
                "Configure API keys (see .env.example)."
            )
            return AggregationResult(providers=statuses, stats=stats, warnings=warnings)

        targets = self._collect(iocs, attachments, warnings)
        stats.indicators = len(targets)
        run = _Run(asyncio.Semaphore(self._max_concurrency), _Budget(self._budgets))

        tasks = [asyncio.create_task(self._investigate(t, run)) for t in targets]
        pending: set[asyncio.Task[None]] = set()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=self._deadline)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    logger.error("Enrichment task failed: %r", task.exception())
        stats.unfinished = len(pending)

        errors_by_provider: dict[str, list[str]] = {}
        used: set[str] = set()
        for target in targets:
            ordered = [r for _, r in sorted(target.results, key=lambda item: item[0])]
            kept = [r for r in ordered if r.verdict is not _V.SKIPPED]
            stats.local_skipped += len(ordered) - len(kept)
            for result in kept:
                if result.from_cache:
                    stats.cache_hits += 1
                else:
                    stats.queried += 1
                if result.verdict is _V.ERROR:
                    stats.errors += 1
                    errors_by_provider.setdefault(result.provider, []).append(result.detail)
                else:
                    used.add(result.provider)
            for holder in target.holders:
                holder.intel = [r.model_copy() for r in kept]

        stats.budget_skipped = sum(run.budget_skipped.values())
        warnings.extend(self._summaries(run, errors_by_provider, stats))
        return AggregationResult(
            providers=statuses,
            providers_used=sorted(used, key=lambda n: self._order.get(n, 0)),
            stats=stats,
            warnings=warnings,
        )

    def _summaries(
        self, run: _Run, errors: Mapping[str, list[str]], stats: AggregationStats
    ) -> list[str]:
        warnings: list[str] = []
        for name in sorted(errors, key=lambda n: self._order.get(n, 0)):
            details = errors[name]
            warnings.append(
                f"{name}: {len(details)} lookup(s) failed, e.g. {details[0][:_MAX_ERROR_EXAMPLE]}"
            )
        for name in sorted(run.budget_skipped, key=lambda n: self._order.get(n, 0)):
            limit = self._budgets.get(name, 0)
            warnings.append(
                f"{name}: {run.budget_skipped[name]} lookup(s) not attempted because the per-run "
                f"limit of {limit} was reached (hashes and URLs are looked up first)."
            )
        if stats.unfinished:
            warnings.append(
                f"{stats.unfinished} indicator(s) were not finished within the "
                f"{self._deadline:g}s deadline; their results are incomplete."
            )
        return warnings


async def run_enrichment(
    iocs: Sequence[IOC] = (),
    attachments: Sequence[Attachment] = (),
    settings: Settings | None = None,
    *,
    cache: IntelCache | None = None,
) -> AggregationResult:
    """One-shot helper: build an aggregator from ``settings``, enrich, and close it.

    Pass a shared ``cache`` to keep results across calls. Long-lived services
    should keep one :class:`IntelAggregator` instead, so rate limiters persist.
    """
    async with IntelAggregator.from_settings(settings, cache=cache) as aggregator:
        return await aggregator.enrich(iocs, attachments)
