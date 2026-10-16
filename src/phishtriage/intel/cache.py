"""TTL cache with single-flight de-duplication for threat-intel lookups.

Why this exists: a phishing mail repeats the same indicators (the same URL in
the text and HTML parts, the same sender domain in ten links). Free API tiers
are tiny, so every duplicate query wastes quota. This cache provides:

* **Result caching.** Keyed by ``(provider, indicator type, indicator)``.
  Hosts, hashes, IPs and e-mail addresses are case-folded; URLs are not
  (paths are case-sensitive).
* **Single-flight.** If a lookup for a key is already running, later callers
  *wait for that same lookup* instead of starting another. Waiting is
  cancellation-safe: cancelling one waiter never cancels the shared lookup.
* **Bounded memory.** At most ``max_entries`` results are kept. Eviction is
  FIFO, which with one uniform TTL is also oldest-expiry-first, so expired
  entries are always dropped before live ones.
* **Only definitive answers are cached.** ``MALICIOUS``, ``SUSPICIOUS``,
  ``CLEAN`` and ``UNKNOWN`` are stored. ``ERROR`` (timeout, rate limit, bad
  key) and ``SKIPPED`` (disabled provider) are never stored, so a transient
  outage cannot poison later lookups.
* **Isolation.** Every caller receives its own copy of the result. Cache hits
  carry ``from_cache=True``, and ``queried_at`` still shows when the provider
  was actually asked.

If the leading lookup raises or is cancelled, waiting callers do not inherit
the failure: they retry once, and if that also fails they query directly
without caching.

Not thread-safe: use one instance per event loop (the process-wide cache is
shared by tasks, not threads). It holds no loop-bound state between calls, so
it survives repeated ``asyncio.run()`` invocations. ``ttl_seconds=0`` disables
storage but keeps single-flight de-duplication.
"""

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Protocol

from phishtriage.config import Settings
from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.logging_config import get_logger

__all__ = ["CacheKey", "CacheStats", "IntelCache"]

logger = get_logger(__name__)

CacheKey = tuple[str, str, str]
Clock = Callable[[], float]
Fetcher = Callable[[], Awaitable[IntelResult]]

_CACHEABLE: Final = frozenset(
    {IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS, IntelVerdict.CLEAN, IntelVerdict.UNKNOWN}
)
_CASE_INSENSITIVE: Final = frozenset(
    {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.EMAIL, IOCType.HASH}
)
_MAX_FOLLOW_ATTEMPTS: Final = 2


class _Lookupable(Protocol):
    """The slice of :class:`~phishtriage.intel.base.IntelProvider` the cache needs."""

    @property
    def name(self) -> str: ...

    async def lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult: ...


@dataclass(frozen=True)
class CacheStats:
    """A point-in-time snapshot of cache activity."""

    hits: int
    misses: int
    joined: int  # lookups that shared an in-flight query instead of starting one
    evictions: int
    size: int
    max_entries: int
    ttl_seconds: float

    @property
    def hit_rate(self) -> float:
        """Fraction of requests answered without a new provider query (0.0 to 1.0)."""
        total = self.hits + self.joined + self.misses
        return (self.hits + self.joined) / total if total else 0.0


class IntelCache:
    """Async TTL cache with single-flight lookups."""

    def __init__(
        self,
        ttl_seconds: float = 3600.0,
        max_entries: int = 10_000,
        *,
        clock: Clock = time.monotonic,
    ) -> None:
        """Create a cache.

        Args:
            ttl_seconds: How long a result stays valid. ``0`` (or less) disables
                storage; single-flight still applies.
            max_entries: Maximum stored results (at least 1).
            clock: Monotonic clock (injectable for tests).
        """
        self._ttl = max(0.0, float(ttl_seconds))
        self._max = max(1, int(max_entries))
        self._clock = clock
        self._entries: OrderedDict[CacheKey, tuple[float, IntelResult]] = OrderedDict()
        self._inflight: dict[CacheKey, asyncio.Future[IntelResult | None]] = {}
        self._hits = 0
        self._misses = 0
        self._joined = 0
        self._evictions = 0

    @classmethod
    def from_settings(cls, settings: Settings) -> "IntelCache":
        """Build a cache from ``cache_ttl_seconds`` and ``cache_max_entries``."""
        return cls(settings.cache_ttl_seconds, settings.cache_max_entries)

    # ----------------------------------------------------------------- keys
    @staticmethod
    def make_key(provider: str, indicator_type: IOCType, indicator: str) -> CacheKey:
        """Build the canonical key for a lookup."""
        value = indicator.strip()
        if indicator_type in _CASE_INSENSITIVE:
            value = value.lower()
        return (provider.strip().lower(), indicator_type.value, value)

    # ------------------------------------------------------------- internals
    def _purge_expired(self) -> None:
        """Drop expired entries from the front (oldest first)."""
        now = self._clock()
        while self._entries:
            key = next(iter(self._entries))
            if self._entries[key][0] > now:
                break
            del self._entries[key]

    def _cached(self, key: CacheKey) -> IntelResult | None:
        self._purge_expired()
        entry = self._entries.get(key)
        if entry is None:
            return None
        self._hits += 1
        return entry[1].model_copy(update={"from_cache": True})

    def _store(self, key: CacheKey, result: IntelResult) -> None:
        if self._ttl <= 0 or result.verdict not in _CACHEABLE:
            return
        self._purge_expired()
        self._entries.pop(key, None)  # re-insert at the end to keep expiry order
        self._entries[key] = (
            self._clock() + self._ttl,
            result.model_copy(update={"from_cache": False}),
        )
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
            self._evictions += 1

    async def _lead(self, key: CacheKey, fetch: Fetcher) -> IntelResult:
        """Run ``fetch`` as the single in-flight lookup for ``key``."""
        future: asyncio.Future[IntelResult | None] = asyncio.get_running_loop().create_future()
        self._inflight[key] = future
        self._misses += 1
        result: IntelResult | None = None
        try:
            result = await fetch()
            self._store(key, result)
            return result.model_copy()
        finally:
            if self._inflight.get(key) is future:
                del self._inflight[key]
            if not future.done():
                future.set_result(result)  # None on failure/cancel: waiters retry

    # ------------------------------------------------------------ public API
    def get(self, provider: str, indicator_type: IOCType, indicator: str) -> IntelResult | None:
        """Return a fresh cached result (``from_cache=True``) or ``None``."""
        return self._cached(self.make_key(provider, indicator_type, indicator))

    def put(self, result: IntelResult) -> None:
        """Store ``result`` if it is a definitive verdict."""
        self._store(self.make_key(result.provider, result.indicator_type, result.indicator), result)

    async def get_or_fetch(
        self,
        provider: str,
        indicator_type: IOCType,
        indicator: str,
        fetch: Fetcher,
    ) -> IntelResult:
        """Return a cached result, join an in-flight lookup, or run ``fetch``.

        Args:
            provider: Provider name (part of the key).
            indicator_type: Kind of indicator.
            indicator: The refanged, live indicator value.
            fetch: Zero-argument coroutine function that performs the lookup.
                Exceptions it raises propagate to the *leading* caller only.
        """
        key = self.make_key(provider, indicator_type, indicator)
        for _ in range(_MAX_FOLLOW_ATTEMPTS):
            hit = self._cached(key)
            if hit is not None:
                return hit
            pending = self._inflight.get(key)
            if pending is None:
                return await self._lead(key, fetch)
            self._joined += 1
            # shield: cancelling this waiter must not cancel the shared lookup
            shared = await asyncio.shield(pending)
            if shared is not None:
                return shared.model_copy()
        logger.debug("In-flight lookup failed repeatedly for %s; querying directly", key[0])
        return await fetch()

    async def lookup(
        self, provider: _Lookupable, indicator: str, indicator_type: IOCType
    ) -> IntelResult:
        """Cached, de-duplicated ``provider.lookup(...)``."""
        return await self.get_or_fetch(
            provider.name,
            indicator_type,
            indicator,
            lambda: provider.lookup(indicator, indicator_type),
        )

    # ------------------------------------------------------------ management
    def clear(self) -> None:
        """Remove all stored results (in-flight lookups are unaffected)."""
        self._entries.clear()

    def __len__(self) -> int:
        self._purge_expired()
        return len(self._entries)

    def stats(self) -> CacheStats:
        """Return a snapshot of hit/miss/eviction counters."""
        return CacheStats(
            hits=self._hits,
            misses=self._misses,
            joined=self._joined,
            evictions=self._evictions,
            size=len(self),
            max_entries=self._max,
            ttl_seconds=self._ttl,
        )
