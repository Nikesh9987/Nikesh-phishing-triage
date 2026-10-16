"""Async token-bucket rate limiter for threat-intel providers.

How it works:

* The bucket holds up to ``burst`` tokens and refills continuously at
  ``requests_per_minute / 60`` tokens per second.
* :meth:`AsyncRateLimiter.acquire` *reserves* a token immediately (the balance
  may go negative) and then sleeps until that reservation matures. Because
  the reservation is made synchronously, with no ``await`` between reading and
  updating the balance, concurrent tasks are spaced out fairly and no lock is
  needed. The limiter is also not bound to an event loop, so it survives
  repeated ``asyncio.run()`` calls (CLI, tests).
* If the wait would exceed the wait budget, :class:`IntelRateLimitError` is raised
  *immediately* instead of stalling a triage for minutes. The aggregator turns
  that into an ``ERROR`` verdict for that indicator.
* :meth:`AsyncRateLimiter.defer` lets the HTTP layer apply a server-sent
  ``Retry-After`` so every later request is spaced accordingly.

Burst note: with the default burst, the worst case in any 60 s window is
``requests_per_minute + burst`` requests. The default ``burst`` is
``max(1, rpm // 6)``, which is 1 for the VirusTotal free tier (4/min), so that
tier is never exceeded.

Not thread-safe: use one instance per event loop / thread.
"""

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from typing import Final

from phishtriage.core.exceptions import IntelRateLimitError

__all__ = ["AsyncRateLimiter"]

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]

_DEFAULT_MAX_WAIT: Final = 30.0


class AsyncRateLimiter:
    """Token bucket with reservation-based fairness."""

    def __init__(
        self,
        requests_per_minute: float,
        *,
        burst: int | None = None,
        max_wait_seconds: float = _DEFAULT_MAX_WAIT,
        name: str = "",
        clock: Clock = time.monotonic,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        """Create a limiter.

        Args:
            requests_per_minute: Sustained rate. Must be positive and finite.
            burst: Bucket capacity (requests allowed back-to-back). Defaults to
                ``max(1, requests_per_minute // 6)``.
            max_wait_seconds: Default longest time :meth:`acquire` may sleep.
            name: Provider name used in errors.
            clock: Monotonic clock (injectable for tests).
            sleep: Async sleep function (injectable for tests).

        Raises:
            ValueError: A numeric argument is out of range.
        """
        if not math.isfinite(requests_per_minute) or requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be a positive, finite number")
        if not math.isfinite(max_wait_seconds) or max_wait_seconds < 0:
            raise ValueError("max_wait_seconds must be a non-negative, finite number")
        capacity = max(1, int(requests_per_minute // 6)) if burst is None else burst
        if capacity < 1:
            raise ValueError("burst must be at least 1")

        self.name = name
        self._rate = requests_per_minute / 60.0  # tokens per second
        self._capacity = float(capacity)
        self._max_wait = max_wait_seconds
        self._clock = clock
        self._sleep = sleep
        self._tokens = self._capacity
        self._updated = clock()

    # ------------------------------------------------------------------ properties
    @property
    def requests_per_minute(self) -> float:
        """The sustained rate this limiter enforces."""
        return self._rate * 60.0

    @property
    def available(self) -> float:
        """Tokens currently available (negative when requests are queued)."""
        self._refill()
        return self._tokens

    # --------------------------------------------------------------------- internals
    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._updated = now

    def _wait_for_next(self) -> float:
        """Seconds until one more token is available (0 if one is available now)."""
        return max(0.0, (1.0 - self._tokens) / self._rate)

    # -------------------------------------------------------------------- public API
    def try_acquire(self) -> bool:
        """Take a token without waiting. Returns ``False`` if none is available."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    async def acquire(self, *, max_wait: float | None = None) -> float:
        """Wait for a token and consume it.

        Args:
            max_wait: Override the wait budget (seconds) for this call.

        Returns:
            Seconds actually waited.

        Raises:
            IntelRateLimitError: the wait would exceed the budget. Nothing is
                consumed in that case.
        """
        self._refill()
        wait = self._wait_for_next()
        limit = self._max_wait if max_wait is None else max(0.0, max_wait)
        if wait > limit:
            raise IntelRateLimitError(
                f"{self.name or 'Provider'} rate limit: the next free slot is "
                f"{wait:.1f}s away, over the {limit:.0f}s wait budget.",
                provider=self.name or "unknown",
                retry_after=wait,
            )
        self._tokens -= 1.0  # reserve now; the balance may go negative
        if wait > 0:
            try:
                await self._sleep(wait)
            except asyncio.CancelledError:
                self._tokens = min(self._capacity, self._tokens + 1.0)  # give it back
                raise
        return wait

    def defer(self, seconds: float) -> None:
        """Make the next request wait at least ``seconds`` (e.g. a ``Retry-After``).

        Safe to call repeatedly: the penalty does not compound, and it never
        *shortens* an existing wait.
        """
        if not math.isfinite(seconds) or seconds <= 0:
            return
        self._refill()
        self._tokens = min(self._tokens, 1.0 - seconds * self._rate)
