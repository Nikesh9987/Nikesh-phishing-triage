"""Tests for the threat-intel layer: limiter, cache, HTTP client, providers, aggregator.

No test uses the network. HTTP is mocked with ``httpx.MockTransport``, DNS with a
fake resolver, and time with a fake clock.
"""

import asyncio
import types
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any
from urllib.parse import parse_qs

import dns.exception
import dns.resolver
import httpx
import pytest

from phishtriage.config import Settings
from phishtriage.core.exceptions import (
    IntelAuthError,
    IntelProviderError,
    IntelRateLimitError,
    IntelTimeoutError,
    IntelUnavailableError,
)
from phishtriage.core.models import (
    IOC,
    Attachment,
    IntelResult,
    IntelVerdict,
    IOCType,
)
from phishtriage.intel.abuseipdb import AbuseIPDBProvider
from phishtriage.intel.aggregator import IntelAggregator, default_budgets, worst_verdict
from phishtriage.intel.base import (
    IntelHttpClient,
    IntelProvider,
    expect_mapping,
    parse_retry_after,
)
from phishtriage.intel.cache import IntelCache
from phishtriage.intel.dnsbl import DNSBLProvider, _interpret
from phishtriage.intel.rate_limiter import AsyncRateLimiter
from phishtriage.intel.urlhaus import URLhausProvider
from phishtriage.intel.virustotal import VirusTotalProvider, _url_id

V = IntelVerdict


class FakeClock:
    """Monotonic clock whose ``sleep`` advances time instead of waiting."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 3))
        self.now += seconds


def result(
    indicator: str = "198.51.100.1",
    verdict: IntelVerdict = V.CLEAN,
    *,
    provider: str = "p",
    ioc_type: IOCType = IOCType.IPV4,
) -> IntelResult:
    return IntelResult(provider=provider, indicator=indicator, indicator_type=ioc_type, verdict=verdict)


def wire(provider: Any, handler: Any) -> Any:
    """Give ``provider`` a mock transport but keep its real default headers (API key)."""
    provider._http = IntelHttpClient(
        provider=provider.name,
        max_retries=0,
        headers=provider._default_headers(),
        transport=httpx.MockTransport(handler),
    )
    return provider


# ================================================================ rate limiter
class TestRateLimiter:
    async def test_first_request_is_immediate_then_spaced(self) -> None:
        clock = FakeClock()
        limiter = AsyncRateLimiter(4, burst=1, max_wait_seconds=20, clock=clock, sleep=clock.sleep)
        for _ in range(3):
            await limiter.acquire()
        assert clock.slept == [15.0, 15.0]

    async def test_burst_allows_back_to_back_requests(self) -> None:
        clock = FakeClock()
        limiter = AsyncRateLimiter(60, burst=3, clock=clock, sleep=clock.sleep)
        for _ in range(3):
            await limiter.acquire()
        assert clock.slept == []
        await limiter.acquire()
        assert clock.slept == [1.0]

    def test_default_burst_is_a_sixth_of_the_rate_and_at_least_one(self) -> None:
        assert AsyncRateLimiter(60).available == pytest.approx(10)
        assert AsyncRateLimiter(4).available == pytest.approx(1)

    async def test_over_budget_fails_fast_and_consumes_nothing(self) -> None:
        clock = FakeClock()
        limiter = AsyncRateLimiter(4, burst=1, max_wait_seconds=5, clock=clock, sleep=clock.sleep)
        await limiter.acquire()
        with pytest.raises(IntelRateLimitError) as info:
            await limiter.acquire()
        assert info.value.http_status == 429
        assert info.value.retry_after == pytest.approx(15, abs=0.01)
        assert clock.slept == []
        await limiter.acquire(max_wait=20)  # a larger budget for one call works
        assert clock.slept == [15.0]

    async def test_defer_applies_a_server_retry_after(self) -> None:
        clock = FakeClock()
        limiter = AsyncRateLimiter(60, burst=1, max_wait_seconds=10, clock=clock, sleep=clock.sleep)
        limiter.defer(30)
        with pytest.raises(IntelRateLimitError) as info:
            await limiter.acquire()
        assert info.value.retry_after == pytest.approx(30, abs=0.01)

    def test_defer_ignores_nonsense(self) -> None:
        limiter = AsyncRateLimiter(60)
        for value in (0, -5, float("nan"), float("inf")):
            limiter.defer(value)
        assert limiter.try_acquire()

    def test_try_acquire_never_waits(self) -> None:
        clock = FakeClock()
        limiter = AsyncRateLimiter(60, burst=2, clock=clock)
        assert [limiter.try_acquire() for _ in range(3)] == [True, True, False]
        clock.now += 1.0
        assert limiter.try_acquire()

    async def test_cancelled_waiter_gives_its_token_back(self) -> None:
        async def cancelled(_: float) -> None:
            raise asyncio.CancelledError

        clock = FakeClock()
        limiter = AsyncRateLimiter(4, burst=1, clock=clock, sleep=cancelled)
        await limiter.acquire()
        with pytest.raises(asyncio.CancelledError):
            await limiter.acquire()
        assert limiter.available == pytest.approx(0, abs=1e-6)

    @pytest.mark.parametrize("rpm", [0, -1, float("inf"), float("nan")])
    def test_invalid_rate_is_rejected(self, rpm: float) -> None:
        with pytest.raises(ValueError):
            AsyncRateLimiter(rpm)

    def test_invalid_burst_and_wait_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            AsyncRateLimiter(10, burst=0)
        with pytest.raises(ValueError):
            AsyncRateLimiter(10, max_wait_seconds=-1)


# ==================================================================== helpers
class TestHelpers:
    def test_parse_retry_after_seconds(self) -> None:
        values = ("30", "0", "abc", None, "", "nan", "-5")
        assert [parse_retry_after(v) for v in values] == [30.0, 0.0, None, None, None, None, 0.0]

    def test_parse_retry_after_http_date(self) -> None:
        future = format_datetime(datetime.now(UTC) + timedelta(seconds=100), usegmt=True)
        assert 90 < (parse_retry_after(future) or 0) <= 100
        assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0

    def test_expect_mapping(self) -> None:
        assert expect_mapping({"a": 1}, provider="p") == {"a": 1}
        with pytest.raises(IntelProviderError):
            expect_mapping([1], provider="p")


# ================================================================== HTTP client
def make_client(handler: Any, *, retries: int = 2, **kwargs: Any) -> tuple[IntelHttpClient, list[float]]:
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    client = IntelHttpClient(
        provider="demo",
        timeout=2,
        max_retries=retries,
        transport=httpx.MockTransport(handler),
        sleep=sleep,
        **kwargs,
    )
    return client, sleeps


class TestHttpClient:
    async def test_success(self) -> None:
        client, _ = make_client(lambda r: httpx.Response(200, json={"ok": True}))
        async with client:
            response = await client.request_json("GET", "https://api.demo.example/x")
        assert (response.status, response.data) == (200, {"ok": True})

    async def test_empty_success_body_is_none(self) -> None:
        client, _ = make_client(lambda r: httpx.Response(204))
        async with client:
            assert (await client.request_json("GET", "https://api.demo.example/x")).data is None

    async def test_allowed_status_is_returned_and_others_raise(self) -> None:
        client, _ = make_client(lambda r: httpx.Response(404))
        async with client:
            assert (await client.request_json("GET", "https://a.example/x", allow_statuses={404})).status == 404
            with pytest.raises(IntelProviderError, match="HTTP 404"):
                await client.request_json("GET", "https://a.example/x")

    @pytest.mark.parametrize("status", [401, 403])
    async def test_auth_errors(self, status: int) -> None:
        client, _ = make_client(lambda r: httpx.Response(status))
        async with client:
            with pytest.raises(IntelAuthError):
                await client.request_json("GET", "https://a.example/x")

    async def test_server_errors_are_retried_with_growing_backoff(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(503) if calls["n"] < 3 else httpx.Response(200, json={"ok": 1})

        client, sleeps = make_client(handler)
        async with client:
            response = await client.request_json("GET", "https://a.example/x")
        assert response.status == 200 and calls["n"] == 3
        assert len(sleeps) == 2 and sleeps[0] < sleeps[1]

    async def test_persistent_server_error_gives_up(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(500)

        client, _ = make_client(handler, retries=1)
        async with client:
            with pytest.raises(IntelUnavailableError):
                await client.request_json("GET", "https://a.example/x")
        assert calls["n"] == 2

    async def test_connection_error_and_timeout_are_mapped(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        def stall(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow", request=request)

        client, _ = make_client(refuse, retries=0)
        async with client:
            with pytest.raises(IntelUnavailableError, match="ConnectError"):
                await client.request_json("GET", "https://a.example/x")
        client, _ = make_client(stall, retries=0)
        async with client:
            with pytest.raises(IntelTimeoutError):
                await client.request_json("GET", "https://a.example/x")

    async def test_429_with_long_retry_after_fails_fast(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(429, headers={"Retry-After": "120"})

        client, sleeps = make_client(handler)
        async with client:
            with pytest.raises(IntelRateLimitError) as info:
                await client.request_json("GET", "https://a.example/x")
        assert info.value.retry_after == 120 and calls["n"] == 1 and sleeps == []

    async def test_429_with_short_retry_after_waits_and_retries(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "1"})
            return httpx.Response(200, json={})

        client, sleeps = make_client(handler)
        async with client:
            assert (await client.request_json("GET", "https://a.example/x")).status == 200
        assert sleeps == [1.0]

    async def test_invalid_json_and_oversized_responses(self) -> None:
        client, _ = make_client(lambda r: httpx.Response(200, content=b"<html>nope</html>"))
        async with client:
            with pytest.raises(IntelProviderError, match="invalid JSON"):
                await client.request_json("GET", "https://a.example/x")
        client, _ = make_client(lambda r: httpx.Response(200, content=b"{" + b"a" * 5000), max_response_bytes=1024)
        async with client:
            with pytest.raises(IntelProviderError, match="exceeded"):
                await client.request_json("GET", "https://a.example/x")

    async def test_redirects_are_not_followed(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

        client, _ = make_client(handler, retries=0)
        async with client:
            with pytest.raises(IntelProviderError, match="HTTP 302"):
                await client.request_json("GET", "https://a.example/x")
        assert calls["n"] == 1

    async def test_secrets_are_sent_but_never_leak_into_messages(self) -> None:
        seen: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("x-apikey"))
            return httpx.Response(503)

        client, _ = make_client(handler, retries=0, headers={"x-apikey": "SECRET123"})
        assert "SECRET123" not in repr(client)
        async with client:
            with pytest.raises(IntelUnavailableError) as info:
                await client.request_json("GET", "https://a.example/x?key=SECRET123")
        assert seen == ["SECRET123"]
        assert "SECRET123" not in info.value.message

    async def test_the_limiter_is_applied(self) -> None:
        clock = FakeClock()
        limiter = AsyncRateLimiter(1, burst=1, max_wait_seconds=0, clock=clock, sleep=clock.sleep)
        client, _ = make_client(lambda r: httpx.Response(200, json={}), limiter=limiter)
        async with client:
            await client.request_json("GET", "https://a.example/x")
            with pytest.raises(IntelRateLimitError):
                await client.request_json("GET", "https://a.example/x")


# ============================================================= provider contract
class Boom(IntelProvider):
    name = "boom"
    supported_types = frozenset({IOCType.IPV4})
    mode = "crash"

    def _requests_per_minute(self) -> float:
        return 60.0

    async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
        if self.mode == "crash":
            raise RuntimeError("secret internals")
        if self.mode == "limit":
            raise IntelRateLimitError("slow down", provider="boom", retry_after=30)
        if self.mode == "provider":
            raise IntelProviderError("upstream said no", provider="boom")
        return self._result(indicator, indicator_type, V.MALICIOUS, score=250, detail="x" * 2000)


class TestProviderContract:
    async def test_unsupported_type_is_skipped(self, fake_provider: Any) -> None:
        provider = fake_provider("abuseipdb", [IOCType.IPV4])
        outcome = await provider.lookup("http://x.example", IOCType.URL)
        assert outcome.verdict is V.SKIPPED and "does not support" in outcome.detail

    async def test_disabled_provider_is_skipped_without_a_query(self, fake_provider: Any) -> None:
        provider = fake_provider("abuseipdb", [IOCType.IPV4], enabled=False)
        outcome = await provider.lookup("198.51.100.1", IOCType.IPV4)
        assert outcome.verdict is V.SKIPPED and "no key" in outcome.detail
        assert provider.calls == []

    @pytest.mark.parametrize("value", ["bad value", "a\x00b", "", "9" * 3000])
    async def test_malformed_indicators_are_errors_not_queries(self, fake_provider: Any, value: str) -> None:
        provider = fake_provider("abuseipdb", [IOCType.IPV4])
        assert (await provider.lookup(value, IOCType.IPV4)).verdict is V.ERROR
        assert provider.calls == []

    async def test_normal_lookup(self, fake_provider: Any) -> None:
        provider = fake_provider("abuseipdb", [IOCType.IPV4], V.MALICIOUS)
        outcome = await provider.lookup(" 198.51.100.1 ", IOCType.IPV4)
        assert (outcome.verdict, outcome.indicator, outcome.score) == (V.MALICIOUS, "198.51.100.1", 90)

    async def test_lookup_never_raises(self) -> None:
        provider = Boom(Settings())
        crashed = await provider.lookup("198.51.100.1", IOCType.IPV4)
        assert crashed.verdict is V.ERROR and "secret internals" not in crashed.detail

        provider.mode = "limit"
        limited = await provider.lookup("198.51.100.1", IOCType.IPV4)
        assert limited.verdict is V.ERROR and "30s" in limited.detail

        provider.mode = "provider"
        assert "upstream said no" in (await provider.lookup("198.51.100.1", IOCType.IPV4)).detail

    async def test_results_are_clamped_and_bounded(self) -> None:
        provider = Boom(Settings())
        provider.mode = "ok"
        outcome = await provider.lookup("198.51.100.1", IOCType.IPV4)
        assert outcome.score == 100 and len(outcome.detail) == 500

    def test_offline_mode_disables_every_provider(self) -> None:
        provider = Boom(Settings(offline=True))
        assert provider.disabled_reason() == "offline mode"
        status = provider.status()
        assert (status.enabled, status.reason) == (False, "offline mode")


# ====================================================================== cache
class TestCache:
    async def test_single_flight_runs_one_query_for_concurrent_callers(self) -> None:
        cache = IntelCache(ttl_seconds=60)
        calls = {"n": 0}

        async def fetch() -> IntelResult:
            calls["n"] += 1
            await asyncio.sleep(0.05)
            return result()

        out = await asyncio.gather(*[cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch) for _ in range(10)])
        assert calls["n"] == 1 and len(out) == 10
        assert cache.stats().joined == 9

    async def test_hit_and_ttl_expiry(self) -> None:
        now = [0.0]
        cache = IntelCache(ttl_seconds=60, clock=lambda: now[0])
        calls = {"n": 0}

        async def fetch() -> IntelResult:
            calls["n"] += 1
            return result()

        first = await cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch)
        now[0] = 59.0
        second = await cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch)
        assert (first.from_cache, second.from_cache, calls["n"]) == (False, True, 1)
        now[0] = 61.0
        third = await cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch)
        assert (third.from_cache, calls["n"]) == (False, 2)

    @pytest.mark.parametrize("verdict", [V.ERROR, V.SKIPPED])
    async def test_errors_and_skips_are_never_cached(self, verdict: IntelVerdict) -> None:
        cache = IntelCache(ttl_seconds=60)
        calls = {"n": 0}

        async def fetch() -> IntelResult:
            calls["n"] += 1
            return result(verdict=verdict)

        for _ in range(3):
            await cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch)
        assert calls["n"] == 3 and len(cache) == 0

    @pytest.mark.parametrize("verdict", [V.MALICIOUS, V.SUSPICIOUS, V.CLEAN, V.UNKNOWN])
    def test_definitive_verdicts_are_cached(self, verdict: IntelVerdict) -> None:
        cache = IntelCache(ttl_seconds=60)
        cache.put(result(verdict=verdict))
        assert cache.get("p", IOCType.IPV4, "198.51.100.1") is not None

    def test_size_cap_evicts_oldest_first(self) -> None:
        cache = IntelCache(ttl_seconds=60, max_entries=3)
        for i in range(10, 15):
            cache.put(result(f"198.51.100.{i}"))
        assert len(cache) == 3 and cache.stats().evictions == 2
        assert cache.get("p", IOCType.IPV4, "198.51.100.10") is None
        assert cache.get("p", IOCType.IPV4, "198.51.100.14") is not None

    def test_key_normalisation(self) -> None:
        assert IntelCache.make_key("VT", IOCType.HASH, " ABCD ") == ("vt", "hash", "abcd")
        assert IntelCache.make_key("VT", IOCType.URL, "http://x.example/Aa")[2] == "http://x.example/Aa"

    async def test_failed_leader_makes_the_waiter_retry(self) -> None:
        cache = IntelCache(ttl_seconds=60)
        state = {"n": 0}

        async def flaky() -> IntelResult:
            state["n"] += 1
            await asyncio.sleep(0.05)
            if state["n"] == 1:
                raise RuntimeError("boom")
            return result()

        leader = asyncio.create_task(cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", flaky))
        await asyncio.sleep(0)
        waiter = asyncio.create_task(cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", flaky))
        outcomes = await asyncio.gather(leader, waiter, return_exceptions=True)
        assert isinstance(outcomes[0], RuntimeError) and isinstance(outcomes[1], IntelResult)
        assert state["n"] == 2

    async def test_cancelling_a_waiter_does_not_cancel_the_shared_lookup(self) -> None:
        cache = IntelCache(ttl_seconds=60)

        async def slow() -> IntelResult:
            await asyncio.sleep(0.1)
            return result(verdict=V.MALICIOUS)

        leader = asyncio.create_task(cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", slow))
        await asyncio.sleep(0)
        waiter = asyncio.create_task(cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", slow))
        await asyncio.sleep(0)
        waiter.cancel()
        outcomes = await asyncio.gather(leader, waiter, return_exceptions=True)
        assert outcomes[0].verdict is V.MALICIOUS
        assert isinstance(outcomes[1], asyncio.CancelledError)

    async def test_callers_get_isolated_copies(self) -> None:
        cache = IntelCache(ttl_seconds=60)

        async def fetch() -> IntelResult:
            return result()

        first = await cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch)
        first.detail = "mutated"
        second = await cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch)
        assert second.detail == ""

    async def test_zero_ttl_stores_nothing_but_still_deduplicates(self) -> None:
        cache = IntelCache(ttl_seconds=0)
        calls = {"n": 0}

        async def fetch() -> IntelResult:
            calls["n"] += 1
            await asyncio.sleep(0.02)
            return result()

        await asyncio.gather(*[cache.get_or_fetch("p", IOCType.IPV4, "198.51.100.1", fetch) for _ in range(5)])
        assert calls["n"] == 1 and len(cache) == 0


# ================================================================== URLhaus
def urlhaus_handler(seen: list[tuple[str, str | None, dict[str, str]]]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        seen.append((request.url.path, request.headers.get("auth-key"), form))
        path = request.url.path
        if path == "/v1/url/":
            if "evil.example/a.exe" in form["url"]:
                return httpx.Response(200, json={
                    "query_status": "ok", "url_status": "online", "threat": "malware_download",
                    "tags": ["exe", "Emotet"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
                    "blacklists": {"spamhaus_dbl": "malware_domain", "surbl": "not listed"}})
            if "gone.example" in form["url"]:
                return httpx.Response(200, json={
                    "query_status": "ok", "url_status": "offline",
                    "urlhaus_reference": "https://attacker.example/phish"})
            if "weird.example" in form["url"]:
                return httpx.Response(200, json={"query_status": "something_new"})
            return httpx.Response(200, json={"query_status": "no_results"})
        if path == "/v1/host/":
            urls = {
                "evil.example": [{"url_status": "online"}, {"url_status": "offline"}],
                "old.example": [{"url_status": "offline"}, {"url_status": "offline"}],
            }.get(form["host"])
            if urls is None:
                return httpx.Response(200, json={"query_status": "no_results"})
            return httpx.Response(200, json={"query_status": "ok", "url_count": str(len(urls)), "urls": urls})
        if path == "/v1/payload/":
            if form.get("sha256_hash", "").startswith("aa"):
                return httpx.Response(200, json={
                    "query_status": "ok", "signature": "Emotet\x00", "file_type": "exe", "url_count": "7"})
            if "md5_hash" in form:
                return httpx.Response(200, json={"query_status": "invalid_hash"})
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(404)

    return handler


class TestUrlhaus:
    @pytest.fixture
    def setup(self) -> tuple[URLhausProvider, list[Any]]:
        seen: list[Any] = []
        provider = wire(URLhausProvider(Settings(urlhaus_auth_key="test-key-123")), urlhaus_handler(seen))
        return provider, seen

    async def test_online_url_is_malicious_with_details(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("http://evil.example/a.exe", IOCType.URL)
        assert (r.verdict, r.score) == (V.MALICIOUS, 95)
        assert "Emotet" in r.detail and "spamhaus_dbl" in r.detail and "surbl" not in r.detail
        assert r.reference_url == "https://urlhaus.abuse.ch/url/1/"

    async def test_offline_url_is_softer_and_foreign_links_are_dropped(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("http://gone.example/x", IOCType.URL)
        assert (r.verdict, r.score, r.reference_url) == (V.MALICIOUS, 75, "")
        assert "distributed malware" in r.detail

    async def test_unlisted_is_unknown_never_clean(self, setup: Any) -> None:
        provider, _ = setup
        assert (await provider.lookup("http://clean.example/", IOCType.URL)).verdict is V.UNKNOWN
        assert (await provider.lookup("fresh.example", IOCType.DOMAIN)).verdict is V.UNKNOWN

    async def test_hosts(self, setup: Any) -> None:
        provider, _ = setup
        online = await provider.lookup("evil.example", IOCType.DOMAIN)
        assert (online.verdict, online.score) == (V.MALICIOUS, 90)
        past = await provider.lookup("old.example", IOCType.DOMAIN)
        assert (past.verdict, past.score) == (V.SUSPICIOUS, 55)

    async def test_hashes(self, setup: Any) -> None:
        provider, _ = setup
        hit = await provider.lookup("aa" * 32, IOCType.HASH)
        assert (hit.verdict, hit.score) == (V.MALICIOUS, 100)
        assert "Emotet" in hit.detail and "\x00" not in hit.detail
        assert (await provider.lookup("bb" * 32, IOCType.HASH)).verdict is V.UNKNOWN
        assert (await provider.lookup("cc" * 16, IOCType.HASH)).verdict is V.ERROR  # invalid_hash

    async def test_internal_and_unsupported_indicators_never_leave_the_machine(self, setup: Any) -> None:
        provider, seen = setup
        for value, kind in [
            ("http://10.0.0.5/x", IOCType.URL),
            ("203.0.113.9", IOCType.IPV4),
            ("intranet", IOCType.DOMAIN),
            ("dd" * 20, IOCType.HASH),  # SHA-1 is unsupported
        ]:
            assert (await provider.lookup(value, kind)).verdict is V.SKIPPED
        assert seen == []

    async def test_unexpected_status_is_an_error(self, setup: Any) -> None:
        provider, _ = setup
        assert (await provider.lookup("http://weird.example/", IOCType.URL)).verdict is V.ERROR

    async def test_the_key_is_sent_in_a_header_only(self, setup: Any) -> None:
        provider, seen = setup
        await provider.lookup("http://clean.example/", IOCType.URL)
        assert seen[0][1] == "test-key-123"
        assert "test-key-123" not in str(seen[0][2])

    async def test_without_a_key_it_is_disabled(self) -> None:
        provider = URLhausProvider(Settings())
        r = await provider.lookup("evil.example", IOCType.DOMAIN)
        assert r.verdict is V.SKIPPED and "URLHAUS_AUTH_KEY" in r.detail


# ================================================================= AbuseIPDB
def abuse_handler(seen: list[tuple[str | None, str, str]]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        ip = request.url.params["ipAddress"]
        seen.append((request.headers.get("key"), ip, request.url.params["maxAgeInDays"]))

        def data(**fields: Any) -> httpx.Response:
            base = {"abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0,
                    "isWhitelisted": False, "isTor": False}
            return httpx.Response(200, json={"data": {**base, **fields}})

        return {
            "185.220.101.5": lambda: data(abuseConfidenceScore=100, totalReports=143, numDistinctUsers=52,
                                          isp="Evil\u202eHosting", countryCode="DE", isTor=True),
            "9.9.9.9": lambda: data(abuseConfidenceScore=40, totalReports=6, numDistinctUsers=3),
            "8.8.4.4": lambda: data(abuseConfidenceScore=3, totalReports=2, numDistinctUsers=2),
            "1.1.1.1": lambda: data(isWhitelisted=True, totalReports=12),
            "9.9.9.10": lambda: data(),
            "8.8.8.8": lambda: httpx.Response(429, headers={"Retry-After": "3600"}),
            "2606:4700::1111": lambda: httpx.Response(422, json={"errors": []}),
        }.get(ip, lambda: httpx.Response(500))()

    return handler


class TestAbuseIpdb:
    @pytest.fixture
    def setup(self) -> tuple[AbuseIPDBProvider, list[Any]]:
        seen: list[Any] = []
        provider = wire(AbuseIPDBProvider(Settings(abuseipdb_api_key="abuse-key-456")), abuse_handler(seen))
        return provider, seen

    @pytest.mark.parametrize(
        ("ip", "verdict", "score"),
        [
            ("185.220.101.5", V.MALICIOUS, 100),
            ("9.9.9.9", V.SUSPICIOUS, 40),
            ("8.8.4.4", V.CLEAN, 3),
            ("1.1.1.1", V.CLEAN, 0),  # whitelisted
            ("9.9.9.10", V.UNKNOWN, 0),  # no reports on file is not evidence of safety
        ],
    )
    async def test_verdict_mapping(self, setup: Any, ip: str, verdict: IntelVerdict, score: int) -> None:
        provider, _ = setup
        r = await provider.lookup(ip, IOCType.IPV4)
        assert (r.verdict, r.score) == (verdict, score)
        assert r.reference_url.endswith(ip)

    async def test_third_party_text_is_sanitised(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("185.220.101.5", IOCType.IPV4)
        assert "\u202e" not in r.detail and "Evil Hosting" in r.detail and "Tor exit node" in r.detail

    @pytest.mark.parametrize("ip", ["10.1.2.3", "203.0.113.5", "198.18.0.1", "127.0.0.1"])
    async def test_non_global_addresses_are_skipped_locally(self, setup: Any, ip: str) -> None:
        provider, seen = setup
        assert (await provider.lookup(ip, IOCType.IPV4)).verdict is V.SKIPPED
        assert seen == []

    async def test_non_global_ipv6_forms_are_skipped(self, setup: Any) -> None:
        provider, seen = setup
        for ip in ("fd00::1", "::ffff:10.0.0.1"):
            assert (await provider.lookup(ip, IOCType.IPV6)).verdict is V.SKIPPED
        assert seen == []

    async def test_quota_and_validation_errors(self, setup: Any) -> None:
        provider, _ = setup
        limited = await provider.lookup("8.8.8.8", IOCType.IPV4)
        assert limited.verdict is V.ERROR and "429" in limited.detail
        assert (await provider.lookup("2606:4700::1111", IOCType.IPV6)).verdict is V.ERROR

    async def test_key_header_and_window(self, setup: Any) -> None:
        provider, seen = setup
        await provider.lookup("9.9.9.9", IOCType.IPV4)
        assert seen == [("abuse-key-456", "9.9.9.9", "90")]

    async def test_without_a_key_it_is_disabled(self) -> None:
        r = await AbuseIPDBProvider(Settings()).lookup("185.220.101.5", IOCType.IPV4)
        assert r.verdict is V.SKIPPED and "ABUSEIPDB_API_KEY" in r.detail


# ================================================================ VirusTotal
def stats(mal: int = 0, sus: int = 0, harmless: int = 0, undetected: int = 0) -> dict[str, int]:
    return {"malicious": mal, "suspicious": sus, "harmless": harmless, "undetected": undetected}


def vt_handler(table: dict[str, Any], seen: list[tuple[str, str | None]]) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.headers.get("x-apikey")))
        for suffix, value in table.items():
            if request.url.path.endswith(suffix):
                if isinstance(value, int):
                    return httpx.Response(value)
                last_stats, attrs = value
                return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": last_stats, **attrs}}})
        return httpx.Response(500)

    return handler


def vt_provider(table: dict[str, Any]) -> tuple[VirusTotalProvider, list[Any]]:
    seen: list[Any] = []
    return wire(VirusTotalProvider(Settings(virustotal_api_key="vt-key-123")), vt_handler(table, seen)), seen


class TestVirusTotal:
    @pytest.mark.parametrize(
        ("counts", "verdict"),
        [
            (stats(45, 2, 0, 20), V.MALICIOUS),
            (stats(3, 0, 60, 10), V.MALICIOUS),
            (stats(2, 0, 60, 10), V.SUSPICIOUS),
            (stats(1, 0, 80, 5), V.SUSPICIOUS),  # a lone detection is often a false positive
            (stats(0, 2, 60, 10), V.SUSPICIOUS),
            (stats(0, 1, 60, 10), V.CLEAN),
            (stats(0, 0, 70, 15), V.CLEAN),
            (stats(0, 0, 0, 0), V.UNKNOWN),
        ],
    )
    async def test_verdict_and_score_are_consistent(self, counts: dict[str, int], verdict: IntelVerdict) -> None:
        provider, _ = vt_provider({"/domains/evil.example": (counts, {})})
        r = await provider.lookup("evil.example", IOCType.DOMAIN)
        assert r.verdict is verdict
        if verdict is V.MALICIOUS:
            assert r.score is not None and 70 <= r.score <= 100
        elif verdict is V.SUSPICIOUS:
            assert r.score is not None and 30 <= r.score < 100
        elif verdict is V.CLEAN:
            assert r.score == 0
        else:
            assert r.score is None

    async def test_hash_details_and_sanitising(self) -> None:
        digest = "aa" * 32
        provider, _ = vt_provider({f"/files/{digest}": (stats(45, 2, 0, 20), {
            "meaningful_name": "invoice\u202e.exe", "type_description": "Win32 EXE",
            "last_analysis_date": 1760000000,
            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"}})})
        r = await provider.lookup(digest, IOCType.HASH)
        assert "trojan.emotet" in r.detail and "45/67" in r.detail and "\u202e" not in r.detail
        assert r.reference_url == f"https://www.virustotal.com/gui/file/{digest}"

    async def test_url_is_looked_up_by_base64_id(self) -> None:
        url = "http://evil.example/a.exe"
        provider, seen = vt_provider({f"/urls/{_url_id(url)}": (stats(8, 0, 60, 20), {})})
        assert (await provider.lookup(url, IOCType.URL)).verdict is V.MALICIOUS
        assert "=" not in _url_id(url) and seen[0][0].endswith(_url_id(url))

    async def test_ip_lookup(self) -> None:
        provider, _ = vt_provider({"/ip_addresses/185.220.101.5": (stats(12, 0, 0, 70), {"as_owner": "Evil Hosting", "country": "DE"})})
        r = await provider.lookup("185.220.101.5", IOCType.IPV4)
        assert r.verdict is V.MALICIOUS and "Evil Hosting" in r.detail

    async def test_not_found_is_unknown(self) -> None:
        provider, _ = vt_provider({"/files/" + "bb" * 32: 404})
        r = await provider.lookup("bb" * 32, IOCType.HASH)
        assert r.verdict is V.UNKNOWN and "never analysed" in r.detail

    async def test_sha1_and_md5_are_accepted(self) -> None:
        provider, seen = vt_provider({"/files/" + "dd" * 20: 404, "/files/" + "ee" * 16: 404})
        await provider.lookup("dd" * 20, IOCType.HASH)
        await provider.lookup("ee" * 16, IOCType.HASH)
        assert len(seen) == 2

    async def test_local_skips_never_leave_the_machine(self) -> None:
        provider, seen = vt_provider({})
        for value, kind in [
            ("zz", IOCType.HASH),
            ("http://10.0.0.5/x", IOCType.URL),
            ("intranet.local", IOCType.DOMAIN),
            ("203.0.113.9", IOCType.IPV4),
            ("fd00::1", IOCType.IPV6),
        ]:
            assert (await provider.lookup(value, kind)).verdict is V.SKIPPED
        assert seen == []

    async def test_key_header(self) -> None:
        provider, seen = vt_provider({"/domains/evil.example": (stats(0, 0, 5, 5), {})})
        await provider.lookup("evil.example", IOCType.DOMAIN)
        assert seen[0][1] == "vt-key-123"

    async def test_without_a_key_it_is_disabled(self) -> None:
        r = await VirusTotalProvider(Settings()).lookup("9.9.9.9", IOCType.IPV4)
        assert r.verdict is V.SKIPPED and "VIRUSTOTAL_API_KEY" in r.detail


# ===================================================================== DNSBL
class FakeResolver:
    """``table`` maps a query name to a list of A answers, or to an exception class."""

    def __init__(self, table: dict[str, Any] | None = None) -> None:
        self.table = table or {}
        self.queries: list[str] = []

    async def resolve(self, name: str, rdtype: str) -> list[Any]:
        self.queries.append(name)
        value = self.table.get(name)
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, type) and issubclass(value, Exception):
            raise value()
        return [types.SimpleNamespace(address=a) for a in value]


TIMEOUT = dns.exception.Timeout


class TestDnsblCodes:
    @pytest.mark.parametrize(
        ("zone", "code", "kind", "verdict"),
        [
            ("zen.spamhaus.org", "127.0.0.2", "listed", V.MALICIOUS),
            ("zen.spamhaus.org", "127.0.0.4", "listed", V.MALICIOUS),
            ("zen.spamhaus.org", "127.0.0.3", "listed", V.SUSPICIOUS),
            ("zen.spamhaus.org", "127.0.0.10", "info", V.UNKNOWN),  # PBL is not abuse
            ("dbl.spamhaus.org", "127.0.1.4", "listed", V.MALICIOUS),
            ("dbl.spamhaus.org", "127.0.1.2", "listed", V.SUSPICIOUS),
            ("multi.uribl.com", "127.0.0.2", "listed", V.MALICIOUS),
            ("multi.uribl.com", "127.0.0.4", "listed", V.SUSPICIOUS),
            ("multi.uribl.com", "127.0.0.1", "blocked", V.UNKNOWN),
            ("bl.spamcop.net", "127.0.0.2", "listed", V.SUSPICIOUS),
            ("zen.spamhaus.org", "127.255.255.254", "blocked", V.UNKNOWN),
            ("zen.spamhaus.org", "93.184.216.34", "blocked", V.UNKNOWN),  # NXDOMAIN rewriting
            ("custom.example", "127.0.0.9", "listed", V.SUSPICIOUS),
        ],
    )
    def test_interpretation(self, zone: str, code: str, kind: str, verdict: IntelVerdict) -> None:
        hit = _interpret(zone, code)
        assert (hit.kind, hit.verdict) == (kind, verdict)


class TestDnsblProvider:
    TABLE: dict[str, Any] = {
        "5.101.220.185.zen.spamhaus.org": ["127.0.0.4", "127.0.0.11"],
        "5.101.220.185.dnsbl-1.uceprotect.net": TIMEOUT,
        "5.4.8.8.zen.spamhaus.org": ["127.255.255.254"],
        "7.7.7.7.zen.spamhaus.org": TIMEOUT,
        "7.7.7.7.bl.spamcop.net": TIMEOUT,
        "7.7.7.7.dnsbl-1.uceprotect.net": TIMEOUT,
        "6.6.6.6.bl.spamcop.net": ["127.0.0.2"],
        "6.6.6.6.dnsbl-1.uceprotect.net": ["127.0.0.2"],
        "evil-phish.com.dbl.spamhaus.org": ["127.0.1.4"],
        "evil-phish.com.multi.uribl.com": ["127.0.0.2"],
        "shared-host.net.multi.uribl.com": ["127.0.0.4"],
        "hijack.com.dbl.spamhaus.org": ["93.184.216.34"],
        "hijack.com.multi.uribl.com": ["93.184.216.34"],
    }

    @pytest.fixture
    def setup(self) -> tuple[DNSBLProvider, FakeResolver]:
        resolver = FakeResolver(self.TABLE)
        return DNSBLProvider(Settings(), resolver=resolver), resolver

    async def test_malware_listing_with_informational_pbl_and_a_timeout(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("185.220.101.5", IOCType.IPV4)
        assert (r.verdict, r.score) == (V.MALICIOUS, 85)
        assert "XBL" in r.detail and "PBL" in r.detail

    async def test_unlisted_is_unknown_never_clean(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("9.9.9.9", IOCType.IPV4)
        assert r.verdict is V.UNKNOWN and "Not listed on 3 of 3" in r.detail

    async def test_refused_queries_are_reported_not_trusted(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("8.8.4.5", IOCType.IPV4)  # reversed: 5.4.4.8
        assert r.verdict is V.UNKNOWN
        assert "Not listed on 2 of 3" in r.detail and "query refused" in r.detail

    async def test_everything_failing_is_an_error(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("7.7.7.7", IOCType.IPV4)
        assert r.verdict is V.ERROR and "No blocklist could answer" in r.detail

    async def test_extra_listings_raise_the_score(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("6.6.6.6", IOCType.IPV4)
        assert (r.verdict, r.score) == (V.SUSPICIOUS, 60)  # 55 + 5 for the second zone

    async def test_phishing_domain(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("evil-phish.com", IOCType.DOMAIN)
        assert (r.verdict, r.score) == (V.MALICIOUS, 100)

    async def test_subdomain_is_also_checked_at_its_registered_domain(self, setup: Any) -> None:
        provider, resolver = setup
        r = await provider.lookup("mail.shared-host.net", IOCType.DOMAIN)
        assert (r.verdict, r.score) == (V.SUSPICIOUS, 40)
        assert "shared-host.net.multi.uribl.com" in resolver.queries

    async def test_rewritten_answers_are_errors(self, setup: Any) -> None:
        provider, _ = setup
        r = await provider.lookup("hijack.com", IOCType.DOMAIN)
        assert r.verdict is V.ERROR and "NXDOMAIN" in r.detail

    async def test_ipv6_uses_nibble_format(self) -> None:
        resolver = FakeResolver()
        await DNSBLProvider(Settings(), resolver=resolver).lookup("2606:4700::1111", IOCType.IPV6)
        first = resolver.queries[0]
        assert first.startswith("1.1.1.1.0.0.0.0") and first.endswith(".zen.spamhaus.org")
        assert first.count(".") == 31 + 3  # 32 nibbles + the 3 labels of the zone

    async def test_internal_indicators_are_never_queried(self, setup: Any) -> None:
        provider, resolver = setup
        for value, kind in [("10.0.0.1", IOCType.IPV4), ("203.0.113.5", IOCType.IPV4),
                            ("intranet.local", IOCType.DOMAIN)]:
            assert (await provider.lookup(value, kind)).verdict is V.SKIPPED
        assert resolver.queries == []

    async def test_zone_configuration(self) -> None:
        resolver = FakeResolver()
        none = DNSBLProvider(Settings(dnsbl_ip_zones="", dnsbl_domain_zones=""), resolver=resolver)
        assert "no DNSBL zones" in (await none.lookup("9.9.9.9", IOCType.IPV4)).detail
        ip_only = DNSBLProvider(Settings(dnsbl_domain_zones=""), resolver=resolver)
        assert (await ip_only.lookup("evil.example", IOCType.DOMAIN)).verdict is V.SKIPPED
        assert (await ip_only.lookup("9.9.9.9", IOCType.IPV4)).verdict is V.UNKNOWN

    def test_offline_mode_disables_it(self) -> None:
        assert DNSBLProvider(Settings(offline=True), resolver=FakeResolver()).disabled_reason() == "offline mode"


# =================================================================== aggregator
def ioc(ioc_type: IOCType, value: str) -> IOC:
    return IOC(type=ioc_type, value=value, defanged=value)


def attachment(name: str, sha256: str) -> Attachment:
    return Attachment(filename=name, size=1, sha256=sha256)


A, B = "aa" * 32, "bb" * 32
T = IOCType


class TestAggregator:
    def build(self, fake_provider: Any, **options: Any) -> tuple[IntelAggregator, dict[str, Any]]:
        providers = {
            "abuseipdb": fake_provider("abuseipdb", [T.IPV4, T.IPV6], V.SUSPICIOUS),
            "urlhaus": fake_provider("urlhaus", [T.URL, T.DOMAIN, T.IPV4, T.HASH]),
            "virustotal": fake_provider("virustotal", [T.HASH, T.URL, T.IPV4, T.DOMAIN], V.CLEAN),
            "dnsbl": fake_provider("dnsbl", [T.IPV4, T.IPV6, T.DOMAIN]),
        }
        aggregator = IntelAggregator(list(providers.values()), cache=IntelCache(ttl_seconds=60), **options)
        return aggregator, providers

    def sample(self) -> tuple[list[IOC], list[Attachment]]:
        iocs = [ioc(T.DOMAIN, "evil.example"), ioc(T.URL, "http://evil.example/a"),
                ioc(T.URL, "http://evil.example/b"), ioc(T.IPV4, "198.51.100.7"),
                ioc(T.EMAIL, "x@evil.example")]
        atts = [attachment("a.exe", A), attachment("copy.exe", A), attachment("b.doc", B),
                Attachment(filename="big", size=9, skipped=True)]
        return iocs, atts

    async def test_hashes_get_the_scarce_virustotal_budget_first(self, fake_provider: Any) -> None:
        aggregator, providers = self.build(fake_provider, budgets={"virustotal": 2})
        iocs, atts = self.sample()
        outcome = await aggregator.enrich(iocs, atts)
        assert sorted(c[:4] for c in providers["virustotal"].calls) == ["aaaa", "bbbb"]
        assert outcome.stats.indicators == 6  # dup hash merged, email and skipped file ignored
        assert outcome.stats.budget_skipped == 4
        assert any("virustotal" in w and "per-run limit of 2" in w for w in outcome.warnings)

    async def test_results_are_written_back_in_provider_order(self, fake_provider: Any) -> None:
        aggregator, _ = self.build(fake_provider, budgets={"virustotal": 2})
        iocs, atts = self.sample()
        await aggregator.enrich(iocs, atts)
        assert [r.provider for r in atts[0].intel] == ["urlhaus", "virustotal"]
        assert atts[0].intel == atts[1].intel  # the shared hash got the same lookups
        ip = iocs[3]
        assert [r.provider for r in ip.intel] == ["abuseipdb", "urlhaus", "dnsbl"]
        assert worst_verdict(ip.intel) is V.SUSPICIOUS
        assert iocs[4].intel == []  # e-mail addresses have no provider
        assert atts[3].intel == []

    async def test_second_run_is_served_from_the_cache(self, fake_provider: Any) -> None:
        aggregator, providers = self.build(fake_provider, budgets={"virustotal": 2})
        iocs, atts = self.sample()
        await aggregator.enrich(iocs, atts)
        before = {name: len(p.calls) for name, p in providers.items()}  # type: ignore[attr-defined]
        again = await aggregator.enrich(iocs, atts)
        after = {name: len(p.calls) for name, p in providers.items()}  # type: ignore[attr-defined]
        assert again.stats.cache_hits > 0
        for name in ("abuseipdb", "urlhaus", "dnsbl"):
            assert after[name] == before[name]
        assert after["virustotal"] - before["virustotal"] <= 2  # fresh budget for the leftovers

    async def test_dnsbl_runs_only_as_fallback_when_asked(self, fake_provider: Any) -> None:
        disabled = fake_provider("abuseipdb", [T.IPV4], enabled=False)
        dnsbl = fake_provider("dnsbl", [T.IPV4, T.DOMAIN])
        await IntelAggregator([disabled, dnsbl], dnsbl_always=False).enrich([ioc(T.IPV4, "198.51.100.7")])
        assert len(dnsbl.calls) == 1  # type: ignore[attr-defined]

        answering = fake_provider("abuseipdb", [T.IPV4], V.MALICIOUS)
        dnsbl2 = fake_provider("dnsbl", [T.IPV4, T.DOMAIN])
        await IntelAggregator([answering, dnsbl2], dnsbl_always=False).enrich([ioc(T.IPV4, "198.51.100.7")])
        assert dnsbl2.calls == []  # type: ignore[attr-defined]

    async def test_errors_are_kept_counted_and_summarised(self, fake_provider: Any) -> None:
        failing = fake_provider("abuseipdb", [T.IPV4], V.ERROR)
        target = ioc(T.IPV4, "198.51.100.7")
        outcome = await IntelAggregator([failing]).enrich([target])
        assert target.intel[0].verdict is V.ERROR
        assert outcome.stats.errors == 1 and outcome.providers_used == []
        assert any(w.startswith("abuseipdb: 1 lookup(s) failed") for w in outcome.warnings)

    async def test_skipped_results_are_not_written_onto_indicators(self, fake_provider: Any) -> None:
        skipping = fake_provider("abuseipdb", [T.IPV4], V.SKIPPED)
        target = ioc(T.IPV4, "198.51.100.7")
        outcome = await IntelAggregator([skipping]).enrich([target])
        assert target.intel == [] and outcome.stats.local_skipped == 1

    async def test_deadline_returns_partial_results(self, fake_provider: Any) -> None:
        slow = fake_provider("abuseipdb", [T.IPV4], V.CLEAN, delay=5)
        outcome = await IntelAggregator([slow], deadline_seconds=0.2).enrich([ioc(T.IPV4, "198.51.100.8")])
        assert outcome.stats.unfinished == 1 and any("deadline" in w for w in outcome.warnings)

    async def test_indicator_cap_keeps_the_highest_priority(self, fake_provider: Any) -> None:
        provider = fake_provider("abuseipdb", [T.IPV4], V.CLEAN)
        iocs = [ioc(T.IPV4, f"198.51.100.{i}") for i in range(10, 15)]
        outcome = await IntelAggregator([provider], max_indicators=2).enrich(iocs)
        assert outcome.stats.indicators == 2 and any("only the 2" in w for w in outcome.warnings)

    async def test_nothing_enabled(self, fake_provider: Any) -> None:
        off = fake_provider("abuseipdb", [T.IPV4], enabled=False)
        outcome = await IntelAggregator([off]).enrich([ioc(T.IPV4, "198.51.100.9")])
        assert any("No threat-intelligence provider is enabled" in w for w in outcome.warnings)

    async def test_offline_settings(self) -> None:
        async with IntelAggregator.from_settings(Settings(offline=True)) as aggregator:
            assert [s.name for s in aggregator.provider_statuses()] == [
                "abuseipdb", "urlhaus", "virustotal", "dnsbl"]
            outcome = await aggregator.enrich([ioc(T.IPV4, "198.51.100.9")])
        assert any(w.startswith("Offline mode") for w in outcome.warnings)

    def test_default_budgets_follow_the_rate_limits(self) -> None:
        assert default_budgets(Settings()) == {"urlhaus": 19, "abuseipdb": 19, "virustotal": 2}
        assert default_budgets(Settings(virustotal_requests_per_minute=60))["virustotal"] == 38

    def test_worst_verdict(self) -> None:
        assert worst_verdict([]) is V.UNKNOWN
        assert worst_verdict([result(verdict=V.ERROR), result(verdict=V.UNKNOWN)]) is V.UNKNOWN
        assert worst_verdict([result(verdict=V.CLEAN), result(verdict=V.SUSPICIOUS)]) is V.SUSPICIOUS
        assert worst_verdict([result(verdict=V.SUSPICIOUS), result(verdict=V.MALICIOUS)]) is V.MALICIOUS