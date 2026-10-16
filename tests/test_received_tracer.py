"""Tests for ``analyzers/received_tracer.py`` (no network: reverse DNS is faked)."""

import pytest

from phishtriage.analyzers import received_tracer as rt
from phishtriage.analyzers.received_tracer import ReceivedTracer, classify_ip, trace_received
from phishtriage.config import Settings
from phishtriage.core.models import HeaderField, IPScope, ParsedMessage

NEWEST = (
    "from mx1.corp.example (mx1.corp.example [10.0.0.5]) by mx2.corp.example with ESMTP id Q3 "
    "for <victim@corp.example>; Mon, 05 Oct 2026 09:00:05 +0000"
)
MIDDLE = (
    "from mail.evil.example (mail.evil.example [203.0.113.5]) by mx1.corp.example with ESMTPS "
    "(version=TLSv1.3) id Q2 for <victim@corp.example>; Mon, 05 Oct 2026 09:00:03 +0000 (UTC)"
)
OLDEST = "from [10.9.9.9] by mail.evil.example with SMTP id Q1; Mon, 05 Oct 2026 07:30:00 +0000"
PUBLIC_HOP = (
    "from mail.example.org ([8.8.8.8]) by mx.corp.example with ESMTP id Z; "
    "Mon, 05 Oct 2026 09:00:00 +0000"
)


def msg(*received: str, extra: tuple[tuple[str, str], ...] = ()) -> ParsedMessage:
    """Build a message; ``received`` is newest first, exactly as in a file."""
    headers = [HeaderField(name="Received", value=v) for v in received]
    headers += [HeaderField(name=n, value=v) for n, v in extra]
    return ParsedMessage(source_format="eml", headers=headers)


def offline() -> ReceivedTracer:
    return ReceivedTracer(resolve_rdns=False)


# ============================================================== classify_ip
class TestClassifyIp:
    @pytest.mark.parametrize(
        ("address", "scope"),
        [
            ("10.1.2.3", IPScope.PRIVATE),
            ("172.31.0.1", IPScope.PRIVATE),
            ("192.168.1.1", IPScope.PRIVATE),
            ("100.64.0.1", IPScope.CGNAT),
            ("127.0.0.1", IPScope.LOOPBACK),
            ("::1", IPScope.LOOPBACK),
            ("169.254.1.1", IPScope.LINK_LOCAL),
            ("fe80::1", IPScope.LINK_LOCAL),
            ("224.0.0.1", IPScope.MULTICAST),
            ("0.0.0.0", IPScope.RESERVED),
            ("203.0.113.5", IPScope.RESERVED),  # documentation range
            ("2001:db8::1", IPScope.RESERVED),
            ("fd00::1", IPScope.UNIQUE_LOCAL),
            ("8.8.8.8", IPScope.PUBLIC),
            ("2606:4700::1111", IPScope.PUBLIC),
            ("::ffff:8.8.8.8", IPScope.PUBLIC),
            ("::ffff:10.0.0.1", IPScope.PRIVATE),
        ],
    )
    def test_scope(self, address: str, scope: IPScope) -> None:
        assert classify_ip(address) is scope

    def test_invalid_address_raises(self) -> None:
        with pytest.raises(ValueError):
            classify_ip("999.1.1.1")


# ============================================================== hop parsing
class TestHopParsing:
    def test_hops_are_oldest_first(self) -> None:
        trace = offline().trace(msg(NEWEST, MIDDLE, OLDEST))
        assert [h.index for h in trace.hops] == [0, 1, 2]
        assert [h.queue_id for h in trace.hops] == ["Q1", "Q2", "Q3"]

    def test_clauses_are_extracted(self) -> None:
        hop = offline().trace(msg(NEWEST, MIDDLE, OLDEST)).hops[1]
        assert hop.from_host == "mail.evil.example"
        assert hop.by_host == "mx1.corp.example"
        assert hop.protocol == "ESMTPS"  # the (version=...) comment is dropped
        assert hop.envelope_for == "victim@corp.example"
        assert hop.timestamp is not None and hop.timestamp.hour == 9

    def test_bracketed_ip_literal_as_host(self) -> None:
        hop = offline().trace(msg(OLDEST)).hops[0]
        assert hop.from_host == "10.9.9.9"
        assert [(i.address, i.scope) for i in hop.ips] == [("10.9.9.9", IPScope.PRIVATE)]

    def test_documentation_ip_is_scope_reserved(self) -> None:
        hop = offline().trace(msg(MIDDLE)).hops[0]
        assert [(i.address, i.scope) for i in hop.ips] == [("203.0.113.5", IPScope.RESERVED)]

    def test_by_clause_is_not_scanned_for_ips(self) -> None:
        raw = (
            "from mail.example.net ([8.8.8.8]) by 2002:a05:6a00:1:b0:1:2:3 with SMTP id x; "
            "Mon, 05 Oct 2026 09:00:00 +0000"
        )
        assert [i.address for i in offline().trace(msg(raw)).hops[0].ips] == ["8.8.8.8"]

    def test_ipv4_mapped_ipv6_becomes_ipv4(self) -> None:
        raw = "from x.example ([::ffff:203.0.113.7]) by y.example; Mon, 05 Oct 2026 09:00:00 +0000"
        (hop_ip,) = offline().trace(msg(raw)).hops[0].ips
        assert (hop_ip.address, hop_ip.version) == ("203.0.113.7", 4)

    def test_ipv6_bracket_literal(self) -> None:
        raw = "from m.example.net ([2606:4700::25]) by mx.corp.example; Mon, 05 Oct 2026 09:00:00 +0000"
        (hop_ip,) = offline().trace(msg(raw)).hops[0].ips
        assert (hop_ip.address, hop_ip.scope) == ("2606:4700::25", IPScope.PUBLIC)

    def test_ipv6_with_tag_prefix(self) -> None:
        raw = "from m.example.net ([IPv6:2606:4700::25]) by mx.corp.example; Mon, 05 Oct 2026 09:00:00 +0000"
        (hop_ip,) = offline().trace(msg(raw)).hops[0].ips
        assert hop_ip.address == "2606:4700::25"

    def test_missing_timestamp_and_garbage_are_flagged_not_fatal(self) -> None:
        trace = offline().trace(msg("from a.example by b.example", "garbage"))
        no_timestamp, garbage = trace.hops[1], trace.hops[0]  # oldest first
        assert any("timestamp" in a for a in no_timestamp.anomalies)
        assert any("could not be parsed" in a for a in garbage.anomalies)


# ================================================================== timing
class TestTiming:
    def test_delays_and_total(self) -> None:
        trace = offline().trace(msg(NEWEST, MIDDLE, OLDEST))
        assert [h.delay_seconds for h in trace.hops] == [None, 5403.0, 2.0]
        assert trace.total_delay_seconds == 5405.0
        assert any("Delay of 1h 30m" in a for a in trace.hops[1].anomalies)

    def test_single_hop_has_no_total(self) -> None:
        assert offline().trace(msg(OLDEST)).total_delay_seconds is None

    def test_backwards_timestamps_are_flagged(self) -> None:
        trace = offline().trace(msg(
            "from b.example ([198.51.100.2]) by c.example; Mon, 05 Oct 2026 09:00:00 +0000",
            "from a.example ([198.51.100.1]) by b.example; Mon, 05 Oct 2026 09:30:00 +0000",
        ))
        assert trace.hops[1].delay_seconds == -1800.0
        assert any("earlier than the previous hop" in a for a in trace.hops[1].anomalies)
        assert any("not monotonic" in w for w in trace.warnings)

    def test_small_clock_skew_is_tolerated(self) -> None:
        trace = offline().trace(msg(
            "from b.example by c.example; Mon, 05 Oct 2026 09:29:00 +0000",
            "from a.example by b.example; Mon, 05 Oct 2026 09:30:00 +0000",
        ))
        assert trace.hops[1].anomalies == []

    def test_future_timestamp_is_flagged(self) -> None:
        trace = offline().trace(msg("from a.example by b.example; Mon, 05 Oct 2099 09:00:00 +0000"))
        assert any("future" in a for a in trace.hops[0].anomalies)


# ============================================================ originating MTA
class TestOrigin:
    def test_default_origin_is_the_oldest_public_hop(self) -> None:
        origin = offline().trace(msg(NEWEST, MIDDLE, OLDEST)).originating_mta
        assert origin is not None
        assert (origin.ip, origin.hop_index, origin.hostname) == ("203.0.113.5", 1, "mail.evil.example")
        assert "Preceded by 1 hop(s)" in origin.reason
        assert "forged" in origin.reason

    def test_trusted_hops_uses_what_your_server_saw(self) -> None:
        origin = offline().trace(msg(NEWEST, MIDDLE, OLDEST), trusted_hops=2).originating_mta
        assert origin is not None and origin.ip == "203.0.113.5"
        assert "trusted hop" in origin.reason

    def test_trusted_hops_ignores_forgeable_older_hops(self) -> None:
        # Only the newest hop is yours and it saw a private IP: do not fall back to older hops.
        trace = offline().trace(msg(NEWEST, MIDDLE, OLDEST), trusted_hops=1)
        assert trace.originating_mta is None
        assert any("No public sending IP" in w for w in trace.warnings)

    def test_trusted_hops_larger_than_chain_warns(self) -> None:
        trace = offline().trace(msg(MIDDLE), trusted_hops=5)
        assert any("exceeds" in w for w in trace.warnings)
        assert trace.originating_mta is not None

    def test_all_private_chain_has_no_origin(self) -> None:
        trace = offline().trace(msg(NEWEST, OLDEST))
        assert trace.originating_mta is None

    def test_ip_literal_host_gives_no_hostname(self) -> None:
        raw = "from [8.8.8.8] by mx.corp.example; Mon, 05 Oct 2026 09:00:00 +0000"
        origin = offline().trace(msg(raw)).originating_mta
        assert origin is not None and origin.hostname is None


# ================================================================ reverse DNS
@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the PTR lookup; returns the list of addresses that were queried."""
    queried: list[str] = []
    table = {"8.8.8.8": ("dns.google", None), "93.184.216.34": (None, "no PTR record")}

    def fake_reverse(resolver: object, address: str) -> tuple[str | None, str | None]:
        queried.append(address)
        return table.get(address, (None, "lookup failed"))

    monkeypatch.setattr(rt, "_reverse_lookup", fake_reverse)
    monkeypatch.setattr(ReceivedTracer, "_build_resolver", lambda self: object())
    return queried


class TestReverseDns:
    def test_public_ip_is_resolved_and_mismatch_flagged(self, fake_dns: list[str]) -> None:
        trace = ReceivedTracer(resolve_rdns=True).trace(msg(PUBLIC_HOP))
        (hop_ip,) = trace.hops[0].ips
        assert hop_ip.rdns == "dns.google"
        assert any("does not match reverse DNS" in a for a in trace.hops[0].anomalies)
        assert trace.originating_mta is not None and trace.originating_mta.rdns == "dns.google"

    def test_matching_claim_is_not_flagged(self, fake_dns: list[str]) -> None:
        raw = "from dns.google ([8.8.8.8]) by mx.corp.example; Mon, 05 Oct 2026 09:00:00 +0000"
        trace = ReceivedTracer(resolve_rdns=True).trace(msg(raw))
        assert trace.hops[0].anomalies == []

    def test_only_public_ips_are_ever_queried(self, fake_dns: list[str]) -> None:
        ReceivedTracer(resolve_rdns=True).trace(msg(NEWEST, MIDDLE, PUBLIC_HOP))
        assert fake_dns == ["8.8.8.8"]  # not 10.0.0.5, not the documentation IP

    def test_missing_ptr_is_recorded(self, fake_dns: list[str]) -> None:
        raw = "from x.example ([93.184.216.34]) by mx.corp.example; Mon, 05 Oct 2026 09:00:00 +0000"
        (hop_ip,) = ReceivedTracer(resolve_rdns=True).trace(msg(raw)).hops[0].ips
        assert hop_ip.rdns is None and hop_ip.rdns_error == "no PTR record"

    def test_offline_means_no_queries(self, fake_dns: list[str]) -> None:
        trace = offline().trace(msg(PUBLIC_HOP))
        assert fake_dns == [] and trace.hops[0].ips[0].rdns is None

    def test_trace_received_honours_offline_settings(self, fake_dns: list[str]) -> None:
        trace_received(msg(PUBLIC_HOP), Settings(offline=True))
        assert fake_dns == []

    def test_missing_resolver_degrades_with_a_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ReceivedTracer, "_build_resolver", lambda self: None)
        trace = ReceivedTracer(resolve_rdns=True).trace(msg(PUBLIC_HOP))
        assert any("No DNS resolver" in w for w in trace.warnings)
        assert len(trace.hops) == 1


# ===================================================================== misc
class TestMisc:
    def test_no_received_headers(self) -> None:
        trace = offline().trace(msg())
        assert trace.hops == [] and trace.originating_mta is None
        assert trace.warnings == ["No Received headers found; the message path cannot be traced."]

    def test_x_originating_ip_is_an_unverified_hint(self) -> None:
        trace = offline().trace(msg(OLDEST, extra=(("X-Originating-IP", "[198.51.100.77]"),)))
        assert any("X-Originating-IP reports 198.51.100.77" in w for w in trace.warnings)

    def test_hop_cap_keeps_the_oldest(self) -> None:
        raws = [
            f"from h{i}.example ([198.51.100.{i}]) by x.example; Mon, 05 Oct 2026 09:00:0{i} +0000"
            for i in range(5)  # newest first: h0 is newest
        ]
        trace = ReceivedTracer(resolve_rdns=False, max_hops=3).trace(msg(*raws))
        assert [h.from_host for h in trace.hops] == ["h4.example", "h3.example", "h2.example"]
        assert any("only the oldest 3" in w for w in trace.warnings)

    def test_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(self: object, *args: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(ReceivedTracer, "_trace", boom)
        trace = offline().trace(msg(OLDEST))
        assert trace.hops == [] and "failed unexpectedly" in trace.warnings[0]