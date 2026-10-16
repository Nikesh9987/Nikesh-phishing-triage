"""End-to-end tests for ``core/pipeline.py`` (no network)."""

import asyncio
import base64
import hashlib
from typing import Any

import pytest

from phishtriage.analyzers.auth_analyzer import AuthAnalyzer
from phishtriage.analyzers.received_tracer import ReceivedTracer
from phishtriage.config import Settings
from phishtriage.core import pipeline as pipeline_module
from phishtriage.core.exceptions import (
    EmptyInputError,
    FileTooLargeError,
    InputError,
    UnsupportedFormatError,
)
from phishtriage.core.models import IntelVerdict, IOCType, Verdict
from phishtriage.core.pipeline import TriagePipeline, analyze_bytes, analyze_bytes_sync
from phishtriage.intel.aggregator import IntelAggregator
from phishtriage.intel.cache import IntelCache

OFFLINE = Settings(offline=True)


@pytest.fixture
def no_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """For tests that run with offline=False: make every DNS stage inert."""
    monkeypatch.setattr(AuthAnalyzer, "_make_dns", lambda self: None)
    monkeypatch.setattr(ReceivedTracer, "_build_resolver", lambda self: None)


def codes(report: Any) -> set[str]:
    return {f.code for f in report.findings}


# ================================================================== reports
class TestPhishingSample:
    async def test_full_report(self, phishing_eml: bytes, pe_bytes: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(phishing_eml, "../../uploads/sample\u202e.eml")

        assert report.filename == "sample.eml"  # path and direction character removed
        assert report.file_size == len(phishing_eml)
        assert report.file_sha256 == hashlib.sha256(phishing_eml).hexdigest()
        assert report.offline is True
        assert report.verdict is Verdict.MALICIOUS and report.risk_score >= 70

        assert {
            "attachment_disguised_executable",
            "link_text_mismatch",
            "html_password_field",
            "lookalike_sender_domain",
            "reply_to_mismatch",
            "dmarc_fail",
            "spf_fail",
        } <= codes(report)

        assert report.message.subject == "URGENT: verify your account"
        assert report.message.from_address is not None
        assert report.message.from_address.domain == "paypa1.example"
        assert len(report.headers) > 5

        origin = report.received.originating_mta
        assert origin is not None and origin.ip == "203.0.113.5" and origin.hop_index == 0
        assert len(report.received.hops) == 2

        auth = report.authentication
        assert auth.spf.status.value == "fail" and auth.dmarc.status.value == "fail"

        (attachment,) = report.attachments
        assert attachment.sha256 == hashlib.sha256(pe_bytes).hexdigest()
        assert attachment.detected_extension == "exe"

        urls = {i.value for i in report.iocs if i.type is IOCType.URL}
        assert "http://evil.example/login" in urls
        assert all(i.defanged != i.value for i in report.iocs if i.type is IOCType.URL)

    async def test_findings_are_unique_and_sorted(self, phishing_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")
        found = [f.code for f in report.findings]
        assert len(found) == len(set(found))

    async def test_payload_bytes_never_reach_the_serialised_report(
        self, phishing_eml: bytes, pe_bytes: bytes
    ) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")
        dumped = report.model_dump_json()
        assert base64.b64encode(pe_bytes).decode()[:24] not in dumped
        assert pe_bytes.hex()[:24] not in dumped

    async def test_offline_mode_is_stated(self, phishing_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")
        assert any(w.startswith("Offline mode") for w in report.warnings)
        assert report.intel_providers_used == []


class TestCleanSample:
    async def test_no_indicators(self, clean_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(clean_eml, "ok.eml")
        assert report.verdict is Verdict.CLEAN and report.risk_score < 15
        assert report.authentication.spf.status.value == "pass"
        assert report.authentication.dmarc.status.value == "pass"
        assert report.attachments == []


# ================================================================== options
class TestOptions:
    async def test_enrich_false_is_stated(self, clean_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(clean_eml, "ok.eml", enrich=False)
        assert any("enrichment was disabled" in w for w in report.warnings)

    async def test_trusted_hops_changes_the_origin(self, phishing_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            two = await pipeline.analyze(phishing_eml, "p.eml", trusted_hops=2)
            one = await pipeline.analyze(phishing_eml, "p.eml", trusted_hops=1)
        assert two.received.originating_mta is not None
        assert two.received.originating_mta.ip == "203.0.113.5"
        assert one.received.originating_mta is None  # your own hop only saw a private IP
        assert any("No public sending IP" in w for w in one.received.warnings)

    async def test_trusted_authserv_ids_are_honoured(self, phishing_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            pinned = await pipeline.analyze(phishing_eml, "p.eml", trusted_authserv_ids=["mx2.corp.example"])
            other = await pipeline.analyze(phishing_eml, "p.eml", trusted_authserv_ids=["other.example"])
        assert pinned.authentication.spf.status.value == "fail"
        assert other.authentication.spf.status.value == "unknown"
        assert any("trusted authserv-id" in w for w in other.authentication.warnings)

    async def test_scan_macros_flag_reaches_the_attachment_stage(
        self, monkeypatch: pytest.MonkeyPatch, phishing_eml: bytes
    ) -> None:
        seen: list[bool] = []
        real = pipeline_module.analyze_attachments

        def spy(message: Any, settings: Any, *, scan_macros: bool) -> Any:
            seen.append(scan_macros)
            return real(message, settings, scan_macros=scan_macros)

        monkeypatch.setattr(pipeline_module, "analyze_attachments", spy)
        async with TriagePipeline(OFFLINE) as pipeline:
            await pipeline.analyze(phishing_eml, "p.eml", scan_macros=False)
            await pipeline.analyze(phishing_eml, "p.eml")
        assert seen == [False, True]

    async def test_custom_brands_replace_the_defaults(self, eml_builder: Any) -> None:
        data = eml_builder(from_='"X" <x@acrne.example>')
        async with TriagePipeline(OFFLINE, brands={"acme": ["acme.example"]}) as pipeline:
            report = await pipeline.analyze(data, "a.eml")
        assert "lookalike_sender_domain" in codes(report)
        async with TriagePipeline(OFFLINE) as pipeline:
            assert "lookalike_sender_domain" not in codes(await pipeline.analyze(data, "a.eml"))

    async def test_provider_statuses_in_offline_mode(self) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            statuses = pipeline.provider_statuses()
        assert [s.name for s in statuses] == ["abuseipdb", "urlhaus", "virustotal", "dnsbl"]
        assert all(not s.enabled and s.reason == "offline mode" for s in statuses)


# ================================================================ bad input
class TestInputErrors:
    async def test_empty_unrecognised_and_oversized(self) -> None:
        async with TriagePipeline(Settings(offline=True, max_upload_bytes=1024)) as pipeline:
            with pytest.raises(EmptyInputError):
                await pipeline.analyze(b"")
            with pytest.raises(UnsupportedFormatError):
                await pipeline.analyze(b"just some prose")
            with pytest.raises(FileTooLargeError):
                await pipeline.analyze(b"Subject: x\r\n\r\n" + b"A" * 2000)

    async def test_invalid_trusted_hops(self, clean_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            with pytest.raises(InputError, match="trusted_hops"):
                await pipeline.analyze(clean_eml, trusted_hops=0)


# ============================================================ stage failures
STAGES = [
    ("extract_iocs", "IOC extraction"),
    ("trace_received", "Received-path analysis"),
    ("analyze_attachments", "Attachment analysis"),
    ("analyze_auth", "Authentication analysis"),
    ("analyze_anomalies", "Anomaly analysis"),
]


class TestDegradation:
    @pytest.mark.parametrize(("function", "label"), STAGES)
    async def test_a_failing_stage_becomes_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, phishing_eml: bytes, function: str, label: str
    ) -> None:
        def boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("secret internals")

        monkeypatch.setattr(pipeline_module, function, boom)
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")
        assert any(label in w and "failed unexpectedly" in w for w in report.warnings)
        assert not any("secret internals" in w for w in report.warnings)
        assert report.message.subject == "URGENT: verify your account"  # the rest survived

    async def test_missing_results_are_empty_not_invented(
        self, monkeypatch: pytest.MonkeyPatch, phishing_eml: bytes
    ) -> None:
        def boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(pipeline_module, "extract_iocs", boom)
        monkeypatch.setattr(pipeline_module, "analyze_attachments", boom)
        async with TriagePipeline(OFFLINE) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")
        assert report.iocs == [] and report.attachments == []
        assert "attachment_disguised_executable" not in codes(report)

    async def test_intel_failure_is_a_warning(self, no_dns: None, clean_eml: bytes) -> None:
        class Broken:
            def provider_statuses(self) -> list[Any]:
                return []

            async def enrich(self, *args: object) -> None:
                raise RuntimeError("boom")

            async def aclose(self) -> None:
                return None

        async with TriagePipeline(Settings(), aggregator=Broken()) as pipeline:  # type: ignore[arg-type]
            report = await pipeline.analyze(clean_eml, "ok.eml")
        assert any("enrichment failed unexpectedly" in w for w in report.warnings)


# ================================================================== enrichment
class TestEnrichment:
    async def test_intel_flows_into_findings_and_the_score(
        self, no_dns: None, phishing_eml: bytes, fake_provider: Any
    ) -> None:
        provider = fake_provider("urlhaus", [IOCType.URL, IOCType.DOMAIN], IntelVerdict.MALICIOUS)
        aggregator = IntelAggregator([provider], cache=IntelCache(ttl_seconds=60))
        async with TriagePipeline(Settings(), aggregator=aggregator) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")

        urls = [i for i in report.iocs if i.type is IOCType.URL]
        assert urls and all(i.intel and i.intel[0].verdict is IntelVerdict.MALICIOUS for i in urls)
        assert "intel_malicious_url" in codes(report)
        assert report.intel_providers_used == ["urlhaus"]
        assert report.risk_score >= 85
        assert provider.calls  # type: ignore[attr-defined]

    async def test_offline_never_calls_a_supplied_aggregator(
        self, phishing_eml: bytes, fake_provider: Any
    ) -> None:
        provider = fake_provider("urlhaus", [IOCType.URL, IOCType.DOMAIN], IntelVerdict.MALICIOUS)
        aggregator = IntelAggregator([provider])
        async with TriagePipeline(OFFLINE, aggregator=aggregator) as pipeline:
            report = await pipeline.analyze(phishing_eml, "p.eml")
        assert provider.calls == []  # type: ignore[attr-defined]
        assert not any(c.startswith("intel_") for c in codes(report))

    async def test_a_floor_is_explained(self, no_dns: None, eml_builder: Any, fake_provider: Any) -> None:
        # A clean-looking message whose only problem is a malicious URL: the floor decides.
        data = eml_builder(text="see http://evil.example/a")
        provider = fake_provider("urlhaus", [IOCType.URL], IntelVerdict.MALICIOUS)
        aggregator = IntelAggregator([provider], cache=IntelCache(ttl_seconds=60))
        async with TriagePipeline(Settings(), aggregator=aggregator) as pipeline:
            report = await pipeline.analyze(data, "a.eml")
        assert report.risk_score >= 85 and report.verdict is Verdict.MALICIOUS
        note = next((f for f in report.findings if f.code == "score_floor_applied"), None)
        assert note is not None and any("intel_malicious_url" in e for e in note.evidence)


# ============================================================ concurrency, helpers
class TestSharedUse:
    async def test_concurrent_analyses_on_one_pipeline(self, phishing_eml: bytes, clean_eml: bytes) -> None:
        async with TriagePipeline(OFFLINE) as pipeline:
            reports = await asyncio.gather(
                *[pipeline.analyze(phishing_eml if i % 2 else clean_eml, f"{i}.eml") for i in range(6)]
            )
        assert len({r.report_id for r in reports}) == 6
        assert [r.verdict is Verdict.MALICIOUS for r in reports] == [bool(i % 2) for i in range(6)]

    async def test_analyze_bytes(self, clean_eml: bytes) -> None:
        report = await analyze_bytes(clean_eml, "ok.eml", OFFLINE)
        assert report.verdict is Verdict.CLEAN

    def test_analyze_bytes_sync(self, clean_eml: bytes) -> None:
        report = analyze_bytes_sync(clean_eml, "ok.eml", OFFLINE)
        assert report.filename == "ok.eml"