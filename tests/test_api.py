"""Tests for the web API: ``api/app.py``, ``api/routes.py``, ``api/dependencies.py``, ``api/schemas.py``.

Everything runs offline through ``TestClient``. Each test builds its own app, so
rate limiters, report stores and caches never leak between tests.
"""

import asyncio
import csv
import hashlib
import io
import json
import logging
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from phishtriage.api import routes as routes_module
from phishtriage.api.app import create_app
from phishtriage.api.dependencies import (
    ReportNotFoundError,
    ReportStore,
    SlidingWindowRateLimiter,
    analyze_options,
    sanitize_filename,
)
from phishtriage.api.schemas import (
    ErrorResponse,
    HashExportItem,
    IocExport,
    IocExportItem,
    ReportSummary,
)
from phishtriage.config import Settings
from phishtriage.core.exceptions import InputError, RateLimitExceeded, UnsupportedFormatError
from phishtriage.core.models import Report, Verdict
from phishtriage.core.pipeline import analyze_bytes_sync
from phishtriage.intel.base import ProviderStatus

MakeClient = Callable[..., TestClient]


@pytest.fixture(autouse=True)
def _no_stale_log_handlers() -> Iterator[None]:
    """The app's lifespan installs a log handler on the current stderr; remove it afterwards."""
    yield
    logging.getLogger("phishtriage").handlers.clear()


@pytest.fixture
def make_client() -> Iterator[MakeClient]:
    """Factory for started test clients (offline, generous rate limit unless overridden)."""
    clients: list[TestClient] = []

    def make(**overrides: Any) -> TestClient:
        settings: dict[str, Any] = {"offline": True, "api_rate_limit_per_minute": 1000}
        settings.update(overrides)
        client = TestClient(create_app(Settings(**settings)), raise_server_exceptions=False)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(make_client: MakeClient) -> TestClient:
    return make_client(max_upload_bytes=50_000)


@pytest.fixture
def report(phishing_eml: bytes) -> Report:
    return analyze_bytes_sync(phishing_eml, "phish.eml", Settings(offline=True))


def upload(client: TestClient, data: bytes, name: str = "m.eml", **form: str) -> Any:
    return client.post("/api/analyze", files={"file": (name, data)}, data=form)


def analyzed(client: TestClient, data: bytes, name: str = "phish.eml", **form: str) -> dict[str, Any]:
    response = upload(client, data, name, **form)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def csv_rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


# ================================================================== system
class TestSystem:
    def test_health(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        assert response.status_code == 200 and data["status"] == "ok"
        assert data["offline"] is True and data["stored_reports"] == 0
        assert [p["name"] for p in data["providers"]] == ["abuseipdb", "urlhaus", "virustotal", "dnsbl"]
        assert all(not p["enabled"] and p["reason"] == "offline mode" for p in data["providers"])

    def test_health_never_reveals_secrets(self, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "secret-key-xyz")
        client = make_client(offline=False)
        text = client.get("/health").text
        assert "secret-key-xyz" not in text
        providers = {p["name"]: p for p in client.get("/health").json()["providers"]}
        assert providers["abuseipdb"]["enabled"] is True

    def test_stored_report_count(self, client: TestClient, phishing_eml: bytes) -> None:
        body = analyzed(client, phishing_eml)
        assert client.get("/health").json()["stored_reports"] == 1
        client.delete(f"/api/report/{body['report']['report_id']}")
        assert client.get("/health").json()["stored_reports"] == 0

    def test_favicon_is_answered_quietly(self, client: TestClient) -> None:
        assert client.get("/favicon.ico").status_code == 204

    def test_missing_service_is_a_503(self, make_client: MakeClient) -> None:
        client = make_client()
        client.app.state.report_store = None  # type: ignore[attr-defined]
        response = client.get("/health")
        assert response.status_code == 503 and response.json()["error"] == "service_unavailable"


# ================================================================ dashboard
class TestDashboard:
    def test_page_and_offline_badge(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")
        for needle in ('id="dropzone"', 'id="analyze-form"', "Phishing Triage", "OFFLINE MODE",
                       'data-max-bytes="50000"', 'data-extensions=".eml,.msg"'):
            assert needle in response.text

    def test_online_page_has_no_offline_badge(self, make_client: MakeClient) -> None:
        text = make_client(offline=False).get("/").text
        assert "OFFLINE MODE" not in text and "enrich" not in text.split('id="opt-enrich"')[0][-30:]

    def test_provider_text_is_escaped(self, make_client: MakeClient) -> None:
        client = make_client(offline=False)
        hostile = ProviderStatus("x", False, '"><script>alert(1)</script>')
        client.app.state.pipeline.provider_statuses = lambda: [hostile]  # type: ignore[attr-defined]
        assert "<script>alert(1)</script>" not in client.get("/").text

    def test_page_has_no_inline_script_or_handlers(self, client: TestClient) -> None:
        text = client.get("/").text
        assert "<script>" not in text and " onclick=" not in text

    @pytest.mark.parametrize(
        ("path", "kind"),
        [("/static/css/app.css", "text/css"), ("/static/js/render.js", "javascript"),
         ("/static/js/upload.js", "javascript"), ("/static/js/clipboard.js", "javascript")],
    )
    def test_static_assets(self, client: TestClient, path: str, kind: str) -> None:
        response = client.get(path)
        assert response.status_code == 200 and kind in response.headers["content-type"]

    def test_missing_static_file_is_a_404(self, client: TestClient) -> None:
        assert client.get("/static/nope.js").status_code == 404
        assert client.get("/static/%2e%2e/config.py").status_code == 404


# ================================================================== analyze
class TestAnalyze:
    def test_response_shape(self, client: TestClient, phishing_eml: bytes) -> None:
        body = analyzed(client, phishing_eml, "../../x/phish.eml")
        assert set(body) == {"summary", "report", "retention_seconds"}
        assert body["retention_seconds"] == 3600
        assert body["report"]["filename"] == "phish.eml"  # path stripped
        assert body["summary"]["report_id"] == body["report"]["report_id"]
        assert body["report"]["verdict"] == "malicious" and body["summary"]["verdict"] == "malicious"
        assert body["report"]["offline"] is True

    def test_payload_bytes_are_not_in_the_response(
        self, client: TestClient, phishing_eml: bytes, pe_bytes: bytes
    ) -> None:
        text = upload(client, phishing_eml, "p.eml").text
        assert pe_bytes.hex()[:24] not in text
        assert hashlib.sha256(pe_bytes).hexdigest() in text  # the hash is, the bytes are not

    def test_extension_is_case_insensitive_and_content_wins_over_the_name(
        self, client: TestClient, phishing_eml: bytes
    ) -> None:
        assert upload(client, phishing_eml, "UPPER.EML").status_code == 200
        body = analyzed(client, phishing_eml, "renamed.msg")
        assert body["report"]["message"]["source_format"] == "eml"

    def test_options_reach_the_analysis(self, client: TestClient, phishing_eml: bytes) -> None:
        pinned = analyzed(client, phishing_eml, trusted_hops="1")
        assert pinned["report"]["received"]["originating_mta"] is None
        trusted = analyzed(client, phishing_eml, trusted_hops="2")
        assert trusted["report"]["received"]["originating_mta"]["ip"] == "203.0.113.5"
        other = analyzed(client, phishing_eml, trusted_authserv="other.example")
        assert other["report"]["authentication"]["spf"]["status"] == "unknown"

    def test_boolean_options_are_accepted(self, client: TestClient, clean_eml: bytes) -> None:
        body = analyzed(client, clean_eml, "ok.eml", enrich="false", scan_macros="false")
        assert any("enrichment was disabled" in w for w in body["report"]["warnings"])

    def test_empty_option_fields_mean_not_set(self, client: TestClient, clean_eml: bytes) -> None:
        analyzed(client, clean_eml, "ok.eml", trusted_hops="", trusted_authserv="")

    @pytest.mark.parametrize(
        ("form", "fragment"),
        [
            ({"trusted_hops": "abc"}, "whole number"),
            ({"trusted_hops": "0"}, "between 1 and 100"),
            ({"trusted_hops": "101"}, "between 1 and 100"),
            ({"trusted_authserv": ",".join(f"s{i}.example" for i in range(11))}, "at most 10"),
        ],
    )
    def test_invalid_options(self, client: TestClient, clean_eml: bytes, form: dict[str, str], fragment: str) -> None:
        response = upload(client, clean_eml, "ok.eml", **form)
        assert response.status_code == 400 and fragment in response.json()["message"]

    def test_overlong_option_is_a_validation_error(self, client: TestClient, clean_eml: bytes) -> None:
        response = upload(client, clean_eml, "ok.eml", trusted_hops="1" * 11)
        assert response.status_code == 422 and response.json()["error"] == "validation_error"


# ============================================================ upload validation
class TestUploadValidation:
    @pytest.mark.parametrize("name", ["a.txt", "noextension", "a.eml.exe", ".eml.bak"])
    def test_bad_extension(self, client: TestClient, phishing_eml: bytes, name: str) -> None:
        response = upload(client, phishing_eml, name)
        assert response.status_code == 415 and response.json()["error"] == "unsupported_format"

    def test_empty_and_whitespace_only(self, client: TestClient) -> None:
        for data in (b"", b"   \r\n\t "):
            response = upload(client, data)
            assert response.status_code == 400 and response.json()["error"] == "empty_input"

    @pytest.mark.parametrize("data", [b"just some prose, not mail", b"\x00\x01\x02 binary", b"Hello: world"])
    def test_content_is_sniffed_not_trusted(self, client: TestClient, data: bytes) -> None:
        assert upload(client, data, "a.eml").status_code == 415

    def test_message_size_cap_from_the_dependency(self, client: TestClient) -> None:
        response = upload(client, b"Received: x\r\n" + b"A" * 100_000)
        assert response.status_code == 413 and response.json()["error"] == "file_too_large"

    def test_request_size_cap_from_the_middleware(self, client: TestClient) -> None:
        response = upload(client, b"Received: x\r\n" + b"A" * 2_000_000)
        assert response.status_code == 413 and response.json()["error"] == "file_too_large"

    def test_chunked_body_without_content_length_is_capped(self, client: TestClient) -> None:
        def chunks() -> Iterator[bytes]:
            for _ in range(30):
                yield b"x" * 65_536

        response = client.post(
            "/api/analyze", content=chunks(), headers={"content-type": "multipart/form-data; boundary=zz"}
        )
        assert response.status_code == 413 and response.json()["error"] == "file_too_large"

    def test_missing_file_field(self, client: TestClient) -> None:
        response = client.post("/api/analyze")
        body = response.json()
        assert response.status_code == 422 and body["error"] == "validation_error"
        assert any("file" in e["field"] for e in body["details"]["errors"])

    def test_rejected_uploads_never_store_a_report(self, client: TestClient) -> None:
        upload(client, b"")
        upload(client, b"prose", "a.eml")
        assert client.get("/health").json()["stored_reports"] == 0


# ================================================================ rate limiting
class TestRateLimit:
    def test_limit_and_retry_after(self, make_client: MakeClient, clean_eml: bytes) -> None:
        client = make_client(api_rate_limit_per_minute=2)
        assert [upload(client, clean_eml, "ok.eml").status_code for _ in range(2)] == [200, 200]
        response = upload(client, clean_eml, "ok.eml")
        body = response.json()
        assert response.status_code == 429 and body["error"] == "rate_limit_exceeded"
        assert int(response.headers["retry-after"]) >= 1
        assert body["details"]["retry_after_seconds"] > 0

    def test_rejected_requests_count_too(self, make_client: MakeClient, clean_eml: bytes) -> None:
        client = make_client(api_rate_limit_per_minute=2)
        assert upload(client, b"").status_code == 400
        assert upload(client, b"prose", "a.eml").status_code == 415
        assert upload(client, clean_eml, "ok.eml").status_code == 429

    def test_only_the_analyze_endpoint_is_limited(self, make_client: MakeClient, clean_eml: bytes) -> None:
        client = make_client(api_rate_limit_per_minute=1)
        body = analyzed(client, clean_eml, "ok.eml")
        assert upload(client, clean_eml, "ok.eml").status_code == 429
        report_id = body["report"]["report_id"]
        for _ in range(5):
            assert client.get("/health").status_code == 200
            assert client.get(f"/api/report/{report_id}").status_code == 200

    def test_limiter_unit(self) -> None:
        now = [0.0]
        limiter = SlidingWindowRateLimiter(2, 10, clock=lambda: now[0])
        limiter.check("a")
        limiter.check("a")
        with pytest.raises(RateLimitExceeded) as info:
            limiter.check("a")
        assert info.value.retry_after == pytest.approx(10)
        limiter.check("b")  # other clients are independent
        now[0] = 4.0
        with pytest.raises(RateLimitExceeded) as later:
            limiter.check("a")  # the rejected request above was not recorded
        assert later.value.retry_after == pytest.approx(6)
        now[0] = 10.5
        limiter.check("a")

    def test_limiter_memory_is_bounded(self) -> None:
        limiter = SlidingWindowRateLimiter(1, 60, max_clients=3)
        for i in range(20):
            limiter.check(f"client-{i}")
        assert len(limiter._hits) <= 3


# =============================================================== report store
class TestReportStore:
    def make(self, report: Report) -> Report:
        return report.model_copy(update={"report_id": uuid.uuid4().hex})

    def test_get_put_delete(self, report: Report) -> None:
        store = ReportStore()
        store.put(report)
        assert store.get(report.report_id) is report and len(store) == 1
        assert store.delete(report.report_id) is True and store.delete(report.report_id) is False
        with pytest.raises(ReportNotFoundError):
            store.get(report.report_id)

    def test_ttl_expiry(self, report: Report) -> None:
        now = [0.0]
        store = ReportStore(ttl_seconds=5, clock=lambda: now[0])
        store.put(report)
        now[0] = 4.9
        assert store.get(report.report_id) is report
        now[0] = 5.1
        with pytest.raises(ReportNotFoundError):
            store.get(report.report_id)
        assert len(store) == 0

    def test_size_cap_evicts_the_oldest(self, report: Report) -> None:
        store = ReportStore(max_reports=2)
        first, second, third = (self.make(report) for _ in range(3))
        for item in (first, second, third):
            store.put(item)
        assert len(store) == 2
        with pytest.raises(ReportNotFoundError):
            store.get(first.report_id)
        assert store.get(third.report_id) is third

    @pytest.mark.parametrize("bad", ["../etc/passwd", "zz", "", "A" * 32, "g" * 32, "a" * 31])
    def test_malformed_ids_are_not_found(self, bad: str) -> None:
        with pytest.raises(ReportNotFoundError) as info:
            ReportStore().get(bad)
        assert info.value.http_status == 404

    def test_retention_property(self) -> None:
        assert ReportStore(ttl_seconds=90).ttl_seconds == 90


# ================================================================ report routes
class TestReportRoutes:
    def test_fetch_and_download(self, client: TestClient, phishing_eml: bytes) -> None:
        body = analyzed(client, phishing_eml)
        report_id = body["report"]["report_id"]
        fetched = client.get(f"/api/report/{report_id}")
        assert fetched.status_code == 200
        assert fetched.json()["report"]["risk_score"] == body["report"]["risk_score"]
        download = client.get(f"/api/report/{report_id}", params={"download": "true"})
        assert download.headers["content-disposition"] == f'attachment; filename="report-{report_id}.json"'

    def test_delete_then_gone(self, client: TestClient, phishing_eml: bytes) -> None:
        report_id = analyzed(client, phishing_eml)["report"]["report_id"]
        deleted = client.delete(f"/api/report/{report_id}")
        assert deleted.status_code == 204 and deleted.content == b""
        again = client.delete(f"/api/report/{report_id}")
        assert again.status_code == 404 and again.json()["error"] == "report_not_found"
        assert client.get(f"/api/report/{report_id}").status_code == 404

    @pytest.mark.parametrize("bad", ["zz", "0" * 32, "..%2f..%2fetc%2fpasswd"])
    def test_unknown_and_malformed_ids(self, client: TestClient, bad: str) -> None:
        assert client.get(f"/api/report/{bad}").status_code == 404
        assert client.delete(f"/api/report/{bad}").status_code == 404

    def test_analysis_timeout(
        self, client: TestClient, phishing_eml: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def slow(*args: object, **kwargs: object) -> None:
            await asyncio.sleep(5)

        monkeypatch.setattr(routes_module, "_ANALYZE_TIMEOUT_SECONDS", 0.05)
        client.app.state.pipeline.analyze = slow  # type: ignore[attr-defined]
        response = upload(client, phishing_eml)
        assert response.status_code == 504 and response.json()["error"] == "analysis_timeout"
        assert client.get("/health").json()["stored_reports"] == 0


# ================================================================ IOC exports
class TestExports:
    @pytest.fixture
    def report_id(self, client: TestClient, phishing_eml: bytes) -> str:
        return str(analyzed(client, phishing_eml)["report"]["report_id"])

    def test_json_contains_only_defanged_values(self, client: TestClient, report_id: str, pe_bytes: bytes) -> None:
        response = client.get(f"/api/export/iocs/{report_id}")
        data = response.json()
        assert response.status_code == 200 and data["report_id"] == report_id
        assert "hxxp[://]evil[.]example/login" in [i["defanged"] for i in data["iocs"]]
        assert "http://evil.example" not in response.text
        assert [a["sha256"] for a in data["attachments"]] == [hashlib.sha256(pe_bytes).hexdigest()]

    def test_text_format_is_ticket_ready(self, client: TestClient, report_id: str, pe_bytes: bytes) -> None:
        response = client.get(f"/api/export/iocs/{report_id}", params={"format": "text"})
        lines = response.text.splitlines()
        assert response.headers["content-type"].startswith("text/plain")
        assert "hxxp[://]evil[.]example/login" in lines and hashlib.sha256(pe_bytes).hexdigest() in lines
        assert len(lines) == len(set(lines)) and not any("http://" in line for line in lines)

    def test_type_filter_is_case_insensitive_and_hash_is_a_type(self, client: TestClient, report_id: str) -> None:
        urls = client.get(f"/api/export/iocs/{report_id}", params={"format": "text", "types": ["URL"]})
        assert urls.text.splitlines() and all(line.startswith("hxxp") for line in urls.text.splitlines())
        only_hashes = client.get(f"/api/export/iocs/{report_id}", params={"types": ["hash"]}).json()
        assert only_hashes["iocs"] == [] and len(only_hashes["attachments"]) == 1
        only_urls = client.get(f"/api/export/iocs/{report_id}", params={"types": ["url"]}).json()
        assert only_urls["attachments"] == []

    def test_include_hashes_switch(self, client: TestClient, report_id: str) -> None:
        data = client.get(f"/api/export/iocs/{report_id}", params={"include_hashes": "false"}).json()
        assert data["attachments"] == [] and data["iocs"]

    def test_csv(self, client: TestClient, report_id: str) -> None:
        response = client.get(f"/api/export/iocs/{report_id}", params={"format": "csv", "download": "true"})
        rows = csv_rows(response.text)
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert response.headers["content-disposition"] == f'attachment; filename="iocs-{report_id}.csv"'
        assert rows[0] == ["kind", "type", "value", "count", "sources", "intel_verdict", "filename"]
        assert {r[0] for r in rows[1:]} == {"indicator", "attachment"}

    def test_download_names(self, client: TestClient, report_id: str) -> None:
        for fmt, ext in (("json", "json"), ("text", "txt"), ("csv", "csv")):
            response = client.get(f"/api/export/iocs/{report_id}", params={"format": fmt, "download": "true"})
            assert response.headers["content-disposition"] == f'attachment; filename="iocs-{report_id}.{ext}"'
        plain = client.get(f"/api/export/iocs/{report_id}")
        assert "content-disposition" not in plain.headers

    def test_bad_requests(self, client: TestClient, report_id: str) -> None:
        unknown = client.get(f"/api/export/iocs/{report_id}", params={"types": "bogus"})
        assert unknown.status_code == 400 and "bogus" in unknown.json()["message"]
        assert client.get(f"/api/export/iocs/{report_id}", params={"format": "xml"}).status_code == 422
        assert client.get(f"/api/export/iocs/{'0' * 32}").status_code == 404

    def test_csv_neutralises_spreadsheet_formulas(self) -> None:
        export = IocExport(
            report_id="0" * 32, filename="x", verdict=Verdict.CLEAN, risk_score=0,
            iocs=[IocExportItem(type="url", defanged="@evil", count=1, sources=[], intel_verdict="unknown")],
            attachments=[HashExportItem(filename='=HYPERLINK("http://x")', size=1, sha256="a" * 64, sha1="", md5="")],
        )
        rows = csv_rows(export.to_csv())
        assert rows[1][2] == "'@evil"
        assert rows[2][6] == "'=HYPERLINK(\"http://x\")"

    def test_export_escapes_hostile_file_names(self, report: Report) -> None:
        hostile = report.model_copy(update={"filename": "a\u202eb.eml"})
        assert IocExport.from_report(hostile).filename == "a\\u202eb.eml"


# ==================================================================== schemas
class TestSchemas:
    def test_summary_digest(self, report: Report) -> None:
        summary = ReportSummary.from_report(report)
        assert summary.verdict is Verdict.MALICIOUS and summary.report_id == report.report_id
        assert summary.from_domain == "paypa1.example"
        assert summary.from_display == '"PayPal Support" <security@paypa1.example>'.replace('"', "")
        assert summary.reply_to == ["attacker@gmail.com"]
        assert (summary.spf.status.value, summary.dmarc.status.value) == ("fail", "fail")
        assert summary.dkim.status.value == "none"
        assert (summary.hop_count, summary.origin_ip) == (2, "203.0.113.5")
        assert summary.ioc_counts["url"] >= 1
        assert (summary.attachment_count, summary.suspicious_attachment_count) == (1, 1)
        assert sum(summary.finding_counts.values()) == len(report.findings)
        assert 1 <= len(summary.top_findings) <= 5
        assert summary.top_findings[0].severity.value == "critical"
        assert summary.warning_count >= 1

    def test_error_details_are_sanitised(self) -> None:
        error = UnsupportedFormatError("bad", details={"filename": "evil\u202e\x00.exe", "size": 3})
        body = ErrorResponse.from_exception(error)
        assert body.details is not None
        assert "\u202e" not in body.details["filename"] and "\x00" not in body.details["filename"]
        assert body.details["size"] == 3

    def test_error_bodies(self) -> None:
        assert ErrorResponse.generic("x", "m").model_dump(exclude_none=True) == {"error": "x", "message": "m"}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("../../etc/passwd.eml", "passwd.eml"),
            ("C:\\Users\\x\\a.eml", "a.eml"),
            ("a\u202eb.eml", "ab.eml"),
            ("  a.eml  ", "a.eml"),
            (None, ""),
            ("", ""),
        ],
    )
    def test_sanitize_filename(self, raw: str | None, expected: str) -> None:
        assert sanitize_filename(raw) == expected

    def test_sanitize_filename_length(self) -> None:
        assert len(sanitize_filename("a" * 300)) == 255

    def test_analyze_options_direct(self) -> None:
        options = analyze_options(trusted_hops="2", trusted_authserv="a, b ,a", enrich=True, scan_macros=False)
        assert (options.trusted_hops, options.trusted_authserv_ids) == (2, ("a", "b"))
        assert (options.enrich, options.scan_macros) == (True, False)
        with pytest.raises(InputError):
            analyze_options(trusted_hops="x", trusted_authserv="", enrich=True, scan_macros=True)


# ============================================================= HTTP behaviour
class TestSecurityAndErrors:
    def test_security_headers_on_every_kind_of_response(self, client: TestClient, clean_eml: bytes) -> None:
        responses = [
            client.get("/"),
            client.get("/health"),
            client.get("/nope"),
            upload(client, clean_eml, "ok.eml"),
            upload(client, b"Received: x\r\n" + b"A" * 2_000_000),  # rejected by the middleware
        ]
        for response in responses:
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["referrer-policy"] == "no-referrer"
            csp = response.headers["content-security-policy"]
            assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp

    def test_dashboard_csp_is_strict(self, client: TestClient) -> None:
        csp = client.get("/").headers["content-security-policy"]
        assert "script-src 'self' https://cdn.tailwindcss.com;" in csp
        assert "'unsafe-eval'" not in csp and "jsdelivr" not in csp

    def test_api_responses_are_not_cached(self, client: TestClient, clean_eml: bytes) -> None:
        assert client.get("/health").headers["cache-control"] == "no-store"
        assert upload(client, clean_eml, "ok.eml").headers["cache-control"] == "no-store"
        assert "cache-control" not in client.get("/").headers

    def test_hsts_only_in_production(self, make_client: MakeClient) -> None:
        assert "strict-transport-security" not in make_client().get("/health").headers
        production = make_client(environment="production")
        assert "max-age=" in production.get("/health").headers["strict-transport-security"]

    def test_error_shapes_are_uniform_json(self, client: TestClient) -> None:
        missing = client.get("/nope")
        assert missing.status_code == 404 and missing.json() == {"error": "not_found", "message": "Not Found"}
        wrong_method = client.get("/api/analyze")
        assert wrong_method.status_code == 405 and wrong_method.json()["error"] == "method_not_allowed"
        assert wrong_method.headers["content-type"].startswith("application/json")

    def test_unhandled_errors_are_clean_500s(self, make_client: MakeClient) -> None:
        app = create_app(Settings(offline=True))

        @app.get("/boom")
        def boom() -> None:
            raise RuntimeError("secret internals")

        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/boom")
        assert response.status_code == 500 and response.json()["error"] == "internal_error"
        assert "secret" not in response.text and "x-frame-options" in response.headers

    def test_api_docs_can_be_switched_off(self, make_client: MakeClient) -> None:
        on = make_client()
        assert on.get("/docs").status_code == 200
        assert "cdn.jsdelivr.net" in on.get("/docs").headers["content-security-policy"]
        assert on.get("/openapi.json").status_code == 200
        off = make_client(enable_api_docs=False)
        assert [off.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")] == [404, 404, 404]

    def test_cors_is_off_unless_configured(self, make_client: MakeClient) -> None:
        origin = {"Origin": "https://soc.example"}
        assert "access-control-allow-origin" not in make_client().get("/health", headers=origin).headers
        configured = make_client(api_cors_origins="https://soc.example")
        assert configured.get("/health", headers=origin).headers["access-control-allow-origin"] == "https://soc.example"
        other = configured.get("/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in other.headers