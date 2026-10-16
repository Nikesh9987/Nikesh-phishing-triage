"""Tests for ``analyzers/header_anomalies.py`` (offline, pure CPU)."""

from datetime import UTC, datetime, timedelta

import pytest

from phishtriage.analyzers import header_anomalies as ha
from phishtriage.analyzers.header_anomalies import DEFAULT_BRANDS, AnomalyAnalyzer, analyze_anomalies
from phishtriage.analyzers.ioc_extractor import IOCExtractor
from phishtriage.analyzers.received_tracer import ReceivedTracer
from phishtriage.core.models import (
    IOC,
    SEVERITY_WEIGHT,
    AuthMethod,
    AuthReport,
    AuthResult,
    AuthSource,
    AuthStatus,
    DmarcPolicy,
    HeaderField,
    Hop,
    HopIP,
    IOCType,
    IPScope,
    OriginatingMTA,
    ParsedAddress,
    ParsedMessage,
    ReceivedTrace,
    Severity,
)
from phishtriage.parsers.base import parse_message

S = Severity
H = HeaderField
NOW = datetime.now(UTC)
ALICE = ParsedAddress(display_name="Alice", address="alice@partner.example")


def msg(
    sender: ParsedAddress | None = ALICE,
    *,
    from_count: int = 1,
    date_header: bool = True,
    extra: tuple[tuple[str, str], ...] = (),
    **fields: object,
) -> ParsedMessage:
    """A clean baseline message; override any field."""
    headers = [H(name="From", value="x") for _ in range(from_count if sender is not None else 0)]
    if date_header:
        headers.append(H(name="Date", value="x"))
    headers += [H(name=n, value=v) for n, v in extra]
    values: dict[str, object] = {
        "from_address": sender,
        "subject": "Hello",
        "message_id": "id1@partner.example",
        "date": NOW - timedelta(hours=1),
    }
    values.update(fields)
    return ParsedMessage(source_format="eml", headers=headers, **values)  # type: ignore[arg-type]


def run(message: ParsedMessage, **kwargs: object) -> dict[str, object]:
    result = analyze_anomalies(message, **kwargs)  # type: ignore[arg-type]
    return {f.code: f for f in result.findings}


def sev(findings: dict[str, object], code: str) -> Severity:
    return findings[code].severity  # type: ignore[attr-defined,no-any-return]


def ioc(ioc_type: IOCType, value: str) -> IOC:
    return IOC(type=ioc_type, value=value, defanged=value)


def addr(address: str, name: str = "") -> ParsedAddress:
    return ParsedAddress(display_name=name, address=address)


# ================================================================== baseline
def test_clean_message_has_no_findings() -> None:
    assert run(msg()) == {}


def test_one_finding_per_code_sorted_by_severity() -> None:
    message = msg(
        addr("x@paypa1.example", "PayPal Support"),
        reply_to=[addr("a@gmail.com")],
        body_html="".join(f'<a href="http://t{i}.evil.example/">https://www.bank{i}.example/</a>' for i in range(3)),
    )
    findings = analyze_anomalies(message).findings
    assert len({f.code for f in findings}) == len(findings)
    weights = [SEVERITY_WEIGHT[f.severity] for f in findings]
    assert weights == sorted(weights, reverse=True)


# ========================================================== header consistency
class TestHeaderConsistency:
    def test_missing_unparseable_and_multiple_from(self) -> None:
        assert sev(run(msg(None)), "missing_from") is S.MEDIUM
        assert sev(run(msg(from_count=2)), "multiple_from") is S.HIGH
        assert sev(run(msg(addr("", "junk"))), "unparseable_from") is S.MEDIUM

    def test_exchange_x500_sender(self) -> None:
        found = run(msg(addr("/O=EXCH/OU=X/CN=RECIPIENTS/CN=bob")))
        assert sev(found, "exchange_x500_sender") is S.LOW

    def test_reply_to_mismatch_severity(self) -> None:
        assert sev(run(msg(reply_to=[addr("a@gmail.com")])), "reply_to_mismatch") is S.HIGH  # free-mail
        assert sev(run(msg(reply_to=[addr("a@other.example")])), "reply_to_mismatch") is S.MEDIUM

    @pytest.mark.parametrize(
        "reply",
        ["alice@mail.partner.example", "alice@partner.example"],
    )
    def test_reply_to_in_the_same_organisation_is_fine(self, reply: str) -> None:
        assert "reply_to_mismatch" not in run(msg(reply_to=[addr(reply)]))

    def test_freemail_to_freemail_is_not_escalated(self) -> None:
        found = run(msg(addr("a@gmail.com"), reply_to=[addr("b@yahoo.com")]))
        assert sev(found, "reply_to_mismatch") is S.MEDIUM

    def test_return_path(self) -> None:
        assert sev(run(msg(return_path="bounce@mailer.other.example")), "return_path_mismatch") is S.LOW
        assert "return_path_mismatch" not in run(msg(return_path="bounce@mail.partner.example"))

    def test_sender_header_and_message_id(self) -> None:
        assert sev(run(msg(extra=(("Sender", "bob@other.example"),))), "sender_header_mismatch") is S.LOW
        found = run(msg(message_id="abc@mailer.other.example"))
        assert sev(found, "message_id_domain_mismatch") is S.INFO

    def test_dates_and_message_id_presence(self) -> None:
        assert sev(run(msg(message_id="")), "missing_message_id") is S.LOW
        assert sev(run(msg(date_header=False)), "missing_date") is S.LOW
        assert sev(run(msg(date=None)), "unparseable_date") is S.LOW
        assert sev(run(msg(date=NOW + timedelta(days=10))), "date_in_future") is S.LOW

    def test_fake_reply_thread(self) -> None:
        assert sev(run(msg(subject="Re: invoice")), "fake_reply_thread") is S.LOW
        assert sev(run(msg(subject="Fwd: invoice")), "fake_reply_thread") is S.LOW
        assert "fake_reply_thread" not in run(msg(subject="Re: x", extra=(("In-Reply-To", "<a@b>"),)))


# ============================================================= display name
class TestDisplayName:
    def test_address_in_display_name_differs_from_sender(self) -> None:
        found = run(msg(addr("x@evil.example", "ceo@corp.example")))
        assert sev(found, "display_name_address_spoof") is S.HIGH

    def test_matching_address_in_display_name_is_fine(self) -> None:
        assert "display_name_address_spoof" not in run(msg(addr("alice@partner.example", "alice@partner.example")))

    def test_domain_in_display_name(self) -> None:
        found = run(msg(addr("x@evil.example", "paypal.com support")))
        assert sev(found, "display_name_domain_mismatch") is S.MEDIUM

    def test_brand_impersonation_severity(self) -> None:
        assert sev(run(msg(addr("x@evil.example", "PayPal Support"))), "display_name_brand_impersonation") is S.MEDIUM
        assert sev(run(msg(addr("x@gmail.com", "PayPal Support"))), "display_name_brand_impersonation") is S.HIGH

    def test_legitimate_brand_sender_is_not_flagged(self) -> None:
        found = run(msg(addr("service@paypal.com", "PayPal")))
        assert not [c for c in found if c.startswith(("display_name", "lookalike"))]
        assert "display_name_brand_impersonation" not in run(msg(addr("a@outlook.com", "Microsoft Team")))

    def test_hidden_characters_are_flagged_and_escaped(self) -> None:
        result = analyze_anomalies(msg(addr("x@evil.example", "Bank\u202e Support")))
        finding = next(f for f in result.findings if f.code == "display_name_hidden_characters")
        assert finding.severity is S.MEDIUM
        assert all("\u202e" not in e for e in finding.evidence)
        assert any("\\u202e" in e for e in finding.evidence)


# ============================================================ lookalike domains
class TestLookalikes:
    @pytest.mark.parametrize(
        ("domain", "brand", "severity"),
        [
            ("paypa1.com", "paypal", S.HIGH),
            ("rnicrosoft.com", "microsoft", S.HIGH),
            ("g00gle.com", "google", S.HIGH),
            ("gooogle.com", "google", S.HIGH),
            ("paypal-secure.net", "paypal", S.MEDIUM),
            ("paypalsecure.net", "paypal", S.MEDIUM),
            ("paypal.com.evil.example", "paypal", S.HIGH),
        ],
    )
    def test_detected(self, domain: str, brand: str, severity: Severity) -> None:
        hit = ha._lookalike(domain, DEFAULT_BRANDS)
        assert hit is not None
        assert (hit[0], hit[2]) == (brand, severity)

    @pytest.mark.parametrize(
        "domain",
        ["paypal.com", "www.paypal.com", "paypal.de", "example.org", "apples.com", "partner.example"],
    )
    def test_not_detected(self, domain: str) -> None:
        assert ha._lookalike(domain, DEFAULT_BRANDS) is None

    def test_sender_lookalike_finding(self) -> None:
        assert sev(run(msg(addr("x@paypa1.example"))), "lookalike_sender_domain") is S.HIGH

    def test_domain_found_in_content(self) -> None:
        found = run(msg(), iocs=[ioc(IOCType.DOMAIN, "secure-paypal.example")])
        assert sev(found, "lookalike_domain_in_content") is S.MEDIUM

    def test_mixed_script_idn_sender(self) -> None:
        found = run(msg(addr("x@p\u0430ypal.com")))  # Cyrillic a
        assert sev(found, "idn_sender_domain") is S.HIGH
        assert "lookalike_sender_domain" in found

    def test_accented_latin_idn_is_low(self) -> None:
        assert sev(run(msg(addr("x@m\u00fcnchen.example"))), "idn_sender_domain") is S.LOW

    def test_custom_brands_replace_the_defaults(self) -> None:
        brands = {"acme": ["acme.example"]}
        assert sev(run(msg(addr("x@acrne.example")), brands=brands), "lookalike_sender_domain") is S.HIGH
        assert "lookalike_sender_domain" not in run(msg(addr("x@acme.example")), brands=brands)
        assert "lookalike_sender_domain" not in run(msg(addr("x@paypa1.example")), brands=brands)


# ================================================================= HTML body
class TestHtml:
    def test_link_text_mismatch(self) -> None:
        html = '<a href="http://evil.example/login">https://www.paypal.com/signin</a>'
        result = analyze_anomalies(msg(body_html=html))
        finding = next(f for f in result.findings if f.code == "link_text_mismatch")
        assert finding.severity is S.HIGH
        assert all("http://evil.example" not in e for e in finding.evidence)  # defanged

    def test_two_label_link_text_is_flagged(self) -> None:
        assert "link_text_mismatch" in run(msg(body_html='<a href="http://evil.example/">paypal.com</a>'))

    def test_link_to_an_ip_is_flagged(self) -> None:
        assert "link_text_mismatch" in run(msg(body_html='<a href="http://203.0.113.9/">paypal.com</a>'))

    @pytest.mark.parametrize(
        "html",
        [
            '<a href="https://login.paypal.com/x">https://www.paypal.com/</a>',
            '<a href="https://www.paypal.com/x">paypal.com</a>',
            '<a href="http://x.example/dl">invoice.pdf</a>',
            '<a href="http://x.example/dl">Click here</a>',
            '<a href="http://x.example/dl">Sign in to paypal.com</a>',
        ],
    )
    def test_no_false_link_mismatch(self, html: str) -> None:
        assert "link_text_mismatch" not in run(msg(body_html=html))

    def test_forms_and_password_fields(self) -> None:
        found = run(msg(body_html='<form action="http://evil.example/p"><input type="password"></form>'))
        assert sev(found, "html_form_in_body") is S.MEDIUM
        assert sev(found, "html_password_field") is S.HIGH

    def test_evidence_is_capped(self) -> None:
        html = "".join(f'<a href="http://t{i}.evil.example/x">https://www.bank{i}.example/</a>' for i in range(12))
        finding = next(f for f in analyze_anomalies(msg(body_html=html)).findings if f.code == "link_text_mismatch")
        assert len(finding.evidence) == 10

    def test_script_text_is_not_visible_text(self) -> None:
        html = '<script>var a="urgent act now";</script><p>Hello</p>'
        assert "social_engineering_language" not in run(msg(body_html=html))


# ==================================================================== URLs
class TestUrls:
    def test_userinfo_trick(self) -> None:
        assert sev(run(msg(), iocs=[ioc(IOCType.URL, "http://paypal.com@203.0.113.9/x")]), "url_userinfo") is S.HIGH
        assert sev(run(msg(), iocs=[ioc(IOCType.URL, "http://user@evil.example/")]), "url_userinfo") is S.MEDIUM

    @pytest.mark.parametrize("url", ["http://203.0.113.9/x", "http://3405803781/x", "http://[2001:db8::1]/x"])
    def test_ip_hosts(self, url: str) -> None:
        assert sev(run(msg(), iocs=[ioc(IOCType.URL, url)]), "url_ip_host") is S.MEDIUM

    def test_idn_host_and_shortener(self) -> None:
        assert sev(run(msg(), iocs=[ioc(IOCType.URL, "http://xn--pypal-4ve.com/")]), "url_idn_host") is S.HIGH
        assert sev(run(msg(), iocs=[ioc(IOCType.URL, "http://bit.ly/abc")]), "url_shortener") is S.LOW

    def test_ordinary_url_is_quiet(self) -> None:
        assert run(msg(), iocs=[ioc(IOCType.URL, "https://partner.example/a")]) == {}


# ================================================================= language
class TestLanguage:
    def test_three_categories_is_medium(self) -> None:
        text = "Your account will be suspended within 24 hours. Verify your account and confirm your password. Invoice attached."
        assert sev(run(msg(body_text=text)), "social_engineering_language") is S.MEDIUM

    def test_two_weak_hits_is_low(self) -> None:
        found = run(msg(body_text="Please see the invoice and refund details."))
        assert sev(found, "social_engineering_language") is S.LOW

    def test_single_hit_and_benign_text_are_ignored(self) -> None:
        assert "social_engineering_language" not in run(msg(body_text="Please see the invoice."))
        assert "social_engineering_language" not in run(msg(body_text="Are we still on for lunch on Friday?"))

    def test_subject_is_included(self) -> None:
        found = run(msg(subject="URGENT: final notice", body_text="see attached invoice"))
        assert "social_engineering_language" in found


# ============================================================= authentication
def res(method: AuthMethod, status: AuthStatus, *, aligned: bool | None = None, domain: str = "partner.example") -> AuthResult:
    return AuthResult(method=method, status=status, source=AuthSource.HEADER, domain=domain, aligned=aligned)


def report(spf: AuthResult, dkim: list[AuthResult], dmarc: AuthResult, **kw: object) -> AuthReport:
    return AuthReport(from_domain="partner.example", spf=spf, dkim=dkim, dmarc=dmarc, **kw)  # type: ignore[arg-type]


class TestAuthentication:
    def test_everything_passing_and_aligned_is_quiet(self) -> None:
        auth = report(
            res(AuthMethod.SPF, S_PASS := AuthStatus.PASS, aligned=True),
            [res(AuthMethod.DKIM, S_PASS, aligned=True)],
            res(AuthMethod.DMARC, S_PASS, aligned=True),
        )
        assert run(msg(), auth=auth) == {}

    def test_spoofed_message(self) -> None:
        auth = report(
            res(AuthMethod.SPF, AuthStatus.FAIL),
            [],
            res(AuthMethod.DMARC, AuthStatus.FAIL),
            dmarc_policy=DmarcPolicy(domain="partner.example", policy="reject"),
        )
        found = run(msg(), auth=auth)
        assert sev(found, "spf_fail") is S.HIGH and sev(found, "dmarc_fail") is S.HIGH
        assert sev(found, "dkim_absent") is S.LOW
        assert "p=reject" in found["dmarc_fail"].evidence[0]  # type: ignore[attr-defined]

    def test_soft_fail_and_alignment(self) -> None:
        soft = run(msg(), auth=report(res(AuthMethod.SPF, AuthStatus.SOFTFAIL), [], res(AuthMethod.DMARC, AuthStatus.UNKNOWN)))
        assert sev(soft, "spf_softfail") is S.MEDIUM
        unaligned = report(
            res(AuthMethod.SPF, AuthStatus.PASS, aligned=False),
            [res(AuthMethod.DKIM, AuthStatus.PASS, aligned=False, domain="esp.example")],
            res(AuthMethod.DMARC, AuthStatus.PASS),
        )
        found = run(msg(), auth=unaligned)
        assert sev(found, "spf_not_aligned") is S.MEDIUM and sev(found, "dkim_not_aligned") is S.LOW

    def test_dkim_failure(self) -> None:
        auth = report(res(AuthMethod.SPF, AuthStatus.PASS, aligned=True), [res(AuthMethod.DKIM, AuthStatus.FAIL)], res(AuthMethod.DMARC, AuthStatus.PASS))
        assert sev(run(msg(), auth=auth), "dkim_fail") is S.MEDIUM

    def test_missing_dmarc_policy(self) -> None:
        auth = report(res(AuthMethod.SPF, AuthStatus.PASS, aligned=True), [res(AuthMethod.DKIM, AuthStatus.PASS, aligned=True)], res(AuthMethod.DMARC, AuthStatus.NONE))
        assert sev(run(msg(), auth=auth), "dmarc_missing") is S.LOW

    def test_no_authentication_information_at_all(self) -> None:
        found = run(msg(), auth=AuthReport())
        assert sev(found, "authentication_unavailable") is S.LOW
        assert "dkim_absent" not in found


# =============================================================== Received trace
def hop(timestamp: datetime | None = None, **kwargs: object) -> Hop:
    return Hop(index=0, raw="r", timestamp=timestamp, **kwargs)  # type: ignore[arg-type]


class TestTrace:
    def test_no_received_headers(self) -> None:
        assert sev(run(msg(), trace=ReceivedTrace()), "no_received_headers") is S.LOW

    def test_findings_from_real_tracer_output(self) -> None:
        raws = [
            "from b.example ([198.51.100.2]) by c.example; Mon, 05 Oct 2026 09:00:00 +0000",
            "from a.example ([198.51.100.1]) by b.example; Mon, 05 Oct 2026 09:30:00 +0000",
            "from z.example by a.example",
            "from f.example by y.example; Mon, 05 Oct 2099 09:00:00 +0000",
        ]
        message = ParsedMessage(source_format="eml", headers=[H(name="Received", value=r) for r in raws])
        trace = ReceivedTracer(resolve_rdns=False).trace(message)
        found = run(msg(), trace=trace)
        assert sev(found, "received_clock_skew") is S.MEDIUM
        assert sev(found, "received_future_timestamp") is S.MEDIUM
        assert sev(found, "received_no_timestamp") is S.LOW

    def test_rdns_mismatch_wording_is_matched(self) -> None:
        trace = ReceivedTrace(hops=[hop(anomalies=["Claimed host 'a.example' does not match reverse DNS 'b.example' of 8.8.8.8."])])
        assert sev(run(msg(), trace=trace), "received_rdns_mismatch") is S.LOW

    def test_origin_without_reverse_dns(self) -> None:
        ip = HopIP(address="8.8.8.8", version=4, scope=IPScope.PUBLIC, rdns_error="no PTR record")
        origin = OriginatingMTA(ip="8.8.8.8", hop_index=0, reason="r")
        found = run(msg(), trace=ReceivedTrace(hops=[hop(ips=[ip])], originating_mta=origin))
        assert sev(found, "origin_no_rdns") is S.LOW

    def test_date_header_far_from_first_hop(self) -> None:
        trace = ReceivedTrace(hops=[hop(timestamp=NOW - timedelta(days=10))])
        assert sev(run(msg(), trace=trace), "date_received_skew") is S.LOW
        close = ReceivedTrace(hops=[hop(timestamp=NOW - timedelta(hours=2))])
        assert "date_received_skew" not in run(msg(), trace=close)


# ============================================================ robustness
class TestRobustness:
    def test_a_failing_stage_does_not_hide_the_others(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(self: object, *args: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(AnomalyAnalyzer, "_header_checks", boom)
        text = "Your account will be suspended within 24 hours. Verify your account and confirm your password. Invoice attached."
        result = analyze_anomalies(msg(body_text=text))
        assert any("header consistency" in w for w in result.warnings)
        assert "social_engineering_language" in {f.code for f in result.findings}

    def test_reply_to_evidence_is_defanged(self) -> None:
        result = analyze_anomalies(msg(reply_to=[addr("attacker@gmail.com")]))
        evidence = next(f for f in result.findings if f.code == "reply_to_mismatch").evidence[0]
        assert "attacker@gmail.com" not in evidence and "[.]" in evidence


# ================================================= realistic samples (via parser)
def test_phishing_sample_end_to_end(phishing_eml: bytes) -> None:
    message = parse_message(phishing_eml)
    iocs = IOCExtractor().extract(message).iocs
    found = set(run(message, iocs=iocs))
    assert {
        "lookalike_sender_domain",
        "reply_to_mismatch",
        "link_text_mismatch",
        "html_password_field",
        "display_name_brand_impersonation",
        "social_engineering_language",
    } <= found


def test_clean_sample_has_nothing_serious(clean_eml: bytes) -> None:
    message = parse_message(clean_eml)
    findings = analyze_anomalies(message, iocs=IOCExtractor().extract(message).iocs).findings
    assert [f.code for f in findings if SEVERITY_WEIGHT[f.severity] >= SEVERITY_WEIGHT[S.MEDIUM]] == []