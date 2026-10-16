"""Tests for ``analyzers/auth_analyzer.py`` (no network: DNS is faked)."""

import ipaddress

import pytest

from phishtriage.analyzers.auth_analyzer import (
    AuthAnalyzer,
    _DnsTemp,
    _SpfEvaluator,
    analyze_auth,
)
from phishtriage.config import Settings
from phishtriage.core.models import (
    AuthSource,
    AuthStatus,
    HeaderField,
    ParsedAddress,
    ParsedMessage,
)

S = AuthStatus


def make(
    headers: list[tuple[str, str]],
    frm: str | None = "alerts@evil.example",
    return_path: str = "bounce@mail.evil.example",
) -> ParsedMessage:
    return ParsedMessage(
        source_format="eml",
        headers=[HeaderField(name=n, value=v) for n, v in headers],
        from_address=ParsedAddress(address=frm) if frm else None,
        return_path=return_path,
    )


def offline() -> AuthAnalyzer:
    return AuthAnalyzer(network=False)


class FakeDns:
    """Stands in for the analyzer's DNS wrapper."""

    def __init__(
        self,
        txt: dict[str, list[str]] | None = None,
        a: dict[str, list[str]] | None = None,
        mx: dict[str, list[str]] | None = None,
        broken: tuple[str, ...] = (),
    ) -> None:
        self.table = {k.lower(): v for k, v in (txt or {}).items()}
        self.a = {k: [ipaddress.ip_address(x) for x in v] for k, v in (a or {}).items()}
        self.m = mx or {}
        self.broken = set(broken)

    def txt(self, name: str) -> list[str]:
        name = name.lower().rstrip(".")
        if name in self.broken or "*" in self.broken:
            raise _DnsTemp("timeout")
        return list(self.table.get(name, []))

    def addresses(self, name: str, version: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        return [x for x in self.a.get(name, []) if x.version == version]

    def mx(self, name: str) -> list[str]:
        return self.m.get(name, [])


def online(monkeypatch: pytest.MonkeyPatch, fake: FakeDns) -> AuthAnalyzer:
    monkeypatch.setattr(AuthAnalyzer, "_make_dns", lambda self: fake)
    return AuthAnalyzer(network=True)


# ====================================================== Authentication-Results
AR_GOOD = (
    "mx.corp.example; spf=pass (sender ok) smtp.mailfrom=bounce@mail.evil.example; "
    "dkim=pass header.d=evil.example header.s=sel1; dmarc=pass (p=REJECT) header.from=evil.example"
)
DKIM_SIG = "v=1; a=rsa-sha256; d=evil.example; s=sel1; h=from:to:subject; bh=x; b=y"


class TestAuthenticationResults:
    def test_everything_passes_and_aligns(self) -> None:
        report = offline().analyze(make([("Authentication-Results", AR_GOOD), ("DKIM-Signature", DKIM_SIG)]))
        assert (report.spf.status, report.spf.aligned) == (S.PASS, True)  # relaxed: subdomain ok
        assert report.spf.domain == "mail.evil.example"
        assert report.dkim_overall is S.PASS
        assert (report.dkim[0].domain, report.dkim[0].selector, report.dkim[0].aligned) == (
            "evil.example", "sel1", True)
        assert (report.dmarc.status, report.dmarc.aligned) == (S.PASS, True)
        assert report.from_domain == "evil.example"
        assert report.warnings == []

    def test_spoofed_message_fails_and_a_planted_header_is_ignored(self) -> None:
        topmost = ("mx.corp.example; spf=fail smtp.mailfrom=x@other.example; dkim=none; "
                   "dmarc=fail header.from=evil.example")
        forged = ("forged.attacker.example; spf=pass smtp.mailfrom=alerts@evil.example; "
                  "dmarc=pass header.from=evil.example")
        report = offline().analyze(make([("Authentication-Results", topmost),
                                         ("Authentication-Results", forged)]))
        assert (report.spf.status, report.spf.aligned) == (S.FAIL, False)
        assert report.dmarc.status is S.FAIL
        assert any("Ignored Authentication-Results" in w and "forged.attacker.example" in w
                   for w in report.warnings)

    def test_pinned_authserv_id_is_enforced(self) -> None:
        topmost = "mx.corp.example; spf=fail smtp.mailfrom=x@other.example"
        planted = "evil.example; spf=pass smtp.mailfrom=alerts@evil.example"
        message = make([("Authentication-Results", planted), ("Authentication-Results", topmost)])
        pinned = AuthAnalyzer(network=False, trusted_authserv_ids=["mx.corp.example"]).analyze(message)
        assert pinned.spf.status is S.FAIL  # not the topmost (planted) one
        nobody = AuthAnalyzer(network=False, trusted_authserv_ids=["other.example"]).analyze(message)
        assert nobody.spf.status is S.UNKNOWN
        assert any("trusted authserv-id" in w for w in nobody.warnings)

    def test_missing_authserv_id_is_tolerated(self) -> None:
        report = offline().analyze(make([("Authentication-Results",
                                          "spf=pass smtp.mailfrom=a@evil.example; dkim=pass header.d=evil.example")]))
        assert report.spf.status is S.PASS

    def test_header_i_and_helo_are_fallback_identities(self) -> None:
        report = offline().analyze(make([("Authentication-Results",
            "mx.corp.example; spf=pass smtp.helo=mail.evil.example; dkim=pass header.i=@evil.example header.s=s1")]))
        assert report.spf.domain == "mail.evil.example"
        assert report.dkim[0].domain == "evil.example"

    def test_unparseable_header_warns(self) -> None:
        report = offline().analyze(make([("Authentication-Results", "")]))
        assert any("could not be parsed" in w for w in report.warnings)

    def test_none_only_header_gives_no_results(self) -> None:
        report = offline().analyze(make([("Authentication-Results", "mx.corp.example; none")]))
        assert report.spf.status is S.UNKNOWN and report.dkim == []

    def test_conflict_with_received_spf_is_reported(self) -> None:
        report = offline().analyze(make([
            ("Authentication-Results", "mx.corp.example; spf=pass smtp.mailfrom=a@evil.example"),
            ("Received-SPF", "fail client-ip=203.0.113.5; envelope-from=<a@evil.example>"),
        ]))
        assert report.spf.status is S.PASS
        assert any("SPF conflict" in w for w in report.warnings)

    def test_multiple_dkim_results_pass_if_any_passes(self) -> None:
        report = offline().analyze(make([("Authentication-Results",
            "mx.corp.example; dkim=fail header.d=a.example header.s=s1; dkim=pass header.d=evil.example header.s=s2")]))
        assert report.dkim_overall is S.PASS

    def test_dkim_pass_for_another_domain_is_not_aligned(self) -> None:
        report = offline().analyze(make([("Authentication-Results",
            "mx.corp.example; dkim=pass header.d=esp.example header.s=s1")]))
        assert report.dkim[0].status is S.PASS and report.dkim[0].aligned is False


# ====================================================== Received-SPF and absence
class TestFallbacksWithoutDns:
    def test_received_spf_only(self) -> None:
        report = offline().analyze(make([("Received-SPF",
            "softfail (domain owner discourages use) client-ip=203.0.113.5; "
            "envelope-from=<bounce@other.example>; helo=x.example")]))
        assert (report.spf.status, report.spf.domain, report.spf.aligned) == (S.SOFTFAIL, "other.example", False)
        assert report.spf.source is AuthSource.HEADER

    def test_no_information_at_all(self) -> None:
        report = offline().analyze(make([]))
        assert (report.spf.status, report.dmarc.status) == (S.UNKNOWN, S.UNKNOWN)
        assert report.dkim == []
        assert any("No SPF, DKIM or DMARC information" in w for w in report.warnings)

    def test_no_from_domain(self) -> None:
        report = offline().analyze(make([], frm=None))
        assert report.from_domain == ""
        assert any("No usable From domain" in w for w in report.warnings)

    def test_analyze_auth_wrapper_in_offline_mode(self) -> None:
        report = analyze_auth(make([("Authentication-Results", AR_GOOD)]), Settings(offline=True))
        assert report.spf.status is S.PASS


# ====================================================================== DKIM
class TestDkimSignatures:
    def test_signature_quirks_without_a_verdict(self) -> None:
        sig = "v=1; a=rsa-sha1; d=evil.example; s=s1; l=10; x=1000; h=to:subject; bh=a; b=b"
        report = offline().analyze(make([("DKIM-Signature", sig)]))
        assert (report.dkim[0].status, report.dkim[0].aligned) == (S.UNKNOWN, True)
        text = " ".join(report.warnings)
        for needle in ("expired", "rsa-sha1", "l=", "does not sign the From"):
            assert needle in text

    def test_malformed_signature(self) -> None:
        report = offline().analyze(make([("DKIM-Signature", "v=1; a=rsa-sha256; d=; s=")]))
        assert report.dkim[0].status is S.PERMERROR
        assert any("malformed" in w for w in report.warnings)

    @pytest.mark.parametrize(
        ("record", "status", "needle"),
        [
            (["v=DKIM1; k=rsa; p=MIGfMA0"], S.UNKNOWN, "Key record found"),
            (["v=DKIM1; t=y; p=MIGfMA0"], S.UNKNOWN, "test mode"),
            (["v=DKIM1; p="], S.FAIL, "revoked"),
            ([], S.PERMERROR, "No DKIM key record"),
        ],
    )
    def test_key_record_lookup(self, monkeypatch: pytest.MonkeyPatch, record: list[str], status: AuthStatus, needle: str) -> None:
        fake = FakeDns(txt={"sel1._domainkey.evil.example": record})
        result = online(monkeypatch, fake).analyze(make([("DKIM-Signature", DKIM_SIG)])).dkim[0]
        assert result.status is status and needle in result.detail
        assert result.source is AuthSource.DNS or status is S.PERMERROR

    def test_dns_failure_is_a_temp_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeDns(broken=("sel1._domainkey.evil.example",))
        result = online(monkeypatch, fake).analyze(make([("DKIM-Signature", DKIM_SIG)])).dkim[0]
        assert result.status is S.TEMPERROR


# ===================================================================== DMARC
SPF_PASS_ONLY = "mx.corp.example; spf=pass smtp.mailfrom=bounce@mail.evil.example; dkim=none"


class TestDmarcViaDns:
    def test_strict_alignment_fails_a_subdomain_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeDns(txt={"_dmarc.evil.example": ["v=DMARC1; p=reject; aspf=s"]})
        report = online(monkeypatch, fake).analyze(make([("Authentication-Results", SPF_PASS_ONLY)]))
        assert report.spf.aligned is False
        assert report.dmarc.status is S.FAIL and report.dmarc.source is AuthSource.DNS
        assert report.dmarc_policy is not None
        assert (report.dmarc_policy.policy, report.dmarc_policy.spf_alignment) == ("reject", "strict")

    def test_relaxed_alignment_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeDns(txt={"_dmarc.evil.example": ["v=DMARC1; p=none"]})
        report = online(monkeypatch, fake).analyze(make([("Authentication-Results", SPF_PASS_ONLY)]))
        assert (report.dmarc.status, report.dmarc.aligned) == (S.PASS, True)
        assert "Computed locally" in report.dmarc.detail

    def test_aligned_dkim_alone_is_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeDns(txt={"_dmarc.evil.example": ["v=DMARC1; p=reject"]})
        ar = ("mx.corp.example; spf=fail smtp.mailfrom=x@other.example; "
              "dkim=pass header.d=evil.example header.s=s1")
        report = online(monkeypatch, fake).analyze(make([("Authentication-Results", ar)]))
        assert report.dmarc.status is S.PASS

    def test_no_record_means_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = online(monkeypatch, FakeDns()).analyze(make([("Authentication-Results", SPF_PASS_ONLY)]))
        assert report.dmarc.status is S.NONE and report.dmarc_policy is None

    def test_policy_is_found_at_the_organizational_domain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeDns(txt={"_dmarc.evil.example": ["v=DMARC1; p=quarantine; sp=reject"]})
        report = online(monkeypatch, fake).analyze(make([], frm="x@sub.evil.example"))
        assert report.dmarc_policy is not None
        assert (report.dmarc_policy.domain, report.dmarc_policy.subdomain_policy) == ("evil.example", "reject")

    def test_header_verdict_beats_dns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeDns(txt={"_dmarc.evil.example": ["v=DMARC1; p=reject"]})
        report = online(monkeypatch, fake).analyze(make([("Authentication-Results", AR_GOOD)]))
        assert report.dmarc.source is AuthSource.HEADER

    def test_dns_failure_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = online(monkeypatch, FakeDns(broken=("*",))).analyze(make([]))
        assert report.dmarc.status is S.UNKNOWN
        assert any("DMARC lookup" in w for w in report.warnings)


# ============================================================ SPF via DNS
SPF_TABLE = {"mail.evil.example": ["v=spf1 ip4:203.0.113.0/24 -all"]}


class TestSpfFallback:
    def test_pass_and_fail_against_the_given_client_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = online(monkeypatch, FakeDns(txt=SPF_TABLE))
        passed = analyzer.analyze(make([]), client_ip="203.0.113.5")
        assert (passed.spf.status, passed.spf.source) == (S.PASS, AuthSource.DNS)
        assert any("evaluated by this tool" in w for w in passed.warnings)
        assert analyzer.analyze(make([]), client_ip="198.51.100.1").spf.status is S.FAIL

    def test_unknown_client_ip_is_not_guessed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = online(monkeypatch, FakeDns(txt=SPF_TABLE))
        assert analyzer.analyze(make([])).spf.status is S.UNKNOWN
        assert online(monkeypatch, FakeDns()).analyze(make([])).spf.status is S.NONE

    def test_helo_is_used_when_the_return_path_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        analyzer = online(monkeypatch, FakeDns(txt={"mail.evil.example": ["v=spf1 +all"]}))
        report = analyzer.analyze(make([], return_path=""), client_ip="203.0.113.5", helo="mail.evil.example")
        assert (report.spf.status, report.spf.domain) == (S.PASS, "mail.evil.example")


# ============================================================ SPF evaluator
ip = ipaddress.ip_address
TABLE = {
    "example.com": ["v=spf1 ip4:203.0.113.0/24 include:_spf.example.net ~all"],
    "_spf.example.net": ["v=spf1 ip4:198.51.100.0/24 -all"],
    "loop.example": ["v=spf1 include:loop.example -all"],
    "macro.example": ["v=spf1 exists:%{i}._x.example -all"],
    "mx.example": ["v=spf1 mx -all"],
    "dup.example": ["v=spf1 -all", "v=spf1 +all"],
    "void.example": ["v=spf1 a:v1.example a:v2.example a:v3.example -all"],
    "cidr.example": ["v=spf1 a/24 -all"],
    "redir.example": ["v=spf1 redirect=target.example"],
    "target.example": ["v=spf1 ip4:203.0.113.0/24 -all"],
    "redir-gone.example": ["v=spf1 redirect=gone.example"],
    "exists.example": ["v=spf1 exists:ok.example -all"],
    "ptr.example": ["v=spf1 ptr -all"],
    "bad.example": ["v=spf1 ip4:not-an-ip -all"],
    "v6.example": ["v=spf1 ip6:2001:db8::/32 -all"],
    "neutral.example": ["v=spf1 ?all"],
    "nomatch.example": ["v=spf1 ip4:192.0.2.1"],
    "temp.example": ["v=spf1 -all"],
    "include-gone.example": ["v=spf1 include:gone.example -all"],
}
A = {"mail.mx.example": ["192.0.2.25"], "cidr.example": ["203.0.113.1"], "ok.example": ["127.0.0.2"]}
MX = {"mx.example": ["mail.mx.example"]}


@pytest.mark.parametrize(
    ("client", "domain", "status", "needle"),
    [
        ("203.0.113.5", "example.com", S.PASS, ""),
        ("198.51.100.9", "example.com", S.PASS, ""),  # via include
        ("192.0.2.1", "example.com", S.SOFTFAIL, ""),
        ("203.0.113.5", "none.example", S.NONE, "No SPF record"),
        ("203.0.113.5", "loop.example", S.PERMERROR, "10-lookup limit"),
        ("203.0.113.5", "macro.example", S.UNKNOWN, "macros"),
        ("192.0.2.25", "mx.example", S.PASS, ""),
        ("192.0.2.99", "mx.example", S.FAIL, ""),
        ("203.0.113.5", "dup.example", S.PERMERROR, "Multiple SPF records"),
        ("203.0.113.5", "void.example", S.PERMERROR, "void"),
        ("203.0.113.77", "cidr.example", S.PASS, ""),
        ("203.0.113.5", "redir.example", S.PASS, ""),
        ("192.0.2.1", "redir.example", S.FAIL, ""),
        ("203.0.113.5", "redir-gone.example", S.PERMERROR, "no SPF record"),
        ("203.0.113.5", "include-gone.example", S.PERMERROR, "no SPF record"),
        ("203.0.113.5", "exists.example", S.PASS, ""),
        ("203.0.113.5", "ptr.example", S.UNKNOWN, "ptr"),
        ("203.0.113.5", "bad.example", S.PERMERROR, "Invalid"),
        ("2001:db8::1", "v6.example", S.PASS, ""),
        ("203.0.113.5", "v6.example", S.FAIL, ""),
        ("203.0.113.5", "neutral.example", S.NEUTRAL, ""),
        ("203.0.113.5", "nomatch.example", S.NEUTRAL, ""),
    ],
)
def test_spf_evaluator(client: str, domain: str, status: AuthStatus, needle: str) -> None:
    result, detail = _SpfEvaluator(FakeDns(TABLE, A, MX), ip(client)).evaluate(domain)
    assert result is status
    assert needle in detail


def test_spf_evaluator_reports_dns_errors() -> None:
    result, detail = _SpfEvaluator(FakeDns(TABLE, broken=("temp.example",)), ip("203.0.113.5")).evaluate("temp.example")
    assert result is S.TEMPERROR and "DNS error" in detail