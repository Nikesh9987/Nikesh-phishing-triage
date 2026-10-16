"""Tests for ``core/defang.py``."""

import pytest

from phishtriage.core.defang import (
    defang_domain,
    defang_email,
    defang_ioc,
    defang_ip,
    defang_text,
    defang_url,
    is_defanged,
    refang,
)
from phishtriage.core.models import IOCType

URLS = [
    "http://evil.example/a",
    "https://Evil.example/login.php?u=http://x.example&v=1",
    "ftp://files.example/f.zip",
    "http://user@evil.example/",
    "https://203.0.113.5:8443/path",
]


class TestDefangUrl:
    def test_basic(self) -> None:
        assert defang_url("http://evil.example/a") == "hxxp[://]evil[.]example/a"

    def test_https_and_ftp_schemes(self) -> None:
        assert defang_url("https://a.example").startswith("hxxps[://]")
        assert defang_url("ftp://a.example").startswith("fxp[://]")

    def test_every_dot_and_at_sign_is_defanged(self) -> None:
        out = defang_url("http://u@evil.example/login.php?x=1")
        assert "." not in out.replace("[.]", "")
        assert "@" not in out.replace("[@]", "")
        assert out == "hxxp[://]u[@]evil[.]example/login[.]php?x=1"

    def test_embedded_redirect_url_is_also_neutralised(self) -> None:
        out = defang_url("https://evil.example/r?u=http://x.example")
        assert "http://" not in out
        assert out == "hxxps[://]evil[.]example/r?u=hxxp[://]x[.]example"

    def test_empty_and_none_like_input(self) -> None:
        assert defang_url("") == ""
        assert defang_url("   ") == ""

    @pytest.mark.parametrize("url", URLS)
    def test_idempotent(self, url: str) -> None:
        once = defang_url(url)
        assert defang_url(once) == once

    @pytest.mark.parametrize("url", URLS)
    def test_round_trip(self, url: str) -> None:
        assert refang(defang_url(url)) == url


class TestOtherDefangers:
    def test_domain(self) -> None:
        assert defang_domain("Mail.Evil.example") == "Mail[.]Evil[.]example"

    def test_email(self) -> None:
        assert defang_email("ceo@evil.example") == "ceo[@]evil[.]example"

    def test_ipv4(self) -> None:
        assert defang_ip("203.0.113.5") == "203[.]0[.]113[.]5"

    def test_ipv6(self) -> None:
        assert defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"

    @pytest.mark.parametrize(
        ("func", "value"),
        [
            (defang_domain, "a.evil.example"),
            (defang_email, "x@evil.example"),
            (defang_ip, "203.0.113.5"),
            (defang_ip, "2001:db8::1"),
        ],
    )
    def test_idempotent(self, func, value: str) -> None:  # type: ignore[no-untyped-def]
        assert func(func(value)) == func(value)

    def test_defang_ioc_dispatch(self) -> None:
        assert defang_ioc(IOCType.URL, "http://a.example") == "hxxp[://]a[.]example"
        assert defang_ioc(IOCType.EMAIL, "a@b.example") == "a[@]b[.]example"
        assert defang_ioc(IOCType.IPV4, "203.0.113.5") == "203[.]0[.]113[.]5"
        assert defang_ioc(IOCType.IPV6, "2001:db8::1") == "2001[:]db8[:][:]1"
        assert defang_ioc(IOCType.DOMAIN, "a.example") == "a[.]example"

    def test_hashes_pass_through_stripped(self) -> None:
        digest = "ab" * 32
        assert defang_ioc(IOCType.HASH, f" {digest} ") == digest


class TestRefang:
    @pytest.mark.parametrize(
        ("defanged", "expected"),
        [
            ("hxxp[://]malicious[.]com/a", "http://malicious.com/a"),
            ("hXXps://evil(.)example/x", "https://evil.example/x"),
            ("http[:]//evil[dot]example", "http://evil.example"),
            ("fxp://files{.}example/f", "ftp://files.example/f"),
            ("user[at]evil[.]example", "user@evil.example"),
            ("user[@]evil[.]example", "user@evil.example"),
            ("203[.]0[.]113[.]5", "203.0.113.5"),
            ("2001[:]db8[:][:]1", "2001:db8::1"),
            ("meows://evil[.]example", "https://evil.example"),
        ],
    )
    def test_known_conventions(self, defanged: str, expected: str) -> None:
        assert refang(defanged) == expected

    def test_plain_text_is_unchanged(self) -> None:
        text = "http://plain.example/path and meet [at] noon"
        assert refang(text) == text

    def test_at_word_is_only_replaced_between_word_characters(self) -> None:
        assert refang("meet [at] noon") == "meet [at] noon"
        assert refang("bob[at]corp[.]example") == "bob@corp.example"

    @pytest.mark.parametrize("bad", [None, 5, b"bytes", ""])
    def test_non_string_input_gives_empty(self, bad: object) -> None:
        assert refang(bad) == ""  # type: ignore[arg-type]


class TestDetectionAndText:
    def test_is_defanged(self) -> None:
        assert is_defanged("hxxp[://]a[.]b")
        assert is_defanged("evil[.]example")
        assert not is_defanged("http://a.b")
        assert not is_defanged(None)  # type: ignore[arg-type]

    def test_defang_text_handles_urls_and_emails_in_prose(self) -> None:
        text = "Visit http://evil.example/a or mail bob@evil.example today."
        out = defang_text(text)
        assert "hxxp[://]evil[.]example/a" in out
        assert "bob[@]evil[.]example" in out
        assert out.startswith("Visit ") and out.endswith(" today.")

    def test_defang_text_leaves_bare_domains_and_versions_alone(self) -> None:
        text = "Upgrade to version 1.2.3 of example.org"
        assert defang_text(text) == text

    def test_defang_text_empty(self) -> None:
        assert defang_text("") == ""
        assert defang_text(None) == ""  # type: ignore[arg-type]