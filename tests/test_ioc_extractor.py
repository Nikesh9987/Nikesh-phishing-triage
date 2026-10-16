"""Tests for ``analyzers/ioc_extractor.py``."""

from phishtriage.analyzers.ioc_extractor import IOCExtractor, extract_iocs
from phishtriage.core.models import IOC, HeaderField, IOCSource, IOCType, ParsedMessage

H = HeaderField


def message(**kwargs: object) -> ParsedMessage:
    return ParsedMessage(source_format="eml", **kwargs)  # type: ignore[arg-type]


def values(iocs: list[IOC], ioc_type: IOCType) -> set[str]:
    return {i.value for i in iocs if i.type is ioc_type}


def extract(**kwargs: object) -> list[IOC]:
    return IOCExtractor().extract(message(**kwargs)).iocs


# ================================================================ text body
class TestTextBody:
    def test_urls_with_trailing_punctuation(self) -> None:
        iocs = extract(body_text="See (http://evil.example/login.php?x=1). Also http://b.example/a, ok!")
        assert values(iocs, IOCType.URL) == {
            "http://evil.example/login.php?x=1",
            "http://b.example/a",
        }

    def test_www_links_get_a_scheme(self) -> None:
        iocs = extract(body_text="go to www.phish.example/pay now")
        assert "http://www.phish.example/pay" in values(iocs, IOCType.URL)

    def test_defanged_input_is_found_as_live_indicator(self) -> None:
        iocs = extract(body_text="hxxps[://]cdn[.]evil[.]example/x[.]js and bob[at]evil[.]example")
        assert "https://cdn.evil.example/x.js" in values(iocs, IOCType.URL)
        assert "bob@evil.example" in values(iocs, IOCType.EMAIL)

    def test_value_is_live_and_defanged_is_safe(self) -> None:
        (url,) = [i for i in extract(body_text="http://evil.example/a") if i.type is IOCType.URL]
        assert url.value == "http://evil.example/a"
        assert url.defanged == "hxxp[://]evil[.]example/a"

    def test_url_host_is_lowercased_but_path_keeps_case(self) -> None:
        iocs = extract(body_text="http://EVIL.Example/Path/ABC")
        assert "http://evil.example/Path/ABC" in values(iocs, IOCType.URL)

    def test_domains_come_from_urls_and_emails(self) -> None:
        iocs = extract(body_text="http://login.evil.example/a and bob@other.example")
        assert values(iocs, IOCType.DOMAIN) == {"login.evil.example", "other.example"}

    def test_emails_are_lowercased(self) -> None:
        assert "help@evil.example" in values(extract(body_text="Help@Evil.example"), IOCType.EMAIL)

    def test_email_in_url_query_is_not_a_separate_email_ioc(self) -> None:
        iocs = extract(body_text="http://evil.example/r?email=victim@corp.example")
        assert values(iocs, IOCType.EMAIL) == set()

    def test_url_userinfo_is_not_an_email_ioc(self) -> None:
        iocs = extract(body_text="http://trusted@evil.example/x")
        assert values(iocs, IOCType.EMAIL) == set()

    def test_cid_reference_is_not_an_email(self) -> None:
        iocs = extract(body_text="[cid:image001.png@01D6A1B2.3C4D5E60]")
        assert values(iocs, IOCType.EMAIL) == set()

    def test_single_integer_host_is_decoded_to_an_ip(self) -> None:
        iocs = extract(body_text="http://3405803781/x")
        assert "203.0.113.5" in values(iocs, IOCType.IPV4)

    def test_empty_body(self) -> None:
        assert extract(body_text="") == []


# ==================================================================== IPs
class TestIpAddresses:
    def test_public_and_documentation_ips_are_reported(self) -> None:
        iocs = extract(body_text="a 8.8.8.8 b 203.0.113.9 c 2001:db8::5 d 2606:4700::1111")
        assert values(iocs, IOCType.IPV4) == {"8.8.8.8", "203.0.113.9"}
        assert values(iocs, IOCType.IPV6) == {"2001:db8::5", "2606:4700::1111"}

    def test_private_loopback_and_link_local_are_skipped_by_default(self) -> None:
        iocs = extract(body_text="10.1.1.1 192.168.0.1 127.0.0.1 169.254.1.1 fd00::1")
        assert values(iocs, IOCType.IPV4) == set()
        assert values(iocs, IOCType.IPV6) == set()

    def test_non_public_ips_can_be_included(self) -> None:
        result = IOCExtractor(include_non_public_ips=True).extract_text("gw 10.1.1.1")
        assert values(result.iocs, IOCType.IPV4) == {"10.1.1.1"}

    def test_version_numbers_and_invalid_octets_are_ignored(self) -> None:
        iocs = extract(body_text="version 1.2.3.4.5 and 999.1.1.1")
        assert values(iocs, IOCType.IPV4) == set()


# ================================================================== headers
class TestHeaders:
    HEADERS = [
        H(name="Received", value="from mail.evil.example ([203.0.113.5]) by mx.corp.example for <victim@corp.example>"),
        H(name="Received", value="from internal (10.0.0.5) by gw"),
        H(name="From", value='"Bank" <alerts@evil.example>'),
        H(name="Reply-To", value="attacker@other.example"),
        H(name="To", value="victim@corp.example"),
        H(name="Message-ID", value="<abc@mailer.example>"),
        H(name="DKIM-Signature", value="v=1; d=signer.example; s=sel; b=abc@junk.example"),
    ]

    def test_received_headers_yield_only_ips(self) -> None:
        iocs = extract(headers=self.HEADERS)
        assert "203.0.113.5" in values(iocs, IOCType.IPV4)
        assert "victim@corp.example" not in values(iocs, IOCType.EMAIL)  # from the Received "for" clause
        sources = {s for i in iocs if i.value == "203.0.113.5" for s in i.sources}
        assert sources == {IOCSource.RECEIVED}

    def test_private_received_ip_is_skipped(self) -> None:
        assert "10.0.0.5" not in values(extract(headers=self.HEADERS), IOCType.IPV4)

    def test_sender_headers_are_scanned_but_recipients_are_not(self) -> None:
        emails = values(extract(headers=self.HEADERS), IOCType.EMAIL)
        assert {"alerts@evil.example", "attacker@other.example"} <= emails
        assert "victim@corp.example" not in emails

    def test_message_id_and_signature_blobs_are_skipped(self) -> None:
        iocs = extract(headers=self.HEADERS)
        assert "abc@mailer.example" not in values(iocs, IOCType.EMAIL)
        assert "junk.example" not in values(iocs, IOCType.DOMAIN)

    def test_decoded_subject_is_scanned_instead_of_the_raw_header(self) -> None:
        iocs = extract(
            headers=[H(name="Subject", value="=?UTF-8?Q?See_http=3A//x?=")],
            subject="See hxxp[://]sub[.]evil[.]example/a",
        )
        assert "http://sub.evil.example/a" in values(iocs, IOCType.URL)


# =================================================================== HTML
class TestHtml:
    def test_attributes_and_visible_text(self) -> None:
        html = (
            '<a href="https://login.evil.example/a?u=1">https://bank.example/</a>'
            '<img src="//track.evil.example/p.gif">'
            '<a href="mailto:Help@Evil.example?subject=x">mail</a>'
        )
        iocs = extract(body_html=html)
        urls = values(iocs, IOCType.URL)
        assert {
            "https://login.evil.example/a?u=1",
            "https://bank.example/",
            "http://track.evil.example/p.gif",
        } <= urls
        assert "help@evil.example" in values(iocs, IOCType.EMAIL)

    def test_script_style_and_comments_are_scanned(self) -> None:
        html = (
            "<script>location='http://js.evil.example/r'</script>"
            "<style>a{background:url(http://css.evil.example/b.png)}</style>"
            '<!--[if mso]><a href="http://mso.evil.example/">x</a><![endif]-->'
        )
        urls = values(extract(body_html=html), IOCType.URL)
        assert {"http://js.evil.example/r", "http://mso.evil.example/"} <= urls
        assert any(u.startswith("http://css.evil.example/b.png") for u in urls)

    def test_meta_refresh_target_is_found(self) -> None:
        html = '<meta http-equiv="refresh" content="0;url=http://redirect.evil.example/x">'
        assert "http://redirect.evil.example/x" in values(extract(body_html=html), IOCType.URL)

    def test_whitespace_inside_href_is_stripped(self) -> None:
        html = '<a href="ht\ntp://evil.example/a">x</a>'
        assert "http://evil.example/a" in values(extract(body_html=html), IOCType.URL)

    def test_sources_are_recorded_per_body_part(self) -> None:
        iocs = extract(body_text="http://same.example/a", body_html='<a href="http://same.example/a">x</a>')
        (url,) = [i for i in iocs if i.type is IOCType.URL and i.value == "http://same.example/a"]
        assert set(url.sources) == {IOCSource.BODY_TEXT, IOCSource.BODY_HTML}
        assert url.count >= 2


# ================================================ dedup, order, caps, safety
class TestDeduplicationAndLimits:
    def test_duplicates_are_merged_with_a_count(self) -> None:
        iocs = extract(body_text="http://a.example/x http://a.example/x http://a.example/x")
        (url,) = [i for i in iocs if i.type is IOCType.URL]
        assert url.count == 3

    def test_results_are_grouped_by_type(self) -> None:
        order = [i.type for i in extract(body_text="203.0.113.9 bob@a.example http://b.example/")]
        ranks = {IOCType.URL: 0, IOCType.EMAIL: 1, IOCType.DOMAIN: 2, IOCType.IPV4: 3}
        assert [ranks[t] for t in order] == sorted(ranks[t] for t in order)

    def test_per_type_cap_warns(self) -> None:
        result = IOCExtractor(max_per_type=2).extract_text("http://a.example http://b.example http://c.example")
        assert len(values(result.iocs, IOCType.URL)) == 2
        assert any("IOC limit (2)" in w and "url" in w for w in result.warnings)

    def test_cap_still_counts_sightings_of_kept_items(self) -> None:
        result = IOCExtractor(max_per_type=1).extract_text("http://a.example http://b.example http://a.example")
        (url,) = [i for i in result.iocs if i.type is IOCType.URL]
        assert url.value == "http://a.example" and url.count == 2

    def test_huge_input_is_truncated_with_a_warning(self) -> None:
        result = IOCExtractor().extract_text("A" * 5_000_100 + " http://late.example/")
        assert any("only the start was scanned" in w for w in result.warnings)
        assert "http://late.example/" not in values(result.iocs, IOCType.URL)

    def test_pathological_input_finishes_quickly(self) -> None:
        # Long runs of address-like characters must not cause catastrophic backtracking.
        hostile = ("a" * 200_000) + "@" + ("b." * 50_000) + "\n" + ("1." * 100_000)
        result = IOCExtractor().extract_text(hostile)
        assert isinstance(result.iocs, list)

    def test_non_string_and_empty_text(self) -> None:
        extractor = IOCExtractor()
        assert extractor.extract_text("").iocs == []
        assert extractor.extract_text(None).iocs == []  # type: ignore[arg-type]

    def test_extract_iocs_uses_settings_cap(self) -> None:
        from phishtriage.config import Settings

        msg = message(body_text=" ".join(f"http://h{i}.example/" for i in range(5)))
        result = extract_iocs(msg, Settings(max_iocs_per_type=3))
        assert len(values(result.iocs, IOCType.URL)) == 3