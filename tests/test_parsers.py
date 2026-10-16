"""Tests for ``parsers/base.py`` and the .eml parser, plus the .msg error path."""

import pytest

from phishtriage.config import Settings
from phishtriage.core.exceptions import (
    EmptyInputError,
    FileTooLargeError,
    InputError,
    MalformedMessageError,
    UnsupportedFormatError,
)
from phishtriage.parsers.base import (
    OLE_MAGIC,
    clean_header_text,
    decode_header_value,
    detect_format,
    looks_like_eml,
    parse_addresses,
    parse_date,
    parse_message,
    validate_input,
)
from phishtriage.parsers.eml_parser import EmlParser

SIMPLE = b"Subject: hi\r\nFrom: a@b.example\r\nDate: Mon, 12 Oct 2026 08:59:00 +0000\r\n\r\nbody\r\n"


# ================================================================= validation
class TestValidation:
    def test_empty_and_whitespace_are_rejected(self) -> None:
        for data in (b"", b"   \r\n\t "):
            with pytest.raises(EmptyInputError):
                validate_input(data, 1024)

    def test_non_bytes_is_rejected(self) -> None:
        with pytest.raises(InputError):
            validate_input("text", 1024)  # type: ignore[arg-type]

    def test_oversized_is_rejected_with_details(self) -> None:
        with pytest.raises(FileTooLargeError) as info:
            validate_input(b"A" * 2000, 1024)
        assert info.value.http_status == 413
        assert info.value.details == {"size": 2000, "limit": 1024}

    def test_parse_message_enforces_the_configured_limit(self) -> None:
        data = b"Subject: x\r\n\r\n" + b"A" * 2000
        with pytest.raises(FileTooLargeError):
            parse_message(data, "a.eml", settings=Settings(max_upload_bytes=1024))


# ================================================================== detection
class TestDetection:
    def test_eml_is_detected_from_content(self) -> None:
        assert detect_format(SIMPLE) == "eml"

    def test_ole_magic_means_msg_even_with_an_eml_name(self) -> None:
        assert detect_format(OLE_MAGIC + b"\x00" * 64, "evil.eml") == "msg"

    def test_text_content_wins_over_a_msg_name(self) -> None:
        assert detect_format(SIMPLE, "renamed.msg") == "eml"

    @pytest.mark.parametrize("data", [b"just some prose", b"\x00\x01\x02 binary", b"Hello: world"])
    def test_unrecognised_content_is_unsupported(self, data: bytes) -> None:
        with pytest.raises(UnsupportedFormatError) as info:
            detect_format(data, "x.eml")
        assert info.value.http_status == 415

    def test_looks_like_eml_heuristics(self) -> None:
        assert looks_like_eml(b"From a@b.example Mon Oct 5\nSubject: x\n\nbody")  # mbox line
        assert looks_like_eml(b"X-Custom: 1\r\n\r\n")
        assert not looks_like_eml(b"Subject: x\x00\r\n")
        assert not looks_like_eml(b"no colon here\r\nSubject: x")


# ============================================================ text helpers
class TestHelpers:
    def test_header_unfolding(self) -> None:
        assert clean_header_text("a\r\n b\r\n\tc") == "a b c"

    def test_control_characters_are_removed(self) -> None:
        assert clean_header_text("a\x00b\x07c") == "abc"

    def test_rfc2047_decoding(self) -> None:
        assert decode_header_value("=?UTF-8?B?QmFuayDwn4+m?=") == "Bank \U0001f3e6"
        assert decode_header_value("=?UTF-8?Q?Urgent:_verify?=") == "Urgent: verify"

    def test_broken_encoded_word_does_not_raise(self) -> None:
        assert isinstance(decode_header_value("=?nonsense-charset?B?!!!?="), str)

    def test_address_parsing(self) -> None:
        parsed = parse_addresses(['"Bob" <bob@Example.COM>, alice@x.example'])
        assert [a.address for a in parsed] == ["bob@Example.COM", "alice@x.example"]
        assert parsed[0].display_name == "Bob"
        assert parsed[0].domain == "example.com"

    def test_address_parsing_drops_empty_entries(self) -> None:
        assert parse_addresses(["", "  "]) == []

    def test_date_parsing(self) -> None:
        parsed = parse_date("Mon, 05 Oct 2026 09:00:00 +0200")
        assert parsed is not None and parsed.utcoffset() is not None
        naive_zone = parse_date("Mon, 05 Oct 2026 09:00:00 -0000")
        assert naive_zone is not None and naive_zone.tzinfo is not None
        assert parse_date(None) is None
        assert parse_date("garbage") is None


# ================================================================= .eml parser
class TestEmlParser:
    def test_basic_fields(self, eml_builder) -> None:  # type: ignore[no-untyped-def]
        data = eml_builder(
            from_='"=?UTF-8?B?QmFuayDwn4+m?=" <Alerts@Evil.Example>',
            subject="=?UTF-8?Q?Urgent:_verify_your_account?=",
        )
        message = parse_message(data, "m.eml")
        assert message.source_format == "eml"
        assert message.subject == "Urgent: verify your account"
        assert message.from_address is not None
        assert message.from_address.display_name == "Bank \U0001f3e6"
        assert message.from_address.domain == "evil.example"
        assert message.message_id == "id1@partner.example"
        assert message.date is not None and message.date.year == 2026
        assert message.parse_warnings == []

    def test_received_headers_keep_order_and_are_unfolded(self, phishing_eml: bytes) -> None:
        hops = parse_message(phishing_eml).get_headers("Received")
        assert len(hops) == 2
        assert hops[0].startswith("from mx1.corp.example")  # newest first, as in the file
        assert all("\n" not in hop and "\r" not in hop for hop in hops)

    def test_bodies(self, phishing_eml: bytes) -> None:
        message = parse_message(phishing_eml)
        assert "http://evil.example/login" in message.body_text
        assert 'href="http://evil.example/login"' in message.body_html

    def test_attachment_is_extracted_in_memory(self, phishing_eml: bytes, pe_bytes: bytes) -> None:
        (attachment,) = parse_message(phishing_eml).attachments
        assert attachment.filename == "invoice.pdf"
        assert attachment.declared_content_type == "application/pdf"
        assert attachment.data == pe_bytes
        assert attachment.size == len(pe_bytes)

    def test_attachment_bytes_never_serialise(self, phishing_eml: bytes) -> None:
        message = parse_message(phishing_eml)
        assert "attachments" not in message.model_dump()
        assert "data" not in message.attachments[0].model_dump()

    def test_path_components_are_stripped_from_filenames(self, eml_builder) -> None:  # type: ignore[no-untyped-def]
        data = eml_builder(attachments=[("../../etc/passwd", b"x", "application", "octet-stream")])
        assert parse_message(data).attachments[0].filename == "passwd"

    def test_attached_message_is_an_attachment_not_body_text(self) -> None:
        raw = (
            b"From: a@b.example\r\nSubject: outer\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            b"--B\r\nContent-Type: text/plain\r\n\r\nouter body\r\n"
            b"--B\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n"
            b"From: boss@corp.example\r\nSubject: Forwarded request\r\n"
            b"Content-Type: text/plain\r\n\r\nPlease wire funds.\r\n--B--\r\n"
        )
        message = parse_message(raw)
        (attachment,) = message.attachments
        assert attachment.filename == "Forwarded request.eml"
        assert attachment.declared_content_type == "message/rfc822"
        assert attachment.size > 0
        assert "wire funds" not in message.body_text

    def test_multiple_from_headers_are_flagged(self) -> None:
        raw = b"From: a@x.example\r\nFrom: b@y.example\r\nSubject: s\r\n\r\nbody"
        message = parse_message(raw)
        assert any("2 From headers" in w for w in message.parse_warnings)

    def test_missing_from_is_flagged(self) -> None:
        message = parse_message(b"Subject: hi\r\nDate: Mon, 12 Oct 2026 08:59:00 +0000\r\n\r\nbody")
        assert message.from_address is None
        assert any("no From header" in w for w in message.parse_warnings)

    def test_unparseable_date_is_flagged(self) -> None:
        message = parse_message(b"From: a@b.example\r\nSubject: s\r\nDate: not a date\r\n\r\nx")
        assert message.date is None
        assert any("Date header could not be parsed" in w for w in message.parse_warnings)

    def test_attachment_cap(self, eml_builder) -> None:  # type: ignore[no-untyped-def]
        data = eml_builder(
            attachments=[(f"f{i}.bin", b"data", "application", "octet-stream") for i in range(3)]
        )
        message = EmlParser(max_attachments=2).parse(data)
        assert len(message.attachments) == 2
        assert any("Attachment limit reached" in w for w in message.parse_warnings)

    def test_header_only_garbage_is_malformed(self) -> None:
        with pytest.raises(MalformedMessageError):
            EmlParser().parse(b"\r\n\r\nno headers at all")


# =============================================================== fixtures
def test_fixture_samples_parse(phishing_eml: bytes, clean_eml: bytes) -> None:
    phish = parse_message(phishing_eml)
    assert phish.from_address is not None and phish.from_address.domain == "paypa1.example"
    assert [r.address for r in phish.reply_to] == ["attacker@gmail.com"]
    clean = parse_message(clean_eml)
    assert clean.subject == "Lunch on Friday?"
    assert clean.attachments == []


# ============================================================ .msg error path
def test_corrupt_msg_is_a_typed_error() -> None:
    pytest.importorskip("extract_msg")
    with pytest.raises(MalformedMessageError) as info:
        parse_message(OLE_MAGIC + b"\x00" * 512, "evil.msg")
    assert info.value.http_status == 422