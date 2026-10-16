from __future__ import annotations
"""Tests for ``analyzers/attachment_analyzer.py``. All samples are synthetic and harmless."""

import hashlib
import io
import types
import zipfile
from collections.abc import Callable
from typing import Any

import pytest

from phishtriage.analyzers import attachment_analyzer as att
from phishtriage.analyzers.attachment_analyzer import AttachmentAnalyzer, analyze_attachments
from phishtriage.config import Settings
from phishtriage.core.models import (
    SEVERITY_WEIGHT,
    Attachment,
    ParsedMessage,
    RawAttachment,
    Severity,
)
from phishtriage.parsers.base import OLE_MAGIC

S = Severity
_filename_flags = att._filename_flags

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
LNK = b"L\x00\x00\x00" + bytes.fromhex("0114020000000000c000000000000046") + b"\x00" * 60
ONENOTE = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + b"\x00" * 32


def analyze(name: str, data: bytes, *, scan_macros: bool = False, **options: Any) -> Attachment:
    analyzer = AttachmentAnalyzer(scan_macros=scan_macros, **options)
    return analyzer.analyze_one(RawAttachment(filename=name, data=data))


def codes(attachment: Attachment) -> dict[str, Any]:  # type: ignore[name-defined]  # noqa: F821
    return {f.code: f for f in attachment.flags}


def zip_bytes(files: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def patch_first_central_entry(data: bytes, offset: int, value: bytes) -> bytes:
    """Overwrite bytes inside the first central-directory header (offset 8 = flags, 24 = size)."""
    start = data.find(b"PK\x01\x02")
    assert start >= 0
    buffer = bytearray(data)
    buffer[start + offset : start + offset + len(value)] = value
    return bytes(buffer)


# ================================================================== hashes
class TestHashesAndLimits:
    def test_hashes_match_hashlib(self) -> None:
        data = b"hello world"
        result = analyze("a.txt", data)
        assert result.md5 == hashlib.md5(data).hexdigest()  # noqa: S324
        assert result.sha1 == hashlib.sha1(data).hexdigest()  # noqa: S324
        assert result.sha256 == hashlib.sha256(data).hexdigest()
        assert result.size == len(data)

    def test_metadata_is_passed_through(self) -> None:
        raw = RawAttachment(
            filename="a.txt", data=b"x", declared_content_type="text/plain", is_inline=True
        )
        result = AttachmentAnalyzer(scan_macros=False).analyze_one(raw)
        assert (result.declared_content_type, result.is_inline) == ("text/plain", True)

    def test_empty_payload_has_no_hashes(self) -> None:
        result = analyze("x.bin", b"")
        assert (result.size, result.md5, result.sha256) == (0, "", "")
        assert codes(result)["empty_payload"].severity is S.INFO

    def test_oversized_attachment_is_listed_but_not_inspected(self) -> None:
        analyzer = AttachmentAnalyzer(max_attachment_bytes=1024, scan_macros=False)
        outcome = analyzer.analyze([RawAttachment(filename="big.bin", data=b"A" * 5000)])
        (item,) = outcome.attachments
        assert item.skipped and item.sha256 == "" and item.size == 5000
        assert "too_large_to_inspect" in codes(item)
        assert any("1,024-byte" in w for w in outcome.warnings)

    def test_one_failing_attachment_does_not_affect_the_others(self) -> None:
        class Flaky(AttachmentAnalyzer):
            def analyze_one(self, raw: RawAttachment) -> Attachment:
                if raw.filename == "bad.bin":
                    raise RuntimeError("boom")
                return super().analyze_one(raw)

        outcome = Flaky(scan_macros=False).analyze(
            [RawAttachment(filename="bad.bin", data=b"x"), RawAttachment(filename="ok.txt", data=b"ok")]
        )
        assert len(outcome.attachments) == 2
        assert outcome.attachments[1].sha256 != ""
        assert any("could not be analyzed" in w for w in outcome.warnings)

    def test_inspection_failure_keeps_the_hashes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(data: bytes) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(att, "_sniff", boom)
        result = analyze("a.bin", b"data")
        assert result.sha256 != "" and "analysis_error" in codes(result)

    def test_flags_are_sorted_most_severe_first(self, pe_bytes: bytes) -> None:
        result = analyze("invoice.pdf.exe", pe_bytes)
        weights = [SEVERITY_WEIGHT[f.severity] for f in result.flags]
        assert weights == sorted(weights, reverse=True)

    def test_analyze_attachments_uses_settings(self) -> None:
        message = ParsedMessage(
            source_format="eml", attachments=[RawAttachment(filename="big.bin", data=b"A" * 2048)]
        )
        outcome = analyze_attachments(message, Settings(max_attachment_bytes=1024), scan_macros=False)
        assert outcome.attachments[0].skipped


# ================================================================= file names
class TestFilenames:
    @pytest.mark.parametrize(
        ("name", "code", "severity"),
        [
            ("setup.exe", "executable_extension", S.HIGH),
            ("tool.jar", "executable_extension", S.HIGH),
            ("run.js", "script_extension", S.HIGH),
            ("shortcut.lnk", "script_extension", S.HIGH),
            ("book.docm", "macro_extension", S.MEDIUM),
            ("disk.iso", "disk_image_extension", S.MEDIUM),
            ("page.html", "html_attachment", S.MEDIUM),
            ("logo.svg", "html_attachment", S.MEDIUM),
            ("notes.one", "onenote_attachment", S.MEDIUM),
            ("pack.rar", "archive_attachment", S.LOW),
        ],
    )
    def test_extension_risk(self, name: str, code: str, severity: Severity) -> None:
        found = {f.code: f for f in _filename_flags(name)}
        assert found[code].severity is severity

    @pytest.mark.parametrize(
        ("name", "severity"),
        [("invoice.pdf.exe", S.HIGH), ("readme.txt.js", S.HIGH), ("report.pdf.docm", S.MEDIUM)],
    )
    def test_double_extension(self, name: str, severity: Severity) -> None:
        found = {f.code: f for f in _filename_flags(name)}
        assert found["double_extension"].severity is severity

    @pytest.mark.parametrize("name", ["my.report.final.pdf", "notes.txt", "archive.pdf.rar", "a.b.c.jpg", ""])
    def test_no_false_double_extension_or_risk(self, name: str) -> None:
        flags = _filename_flags(name)
        # archive.pdf.rar legitimately flags as archive_attachment; ensure no double_extension false positive
        assert [f for f in flags if f.code == "double_extension"] == []

    def test_bidi_override_is_flagged_and_shown_escaped(self) -> None:
        found = {f.code: f for f in _filename_flags("photo\u202egpj.exe")}
        assert found["bidi_override"].severity is S.HIGH
        assert "executable_extension" in found
        assert "\u202e" not in found["bidi_override"].description
        assert "\\u202e" in found["bidi_override"].description

    def test_invisible_and_control_characters(self) -> None:
        assert "invisible_characters" in {f.code for f in _filename_flags("a\u200bb.pdf")}
        assert "control_characters" in {f.code for f in _filename_flags("a\x01b.pdf")}

    @pytest.mark.parametrize("name", ["invoice.pdf ", "invoice.pdf.", "invoice.exe "])
    def test_trailing_space_or_dot(self, name: str) -> None:
        assert "trailing_space_or_dot" in {f.code for f in _filename_flags(name)}

    def test_trailing_space_does_not_hide_the_real_extension(self) -> None:
        assert "executable_extension" in {f.code for f in _filename_flags("invoice.exe ")}

    def test_whitespace_padding(self) -> None:
        name = "invoice" + " " * 12 + ".exe"
        assert "whitespace_padding" in {f.code for f in _filename_flags(name)}


# ============================================================== type detection
class TestDetectionAndMismatch:
    def test_executable_disguised_as_a_document_is_critical(self, pe_bytes: bytes) -> None:
        result = analyze("report.pdf", pe_bytes)
        assert codes(result)["disguised_executable"].severity is S.CRITICAL
        assert result.detected_extension == "exe"
        assert result.is_suspicious

    def test_honest_executable_name_is_not_a_mismatch(self, pe_bytes: bytes) -> None:
        found = codes(analyze("setup.exe", pe_bytes))
        assert "disguised_executable" not in found and "extension_mismatch" not in found

    def test_double_extension_pe(self, pe_bytes: bytes) -> None:
        found = codes(analyze("invoice.pdf.exe", pe_bytes))
        assert {"executable_extension", "double_extension"} <= set(found)

    def test_elf_and_lnk_content(self) -> None:
        elf = analyze("update.txt", b"\x7fELF" + b"\x00" * 60)
        assert elf.detected_extension == "elf" and "disguised_executable" in codes(elf)
        lnk = analyze("invoice.pdf", LNK)
        assert lnk.detected_extension == "lnk" and "disguised_executable" in codes(lnk)

    def test_png_named_jpg_is_a_mismatch(self) -> None:
        result = analyze("photo.jpg", PNG)
        assert result.detected_mime == "image/png"
        assert codes(result)["extension_mismatch"].severity is S.MEDIUM

    def test_matching_png_has_no_flags(self) -> None:
        assert codes(analyze("photo.png", PNG)) == {}

    def test_text_named_pdf_is_a_mismatch(self) -> None:
        result = analyze("notes.pdf", b"just some text, not a pdf")
        assert result.detected_mime == "text/plain"
        assert "extension_mismatch" in codes(result)

    def test_plain_text_is_clean(self) -> None:
        result = analyze("notes.txt", b"hello")
        assert (result.detected_extension, codes(result)) == ("txt", {})

    def test_other_formats_are_recognised(self) -> None:
        assert analyze("a.iso", b"\x00" * 0x8001 + b"CD001").detected_extension == "iso"
        assert analyze("n.one", ONENOTE).detected_extension == "one"
        assert "onenote_attachment" in codes(analyze("n.one", ONENOTE))
        rar = analyze("x.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 16)
        assert rar.detected_extension == "rar" and "archive_attachment" in codes(rar)

    def test_attached_email_is_noted(self) -> None:
        result = analyze("fwd.eml", b"From: a@b.example\r\nSubject: x\r\n\r\nbody")
        assert codes(result)["embedded_message"].severity is S.INFO

    def test_unknown_binary_is_not_flagged_for_having_no_type(self) -> None:
        assert codes(analyze("data.bin", bytes(range(256)))) == {}

    def test_is_suspicious_threshold(self) -> None:
        assert not analyze("notes.txt", b"hello").is_suspicious
        assert analyze("book.docm", zip_bytes({"[Content_Types].xml": "<Types/>", "word/document.xml": "x"})).is_suspicious


# ================================================================ ZIP / OOXML
REMOTE_TEMPLATE = (
    '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" TargetMode="External"/>'
    "</Relationships>"
)


class TestArchivesAndOoxml:
    def test_plain_docx(self, make_docx: Callable[..., bytes]) -> None:
        result = analyze("scan.docx", make_docx())
        assert result.detected_extension == "docx"
        assert "wordprocessingml" in result.detected_mime
        assert codes(result) == {}

    def test_xlsx_is_detected_from_its_parts(self) -> None:
        data = zip_bytes({"[Content_Types].xml": "<Types/>", "xl/workbook.xml": "<workbook/>"})
        assert analyze("sheet.xlsx", data).detected_extension == "xlsx"

    def test_remote_template_is_flagged_and_defanged(self, make_docx: Callable[..., bytes]) -> None:
        result = analyze("scan.docx", make_docx({"word/_rels/settings.xml.rels": REMOTE_TEMPLATE}))
        flag = codes(result)["remote_template"]
        assert flag.severity is S.HIGH
        assert "hxxp[://]evil[.]example/t[.]dotm" in flag.description
        assert "http://evil.example" not in flag.description

    def test_internal_and_hyperlink_relationships_are_ignored(self, make_docx: Callable[..., bytes]) -> None:
        rels = (
            '<Relationships><Relationship Id="1" Type=".../styles" Target="styles.xml"/>'
            '<Relationship Id="2" Type=".../hyperlink" Target="http://evil.example/" TargetMode="External"/>'
            "</Relationships>"
        )
        assert "remote_template" not in codes(analyze("a.docx", make_docx({"word/_rels/document.xml.rels": rels})))

    def test_embedded_objects_and_activex(self, make_docx: Callable[..., bytes]) -> None:
        extra = {"word/embeddings/oleObject1.bin": b"x", "word/activeX/activeX1.xml": "<x/>"}
        found = codes(analyze("a.docx", make_docx(extra)))
        assert found["embedded_objects"].severity is S.MEDIUM
        assert found["activex_controls"].severity is S.MEDIUM

    def test_macro_project_is_detected_structurally(self, make_docx: Callable[..., bytes]) -> None:
        result = analyze("a.docx", make_docx(macros=True))
        assert result.detected_extension == "docm"
        assert "macroenabled" in result.detected_mime
        assert codes(result)["vba_macros"].severity is S.MEDIUM

    def test_archive_with_an_executable(self, pe_bytes: bytes) -> None:
        data = zip_bytes({"readme.txt": "hi", "payload/setup.exe": pe_bytes})
        result = analyze("files.zip", data)
        flag = codes(result)["archive_contains_executable"]
        assert flag.severity is S.HIGH and "payload/setup.exe" in flag.description
        assert result.detected_extension == "zip"

    def test_jar_is_recognised(self) -> None:
        result = analyze("x.jar", zip_bytes({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0"}))
        assert result.detected_mime == "application/java-archive"

    def test_encrypted_entries_are_flagged(self) -> None:
        data = patch_first_central_entry(zip_bytes({"a.txt": "x"}), 8, b"\x01\x00")
        assert codes(analyze("a.zip", data))["encrypted_archive"].severity is S.MEDIUM

    def test_decompression_bomb_is_flagged_without_extracting(self) -> None:
        size = (200 * 1024 * 1024).to_bytes(4, "little")
        data = patch_first_central_entry(zip_bytes({"a.txt": "x"}), 24, size)
        flag = codes(analyze("a.zip", data))["zip_bomb_suspect"]
        assert flag.severity is S.MEDIUM and "200 MiB" in flag.description

    def test_corrupt_zip_is_a_low_flag_not_an_error(self) -> None:
        result = analyze("a.zip", b"PK\x03\x04" + b"\x00" * 40)
        assert codes(result)["malformed_archive"].severity is S.LOW

    def test_corrupt_ole_is_a_low_flag_not_an_error(self) -> None:
        result = analyze("a.doc", OLE_MAGIC + b"\x00" * 512)
        assert "malformed_ole" in codes(result)


# ================================================================== macros
def fake_olevba(*, vba: bool = True, xlm: bool = False, findings: tuple[tuple[str, str, str], ...] = ()) -> Any:
    class Parser:
        nb_autoexec = 0
        nb_suspicious = 0

        def __init__(self, name: str, data: bytes | None = None) -> None:
            pass

        def detect_vba_macros(self) -> bool:
            return vba

        def detect_xlm_macros(self) -> bool:
            return xlm

        def analyze_macros(self, show_decoded_strings: bool = False) -> list[tuple[str, str, str]]:
            return list(findings)

        def close(self) -> None:
            pass

    return types.SimpleNamespace(VBA_Parser=Parser)


class TestMacros:
    AUTO = ("AutoExec", "AutoOpen", "runs on open")
    SUSPICIOUS = ("Suspicious", "Shell", "runs programs")

    def scan(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes], fake: Any) -> dict[str, Any]:
        monkeypatch.setattr(att, "_load_olevba", lambda: fake)
        return codes(analyze("a.docm", make_docx(macros=True), scan_macros=True))

    def test_autoexec_plus_suspicious_is_critical(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        found = self.scan(monkeypatch, make_docx, fake_olevba(findings=(self.AUTO, self.SUSPICIOUS)))
        assert found["malicious_vba_pattern"].severity is S.CRITICAL
        assert "AutoOpen" in found["malicious_vba_pattern"].description
        assert "vba_macros" in found

    def test_autoexec_alone(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        found = self.scan(monkeypatch, make_docx, fake_olevba(findings=(self.AUTO,)))
        assert found["vba_autoexec"].severity is S.HIGH and "malicious_vba_pattern" not in found

    def test_suspicious_alone(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        found = self.scan(monkeypatch, make_docx, fake_olevba(findings=(self.SUSPICIOUS,)))
        assert found["vba_suspicious"].severity is S.HIGH

    def test_xlm_macros(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        found = self.scan(monkeypatch, make_docx, fake_olevba(vba=False, xlm=True))
        assert found["xlm_macros"].severity is S.HIGH and "vba_macros" not in found

    def test_missing_oletools_falls_back_to_presence(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        monkeypatch.setattr(att, "_load_olevba", lambda: None)
        found = codes(analyze("a.docm", make_docx(macros=True), scan_macros=True))
        assert "detailed analysis unavailable" in found["vba_macros"].description

    def test_parser_crash_falls_back_to_presence(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        class Broken:
            VBA_Parser = staticmethod(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

        monkeypatch.setattr(att, "_load_olevba", lambda: Broken)
        found = codes(analyze("a.docm", make_docx(macros=True), scan_macros=True))
        assert "detailed analysis failed" in found["vba_macros"].description

    def test_scan_can_be_disabled(self, monkeypatch: pytest.MonkeyPatch, make_docx: Callable[..., bytes]) -> None:
        def must_not_run() -> None:
            raise AssertionError("olevba must not be loaded")

        monkeypatch.setattr(att, "_load_olevba", must_not_run)
        assert "vba_macros" in codes(analyze("a.docm", make_docx(macros=True), scan_macros=False))


# ============================================================ PDF / RTF / HTML
class TestContentScans:
    @pytest.mark.parametrize(
        ("body", "code", "severity"),
        [
            (b"<< /S /JavaScript /JS (app.alert(1)) >>", "pdf_javascript", S.HIGH),
            (b"<< /Type /Action /S /Launch /F (cmd.exe) >>", "pdf_launch_action", S.HIGH),
            (b"<< /Type /EmbeddedFiles >>", "pdf_embedded_file", S.MEDIUM),
            (b"<< /OpenAction 4 0 R >>", "pdf_auto_action", S.MEDIUM),
            (b"trailer << /Encrypt 9 0 R >>", "pdf_encrypted", S.LOW),
        ],
    )
    def test_pdf_indicators(self, body: bytes, code: str, severity: Severity) -> None:
        result = analyze("statement.pdf", b"%PDF-1.7\n" + body)
        assert result.detected_mime == "application/pdf"
        assert codes(result)[code].severity is severity

    def test_clean_pdf_and_lookalike_names(self) -> None:
        clean = analyze("a.pdf", b"%PDF-1.4\n1 0 obj << /Type /Catalog /JavaScriptFoo 1 >> endobj")
        assert codes(clean) == {}

    def test_rtf_embedded_object(self) -> None:
        result = analyze("a.rtf", rb"{\rtf1{\object\objemb{\*\objdata 0105}}}")
        assert codes(result)["rtf_embedded_object"].severity is S.HIGH
        assert codes(analyze("b.rtf", rb"{\rtf1 hello}")) == {}

    def test_rtf_named_doc_is_a_mismatch(self) -> None:
        assert "extension_mismatch" in codes(analyze("memo.doc", rb"{\rtf1 hello}"))

    def test_html_credential_form_and_smuggling(self) -> None:
        page = (
            b'<html><body><form><input type="password" name="p"></form>'
            b'<script>var b=new Blob([atob("QQ==")]);a.href=URL.createObjectURL(b);</script></body></html>'
        )
        found = codes(analyze("login.html", page))
        assert found["html_credential_form"].severity is S.HIGH
        assert found["html_smuggling"].severity is S.HIGH
        assert found["html_attachment"].severity is S.MEDIUM

    def test_html_obfuscation_and_redirect(self) -> None:
        assert "html_obfuscated_script" in codes(analyze("a.html", b'<html><script>eval(atob("QQ=="))</script></html>'))
        redirect = b'<html><meta http-equiv="refresh" content="0;url=http://x.example/"></html>'
        assert "html_redirect" in codes(analyze("a.html", redirect))

    def test_plain_html_only_has_the_attachment_flag(self) -> None:
        assert set(codes(analyze("a.html", b"<html><body>Hello</body></html>"))) == {"html_attachment"}

    def test_svg_with_script(self) -> None:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        result = analyze("logo.svg", svg)
        assert result.detected_extension == "svg"
        assert codes(result)["svg_script"].severity is S.HIGH
        assert "svg_script" not in codes(analyze("ok.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'))