"""Tests for ``cli/main.py`` and ``cli/render.py`` (offline; output captured)."""

import hashlib
import io
import json
import logging
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from phishtriage.cli.main import _split_csv, build_parser, main, read_input
from phishtriage.core.exceptions import FileTooLargeError, InputError
from phishtriage.core.models import TOOL_VERSION


@pytest.fixture(autouse=True)
def _cli_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Offline by default, wide terminal, and no log handler left pointing at a dead stream."""
    monkeypatch.setenv("PHISHTRIAGE_OFFLINE", "true")
    monkeypatch.setenv("COLUMNS", "200")
    yield
    logging.getLogger("phishtriage").handlers.clear()


@pytest.fixture
def phish(tmp_path: Path, phishing_eml: bytes) -> Path:
    path = tmp_path / "phish.eml"
    path.write_bytes(phishing_eml)
    return path


@pytest.fixture
def clean(tmp_path: Path, clean_eml: bytes) -> Path:
    path = tmp_path / "clean.eml"
    path.write_bytes(clean_eml)
    return path


def run(capsys: pytest.CaptureFixture[str], *argv: object) -> tuple[int, str, str]:
    code = main([str(a) for a in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ================================================================== parsing
class TestArguments:
    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as info:
            main(["--version"])
        assert info.value.code == 0
        assert TOOL_VERSION in capsys.readouterr().out

    def test_a_command_is_required(self) -> None:
        with pytest.raises(SystemExit) as info:
            main([])
        assert info.value.code == 2

    @pytest.mark.parametrize("hops", ["0", "-1", "abc"])
    def test_trusted_hops_must_be_a_positive_integer(self, hops: str, phish: Path) -> None:
        with pytest.raises(SystemExit) as info:
            main(["analyze", str(phish), "--trusted-hops", hops])
        assert info.value.code == 2

    def test_stdin_can_only_be_given_once(self) -> None:
        with pytest.raises(SystemExit) as info:
            main(["analyze", "-", "-"])
        assert info.value.code == 2

    def test_csv_splitting(self) -> None:
        assert _split_csv(["a, b", "c", " ", ",d"]) == ["a", "b", "c", "d"]

    def test_parser_defaults(self) -> None:
        args = build_parser().parse_args(["iocs", "x.eml"])
        assert (args.format, args.enrich, args.types, args.no_hashes) == ("table", False, None, False)


# =================================================================== reading
class TestReadInput:
    def test_reads_a_file(self, phish: Path, phishing_eml: bytes) -> None:
        assert read_input(str(phish), 1_000_000) == phishing_eml

    def test_limit_is_enforced(self, phish: Path) -> None:
        with pytest.raises(FileTooLargeError):
            read_input(str(phish), 100)

    def test_missing_file_and_directory(self, tmp_path: Path) -> None:
        with pytest.raises(InputError, match="not found"):
            read_input(str(tmp_path / "nope.eml"), 1000)
        with pytest.raises(InputError, match="directory"):
            read_input(str(tmp_path), 1000)

    def test_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"x" * 50)))
        assert read_input("-", 100) == b"x" * 50
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"x" * 500)))
        with pytest.raises(FileTooLargeError):
            read_input("-", 100)


# ================================================================== analyze
class TestAnalyze:
    def test_table_output(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        code, out, err = run(capsys, "analyze", phish)
        assert code == 0 and err == ""
        for needle in ("Phishing Triage", "MALICIOUS", "Findings", "Authentication",
                       "Delivery path", "estimated origin", "Attachments", "Offline mode"):
            assert needle in out

    def test_urls_and_addresses_are_defanged(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        _, out, _ = run(capsys, "analyze", phish)
        assert "hxxp[://]evil[.]example/login" in out
        assert "http://evil.example" not in out
        assert "security@paypa1.example" not in out

    def test_hashes_are_printed_unwrapped(
        self, capsys: pytest.CaptureFixture[str], phish: Path, phishing_eml: bytes, pe_bytes: bytes
    ) -> None:
        _, out, _ = run(capsys, "analyze", phish)
        assert hashlib.sha256(phishing_eml).hexdigest() in out
        assert hashlib.sha256(pe_bytes).hexdigest() in out

    def test_markup_in_a_subject_is_shown_literally(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path, eml_builder: Any
    ) -> None:
        path = tmp_path / "m.eml"
        path.write_bytes(eml_builder(subject="[bold red]URGENT[/] verify"))
        _, out, _ = run(capsys, "analyze", path)
        assert "[bold red]URGENT[/] verify" in out

    def test_direction_overrides_are_escaped_in_tables_and_json(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path, eml_builder: Any
    ) -> None:
        path = tmp_path / "m.eml"
        path.write_bytes(eml_builder(from_='"Bank\u202e Support" <x@evil.example>'))
        _, table, _ = run(capsys, "analyze", path)
        assert "\u202e" not in table and "\\u202e" in table
        _, raw_json, _ = run(capsys, "analyze", path, "--json")
        assert "\u202e" not in raw_json and "\\u202e" in raw_json

    def test_json_output(self, capsys: pytest.CaptureFixture[str], phish: Path, pe_bytes: bytes) -> None:
        code, out, _ = run(capsys, "analyze", phish, "--json")
        data = json.loads(out)
        assert code == 0 and isinstance(data, dict)
        assert data["verdict"] == "malicious" and data["risk_score"] >= 70
        assert data["filename"] == "phish.eml" and data["offline"] is True
        assert pe_bytes.hex()[:24] not in out

    def test_output_file_is_written_as_well(
        self, capsys: pytest.CaptureFixture[str], phish: Path, tmp_path: Path
    ) -> None:
        target = tmp_path / "report.json"
        code, out, err = run(capsys, "analyze", phish, "-o", target)
        assert code == 0 and "MALICIOUS" in out and "Wrote JSON report" in err
        assert json.loads(target.read_text())["verdict"] == "malicious"

    def test_several_files(self, capsys: pytest.CaptureFixture[str], phish: Path, clean: Path) -> None:
        _, out, _ = run(capsys, "analyze", phish, clean)
        assert out.count(" Phishing Triage ") == 2
        _, raw, _ = run(capsys, "analyze", phish, clean, "--json")
        data = json.loads(raw)
        assert isinstance(data, list) and [d["filename"] for d in data] == ["phish.eml", "clean.eml"]

    def test_stdin(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, phishing_eml: bytes) -> None:
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(phishing_eml)))
        code, out, _ = run(capsys, "analyze", "-", "--json")
        assert code == 0 and json.loads(out)["filename"] == ""

    def test_options_reach_the_pipeline(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        _, out, _ = run(capsys, "analyze", phish, "--json", "--trusted-hops", "1")
        assert json.loads(out)["received"]["originating_mta"] is None
        _, out, _ = run(capsys, "analyze", phish, "--json", "--trusted-authserv", "other.example")
        assert json.loads(out)["authentication"]["spf"]["status"] == "unknown"

    def test_headers_flag(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        _, plain, _ = run(capsys, "analyze", phish)
        _, with_headers, _ = run(capsys, "analyze", phish, "--headers")
        assert "Raw headers" not in plain and "Raw headers" in with_headers

    def test_verbose_logging_stays_on_stderr(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        code, out, err = run(capsys, "analyze", phish, "--json", "-vv")
        assert code == 0 and json.loads(out)["verdict"] == "malicious"
        assert "phishtriage" in err

    def test_no_color_flag(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        code, out, _ = run(capsys, "analyze", phish, "--no-color")
        assert code == 0 and "\x1b[" not in out


# ================================================================= exit codes
class TestExitCodes:
    def test_fail_on_threshold(self, capsys: pytest.CaptureFixture[str], phish: Path, clean: Path) -> None:
        assert run(capsys, "analyze", phish, "--fail-on", "suspicious")[0] == 10
        assert run(capsys, "analyze", phish, "--fail-on", "malicious")[0] == 10
        assert run(capsys, "analyze", clean, "--fail-on", "suspicious")[0] == 0
        assert run(capsys, "analyze", phish)[0] == 0  # a verdict is a result, not an error

    def test_missing_file(self, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
        code, out, err = run(capsys, "analyze", tmp_path / "nope.eml")
        assert code == 2 and out == "" and "File not found" in err

    def test_unrecognised_content(self, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
        junk = tmp_path / "junk.txt"
        junk.write_text("not an email")
        code, _, err = run(capsys, "analyze", junk)
        assert code == 2 and "not a recognised" in err

    def test_one_bad_file_does_not_stop_the_others(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path, phish: Path
    ) -> None:
        junk = tmp_path / "junk.txt"
        junk.write_text("not an email")
        code, out, err = run(capsys, "analyze", junk, phish, "--json")
        assert code == 2 and "junk.txt" in err  # the first failing file decides the code
        data = json.loads(out)
        assert isinstance(data, list) and len(data) == 1 and data[0]["filename"] == "phish.eml"

    def test_oversized_file(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, phish: Path) -> None:
        monkeypatch.setenv("PHISHTRIAGE_MAX_UPLOAD_BYTES", "1024")
        phish.write_bytes(b"Subject: x\r\n\r\n" + b"A" * 3000)
        code, _, err = run(capsys, "analyze", phish)
        assert code == 2 and "limit" in err

    def test_invalid_configuration(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PHISHTRIAGE_LOG_LEVEL", "nonsense")
        code, out, err = run(capsys, "status")
        assert code == 78 and out == "" and "Invalid configuration" in err


# ====================================================================== iocs
class TestIocs:
    def test_text_format_is_ticket_ready(
        self, capsys: pytest.CaptureFixture[str], phish: Path, pe_bytes: bytes
    ) -> None:
        code, out, _ = run(capsys, "iocs", phish, "--format", "text")
        lines = out.splitlines()
        assert code == 0
        assert "hxxp[://]evil[.]example/login" in lines
        assert hashlib.sha256(pe_bytes).hexdigest() in lines
        assert len(lines) == len(set(lines))
        assert not any("http://" in line or "|" in line for line in lines)

    def test_type_filter_and_hash_switch(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        _, out, _ = run(capsys, "iocs", phish, "--format", "text", "--type", "url", "--no-hashes")
        lines = out.splitlines()
        assert lines and all(line.startswith("hxxp") for line in lines)

    def test_json_format_contains_only_defanged_values(
        self, capsys: pytest.CaptureFixture[str], phish: Path, pe_bytes: bytes
    ) -> None:
        _, out, _ = run(capsys, "iocs", phish, "--format", "json", "--type", "hash")
        data = json.loads(out)
        assert data["iocs"] == []
        assert [a["sha256"] for a in data["attachments"]] == [hashlib.sha256(pe_bytes).hexdigest()]
        _, full, _ = run(capsys, "iocs", phish, "--format", "json")
        assert "http://evil.example" not in full
        assert any(i["defanged"].startswith("hxxp") for i in json.loads(full)["iocs"])

    def test_table_format(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        code, out, _ = run(capsys, "iocs", phish)
        assert code == 0 and "Indicator (defanged)" in out and "Attachment hashes" in out

    def test_several_files_are_merged_in_text_mode(self, capsys: pytest.CaptureFixture[str], phish: Path) -> None:
        _, once, _ = run(capsys, "iocs", phish, "--format", "text")
        _, twice, _ = run(capsys, "iocs", phish, phish, "--format", "text")
        assert once == twice  # duplicates across files are removed


# ===================================================================== status
class TestStatus:
    def test_table(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PHISHTRIAGE_OFFLINE", "false")
        code, out, _ = run(capsys, "status")
        assert code == 0
        for name in ("abuseipdb", "urlhaus", "virustotal", "dnsbl"):
            assert name in out
        assert "ENABLED" in out  # dnsbl needs no key

    def test_json_and_secrets(self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PHISHTRIAGE_OFFLINE", "false")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "secret-key-xyz")
        _, out, _ = run(capsys, "status", "--json")
        providers = {p["name"]: p for p in json.loads(out)["providers"]}
        assert providers["abuseipdb"]["enabled"] is True
        assert providers["urlhaus"]["enabled"] is False
        assert "secret-key-xyz" not in out
        _, table, _ = run(capsys, "status")
        assert "secret-key-xyz" not in table

    def test_offline_disables_everything(self, capsys: pytest.CaptureFixture[str]) -> None:
        _, out, _ = run(capsys, "status", "--json")
        data = json.loads(out)
        assert data["offline"] is True
        assert all(not p["enabled"] and p["reason"] == "offline mode" for p in data["providers"])

    def test_offline_flag_overrides_the_environment(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PHISHTRIAGE_OFFLINE", "false")
        _, out, _ = run(capsys, "status", "--json", "--offline")
        assert json.loads(out)["offline"] is True