"""Shared pytest fixtures.

All sample data is synthetic and built in code:

* ``eml_builder``: factory for RFC 5322 messages (any headers, bodies, attachments).
* ``phishing_eml`` / ``clean_eml``: ready-made samples used by several test files.
* ``pe_bytes``: a tiny, non-executable stub that carries valid PE headers.
* ``make_docx``: factory for minimal OOXML (zip) documents.
* ``fake_provider``: factory for threat-intel providers that never touch the network.
* ``offline_settings``: ``Settings(offline=True)``.

An autouse fixture isolates every test from the developer's environment, so
real API keys or a local ``.env`` can never change a result.
"""

import asyncio
import io
import os
import zipfile
from collections.abc import Callable, Iterator, Sequence
from email.message import EmailMessage
from typing import Any

import pytest

from phishtriage.config import Settings, get_settings
from phishtriage.core.models import IntelResult, IntelVerdict, IOCType
from phishtriage.intel.base import IntelProvider

_SECRET_ENV_NAMES = ("URLHAUS_AUTH_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY")

PHISH_RECEIVED = (
    # newest first, exactly as in a real file
    "from mx1.corp.example (mx1.corp.example [10.0.0.5]) by mx2.corp.example with ESMTP id Q2; "
    "Mon, 12 Oct 2026 09:00:04 +0000",
    "from mail.evil.example (mail.evil.example [203.0.113.5]) by mx1.corp.example with ESMTPS "
    "id Q1; Mon, 12 Oct 2026 09:00:00 +0000",
)


# ------------------------------------------------------------------ isolation
@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[None]:
    """No inherited configuration, no local ``.env``, fresh settings cache."""
    for name in list(os.environ):
        if name.startswith("PHISHTRIAGE_") or name in _SECRET_ENV_NAMES:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def offline_settings() -> Settings:
    """Settings with every network feature disabled."""
    return Settings(offline=True)


# ------------------------------------------------------------------- builders
@pytest.fixture
def pe_bytes() -> bytes:
    """A 200-byte stub with valid MZ/PE headers. It cannot run."""
    stub = bytearray(b"MZ" + b"\x00" * 62)
    stub[0x3C:0x40] = (0x80).to_bytes(4, "little")
    stub += b"\x00" * (0x80 - len(stub))
    stub += b"PE\x00\x00" + b"\x00" * 60
    return bytes(stub)


EmlBuilder = Callable[..., bytes]


@pytest.fixture
def eml_builder() -> EmlBuilder:
    """Return ``build(**options) -> bytes`` producing a complete ``.eml``.

    ``received`` is newest first. ``attachments`` holds
    ``(filename, data, maintype, subtype)`` tuples. Pass ``from_=None`` to omit
    the From header. ``headers`` adds or overrides extra headers.
    """

    def build(
        *,
        from_: str | None = '"Alice" <alice@partner.example>',
        to: str = "victim@corp.example",
        subject: str = "Hello",
        date: str | None = "Mon, 12 Oct 2026 08:59:00 +0000",
        message_id: str | None = "<id1@partner.example>",
        received: Sequence[str] = (),
        headers: dict[str, str] | None = None,
        text: str = "Hello there.",
        html: str | None = None,
        attachments: Sequence[tuple[str, bytes, str, str]] = (),
    ) -> bytes:
        message = EmailMessage()
        for hop in received:
            message["Received"] = hop
        if from_ is not None:
            message["From"] = from_
        message["To"] = to
        message["Subject"] = subject
        if date is not None:
            message["Date"] = date
        if message_id is not None:
            message["Message-ID"] = message_id
        for name, value in (headers or {}).items():
            message[name] = value
        message.set_content(text)
        if html is not None:
            message.add_alternative(html, subtype="html")
        for filename, data, maintype, subtype in attachments:
            message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
        return message.as_bytes()

    return build


@pytest.fixture
def phishing_eml(eml_builder: EmlBuilder, pe_bytes: bytes) -> bytes:
    """A message with most classic phishing traits (all addresses are fictional)."""
    return eml_builder(
        from_='"PayPal Support" <security@paypa1.example>',
        subject="URGENT: verify your account",
        received=PHISH_RECEIVED,
        headers={
            "Reply-To": "attacker@gmail.com",
            "Authentication-Results": (
                "mx2.corp.example; spf=fail smtp.mailfrom=bounce@evil.example; dkim=none; "
                "dmarc=fail header.from=paypa1.example"
            ),
        },
        text="Your account will be suspended within 24 hours. Verify at http://evil.example/login",
        html=(
            '<a href="http://evil.example/login">https://www.paypal.com/signin</a>'
            '<form><input type="password"></form>'
        ),
        attachments=[("invoice.pdf", pe_bytes, "application", "pdf")],
    )


@pytest.fixture
def clean_eml(eml_builder: EmlBuilder) -> bytes:
    """An ordinary, fully authenticated message."""
    return eml_builder(
        subject="Lunch on Friday?",
        received=PHISH_RECEIVED,
        headers={
            "Authentication-Results": (
                "mx2.corp.example; spf=pass smtp.mailfrom=alice@partner.example; "
                "dkim=pass header.d=partner.example header.s=s1; dmarc=pass header.from=partner.example"
            )
        },
        text="Are we still on for lunch on Friday?",
    )


@pytest.fixture
def make_docx() -> Callable[..., bytes]:
    """Return ``make(extra_files=None, macros=False) -> bytes`` for a minimal .docx archive."""

    def make(extra_files: dict[str, bytes | str] | None = None, *, macros: bool = False) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", "<w:document/>")
            if macros:
                archive.writestr("word/vbaProject.bin", b"\x00" * 16)
            for name, content in (extra_files or {}).items():
                archive.writestr(name, content)
        return buffer.getvalue()

    return make


@pytest.fixture
def fake_provider() -> Callable[..., IntelProvider]:
    """Return ``make(name, types, verdict, ...) -> provider`` that never uses the network.

    The returned provider records every indicator it was asked about in ``.calls``.
    """

    def make(
        name: str,
        types: Sequence[IOCType],
        verdict: IntelVerdict = IntelVerdict.UNKNOWN,
        *,
        enabled: bool = True,
        delay: float = 0.0,
    ) -> IntelProvider:
        class Fake(IntelProvider):
            calls: list[str] = []
            supported_types = frozenset(types)

            def _requests_per_minute(self) -> float:
                return 6000.0

            def _config_problem(self) -> str | None:
                return None if enabled else "no key"

            async def _lookup(self, indicator: str, indicator_type: IOCType) -> IntelResult:
                self.calls.append(indicator)
                if delay:
                    await asyncio.sleep(delay)
                return self._result(
                    indicator,
                    indicator_type,
                    verdict,
                    score=90 if verdict is IntelVerdict.MALICIOUS else None,
                    detail="fake",
                )

        Fake.name = name  # type: ignore[misc]
        Fake.calls = []
        return Fake(Settings())

    return make