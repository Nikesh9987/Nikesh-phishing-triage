"""Defang and refang utilities for indicators of compromise.

*Defanging* makes an indicator safe to paste into tickets, chat, or email, where
it could otherwise become a clickable link or trigger a mail-gateway rewrite::

    http://evil.example/a.php  ->  hxxp[://]evil[.]example/a[.]php
    user@evil.example          ->  user[@]evil[.]example
    203.0.113.5                ->  203[.]0[.]113[.]5

*Refanging* reverses it, so lookups and regexes work on the real value. It also
understands the many ad-hoc conventions seen in the wild (``hxxp``, ``[.]``,
``(dot)``, ``[at]``, ``[:]`` ...).

Guarantees:

* **Never raises.** Malformed input is returned best-effort.
* **Idempotent.** ``defang_x(defang_x(v)) == defang_x(v)``, because every
  defang function refangs its input first.
* **Whole-string defanging.** Every dot in a URL is defanged, including those in
  the path and query. Redirect-style URLs that embed a second URL are therefore
  also neutralised.
* Hashes and other non-routable values pass through unchanged.
"""

import re

from phishtriage.core.models import IOCType

__all__ = [
    "defang_domain",
    "defang_email",
    "defang_ioc",
    "defang_ip",
    "defang_text",
    "defang_url",
    "is_defanged",
    "refang",
]

# ----------------------------------------------------------------------- refang rules
# Order matters: separators first, then dots/at-signs, then the scheme (which
# relies on "://" being restored).
_RE_COLON_SLASHES = re.compile(r"[\[({]\s*:\s*/{2}\s*[\])}]")  # [://]
_RE_COLON = re.compile(r"[\[({]\s*:\s*[\])}]")  # [:]
_RE_DOT = re.compile(r"[\[({]\s*\.\s*[\])}]|[\[({]\s*dot\s*[\])}]", re.IGNORECASE)
_RE_AT_SYMBOL = re.compile(r"[\[({]\s*@\s*[\])}]")  # [@]
_RE_AT_WORD = re.compile(r"(?<=\w)[\[({]\s*at\s*[\])}](?=\w)", re.IGNORECASE)  # user[at]host
_RE_HTTP_SCHEME = re.compile(r"\b(?:hxxp|hxtp|h\*\*p|meow)(s?)(?=://)", re.IGNORECASE)
_RE_FTP_SCHEME = re.compile(r"\bfxp(s?)(?=://)", re.IGNORECASE)

# ----------------------------------------------------------------------- defang rules
_RE_SCHEME_SEP = re.compile(r"\b([A-Za-z][A-Za-z0-9+.\-]*)://")
_SCHEME_MAP = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}

# Used only by defang_text(): conservative, delimiter-bounded matchers.
_RE_TEXT_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s<>\"'`]+")
_RE_TEXT_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")

# Any marker that indicates an indicator has already been defanged.
_RE_DEFANG_MARKER = re.compile(
    r"[\[({]\s*(?:\.|:|@|://|dot|at)\s*[\])}]|\b(?:hxxps?|fxps?|hxtp|meow)(?:\[?:)", re.IGNORECASE
)


def refang(text: str) -> str:
    """Convert a defanged indicator (or text containing some) back to its live form.

    Handles ``hxxp``/``hXXp``/``hxtp``/``h**p``/``meow`` for http(s), ``fxp`` for
    ftp, and the bracket styles ``[.]``, ``(.)``, ``{.}``, ``[dot]``, ``[:]``,
    ``[://]``, ``[@]``, and ``user[at]host``. Matching is case-insensitive. Text
    without obfuscation is returned unchanged.

    Args:
        text: A single indicator or a larger block of text.

    Returns:
        The refanged text. Non-string input yields ``""``.
    """
    if not isinstance(text, str) or not text:
        return ""
    out = _RE_COLON_SLASHES.sub("://", text)
    out = _RE_COLON.sub(":", out)
    out = _RE_DOT.sub(".", out)
    out = _RE_AT_SYMBOL.sub("@", out)
    out = _RE_AT_WORD.sub("@", out)
    out = _RE_HTTP_SCHEME.sub(lambda m: f"http{m.group(1).lower()}", out)
    out = _RE_FTP_SCHEME.sub(lambda m: f"ftp{m.group(1).lower()}", out)
    return out


def is_defanged(text: str) -> bool:
    """Return True if ``text`` contains recognisable defanging markers."""
    return isinstance(text, str) and bool(_RE_DEFANG_MARKER.search(text))


def defang_url(url: str) -> str:
    """Defang a URL: scheme, ``://``, every dot, and any ``@``.

    >>> defang_url("https://evil.example/login.php?u=http://x.example")
    'hxxps[://]evil[.]example/login[.]php?u=hxxp[://]x[.]example'
    """
    text = refang(url).strip()
    if not text:
        return ""

    def _scheme(match: re.Match[str]) -> str:
        scheme = match.group(1)
        return f"{_SCHEME_MAP.get(scheme.lower(), scheme)}[://]"

    # Single pass: the replacement contains "://", so a second pass would nest brackets.
    text = _RE_SCHEME_SEP.sub(_scheme, text)
    return text.replace(".", "[.]").replace("@", "[@]")


def defang_domain(domain: str) -> str:
    """Defang a hostname by bracketing its dots.

    >>> defang_domain("Mail.Evil.example")
    'Mail[.]Evil[.]example'
    """
    return refang(domain).strip().replace(".", "[.]")


def defang_email(address: str) -> str:
    """Defang an email address: the ``@`` and every dot.

    >>> defang_email("ceo@evil.example")
    'ceo[@]evil[.]example'
    """
    return refang(address).strip().replace("@", "[@]").replace(".", "[.]")


def defang_ip(address: str) -> str:
    """Defang an IPv4 (dots) or IPv6 (colons) address.

    >>> defang_ip("203.0.113.5")
    '203[.]0[.]113[.]5'
    >>> defang_ip("2001:db8::1")
    '2001[:]db8[:][:]1'
    """
    text = refang(address).strip()
    return text.replace(":", "[:]") if ":" in text else text.replace(".", "[.]")


def defang_text(text: str) -> str:
    """Defang every URL and email address embedded in free text.

    Intended for evidence strings and warnings that may quote indicators.
    Bare domains and IP addresses are *not* detected here (that would break
    version numbers and prose). Use the specific functions for those.
    """
    if not isinstance(text, str) or not text:
        return ""
    out = _RE_TEXT_URL.sub(lambda m: defang_url(m.group(0)), text)
    return _RE_TEXT_EMAIL.sub(lambda m: defang_email(m.group(0)), out)


def defang_ioc(ioc_type: IOCType, value: str) -> str:
    """Defang ``value`` according to its :class:`IOCType`.

    Hashes (and any unknown type) are returned unchanged and stripped.
    """
    if ioc_type is IOCType.URL:
        return defang_url(value)
    if ioc_type is IOCType.EMAIL:
        return defang_email(value)
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return defang_ip(value)
    if ioc_type is IOCType.DOMAIN:
        return defang_domain(value)
    return value.strip() if isinstance(value, str) else ""
