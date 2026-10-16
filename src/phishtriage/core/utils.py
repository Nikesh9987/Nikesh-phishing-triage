"""Shared string sanitization, integer coercion, and domain extraction utilities."""

import re
import warnings
from functools import lru_cache
from typing import Final

import tldextract

_CTRL_RE: Final = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


@lru_cache(maxsize=1)
def _tld_extractor() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(cache_dir=False, suffix_list_urls=())


def get_organizational_domain(domain_or_host: str) -> str:
    """Return the registered / organizational domain under the public suffix."""
    if not domain_or_host:
        return ""
    cleaned = domain_or_host.strip().lower().rstrip(".")
    if not cleaned:
        return ""

    ext = _tld_extractor()(cleaned)
    top_domain = None
    if hasattr(ext, "top_domain_under_public_suffix"):
        top_domain = ext.top_domain_under_public_suffix
    elif hasattr(ext, "registered_domain"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            top_domain = ext.registered_domain

    if top_domain:
        return top_domain

    # Fallback for testing/RFC reserved TLDs like .example, .test, .local
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return cleaned


# Alias for backward compatibility
org_domain = get_organizational_domain


def clean_text(value: object, limit: int = 100) -> str:
    """Strip bidi/control chars, trim whitespace, and enforce max length."""
    if value is None:
        return ""
    s = str(value)
    s = _CTRL_RE.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def safe_int(value: object) -> int:
    """Safely cast numeric or string values to an integer, returning 0 on failure."""
    if value is None:
        return 0
    try:
        return int(float(str(value).strip()))
    except (ValueError, TypeError):
        return 0
