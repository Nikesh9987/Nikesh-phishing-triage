"""Attachment hashing, content-type detection, and suspicious-trait flagging.

For every attachment (all in memory, nothing executed or written to disk):

* MD5 / SHA-1 / SHA-256. MD5 and SHA-1 exist only for compatibility with
  ticketing and threat-intel tools; SHA-256 is the identifier to trust.
* **Magic-byte type detection.** Security-relevant formats (PE, ELF, OLE, ZIP,
  PDF, RTF, LNK, ISO, OneNote, RAR, 7z, CAB) are recognised by an internal
  signature table, then ``filetype`` covers common media/archive formats, then a
  text heuristic identifies HTML, SVG, ``.eml`` and plain text. The file name is
  never used for detection, since attackers choose it.
* **Filename tricks:** double extensions (``invoice.pdf.exe``), Unicode
  direction overrides (RLO), invisible characters, trailing dots/spaces
  (Windows ignores them), whitespace padding, control characters.
* **Extension risk** (executables, scripts, macro-enabled Office, disk images,
  HTML/SVG, OneNote, archives) and **extension/content mismatch**, with a
  CRITICAL ``disguised_executable`` flag when an executable hides under a
  harmless name.
* **Deep checks by type:**
    - OOXML/ZIP: macro projects, remote template injection, embedded objects,
      ActiveX, executables inside archives, encrypted archives, zip-bomb ratio.
    - OLE (``.doc``/``.xls``/``.ppt``/``.msi``/``.msg``): subtype, embedded
      packager objects, password-protected documents.
    - VBA/XLM macros via ``oletools`` (parse-only, never executed): auto-exec
      triggers and suspicious keywords.
    - PDF: JavaScript, launch actions, embedded files, auto-open actions.
    - RTF: embedded objects (``\\objdata``, the classic exploit carrier).
    - HTML/SVG: HTML smuggling, credential forms, script in SVG, redirects.

Limits and honesty:

* Attachments over ``max_attachment_bytes`` are listed but not hashed or
  inspected (``skipped=True``), per the setting's documented behaviour.
* PDF checks are keyword indicators on the raw bytes. Keywords hidden inside
  compressed object streams are not visible, so a clean result is not proof of
  safety.
* ZIP inspection reads only the central directory plus a few small XML parts
  (hard-capped at 1 MiB each), so archive bombs cannot expand in memory.
* Macro scanning is CPU-bound and synchronous. Async callers should run
  :func:`analyze_attachments` via ``asyncio.to_thread``.
* Never raises. One bad attachment never affects the others.
"""

import hashlib
import io
import logging
import re
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Final

import filetype
import olefile

from phishtriage.config import Settings, get_settings
from phishtriage.core.defang import defang_text
from phishtriage.core.models import (
    SEVERITY_WEIGHT,
    Attachment,
    AttachmentFlag,
    ParsedMessage,
    RawAttachment,
    Severity,
)
from phishtriage.logging_config import get_logger
from phishtriage.parsers.base import OLE_MAGIC, looks_like_eml

__all__ = ["AttachmentAnalysis", "AttachmentAnalyzer", "analyze_attachments"]

logger = get_logger(__name__)

_MIB: Final = 1024 * 1024
_MAX_SCAN_BYTES: Final = 5 * _MIB  # PDF / RTF keyword scans
_MAX_TEXT_SCAN: Final = 2 * _MIB  # HTML / SVG scans
_MAX_MACRO_SCAN_BYTES: Final = 20 * _MIB
_MAX_ZIP_PART_READ: Final = 1 * _MIB
_MAX_OLE_STREAMS: Final = 5000
_MAX_REL_PARTS: Final = 20
_MAX_LISTED: Final = 5

_S = Severity


def _flag(code: str, severity: Severity, description: str) -> AttachmentFlag:
    return AttachmentFlag(code=code, severity=severity, description=description[:600])


# ============================================================ extension knowledge
def _risk(
    code: str, severity: Severity, label: str, *exts: str
) -> dict[str, tuple[str, Severity, str]]:
    return dict.fromkeys(exts, (code, severity, label))


_RISKY: Final[dict[str, tuple[str, Severity, str]]] = {}
_RISKY.update(_risk(
    "executable_extension", _S.HIGH, "a Windows executable or loadable code module",
    "exe", "scr", "com", "pif", "dll", "cpl", "msi", "msp", "sys", "drv", "ocx", "xll", "wll",
    "application", "gadget", "jar", "appx", "msix",
))  # fmt: skip
_RISKY.update(_risk(
    "script_extension", _S.HIGH, "a script or shortcut that executes code",
    "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ws", "vb", "ps1", "ps2", "psm1",
    "psc1", "hta", "reg", "inf", "scf", "sct", "lnk", "url", "chm", "iqy", "slk", "msh", "jnlp",
    "settingcontent-ms", "library-ms", "search-ms",
))  # fmt: skip
_RISKY.update(_risk(
    "macro_extension", _S.MEDIUM, "a macro-capable Office document",
    "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "ppsm", "sldm", "xlsb",
))  # fmt: skip
_RISKY.update(_risk(
    "disk_image_extension", _S.MEDIUM,
    "a disk image, which can be used to evade Mark-of-the-Web controls",
    "iso", "img", "vhd", "vhdx", "dmg",
))  # fmt: skip
_RISKY.update(_risk(
    "html_attachment", _S.MEDIUM,
    "an HTML/SVG page (common in credential harvesting and HTML smuggling)",
    "html", "htm", "xhtml", "shtml", "mht", "mhtml", "svg",
))  # fmt: skip
_RISKY.update(
    _risk(
        "onenote_attachment",
        _S.MEDIUM,
        "a OneNote file (can embed launchable objects)",
        "one",
        "onepkg",
    )
)
_RISKY.update(_risk("archive_attachment", _S.LOW, "a compressed archive that hides its contents from gateways",
                    "rar", "7z", "ace", "cab", "arj", "lzh"))  # fmt: skip

_EXEC_CODES: Final = frozenset({"executable_extension", "script_extension"})
_EXEC_EXTS: Final = frozenset(e for e, (code, _, _) in _RISKY.items() if code in _EXEC_CODES)
_EXEC_CONTENT: Final = frozenset({"exe", "dll", "elf", "lnk"})
_DECOY_EXTS: Final = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg",
     "png", "gif", "bmp", "htm", "html", "zip", "mp3", "mp4"}
)  # fmt: skip

_FAMILIES: Final[dict[str, str]] = {}


def _family(name: str, *exts: str) -> None:
    for ext in exts:
        _FAMILIES[ext] = name


_family("ole-word", "doc", "dot")
_family("ole-excel", "xls", "xlt", "xla")
_family("ole-ppt", "ppt", "pot", "pps", "ppa")
_family("ole", "ole", "msi", "msp", "msg", "pub", "vsd", "mpp")
_family("ooxml-word", "docx", "docm", "dotx", "dotm")
_family("ooxml-excel", "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb")
_family("ooxml-ppt", "pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam", "sldm")
_family("odf", "odt", "ods", "odp", "odg")
_family("jar", "jar", "war", "ear")
_family("zipbased", "apk", "epub", "xpi", "whl", "nupkg", "vsix")
_family("jpeg", "jpg", "jpeg", "jpe", "jfif")
_family("tiff", "tif", "tiff")
_family("html", "html", "htm", "xhtml", "shtml")
_family(
    "text", "txt", "log", "csv", "tsv", "json", "xml", "ini", "cfg", "conf", "md", "yml", "yaml",
    "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "ps1", "reg", "inf", "sh", "py", "url", "ics",
    "vcf", "eml", "asc", "sct", "hta", "iqy", "slk",
)  # fmt: skip
_ZIP_FAMILIES: Final = frozenset(
    {"ooxml-word", "ooxml-excel", "ooxml-ppt", "odf", "jar", "zipbased", "zip"}
)
_KNOWN_EXTS: Final = (
    frozenset(_FAMILIES)
    | frozenset(_RISKY)
    | frozenset({"pdf", "png", "gif", "bmp", "webp", "ico", "zip", "gz", "bz2", "rtf", "mp3",
                 "mp4", "wav", "avi", "mov"})
)  # fmt: skip


def _compatible(declared: str, detected: str) -> bool:
    """True if a declared extension is a plausible name for the detected content."""
    fd, fx = _FAMILIES.get(declared, declared), _FAMILIES.get(detected, detected)
    if fd == fx:
        return True
    if "zip" in (fd, fx):
        return (fx if fd == "zip" else fd) in _ZIP_FAMILIES
    return fd.startswith("ole") and fx.startswith("ole") and "ole" in (fd, fx)


# ============================================================== filename analysis
_BIDI_OVERRIDE: Final = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_INVISIBLE: Final = frozenset("\u200b\u200c\u200d\u2060\ufeff\u200e\u200f\u061c")
_CTRL_RE: Final = re.compile(r"[\x00-\x1f\x7f]")
_PAD_RE: Final = re.compile(r"[ \u00a0\u2000-\u200a\u3000]{5,}")


def _ext_of(name: str) -> str:
    """Lower-cased extension as Windows sees it (trailing dots/spaces ignored)."""
    stem, dot, ext = name.rstrip(" .\u00a0").rpartition(".")
    return ext.strip().lower() if dot and stem else ""


def _filename_flags(name: str) -> list[AttachmentFlag]:
    flags: list[AttachmentFlag] = []
    if not name:
        return flags
    shown = ascii(name)
    if any(c in _BIDI_OVERRIDE for c in name):
        flags.append(_flag("bidi_override", _S.HIGH,
            f"Filename contains Unicode direction-override characters that can disguise the real extension: {shown}."))  # fmt: skip
    if any(c in _INVISIBLE for c in name):
        flags.append(
            _flag(
                "invisible_characters",
                _S.MEDIUM,
                f"Filename contains invisible characters: {shown}.",
            )
        )
    if _CTRL_RE.search(name):
        flags.append(
            _flag(
                "control_characters", _S.MEDIUM, f"Filename contains control characters: {shown}."
            )
        )
    stripped = name.rstrip(" .\u00a0")
    if stripped != name:
        flags.append(_flag("trailing_space_or_dot", _S.MEDIUM,
            "Filename ends in spaces or dots; Windows ignores them, so the real extension may differ from what is shown."))  # fmt: skip
    if _PAD_RE.search(stripped):
        flags.append(_flag("whitespace_padding", _S.MEDIUM,
            "Filename contains a long run of whitespace, typically used to push the real extension out of view."))  # fmt: skip

    ext = _ext_of(name)
    risky = _RISKY.get(ext)
    if risky:
        flags.append(_flag(risky[0], risky[1], f"Extension '.{ext}' indicates {risky[2]}."))
        parts = stripped.split(".")
        if (
            len(parts) >= 3
            and parts[-2].strip().lower() in _DECOY_EXTS
            and SEVERITY_WEIGHT[risky[1]] >= 2
        ):
            severity = _S.HIGH if risky[0] in _EXEC_CODES else _S.MEDIUM
            flags.append(_flag("double_extension", severity,
                f"Double extension '.{parts[-2].strip().lower()}.{ext}': a document-like name hiding a risky type."))  # fmt: skip
    return flags


# ================================================================ type detection
@dataclass(frozen=True)
class _Sniff:
    kind: str  # internal routing key: pe elf ole zip ooxml jar pdf rtf lnk iso one rar 7z cab html svg eml text other unknown
    mime: str = ""
    ext: str = ""


_LNK_GUID: Final = bytes.fromhex("0114020000000000c000000000000046")
_ONE_MAGIC: Final = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
_HTML_RE: Final = re.compile(
    r"<\s*(?:!doctype\s+html|html[\s>]|head[\s>]|body[\s>]|script[\s>]|iframe[\s>]|form[\s>]|meta\s)"
)
_SVG_RE: Final = re.compile(r"<svg[\s>]")


def _decode_text(data: bytes, limit: int) -> str:
    chunk = data[:limit]
    if chunk.startswith((b"\xff\xfe", b"\xfe\xff")):
        return chunk.decode("utf-16", "replace")
    return chunk.decode("utf-8", "replace")


def _sniff_pe(data: bytes) -> _Sniff | None:
    if len(data) < 0x40:
        return None
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if 0 < offset <= len(data) - 26 and data[offset : offset + 4] == b"PE\x00\x00":
        characteristics = int.from_bytes(data[offset + 22 : offset + 24], "little")
        if characteristics & 0x2000:
            return _Sniff("pe", "application/vnd.microsoft.portable-executable", "dll")
        return _Sniff("pe", "application/vnd.microsoft.portable-executable", "exe")
    if b"This program cannot be run in DOS mode" in data[:512]:
        return _Sniff("pe", "application/x-dosexec", "exe")
    return None


def _is_iso(data: bytes) -> bool:
    return any(data[off : off + 5] == b"CD001" for off in (0x8001, 0x8801, 0x9001))


def _sniff_text(data: bytes) -> _Sniff | None:
    sample = data[:8192]
    bom = sample.startswith((b"\xff\xfe", b"\xfe\xff"))
    if not bom:
        if b"\x00" in sample:
            return None
        controls = sum(1 for b in sample if b < 9 or 13 < b < 32 or b == 127)
        if sample and controls / len(sample) > 0.02:
            return None
    if looks_like_eml(data):
        return _Sniff("eml", "message/rfc822", "eml")
    head = _decode_text(data, 2048).lower().lstrip("\ufeff \t\r\n")
    if _SVG_RE.search(head) and "<html" not in head:
        return _Sniff("svg", "image/svg+xml", "svg")
    if _HTML_RE.search(head):
        return _Sniff("html", "text/html", "html")
    if head.startswith("#!"):
        return _Sniff("text", "text/x-shellscript", "sh")
    return _Sniff("text", "text/plain", "txt")


def _sniff(data: bytes) -> _Sniff:
    """Detect content type from bytes only."""
    head = data[:4096]
    if head.startswith(b"MZ"):
        found = _sniff_pe(data)
        if found:
            return found
    if head.startswith(b"\x7fELF"):
        return _Sniff("elf", "application/x-elf", "elf")
    if head.startswith(OLE_MAGIC):
        return _Sniff("ole", "application/x-ole-storage", "ole")
    if b"%PDF-" in head[:1024]:
        return _Sniff("pdf", "application/pdf", "pdf")
    if head.startswith(b"{\\rt"):
        return _Sniff("rtf", "application/rtf", "rtf")
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return _Sniff("zip", "application/zip", "zip")
    if head.startswith(b"Rar!\x1a\x07"):
        return _Sniff("rar", "application/vnd.rar", "rar")
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return _Sniff("7z", "application/x-7z-compressed", "7z")
    if head.startswith(b"MSCF"):
        return _Sniff("cab", "application/vnd.ms-cab-compressed", "cab")
    if head.startswith(b"L\x00\x00\x00") and head[4:20] == _LNK_GUID:
        return _Sniff("lnk", "application/x-ms-shortcut", "lnk")
    if head.startswith(_ONE_MAGIC):
        return _Sniff("one", "application/onenote", "one")
    if _is_iso(data):
        return _Sniff("iso", "application/x-iso9660-image", "iso")
    try:
        guessed = filetype.guess(data[:8192])
    except Exception:  # noqa: BLE001 - third-party sniffing on hostile bytes
        guessed = None
    if guessed is not None:
        return _Sniff("other", str(guessed.mime), str(guessed.extension))
    return _sniff_text(data) or _Sniff("unknown")


# ================================================================ container checks
_OOXML_MIME: Final = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "docm": "application/vnd.ms-word.document.macroenabled.12",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "xlsm": "application/vnd.ms-excel.sheet.macroenabled.12",
    "xlsb": "application/vnd.ms-excel.sheet.binary.macroenabled.12",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "pptm": "application/vnd.ms-powerpoint.presentation.macroenabled.12",
}
_OLE_SUBTYPES: Final = (
    ("worddocument", "doc", "application/msword"),
    ("workbook", "xls", "application/vnd.ms-excel"),
    ("book", "xls", "application/vnd.ms-excel"),
    ("powerpoint document", "ppt", "application/vnd.ms-powerpoint"),
    ("__properties_version1.0", "msg", "application/vnd.ms-outlook"),
)
_REL_TAG_RE: Final = re.compile(r"<Relationship\b[^>]*>", re.IGNORECASE)
_REL_TARGET_RE: Final = re.compile(r"""Target\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_REL_TYPE_RE: Final = re.compile(r"""Type\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


@dataclass
class _Container:
    sniff: _Sniff
    macros_present: bool = False
    skip_macro_scan: bool = False
    flags: list[AttachmentFlag] = field(default_factory=list)


def _read_zip_part(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size > _MAX_ZIP_PART_READ:
        return b""
    try:
        with zf.open(info) as handle:
            return handle.read(_MAX_ZIP_PART_READ + 1)[:_MAX_ZIP_PART_READ]
    except Exception:  # noqa: BLE001 - corrupt/encrypted member
        return b""


def _remote_relationships(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo]) -> list[str]:
    """External template / OLE targets referenced from OOXML relationship parts."""
    found: list[str] = []
    rels = [i for i in infos if i.filename.lower().endswith(".rels")][:_MAX_REL_PARTS]
    for info in rels:
        text = _read_zip_part(zf, info).decode("utf-8", "replace")
        for tag in _REL_TAG_RE.findall(text):
            if "targetmode" not in tag.lower() or "external" not in tag.lower():
                continue
            kind = (_REL_TYPE_RE.search(tag) or [None, ""])[1].lower()  # type: ignore[index]
            if not any(k in kind for k in ("attachedtemplate", "oleobject", "/frame")):
                continue
            target = _REL_TARGET_RE.search(tag)
            if target:
                found.append(defang_text(target.group(1)[:200]))
    return found


def _inspect_zip(data: bytes) -> _Container:
    """Classify a ZIP container and run archive/OOXML checks (central directory only)."""
    generic = _Sniff("zip", "application/zip", "zip")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001 - BadZipFile, NotImplementedError, ...
        return _Container(generic, flags=[_flag("malformed_archive", _S.LOW, "ZIP signature present but the archive structure is invalid.")])  # fmt: skip

    flags: list[AttachmentFlag] = []
    with zf:
        infos = zf.infolist()
        lowered = [i.filename.lower() for i in infos]
        names = set(lowered)

        total = sum(i.file_size for i in infos)
        if total > 100 * _MIB and total / max(len(data), 1) > 1000:
            flags.append(_flag("zip_bomb_suspect", _S.MEDIUM,
                f"Archive expands to {total // _MIB} MiB (ratio > 1000:1); possible decompression bomb."))  # fmt: skip
        if any(i.flag_bits & 0x1 for i in infos):
            flags.append(_flag("encrypted_archive", _S.MEDIUM,
                "Archive contains password-protected entries that gateways cannot scan (the password is often in the email body)."))  # fmt: skip

        macros = any(n.endswith("vbaproject.bin") for n in lowered)
        if "[content_types].xml" in names:
            prefixes = {"word/": "docx", "xl/": "xlsx", "ppt/": "pptx"}
            base = next(
                (e for p, e in prefixes.items() if any(n.startswith(p) for n in lowered)), ""
            )
            if base == "xlsx" and "xl/workbook.bin" in names:
                base = "xlsb"
            if base:
                ext = (
                    {"docx": "docm", "xlsx": "xlsm", "pptx": "pptm"}[base]
                    if macros and base != "xlsb"
                    else base
                )
                sniff = _Sniff("ooxml", _OOXML_MIME[ext], ext)
                for target in _remote_relationships(zf, infos)[:_MAX_LISTED]:
                    flags.append(_flag("remote_template", _S.HIGH,
                        f"Document loads external content (template/OLE object) from {target}."))  # fmt: skip
                embedded = [i.filename for i in infos if "/embeddings/" in i.filename.lower()]
                if embedded:
                    flags.append(_flag("embedded_objects", _S.MEDIUM,
                        f"Contains {len(embedded)} embedded object(s): {', '.join(embedded[:_MAX_LISTED])}."))  # fmt: skip
                if any("/activex/" in n for n in lowered):
                    flags.append(
                        _flag("activex_controls", _S.MEDIUM, "Document contains ActiveX controls.")
                    )
                return _Container(sniff, macros_present=macros, flags=flags)
        if "meta-inf/manifest.mf" in names:
            return _Container(_Sniff("jar", "application/java-archive", "jar"), flags=flags)

        risky = [
            i.filename for i in infos
            if _ext_of(i.filename.rsplit("/", 1)[-1]) in _EXEC_EXTS
        ]  # fmt: skip
        if risky:
            flags.append(_flag("archive_contains_executable", _S.HIGH,
                f"Archive contains {len(risky)} executable/script file(s): {', '.join(ascii(n) for n in risky[:_MAX_LISTED])}."))  # fmt: skip
    return _Container(generic, flags=flags)


def _inspect_ole(data: bytes) -> _Container:
    """Classify an OLE container by its streams and flag encrypted/embedded content."""
    generic = _Sniff("ole", "application/x-ole-storage", "ole")
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return _Container(generic, flags=[_flag("malformed_ole", _S.LOW, "OLE signature present but the container is invalid.")])  # fmt: skip
    try:
        entries = ole.listdir(streams=True, storages=False)[:_MAX_OLE_STREAMS]
        names = {"/".join(parts).lower() for parts in entries}
    except Exception:  # noqa: BLE001
        names = set()
    finally:
        ole.close()

    sniff = generic
    for needle, ext, mime in _OLE_SUBTYPES:
        if needle in names:
            sniff = _Sniff("ole", mime, ext)
            break

    flags: list[AttachmentFlag] = []
    encrypted = "encryptedpackage" in names
    if encrypted:
        flags.append(_flag("encrypted_document", _S.MEDIUM, "Password-protected Office document; its content cannot be inspected."))  # fmt: skip
    if any("ole10native" in n for n in names):
        flags.append(_flag("ole_embedded_object", _S.MEDIUM, "Contains an embedded OLE packager object (file or script payload)."))  # fmt: skip
    macros = any(n.startswith("macros/") or "_vba_project_cur" in n for n in names)
    return _Container(sniff, macros_present=macros, skip_macro_scan=encrypted, flags=flags)


# ================================================================== content scans
_PDF_CHECKS: Final = (
    ("pdf_javascript", _S.HIGH, re.compile(rb"/JavaScript(?![A-Za-z])|/JS\s*(?:\(|<|\d+\s+\d+\s+R)"),
     "PDF contains JavaScript."),
    ("pdf_launch_action", _S.HIGH, re.compile(rb"/Launch(?![A-Za-z])"),
     "PDF contains a /Launch action that can start external programs."),
    ("pdf_embedded_file", _S.MEDIUM, re.compile(rb"/EmbeddedFiles?(?![A-Za-z])"),
     "PDF contains embedded file(s)."),
    ("pdf_auto_action", _S.MEDIUM, re.compile(rb"/OpenAction(?![A-Za-z])|/AA\s*(?:<<|\d+\s+\d+\s+R)"),
     "PDF defines an action that runs automatically when opened."),
    ("pdf_encrypted", _S.LOW, re.compile(rb"/Encrypt(?![A-Za-z])"),
     "PDF is encrypted; its content may not be fully inspectable."),
)  # fmt: skip
_RTF_OBJ_RE: Final = re.compile(rb"\\(?:objdata|objupdate|objautlink)", re.IGNORECASE)
_PASSWORD_INPUT_RE: Final = re.compile(r"""type\s*=\s*["']?password""")
_META_REFRESH_RE: Final = re.compile(r"""http-equiv\s*=\s*["']?refresh""")


def _pdf_flags(data: bytes) -> list[AttachmentFlag]:
    window = data[:_MAX_SCAN_BYTES]
    return [
        _flag(code, sev, text) for code, sev, pattern, text in _PDF_CHECKS if pattern.search(window)
    ]


def _rtf_flags(data: bytes) -> list[AttachmentFlag]:
    if _RTF_OBJ_RE.search(data[:_MAX_SCAN_BYTES]):
        return [_flag("rtf_embedded_object", _S.HIGH,
            "RTF contains embedded OLE objects, a common carrier for exploits and droppers.")]  # fmt: skip
    return []


def _html_flags(data: bytes, kind: str) -> list[AttachmentFlag]:
    text = _decode_text(data, _MAX_TEXT_SCAN).lower()
    flags: list[AttachmentFlag] = []
    if kind == "svg" and "<script" in text:
        flags.append(
            _flag(
                "svg_script",
                _S.HIGH,
                "SVG file contains script, which runs when opened in a browser.",
            )
        )
    if "blob(" in text and any(
        k in text for k in ("createobjecturl", "mssaveoropenblob", "msSaveBlob".lower())
    ):
        flags.append(_flag("html_smuggling", _S.HIGH,
            "Page builds a file in the browser (Blob + download): the HTML smuggling technique."))  # fmt: skip
    if _PASSWORD_INPUT_RE.search(text):
        flags.append(_flag("html_credential_form", _S.HIGH,
            "Attachment contains a password input field: a likely credential-harvesting page."))  # fmt: skip
    if ("eval(" in text or "document.write(" in text) and any(
        k in text for k in ("atob(", "unescape(", "fromcharcode")
    ):
        flags.append(_flag("html_obfuscated_script", _S.MEDIUM, "Page runs decoded/obfuscated script (eval/document.write with atob/unescape/fromCharCode)."))  # fmt: skip
    if _META_REFRESH_RE.search(text) or any(
        k in text for k in ("window.location", "location.replace(", "location.href")
    ):
        flags.append(_flag("html_redirect", _S.MEDIUM, "Page redirects the browser automatically."))
    return flags


# ============================================================== macro analysis
_AUTOEXEC_SEVERITY_NOTE: Final = "Macro runs automatically when the document is opened"


@lru_cache(maxsize=1)
def _load_olevba() -> Any | None:
    """Import ``oletools.olevba`` lazily (it is slow to import) and silence its logging."""
    try:
        from oletools import olevba  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        logger.warning("oletools is unavailable; macro analysis is limited to presence checks")
        return None
    for name in ("olevba", "oletools", "olevba3"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    return olevba


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))[: _MAX_LISTED + 3]


def _static_macro_flags(present: bool, note: str = "") -> list[AttachmentFlag]:
    if not present:
        return []
    return [_flag("vba_macros", _S.MEDIUM, f"Contains a VBA macro project.{note}")]


def _macro_flags(data: bytes, static_present: bool) -> list[AttachmentFlag]:
    """Parse (never execute) VBA/XLM macros with oletools and flag risky behaviour."""
    if len(data) > _MAX_MACRO_SCAN_BYTES:
        return _static_macro_flags(static_present, " (file too large for detailed macro analysis)")
    olevba = _load_olevba()
    if olevba is None:
        return _static_macro_flags(static_present, " (detailed analysis unavailable)")

    parser: Any = None
    try:
        parser = olevba.VBA_Parser("attachment", data=data)
        has_vba = bool(parser.detect_vba_macros())
        detect_xlm = getattr(parser, "detect_xlm_macros", None)
        has_xlm = bool(detect_xlm()) if callable(detect_xlm) else False
        autoexec: list[str] = []
        suspicious: list[str] = []
        if has_vba:
            for kind, keyword, _desc in parser.analyze_macros(show_decoded_strings=False) or []:
                if kind == "AutoExec":
                    autoexec.append(str(keyword))
                elif kind == "Suspicious":
                    suspicious.append(str(keyword))
            if not autoexec and getattr(parser, "nb_autoexec", 0):
                autoexec.append("(auto-execute keyword)")
            if not suspicious and getattr(parser, "nb_suspicious", 0):
                suspicious.append("(suspicious keyword)")
    except Exception:  # noqa: BLE001 - FileOpenError and parser bugs on hostile files
        logger.debug("olevba could not analyse attachment", exc_info=True)
        return _static_macro_flags(static_present, " (detailed analysis failed)")
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:  # noqa: BLE001
                logger.debug("olevba close failed", exc_info=True)

    flags: list[AttachmentFlag] = []
    if has_vba:
        flags.append(_flag("vba_macros", _S.MEDIUM, "Contains VBA macros."))
        auto, susp = _unique(autoexec), _unique(suspicious)
        if auto and susp:
            flags.append(_flag("malicious_vba_pattern", _S.CRITICAL,
                f"{_AUTOEXEC_SEVERITY_NOTE} ({', '.join(auto)}) and uses suspicious functionality ({', '.join(susp)})."))  # fmt: skip
        elif auto:
            flags.append(
                _flag("vba_autoexec", _S.HIGH, f"{_AUTOEXEC_SEVERITY_NOTE}: {', '.join(auto)}.")
            )
        elif susp:
            flags.append(
                _flag(
                    "vba_suspicious",
                    _S.HIGH,
                    f"Macro uses suspicious functionality: {', '.join(susp)}.",
                )
            )
    if has_xlm:
        flags.append(_flag("xlm_macros", _S.HIGH, "Contains Excel 4.0 (XLM) macros, a technique used to evade VBA scanners."))  # fmt: skip
    return flags


# ================================================================= analyzer
@dataclass
class AttachmentAnalysis:
    """Per-attachment results plus non-fatal warnings."""

    attachments: list[Attachment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data, usedforsecurity=False).hexdigest(),
        hashlib.sha1(data, usedforsecurity=False).hexdigest(),  # noqa: S324 - compatibility hash only
        hashlib.sha256(data).hexdigest(),
    )


def _mismatch_flags(declared_ext: str, sniff: _Sniff) -> list[AttachmentFlag]:
    if not declared_ext or not sniff.ext:
        return []
    if sniff.ext in _EXEC_CONTENT and declared_ext not in _EXEC_EXTS:
        return [_flag("disguised_executable", _S.CRITICAL,
            f"Content is a {sniff.ext.upper()} executable but the file is named '.{declared_ext}'.")]  # fmt: skip
    if declared_ext in _KNOWN_EXTS and not _compatible(declared_ext, sniff.ext):
        return [_flag("extension_mismatch", _S.MEDIUM,
            f"Extension '.{declared_ext}' does not match the detected content ({sniff.mime or sniff.ext}).")]  # fmt: skip
    return []


class AttachmentAnalyzer:
    """Analyze attachments held in memory."""

    def __init__(self, max_attachment_bytes: int = 50 * _MIB, scan_macros: bool = True) -> None:
        """Create an analyzer.

        Args:
            max_attachment_bytes: Larger attachments are listed but not hashed
                or inspected.
            scan_macros: Run the oletools macro scan (CPU-heavy on big files).
        """
        self._max_bytes = max(1, max_attachment_bytes)
        self._scan_macros = scan_macros

    def analyze(self, attachments: Sequence[RawAttachment]) -> AttachmentAnalysis:
        """Analyze every attachment; failures degrade to a warning per item."""
        result = AttachmentAnalysis()
        for position, raw in enumerate(attachments, start=1):
            try:
                item = self.analyze_one(raw)
            except Exception:  # noqa: BLE001 - last-resort guard
                logger.exception("Attachment #%d analysis failed", position)
                result.warnings.append(
                    f"Attachment #{position} ({raw.filename!r}) could not be analyzed."
                )
                item = Attachment(filename=raw.filename or "(unnamed)", size=len(raw.data))
            if item.skipped:
                result.warnings.append(
                    f"Attachment {item.filename!r} ({item.size:,} bytes) exceeds the "
                    f"{self._max_bytes:,}-byte inspection limit and was not hashed or analyzed."
                )
            result.attachments.append(item)
        return result

    def analyze_one(self, raw: RawAttachment) -> Attachment:
        """Analyze a single attachment."""
        data = raw.data
        size = len(data)
        flags = _filename_flags(raw.filename)
        md5 = sha1 = sha256 = mime = ext = ""
        skipped = False

        if size == 0:
            flags.append(
                _flag("empty_payload", _S.INFO, "Attachment has no data (no payload to hash).")
            )
        elif size > self._max_bytes:
            skipped = True
            flags.append(
                _flag(
                    "too_large_to_inspect", _S.LOW, "Attachment exceeds the inspection size limit."
                )
            )
        else:
            md5, sha1, sha256 = _hashes(data)
            try:
                mime, ext = self._inspect(raw, data, flags)
            except Exception:  # noqa: BLE001 - keep hashes even if inspection fails
                logger.exception("Content inspection failed for %r", raw.filename)
                flags.append(
                    _flag(
                        "analysis_error",
                        _S.LOW,
                        "Content inspection failed; only hashes are available.",
                    )
                )

        flags.sort(key=lambda f: SEVERITY_WEIGHT[f.severity], reverse=True)
        return Attachment(
            filename=raw.filename or "(unnamed)",
            size=size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            declared_content_type=raw.declared_content_type,
            detected_mime=mime,
            detected_extension=ext,
            is_inline=raw.is_inline,
            skipped=skipped,
            flags=flags,
        )

    # ---------------------------------------------------------------- inspection
    def _inspect(
        self, raw: RawAttachment, data: bytes, flags: list[AttachmentFlag]
    ) -> tuple[str, str]:
        sniff = _sniff(data)
        container = _Container(sniff)
        if sniff.kind == "zip":
            container = _inspect_zip(data)
        elif sniff.kind == "ole":
            container = _inspect_ole(data)
        sniff = container.sniff
        flags.extend(container.flags)

        if sniff.kind in ("ooxml", "ole") and not container.skip_macro_scan:
            if self._scan_macros:
                flags.extend(_macro_flags(data, container.macros_present))
            else:
                flags.extend(_static_macro_flags(container.macros_present))
        elif sniff.kind == "pdf":
            flags.extend(_pdf_flags(data))
        elif sniff.kind == "rtf":
            flags.extend(_rtf_flags(data))
        elif sniff.kind in ("html", "svg"):
            flags.extend(_html_flags(data, sniff.kind))
        if sniff.kind == "eml" or sniff.ext == "msg":
            flags.append(_flag("embedded_message", _S.INFO, "Attachment is itself an email message; analyze it separately."))  # fmt: skip

        flags.extend(_mismatch_flags(_ext_of(raw.filename), sniff))
        return sniff.mime, sniff.ext


def analyze_attachments(
    message: ParsedMessage,
    settings: Settings | None = None,
    *,
    scan_macros: bool = True,
) -> AttachmentAnalysis:
    """Analyze ``message.attachments`` using limits from ``settings``.

    Synchronous and CPU-bound. Async callers should wrap it in
    ``asyncio.to_thread``.
    """
    cfg = settings or get_settings()
    analyzer = AttachmentAnalyzer(
        max_attachment_bytes=cfg.max_attachment_bytes, scan_macros=scan_macros
    )
    return analyzer.analyze(message.attachments)
