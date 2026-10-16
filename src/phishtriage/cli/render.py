"""Terminal rendering for the CLI (``rich``).

Rules that every function here follows:

* **Untrusted text never reaches rich as markup.** Dynamic values are wrapped in
  :class:`rich.text.Text`, and consoles are created with ``markup=False``, so
  ``[red]`` in a subject line is shown literally.
* **Safe to paste.** Control and direction-override characters are escaped as
  ``\\uXXXX``, whitespace is collapsed, and URLs and e-mail addresses are
  defanged (:func:`phishtriage.core.defang.defang_text`).
* **Copy-friendly hashes.** Hash lines are printed with ``soft_wrap=True`` so a
  terminal never inserts line breaks into them.
* Pure presentation: nothing here performs I/O other than writing to the
  supplied console, and nothing raises on well-typed input.
"""

import unicodedata
from collections.abc import Collection, Iterable, Sequence
from datetime import datetime
from typing import Any, Final

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishtriage.config import Settings
from phishtriage.core.defang import defang_text
from phishtriage.core.models import (
    IOC,
    TOOL_VERSION,
    Attachment,
    AuthReport,
    AuthResult,
    AuthStatus,
    Finding,
    IntelResult,
    IntelVerdict,
    ParsedAddress,
    ReceivedTrace,
    Report,
    Severity,
    Verdict,
)
from phishtriage.intel.base import ProviderStatus

__all__ = [
    "IOC_TYPE_CHOICES",
    "ioc_text_lines",
    "iocs_json",
    "make_console",
    "render_error",
    "render_iocs",
    "render_report",
    "render_status",
]

#: Values accepted by ``--type`` on the ``iocs`` command.
IOC_TYPE_CHOICES: Final = ("url", "email", "ipv4", "ipv6", "domain", "hash")

_MAX_EVIDENCE_LINES: Final = 3
_MAX_FLAGS_SHOWN: Final = 6
_MAX_IOC_ROWS: Final = 200
_MAX_HEADER_ROWS: Final = 300
_MAX_RECIPIENTS_SHOWN: Final = 3

_VERDICT_LABEL: Final[dict[Verdict, tuple[str, str, str]]] = {
    # verdict -> (label, badge style, panel border colour)
    Verdict.MALICIOUS: ("MALICIOUS", "bold white on red", "red"),
    Verdict.SUSPICIOUS: ("SUSPICIOUS", "bold black on yellow", "yellow"),
    Verdict.LOW_RISK: ("LOW RISK", "bold black on cyan", "cyan"),
    Verdict.CLEAN: ("CLEAN (no indicators)", "bold white on green", "green"),
}
_SEVERITY_STYLE: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_AUTH_STYLE: Final[dict[AuthStatus, str]] = {
    AuthStatus.PASS: "bold white on green",
    AuthStatus.FAIL: "bold white on red",
    AuthStatus.SOFTFAIL: "bold black on yellow",
    AuthStatus.NEUTRAL: "black on yellow",
    AuthStatus.TEMPERROR: "bold white on magenta",
    AuthStatus.PERMERROR: "bold white on magenta",
    AuthStatus.NONE: "dim",
    AuthStatus.POLICY: "dim",
    AuthStatus.UNKNOWN: "dim",
}


# ================================================================== helpers
def make_console(*, no_color: bool = False, stderr: bool = False) -> Console:
    """Create a console with markup, emoji and auto-highlighting disabled."""
    return Console(stderr=stderr, no_color=no_color, markup=False, emoji=False, highlight=False)


def _escape_ctrl(text: str) -> str:
    """Show control and format (bidi, zero-width) characters as ``\\uXXXX``."""
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf") else c for c in text
    )


def _safe(value: object, limit: int = 200) -> str:
    """One safe, defanged line of at most ``limit`` characters."""
    text = " ".join(str(value)[: limit * 2].split())
    return defang_text(_escape_ctrl(text))[:limit]


def _txt(value: object, style: str = "", limit: int = 200) -> Text:
    return Text(_safe(value, limit), style=style)


def _dash() -> Text:
    return Text("-", style="dim")


def _addr(address: ParsedAddress | None) -> str:
    if address is None:
        return "(none)"
    name, mail = address.display_name, address.address
    if name and mail:
        return f"{name} <{mail}>"
    return name or mail or "(none)"


def _addr_list(addresses: Sequence[ParsedAddress]) -> str:
    if not addresses:
        return "(none)"
    shown = ", ".join(_addr(a) for a in addresses[:_MAX_RECIPIENTS_SHOWN])
    extra = len(addresses) - _MAX_RECIPIENTS_SHOWN
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _fmt_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB"):
        if value < 1024:
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _fmt_delay(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    sign = "-" if seconds < 0 else ""
    total = int(abs(seconds))
    if total < 60:
        return f"{sign}{total}s"
    if total < 3600:
        return f"{sign}{total // 60}m {total % 60}s"
    if total < 86400:
        return f"{sign}{total // 3600}h {total % 3600 // 60}m"
    return f"{sign}{total // 86400}d {total % 86400 // 3600}h"


def _fmt_dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S %z").strip() if value else "(none)"


def _section(console: Console, title: str) -> None:
    console.print()
    console.rule(Text(title, style="bold"), align="left", style="dim")


def _lines(parts: Iterable[Text]) -> Text:
    return Text("\n").join(list(parts))


def _badge(status: AuthStatus) -> Text:
    return Text(f" {status.value.upper()} ", style=_AUTH_STYLE.get(status, "dim"))


def _aligned_cell(aligned: bool | None) -> Text:
    if aligned is True:
        return Text("aligned", style="green")
    if aligned is False:
        return Text("NOT aligned", style="bold red")
    return _dash()


def _intel_cell(results: Sequence[IntelResult]) -> Text:
    """Summarise provider verdicts without ever implying 'safe'."""
    flagged = [
        r for r in results if r.verdict in (IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS)
    ]
    if flagged:
        worst_bad = any(r.verdict is IntelVerdict.MALICIOUS for r in flagged)
        text = "; ".join(
            f"{r.provider}: {r.verdict.value}" + (f" ({r.score})" if r.score is not None else "")
            for r in flagged
        )
        return _txt(text, "bold red" if worst_bad else "yellow", 160)
    if not results:
        return _dash()
    if any(r.verdict is IntelVerdict.CLEAN for r in results):
        return Text("no detections", style="green")
    if any(r.verdict is IntelVerdict.UNKNOWN for r in results):
        return Text("no data", style="dim")
    return Text("lookup failed", style="dim")


# ================================================================ summary panel
def _render_summary(console: Console, report: Report) -> None:
    label, style, border = _VERDICT_LABEL[report.verdict]
    msg = report.message
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row(
        "Verdict",
        Text.assemble((f" {label} ", style), f"   risk score {report.risk_score}/100"),
    )
    grid.add_row("File", _txt(f"{report.filename or '(stdin)'}  ({_fmt_size(report.file_size)}, "
                              f"{msg.source_format})"))
    grid.add_row("Subject", _txt(msg.subject or "(none)", limit=300))
    grid.add_row("From", _txt(_addr(msg.from_address), limit=300))
    grid.add_row("Reply-To", _txt(_addr_list(msg.reply_to), limit=300))
    grid.add_row("Return-Path", _txt(msg.return_path or "(none)"))
    grid.add_row("To", _txt(_addr_list(msg.to), limit=300))
    grid.add_row("Date", _txt(_fmt_dt(msg.date)))
    grid.add_row("Message-ID", _txt(msg.message_id or "(none)"))
    console.print(Panel(grid, title=Text(" Phishing Triage ", style="bold"), border_style=border,
                        padding=(1, 2)))
    console.print(Text(f"File SHA-256: {report.file_sha256}"), soft_wrap=True)
    if report.verdict in (Verdict.CLEAN, Verdict.LOW_RISK):
        console.print(
            Text("Note: this verdict means few or no indicators were found. It does not prove "
                 "the message is safe.", style="dim italic")
        )


# ===================================================================== findings
def _finding_cell(finding: Finding) -> Text:
    parts = [_txt(finding.title, "bold", 200), _txt(finding.code, "dim", 80)]
    shown = finding.evidence[:_MAX_EVIDENCE_LINES]
    parts.extend(_txt(f"  - {line}", "", 240) for line in shown)
    hidden = len(finding.evidence) - len(shown)
    if hidden > 0:
        parts.append(Text(f"  (+{hidden} more in the JSON report)", style="dim"))
    return _lines(parts)


def _render_findings(console: Console, report: Report) -> None:
    _section(console, f"Findings ({len(report.findings)})")
    if not report.findings:
        console.print(Text("No findings.", style="dim"))
        return
    table = Table(box=box.MINIMAL, show_lines=True, pad_edge=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Finding", overflow="fold")
    for finding in report.findings:
        table.add_row(
            Text(f" {finding.severity.value.upper()} ", style=_SEVERITY_STYLE[finding.severity]),
            _finding_cell(finding),
        )
    console.print(table)


# ================================================================ authentication
def _render_auth(console: Console, report: Report) -> None:
    auth: AuthReport = report.authentication
    _section(console, f"Authentication (From domain: {_safe(auth.from_domain or 'unknown', 80)})")
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    for column in ("Check", "Result", "Alignment", "Domain", "Source", "Detail"):
        table.add_column(column, overflow="fold", no_wrap=column in ("Check", "Result"))

    def add(label: str, result: AuthResult) -> None:
        table.add_row(
            label,
            _badge(result.status),
            _aligned_cell(result.aligned),
            _txt(result.domain or "-", limit=80),
            Text(result.source.value, style="dim"),
            _txt(result.detail, "dim", 110),
        )

    add("SPF", auth.spf)
    if auth.dkim:
        for result in auth.dkim:
            add(f"DKIM ({_safe(result.selector, 30)})" if result.selector else "DKIM", result)
    else:
        table.add_row("DKIM", _badge(AuthStatus.NONE), _dash(), _dash(),
                      Text("absent", style="dim"), Text("No DKIM signature", style="dim"))
    add("DMARC", auth.dmarc)
    console.print(table)

    policy = auth.dmarc_policy
    if policy is not None:
        console.print(_txt(
            f"Published DMARC policy ({policy.domain}): p={policy.policy or 'unspecified'}, "
            f"sp={policy.subdomain_policy or 'inherit'}, pct={policy.percentage}, "
            f"aspf={policy.spf_alignment}, adkim={policy.dkim_alignment}", "dim", 300))


# ================================================================ received path
def _hop_ip_cell(hop_ips: Sequence[Any]) -> Text:
    if not hop_ips:
        return _dash()
    parts: list[Text] = []
    for ip in hop_ips:
        parts.append(_txt(f"{ip.address} [{ip.scope.value}]", "", 100))
        if ip.rdns:
            parts.append(_txt(f"  rDNS {ip.rdns}", "dim", 120))
        elif ip.rdns_error:
            parts.append(_txt(f"  rDNS: {ip.rdns_error}", "dim", 80))
    return _lines(parts)


def _render_received(console: Console, report: Report) -> None:
    trace: ReceivedTrace = report.received
    _section(console, f"Delivery path ({len(trace.hops)} hop(s), oldest first)")
    if trace.hops:
        origin_index = trace.originating_mta.hop_index if trace.originating_mta else -1
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("From -> By", overflow="fold")
        table.add_column("Sending IP", overflow="fold")
        table.add_column("Delay", justify="right", no_wrap=True)
        table.add_column("Notes", overflow="fold")
        for hop in trace.hops:
            route = Text.assemble(
                (_safe(hop.from_host or "?", 70), "bold"), " -> ", _safe(hop.by_host or "?", 70)
            )
            notes = [_txt(a, "yellow", 200) for a in hop.anomalies]
            if hop.index == origin_index:
                notes.insert(0, Text("* estimated origin", style="bold green"))
            table.add_row(
                str(hop.index + 1), route, _hop_ip_cell(hop.ips),
                _fmt_delay(hop.delay_seconds), _lines(notes) if notes else _dash(),
            )
        console.print(table)
    origin = trace.originating_mta
    if origin is not None:
        label = _safe(origin.hostname or origin.rdns or "unknown host", 100)
        console.print(Text.assemble(("Originating MTA: ", "bold"), f"{origin.ip} ({label})"))
        console.print(_txt(origin.reason, "dim", 400))
    else:
        console.print(Text("No public originating IP could be identified.", style="dim"))
    if trace.total_delay_seconds is not None:
        console.print(Text(f"Total transit time: {_fmt_delay(trace.total_delay_seconds)}",
                           style="dim"))


# ==================================================================== raw headers
def _render_headers(console: Console, report: Report) -> None:
    _section(console, f"Raw headers ({len(report.headers)})")
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("Header", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold")
    for header in report.headers[:_MAX_HEADER_ROWS]:
        table.add_row(_txt(header.name, "bold", 60), _txt(header.value, "", 400))
    console.print(table)
    hidden = len(report.headers) - _MAX_HEADER_ROWS
    if hidden > 0:
        console.print(Text(f"(+{hidden} more headers in the JSON report)", style="dim"))


# =========================================================================== IOCs
def _select(iocs: Iterable[IOC], types: Collection[str] | None) -> list[IOC]:
    return [i for i in iocs if types is None or i.type.value in types]


def _ioc_table(iocs: Sequence[IOC], *, max_rows: int = _MAX_IOC_ROWS) -> Table:
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("Type", no_wrap=True)
    table.add_column("Indicator (defanged)", overflow="fold")
    table.add_column("Seen", justify="right", no_wrap=True)
    table.add_column("Found in", overflow="fold")
    table.add_column("Threat intel", overflow="fold")
    for ioc in iocs[:max_rows]:
        table.add_row(
            ioc.type.value,
            Text(_escape_ctrl(ioc.defanged)[:400]),
            str(ioc.count),
            _txt(", ".join(s.value for s in ioc.sources), "dim", 80),
            _intel_cell(ioc.intel),
        )
    return table


def _print_hashes(console: Console, attachments: Sequence[Attachment]) -> None:
    rows = [a for a in attachments if a.sha256]
    if not rows:
        return
    console.print(Text("Attachment hashes", style="bold"))
    for attachment in rows:
        console.print(_txt(f"  {attachment.filename}", "", 120))
        for label, value in (("sha256", attachment.sha256), ("sha1", attachment.sha1),
                             ("md5", attachment.md5)):
            if value:
                console.print(Text(f"    {label:<7}{value}"), soft_wrap=True)


def _render_iocs_section(console: Console, report: Report) -> None:
    _section(console, f"Indicators ({len(report.iocs)})")
    if not report.iocs:
        console.print(Text("No indicators extracted.", style="dim"))
        return
    console.print(_ioc_table(report.iocs))
    hidden = len(report.iocs) - _MAX_IOC_ROWS
    if hidden > 0:
        console.print(Text(f"(+{hidden} more in the JSON report)", style="dim"))


def render_iocs(
    console: Console,
    report: Report,
    *,
    types: Collection[str] | None = None,
    include_hashes: bool = True,
) -> None:
    """Print only the indicator table (and attachment hashes) of ``report``."""
    selected = _select(report.iocs, types)
    if selected:
        console.print(_ioc_table(selected))
    else:
        console.print(Text("No matching indicators.", style="dim"))
    if include_hashes and (types is None or "hash" in types):
        _print_hashes(console, report.attachments)


def ioc_text_lines(
    report: Report, types: Collection[str] | None = None, include_hashes: bool = True
) -> list[str]:
    """Defanged IOCs (then attachment SHA-256 hashes), one per line, de-duplicated.

    Intended for pasting into tickets. Control and direction characters are escaped.
    """
    lines = [_escape_ctrl(i.defanged) for i in _select(report.iocs, types)]
    if include_hashes and (types is None or "hash" in types):
        lines.extend(a.sha256 for a in report.attachments if a.sha256)
    return list(dict.fromkeys(line for line in lines if line))


def iocs_json(
    report: Report,
    label: str,
    types: Collection[str] | None = None,
    include_hashes: bool = True,
) -> dict[str, Any]:
    """Machine-readable IOC summary. Only defanged values are included, on purpose."""
    attachments: list[dict[str, Any]] = []
    if include_hashes and (types is None or "hash" in types):
        attachments = [
            {"filename": _escape_ctrl(a.filename), "size": a.size, "sha256": a.sha256,
             "sha1": a.sha1, "md5": a.md5}
            for a in report.attachments if a.sha256
        ]
    return {
        "file": _escape_ctrl(report.filename or label),
        "verdict": report.verdict.value,
        "risk_score": report.risk_score,
        "iocs": [
            {
                "type": i.type.value,
                "defanged": _escape_ctrl(i.defanged),
                "count": i.count,
                "sources": [s.value for s in i.sources],
                "intel_verdict": i.worst_intel_verdict.value,
            }
            for i in _select(report.iocs, types)
        ],
        "attachments": attachments,
    }


# ================================================================== attachments
def _flags_cell(attachment: Attachment) -> Text:
    if not attachment.flags:
        return Text("none", style="dim")
    parts = [
        Text(f"{f.severity.value} {f.code}", style=_SEVERITY_STYLE[f.severity])
        for f in attachment.flags[:_MAX_FLAGS_SHOWN]
    ]
    hidden = len(attachment.flags) - _MAX_FLAGS_SHOWN
    if hidden > 0:
        parts.append(Text(f"(+{hidden} more)", style="dim"))
    return _lines(parts)


def _render_attachments(console: Console, report: Report) -> None:
    _section(console, f"Attachments ({len(report.attachments)})")
    if not report.attachments:
        console.print(Text("No attachments.", style="dim"))
        return
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("File", overflow="fold")
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("Detected type", overflow="fold")
    table.add_column("Flags", overflow="fold")
    table.add_column("Threat intel", overflow="fold")
    for attachment in report.attachments:
        detected = _lines([
            _txt(attachment.detected_extension or "?", "bold", 20),
            _txt(attachment.detected_mime or ("not inspected" if attachment.skipped else "-"),
                 "dim", 60),
        ])
        table.add_row(
            _txt(attachment.filename, "", 100),
            _fmt_size(attachment.size),
            detected,
            _flags_cell(attachment),
            _intel_cell(attachment.intel),
        )
    console.print(table)
    _print_hashes(console, report.attachments)


# ================================================================ notes / footer
def _render_notes(console: Console, report: Report) -> None:
    sources = (("report", report.warnings), ("received", report.received.warnings),
               ("authentication", report.authentication.warnings))
    notes = list(dict.fromkeys((src, w) for src, items in sources for w in items))
    if not notes:
        return
    _section(console, f"Notes and warnings ({len(notes)})")
    for source, warning in notes:
        console.print(Text.assemble(("  - ", "yellow"), (f"[{source}] ", "dim"),
                                    _safe(warning, 500)))


def _render_footer(console: Console, report: Report) -> None:
    used = ", ".join(report.intel_providers_used) or ("offline" if report.offline else "none")
    console.print()
    console.print(Text(
        f"phishtriage {report.tool_version} | report {report.report_id} | "
        f"{report.generated_at:%Y-%m-%d %H:%M:%S} UTC | threat intel: {used}", style="dim"))


def render_report(console: Console, report: Report, *, show_headers: bool = False) -> None:
    """Render a full report: summary, findings, authentication, path, IOCs, attachments."""
    _render_summary(console, report)
    _render_findings(console, report)
    _render_auth(console, report)
    _render_received(console, report)
    if show_headers:
        _render_headers(console, report)
    _render_iocs_section(console, report)
    _render_attachments(console, report)
    _render_notes(console, report)
    _render_footer(console, report)


# ======================================================================== status
def render_status(console: Console, settings: Settings, statuses: Sequence[ProviderStatus]) -> None:
    """Print configuration highlights and the state of every threat-intel provider."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(overflow="fold")
    offline = "yes (no network activity at all)" if settings.offline else "no"
    rows = (
        ("Version", TOOL_VERSION),
        ("Environment", settings.environment),
        ("Offline mode", offline),
        ("Max upload", _fmt_size(settings.max_upload_bytes)),
        ("Max attachment", _fmt_size(settings.max_attachment_bytes)),
        ("HTTP timeout", f"{settings.http_timeout_seconds:g}s, {settings.http_max_retries} retries"),
        ("DNS resolvers", ", ".join(settings.dns_nameservers) or "system default"),
        ("Intel cache", f"{settings.cache_ttl_seconds}s TTL, {settings.cache_max_entries} entries"),
    )
    for key, value in rows:
        grid.add_row(key, _txt(value, limit=120))
    console.print(Panel(grid, title=Text(" Configuration ", style="bold"), padding=(1, 2)))

    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("Provider", style="bold", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Rate limit", no_wrap=True)
    table.add_column("Note", overflow="fold")
    for status in statuses:
        rpm = getattr(settings, f"{status.name}_requests_per_minute", None)
        state = Text(" ENABLED ", style="bold white on green") if status.enabled else Text(
            " disabled ", style="dim")
        table.add_row(status.name, state, f"{rpm}/min" if rpm else "-",
                      _txt(status.reason or "ready", "dim", 120))
    console.print(table)


# ======================================================================== errors
def render_error(console: Console, label: str, message: str) -> None:
    """Print ``error: <label>: <message>`` (intended for a stderr console)."""
    console.print(Text.assemble(("error: ", "bold red"), (f"{_safe(label, 120)}: " if label else "",
                                                          "bold"), _safe(message, 500)))