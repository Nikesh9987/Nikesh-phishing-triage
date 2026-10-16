"""``phishtriage`` command-line interface.

Commands::

    phishtriage analyze FILE...   full triage report (tables or JSON)
    phishtriage iocs    FILE...   only the indicators, ready to paste into a ticket
    phishtriage status            configuration and threat-intel provider state

Conventions:

* **stdout** carries results only (tables, or JSON/text with ``--json`` /
  ``--format``). **stderr** carries errors, notices and logs, so pipes stay clean.
* ``FILE`` may be ``-`` to read one message from standard input.
* With several files, every file is processed and printed; failures are reported
  on stderr and do not stop the others. The exit code is that of the first
  failing file.
* JSON: one file gives an object, several files give an array (failed files are
  omitted from it). All non-ASCII characters are escaped, so hostile text can
  never reach a terminal raw.

Exit codes: see ``phishtriage --help``.
"""

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError
from rich.text import Text

from phishtriage.cli.render import (
    IOC_TYPE_CHOICES,
    ioc_text_lines,
    iocs_json,
    make_console,
    render_error,
    render_iocs,
    render_report,
    render_status,
)
from phishtriage.config import Settings, get_settings
from phishtriage.core.exceptions import (
    ConfigurationError,
    FileTooLargeError,
    InputError,
    PhishTriageError,
)
from phishtriage.core.models import TOOL_VERSION, Report, Verdict
from phishtriage.core.pipeline import TriagePipeline
from phishtriage.logging_config import configure_logging, get_logger

__all__ = ["build_parser", "main", "read_input"]

logger = get_logger(__name__)

_EXIT_THRESHOLD: Final = 10
_EXIT_SIGINT: Final = 130
_EXIT_PIPE: Final = 141
_STDIN_LABEL: Final = "<stdin>"
_VERDICT_RANK: Final[dict[Verdict, int]] = {
    Verdict.CLEAN: 0,
    Verdict.LOW_RISK: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}

_EPILOG: Final = """\
exit codes:
  0    success
  2    bad input or arguments (missing, empty, oversized or unrecognised file)
  3    the message could not be parsed
  10   --fail-on threshold reached
  78   invalid configuration
  130  interrupted
With several files the exit code is that of the first failing file.

configuration: environment variables / .env (see .env.example).
Threat-intel API keys are read from there, never from the command line.
"""


# ====================================================================== input
def read_input(spec: str, limit: int) -> bytes:
    """Read one message (a path, or ``-`` for stdin), never more than ``limit`` bytes.

    Raises:
        InputError: the file is missing, a directory, or unreadable.
        FileTooLargeError: the input exceeds ``limit`` bytes.
    """
    if spec == "-":
        try:
            data = sys.stdin.buffer.read(limit + 1)
        except OSError as exc:
            raise InputError(f"Cannot read standard input: {exc.strerror or 'I/O error'}") from None
        if len(data) > limit:
            raise FileTooLargeError(len(data), limit)
        return data

    path = Path(spec)
    try:
        if not path.exists():
            raise InputError(f"File not found: {spec}")
        if path.is_dir():
            raise InputError(f"Is a directory, not a message file: {spec}")
        size = path.stat().st_size
        if size > limit:
            raise FileTooLargeError(size, limit)
        with path.open("rb") as handle:
            data = handle.read(limit + 1)  # re-check: pipes and growing files report size 0
    except OSError as exc:
        raise InputError(f"Cannot read {spec}: {exc.strerror or type(exc).__name__}") from None
    if len(data) > limit:
        raise FileTooLargeError(len(data), limit)
    return data


# ===================================================================== parser
def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _split_csv(values: Sequence[str]) -> list[str]:
    return [part.strip() for value in values for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--offline", action="store_true",
                        help="no network activity at all (no threat intel, no DNS lookups)")
    common.add_argument("--no-color", action="store_true", help="disable colours")
    common.add_argument("-v", "--verbose", action="count", default=0,
                        help="log to stderr: -v info, -vv debug")

    inputs = argparse.ArgumentParser(add_help=False)
    inputs.add_argument("files", nargs="+", metavar="FILE",
                        help=".eml or .msg file(s); use '-' to read one message from stdin")
    inputs.add_argument("--trusted-hops", type=_positive_int, metavar="N",
                        help="number of NEWEST Received hops run by your own servers; the origin "
                             "is then taken from what your server observed")
    inputs.add_argument("--trusted-authserv", action="append", default=[], metavar="ID",
                        help="only trust Authentication-Results from this authserv-id "
                             "(repeatable, or comma-separated)")
    inputs.add_argument("--no-macros", action="store_true",
                        help="skip the CPU-heavy Office macro scan")

    parser = argparse.ArgumentParser(
        prog="phishtriage",
        description="Phishing triage and e-mail header analysis for SOC analysts.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    analyze = sub.add_parser("analyze", parents=[common, inputs],
                             help="full triage report",
                             description="Analyze one or more messages and print a triage report.")
    analyze.add_argument("--no-enrich", action="store_true", help="skip threat-intel lookups")
    analyze.add_argument("--json", action="store_true", help="print the report as JSON on stdout")
    analyze.add_argument("-o", "--output", metavar="PATH",
                         help="also write the JSON report to PATH (overwrites)")
    analyze.add_argument("--headers", action="store_true", help="include all raw headers")
    analyze.add_argument("--fail-on", choices=("low_risk", "suspicious", "malicious"),
                         help=f"exit with code {_EXIT_THRESHOLD} if a verdict reaches this level")

    iocs = sub.add_parser("iocs", parents=[common, inputs],
                          help="extract indicators for tickets",
                          description="Extract defanged indicators of compromise and attachment "
                                      "hashes.")
    iocs.add_argument("--enrich", action="store_true",
                      help="query threat-intel providers (off by default for speed)")
    iocs.add_argument("--type", dest="types", action="append", choices=IOC_TYPE_CHOICES,
                      help="only this indicator type (repeatable); 'hash' = attachment SHA-256")
    iocs.add_argument("--format", choices=("table", "text", "json"), default="table",
                      help="table (default), text (one defanged value per line), or json")
    iocs.add_argument("--no-hashes", action="store_true", help="leave out attachment hashes")

    status = sub.add_parser("status", parents=[common], help="configuration and provider state",
                            description="Show configuration highlights and which threat-intel "
                                        "providers are enabled.")
    status.add_argument("--json", action="store_true", help="print as JSON on stdout")
    return parser


# =================================================================== execution
@dataclass
class _Outcome:
    label: str
    report: Report | None = None
    error: PhishTriageError | None = None


def _load_settings(args: argparse.Namespace) -> Settings:
    try:
        settings = get_settings()
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'settings'}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigurationError(f"Invalid configuration: {problems}") from None
    if args.offline and not settings.offline:
        settings = settings.model_copy(update={"offline": True})
    return settings


async def _run_async(args: argparse.Namespace, settings: Settings, *, enrich: bool) -> list[_Outcome]:
    authserv = _split_csv(args.trusted_authserv) or None
    outcomes: list[_Outcome] = []
    async with TriagePipeline(settings) as pipeline:
        for spec in args.files:
            label = _STDIN_LABEL if spec == "-" else spec
            try:
                data = await asyncio.to_thread(read_input, spec, settings.max_upload_bytes)
                report = await pipeline.analyze(
                    data,
                    None if spec == "-" else spec,
                    trusted_hops=args.trusted_hops,
                    trusted_authserv_ids=authserv,
                    enrich=enrich,
                    scan_macros=not args.no_macros,
                )
                outcomes.append(_Outcome(label, report=report))
            except PhishTriageError as exc:
                outcomes.append(_Outcome(label, error=exc))
            except Exception as exc:  # noqa: BLE001 - keep processing the remaining files
                logger.debug("Unexpected failure for %s", label, exc_info=True)
                outcomes.append(_Outcome(label, error=PhishTriageError(
                    f"Unexpected {type(exc).__name__}; re-run with -vv for details.")))
    return outcomes


def _report_errors(err: Any, outcomes: Sequence[_Outcome]) -> None:
    for outcome in outcomes:
        if outcome.error is not None:
            render_error(err, outcome.label, outcome.error.message)


def _exit_code(outcomes: Sequence[_Outcome], fail_on: str | None = None) -> int:
    for outcome in outcomes:
        if outcome.error is not None:
            return outcome.error.exit_code
    if fail_on is not None:
        limit = _VERDICT_RANK[Verdict(fail_on)]
        if any(o.report is not None and _VERDICT_RANK[o.report.verdict] >= limit for o in outcomes):
            return _EXIT_THRESHOLD
    return 0


def _dump(payload: Any) -> str:
    """JSON text with every non-ASCII character escaped (terminal-safe)."""
    return json.dumps(payload, indent=2, ensure_ascii=True)


def _shape(items: list[dict[str, Any]], single: bool) -> Any:
    """One requested file -> object; several -> array."""
    return items[0] if single and items else items


def _write_file(path: str, text: str) -> None:
    try:
        Path(path).write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise InputError(f"Cannot write {path}: {exc.strerror or type(exc).__name__}") from None


# =================================================================== commands
def _cmd_analyze(args: argparse.Namespace, settings: Settings, out: Any, err: Any) -> int:
    outcomes = asyncio.run(_run_async(args, settings, enrich=not args.no_enrich))
    _report_errors(err, outcomes)
    reports = [o.report for o in outcomes if o.report is not None]

    payload = ""
    if (args.json or args.output) and reports:
        payload = _dump(_shape([r.to_json_dict() for r in reports], len(args.files) == 1))

    if args.json:
        if payload:
            sys.stdout.write(payload + "\n")
    else:
        for index, report in enumerate(reports):
            if index:
                out.print()
                out.rule(style="dim")
            render_report(out, report, show_headers=args.headers)
    if args.output and payload:
        _write_file(args.output, payload)
        err.print(Text(f"Wrote JSON report to {args.output}", style="dim"))
    return _exit_code(outcomes, args.fail_on)


def _cmd_iocs(args: argparse.Namespace, settings: Settings, out: Any, err: Any) -> int:
    outcomes = asyncio.run(_run_async(args, settings, enrich=args.enrich))
    _report_errors(err, outcomes)
    good = [(o.label, o.report) for o in outcomes if o.report is not None]
    types = frozenset(args.types) if args.types else None
    hashes = not args.no_hashes

    if args.format == "text":
        lines = list(dict.fromkeys(
            line for _, report in good for line in ioc_text_lines(report, types, hashes)))
        if lines:
            sys.stdout.write("\n".join(lines) + "\n")
    elif args.format == "json":
        items = [iocs_json(report, label, types, hashes) for label, report in good]
        if items:
            sys.stdout.write(_dump(_shape(items, len(args.files) == 1)) + "\n")
    else:
        for label, report in good:
            if len(args.files) > 1:
                out.rule(Text(label), align="left", style="dim")
            render_iocs(out, report, types=types, include_hashes=hashes)
    return _exit_code(outcomes)


def _cmd_status(args: argparse.Namespace, settings: Settings, out: Any, err: Any) -> int:
    async def collect() -> list[Any]:
        async with TriagePipeline(settings) as pipeline:
            return list(pipeline.provider_statuses())

    statuses = asyncio.run(collect())
    if args.json:
        payload = {
            "version": TOOL_VERSION,
            "offline": settings.offline,
            "providers": [{"name": s.name, "enabled": s.enabled, "reason": s.reason}
                          for s in statuses],
        }
        sys.stdout.write(_dump(payload) + "\n")
    else:
        render_status(out, settings, statuses)
    return 0


_COMMANDS: Final = {"analyze": _cmd_analyze, "iocs": _cmd_iocs, "status": _cmd_status}


# ======================================================================= main
def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    for stream in (sys.stdout, sys.stderr):  # never crash on unusual characters
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(errors="backslashreplace")

    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "files", []).count("-") > 1:
        parser.error("standard input ('-') can only be given once")

    out = make_console(no_color=args.no_color)
    err = make_console(no_color=args.no_color, stderr=True)
    try:
        settings = _load_settings(args)
        level = {0: "WARNING", 1: "INFO"}.get(args.verbose, "DEBUG")
        configure_logging(level, settings.log_format, secrets=settings.secret_values())
        return _COMMANDS[args.command](args, settings, out, err)
    except PhishTriageError as exc:
        render_error(err, "", exc.message)
        return exc.exit_code
    except KeyboardInterrupt:
        err.print(Text("Interrupted.", style="dim"))
        return _EXIT_SIGINT
    except BrokenPipeError:  # e.g. `phishtriage ... | head`
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return _EXIT_PIPE


if __name__ == "__main__":
    sys.exit(main())