"""Risk scoring: findings -> 0-100 score and verdict.

Pipeline position::

    anomaly findings  --\
    attachment flags  ---+--> merge_findings --> score_findings --> ScoreResult
    threat-intel hits --/

Method
------
1. Every finding is worth some **points** (a per-code override, else a default
   per severity: info 0, low 4, medium 10, high 22, critical 45).
2. Points are combined as independent probabilities (**noisy-OR**):
   ``score = 100 * (1 - prod(1 - points_i / 100))``. Many weak signals add up
   but saturate; one strong signal is not drowned out.
3. A few **high-confidence findings set a minimum score** (floors), e.g. an
   executable disguised as a PDF or a malware-listed URL. Floors only ever
   raise the score, and :attr:`ScoreResult.floors_applied` records which
   ones did.
4. The score maps to a verdict: ``>=70`` malicious, ``>=40`` suspicious,
   ``>=15`` low risk, otherwise clean.

Interpretation (state this in any UI):

* ``CLEAN`` means *no indicators were found*, not *safe*. A fresh, targeted
  phish with no known-bad infrastructure and good authentication can score
  clean. Threat-intel ``UNKNOWN`` and ``ERROR`` results never add or remove
  points.
* The weights are heuristics tuned for triage, not calibrated probabilities.
  Tune :data:`CODE_POINTS`, :data:`FLOORS` and :data:`VERDICT_BANDS` for your
  environment.

Threat-intel findings: ``MALICIOUS`` hash/URL verdicts are CRITICAL, domain/IP
verdicts HIGH; ``SUSPICIOUS`` is MEDIUM (hash/URL) or LOW (domain/IP). If two
or more providers flag the same indicator, severity goes up one level.

Every string placed in a finding is defanged and stripped of control/bidi
characters. Pure CPU, no I/O, never raises on well-typed input.
"""

import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final

from phishtriage.core.defang import defang_text
from phishtriage.core.models import (
    IOC,
    SEVERITY_WEIGHT,
    Attachment,
    Finding,
    IntelResult,
    IntelVerdict,
    IOCType,
    Severity,
    Verdict,
)

__all__ = [
    "CODE_POINTS",
    "FLOORS",
    "VERDICT_BANDS",
    "ScoreResult",
    "attachment_findings",
    "intel_findings",
    "merge_findings",
    "points_for",
    "score_findings",
    "verdict_for",
]

_S = Severity
_MAX_EVIDENCE: Final = 10

#: Default points per severity.
SEVERITY_POINTS: Final[dict[Severity, int]] = {
    _S.INFO: 0,
    _S.LOW: 4,
    _S.MEDIUM: 10,
    _S.HIGH: 22,
    _S.CRITICAL: 45,
}

#: Per-code overrides (finding ``code`` -> points). Everything else uses the severity default.
CODE_POINTS: Final[dict[str, int]] = {
    # authentication
    "dmarc_fail": 20,
    "spf_fail": 14,
    "spf_softfail": 7,
    "spf_not_aligned": 10,
    "dkim_fail": 7,
    "dkim_not_aligned": 3,
    "dkim_absent": 2,
    "dmarc_missing": 3,
    "authentication_unavailable": 3,
    # sender identity and content
    "lookalike_sender_domain": 28,
    "display_name_address_spoof": 26,
    "link_text_mismatch": 30,
    "html_password_field": 30,
    # weak or routine signals
    "return_path_mismatch": 2,
    "missing_message_id": 2,
    "missing_date": 2,
    "no_received_headers": 3,
    "origin_no_rdns": 3,
    "received_rdns_mismatch": 3,
    # attachments
    "attachment_disguised_executable": 50,
    "attachment_malicious_vba_pattern": 50,
    "attachment_html_credential_form": 40,
    "attachment_html_smuggling": 35,
}

#: Minimum score when the finding is present (code -> floor).
FLOORS: Final[dict[str, int]] = {
    "attachment_disguised_executable": 70,
    "attachment_malicious_vba_pattern": 70,
    "attachment_html_credential_form": 70,
    "attachment_html_smuggling": 60,
    "attachment_bidi_override": 55,
    "attachment_remote_template": 55,
    "html_password_field": 55,
    "intel_malicious_hash": 85,
    "intel_malicious_url": 85,
    "intel_malicious_domain": 60,
    "intel_malicious_ip": 50,
}

#: ``(minimum score, verdict)``, highest band first.
VERDICT_BANDS: Final[tuple[tuple[int, Verdict], ...]] = (
    (70, Verdict.MALICIOUS),
    (40, Verdict.SUSPICIOUS),
    (15, Verdict.LOW_RISK),
)

_LADDER: Final = (_S.INFO, _S.LOW, _S.MEDIUM, _S.HIGH, _S.CRITICAL)

_INTEL_CATEGORY: Final[dict[IOCType, str]] = {
    IOCType.HASH: "hash",
    IOCType.URL: "url",
    IOCType.DOMAIN: "domain",
    IOCType.IPV4: "ip",
    IOCType.IPV6: "ip",
}
_INTEL_NOUN: Final = {
    "hash": "an attachment hash",
    "url": "a URL",
    "domain": "a domain",
    "ip": "an IP address",
}
_INTEL_SEVERITY: Final[dict[tuple[str, str], Severity]] = {
    ("malicious", "hash"): _S.CRITICAL,
    ("malicious", "url"): _S.CRITICAL,
    ("malicious", "domain"): _S.HIGH,
    ("malicious", "ip"): _S.HIGH,
    ("suspicious", "hash"): _S.MEDIUM,
    ("suspicious", "url"): _S.MEDIUM,
    ("suspicious", "domain"): _S.LOW,
    ("suspicious", "ip"): _S.LOW,
}


# ================================================================== helpers
def _safe(value: object, limit: int = 200) -> str:
    """Render untrusted text for reports: one line, control/bidi escaped, defanged."""
    text = " ".join(str(value)[: limit * 2].split())
    text = "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf") else c for c in text
    )
    return defang_text(text)[:limit]


def _bump(severity: Severity) -> Severity:
    return _LADDER[min(_LADDER.index(severity) + 1, len(_LADDER) - 1)]


def merge_findings(*groups: Iterable[Finding]) -> list[Finding]:
    """Merge findings from several sources into one finding per ``code``.

    Evidence is combined (capped at 10 lines) and the highest severity wins,
    together with its title and detail. Inputs are never mutated. The result is
    sorted most severe first, keeping first-seen order within a severity.
    """
    merged: dict[str, Finding] = {}
    for group in groups:
        for finding in group:
            existing = merged.get(finding.code)
            if existing is None:
                item = finding.model_copy(deep=True)
                item.evidence = item.evidence[:_MAX_EVIDENCE]
                merged[finding.code] = item
                continue
            existing.evidence = list(dict.fromkeys([*existing.evidence, *finding.evidence]))[
                :_MAX_EVIDENCE
            ]
            if SEVERITY_WEIGHT[finding.severity] > SEVERITY_WEIGHT[existing.severity]:
                existing.severity = finding.severity
                existing.title = finding.title
                existing.detail = finding.detail or existing.detail
    return sorted(merged.values(), key=lambda f: -SEVERITY_WEIGHT[f.severity])


# ================================================================ conversions
def attachment_findings(attachments: Sequence[Attachment]) -> list[Finding]:
    """Convert attachment flags into findings coded ``attachment_<flag code>``."""
    raw: list[Finding] = []
    for attachment in attachments:
        name = _safe(attachment.filename, 80)
        for flag in attachment.flags:
            raw.append(
                Finding(
                    code=f"attachment_{flag.code}",
                    severity=flag.severity,
                    title=f"Attachment: {flag.code.replace('_', ' ')}",
                    detail=flag.description[:600],
                    evidence=[f"{name}: {_safe(flag.description, 160)}"],
                )
            )
    return merge_findings(raw)


def _intel_subjects(
    iocs: Sequence[IOC], attachments: Sequence[Attachment]
) -> Iterable[tuple[str, str, Sequence[IntelResult]]]:
    """Yield ``(category, display label, intel results)`` for everything with intel."""
    for ioc in iocs:
        category = _INTEL_CATEGORY.get(ioc.type)
        if category and ioc.intel:
            yield category, _safe(ioc.defanged), ioc.intel
    for attachment in attachments:
        if attachment.sha256 and attachment.intel:
            yield (
                "hash",
                f"{_safe(attachment.filename, 80)} ({attachment.sha256})",
                attachment.intel,
            )


def intel_findings(iocs: Sequence[IOC], attachments: Sequence[Attachment]) -> list[Finding]:
    """Convert threat-intel verdicts into findings coded ``intel_<level>_<category>``.

    Only MALICIOUS and SUSPICIOUS verdicts produce findings. UNKNOWN, CLEAN,
    ERROR and SKIPPED are ignored here (they are still visible on the models).
    """
    raw: list[Finding] = []
    for category, label, results in _intel_subjects(iocs, attachments):
        if any(r.verdict is IntelVerdict.MALICIOUS for r in results):
            level = "malicious"
        elif any(r.verdict is IntelVerdict.SUSPICIOUS for r in results):
            level = "suspicious"
        else:
            continue
        flagged = [
            r for r in results if r.verdict in (IntelVerdict.MALICIOUS, IntelVerdict.SUSPICIOUS)
        ]
        providers = sorted({r.provider for r in flagged})
        severity = _INTEL_SEVERITY[(level, category)]
        if len(providers) >= 2:
            severity = _bump(severity)
        top = max((r.score for r in flagged if r.score is not None), default=None)
        evidence = f"{label}: {', '.join(providers)}"
        if top is not None:
            evidence += f" (top score {top})"
        raw.append(
            Finding(
                code=f"intel_{level}_{category}",
                severity=severity,
                title=f"Threat intelligence flags {_INTEL_NOUN[category]} as {level}",
                detail=(
                    "Third-party feeds flag an indicator found in this message. Feeds can "
                    "contain false positives: confirm before blocking."
                ),
                evidence=[evidence],
            )
        )
    return merge_findings(raw)


# ===================================================================== scoring
@dataclass(frozen=True)
class ScoreResult:
    """Outcome of :func:`score_findings`."""

    score: int
    verdict: Verdict
    raw_score: int  # before floors
    contributions: tuple[tuple[str, int], ...] = ()  # (code, points), largest first
    floors_applied: tuple[tuple[str, int], ...] = field(default=())  # floors above raw_score


def points_for(finding: Finding) -> int:
    """Points a finding contributes (override by code, else by severity)."""
    return CODE_POINTS.get(finding.code, SEVERITY_POINTS[finding.severity])


def verdict_for(score: int) -> Verdict:
    """Map a 0-100 score to a :class:`Verdict`."""
    for minimum, verdict in VERDICT_BANDS:
        if score >= minimum:
            return verdict
    return Verdict.CLEAN


def score_findings(findings: Iterable[Finding]) -> ScoreResult:
    """Compute the risk score and verdict for ``findings`` (one per code expected)."""
    contributions: list[tuple[str, int]] = []
    floors: list[tuple[str, int]] = []
    remaining = 1.0
    for finding in findings:
        points = max(0, min(100, points_for(finding)))
        if points:
            contributions.append((finding.code, points))
            remaining *= 1.0 - points / 100.0
        floor = FLOORS.get(finding.code)
        if floor:
            floors.append((finding.code, floor))

    raw = max(0, min(100, round(100.0 * (1.0 - remaining))))
    score = max([raw, *(floor for _, floor in floors)])
    contributions.sort(key=lambda item: -item[1])
    return ScoreResult(
        score=score,
        verdict=verdict_for(score),
        raw_score=raw,
        contributions=tuple(contributions),
        floors_applied=tuple((code, floor) for code, floor in floors if floor > raw),
    )
