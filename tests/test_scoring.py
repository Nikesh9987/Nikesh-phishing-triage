"""Tests for ``core/scoring.py``."""

import pytest

from phishtriage.core.models import (
    IOC,
    Attachment,
    AttachmentFlag,
    Finding,
    IntelResult,
    IntelVerdict,
    IOCType,
    Severity,
    Verdict,
)
from phishtriage.core.scoring import (
    CODE_POINTS,
    FLOORS,
    SEVERITY_POINTS,
    VERDICT_BANDS,
    attachment_findings,
    intel_findings,
    merge_findings,
    points_for,
    score_findings,
    verdict_for,
)

S = Severity
V = IntelVerdict


def finding(code: str, severity: Severity = S.LOW, **kwargs: object) -> Finding:
    return Finding(code=code, severity=severity, title=kwargs.pop("title", code), **kwargs)  # type: ignore[arg-type]


def intel(provider: str, verdict: IntelVerdict, ioc_type: IOCType, score: int | None = None) -> IntelResult:
    return IntelResult(provider=provider, indicator="x", indicator_type=ioc_type, verdict=verdict, score=score)


def url_ioc(value: str, *results: IntelResult) -> IOC:
    return IOC(type=IOCType.URL, value=value, defanged=value, intel=list(results))


# ================================================================ merging
class TestMerge:
    def test_one_finding_per_code_with_combined_evidence(self) -> None:
        merged = merge_findings(
            [finding("a", evidence=["one", "two"])],
            [finding("a", evidence=["two", "three"])],
        )
        assert len(merged) == 1 and merged[0].evidence == ["one", "two", "three"]

    def test_highest_severity_wins_with_its_title(self) -> None:
        merged = merge_findings(
            [finding("a", S.LOW, title="weak")], [finding("a", S.HIGH, title="strong", detail="why")]
        )
        assert (merged[0].severity, merged[0].title, merged[0].detail) == (S.HIGH, "strong", "why")

    def test_inputs_are_not_mutated(self) -> None:
        original = finding("a", evidence=["one"])
        merge_findings([original], [finding("a", evidence=["two"])])
        assert original.evidence == ["one"]

    def test_sorted_most_severe_first_keeping_order_within_a_severity(self) -> None:
        merged = merge_findings([finding("l1", S.LOW), finding("c", S.CRITICAL), finding("l2", S.LOW)])
        assert [f.code for f in merged] == ["c", "l1", "l2"]

    def test_evidence_is_capped(self) -> None:
        merged = merge_findings([finding("a", evidence=[f"e{i}" for i in range(30)])])
        assert len(merged[0].evidence) == 10


# ================================================================== points
class TestPoints:
    def test_override_beats_severity_default(self) -> None:
        assert points_for(finding("dmarc_fail", S.HIGH)) == CODE_POINTS["dmarc_fail"] == 20
        assert points_for(finding("unlisted_code", S.HIGH)) == SEVERITY_POINTS[S.HIGH] == 22

    def test_policy_tables_are_sane(self) -> None:
        assert all(0 <= p <= 100 for p in CODE_POINTS.values())
        assert all(1 <= floor <= 100 for floor in FLOORS.values())
        assert [m for m, _ in VERDICT_BANDS] == sorted((m for m, _ in VERDICT_BANDS), reverse=True)

    def test_intel_floors_refer_to_codes_that_intel_findings_can_produce(self) -> None:
        producible = {f"intel_malicious_{c}" for c in ("hash", "url", "domain", "ip")}
        assert {code for code in FLOORS if code.startswith("intel_")} <= producible


# ================================================================== scoring
class TestScore:
    def test_nothing_is_clean_zero(self) -> None:
        outcome = score_findings([])
        assert (outcome.score, outcome.verdict, outcome.floors_applied) == (0, Verdict.CLEAN, ())

    def test_info_findings_add_nothing(self) -> None:
        assert score_findings([finding("a", S.INFO)]).score == 0

    def test_weak_signals_saturate_instead_of_exploding(self) -> None:
        assert score_findings([finding(f"w{i}", S.LOW) for i in range(10)]).score == 34

    def test_independent_signals_combine_as_noisy_or(self) -> None:
        outcome = score_findings([finding("a", S.HIGH), finding("b", S.HIGH)])
        assert outcome.score == 39 and outcome.verdict is Verdict.LOW_RISK  # not 44

    def test_score_never_exceeds_100(self) -> None:
        assert score_findings([finding(f"c{i}", S.CRITICAL) for i in range(20)]).score == 100

    def test_a_floor_raises_the_score(self) -> None:
        outcome = score_findings([finding("attachment_disguised_executable", S.CRITICAL)])
        assert (outcome.raw_score, outcome.score, outcome.verdict) == (50, 70, Verdict.MALICIOUS)
        assert outcome.floors_applied == (("attachment_disguised_executable", 70),)

    def test_a_floor_below_the_raw_score_is_not_reported(self) -> None:
        outcome = score_findings([
            finding("attachment_disguised_executable", S.CRITICAL),
            finding("lookalike_sender_domain", S.HIGH),
            finding("dmarc_fail", S.HIGH),
        ])
        assert outcome.raw_score == outcome.score == 71 and outcome.floors_applied == ()

    def test_contributions_are_listed_largest_first(self) -> None:
        outcome = score_findings([finding("a", S.LOW), finding("b", S.HIGH), finding("c", S.INFO)])
        assert outcome.contributions == (("b", 22), ("a", 4))

    @pytest.mark.parametrize(
        ("score", "verdict"),
        [
            (0, Verdict.CLEAN), (14, Verdict.CLEAN),
            (15, Verdict.LOW_RISK), (39, Verdict.LOW_RISK),
            (40, Verdict.SUSPICIOUS), (69, Verdict.SUSPICIOUS),
            (70, Verdict.MALICIOUS), (100, Verdict.MALICIOUS),
        ],
    )
    def test_verdict_bands(self, score: int, verdict: Verdict) -> None:
        assert verdict_for(score) is verdict

    def test_routine_noise_alone_is_never_suspicious(self) -> None:
        noise = ["return_path_mismatch", "missing_message_id", "missing_date", "dkim_absent",
                 "dmarc_missing", "origin_no_rdns", "received_rdns_mismatch", "no_received_headers"]
        assert score_findings([finding(code, S.LOW) for code in noise]).verdict in (
            Verdict.CLEAN, Verdict.LOW_RISK)


# ================================================== attachment flag conversion
class TestAttachmentFindings:
    def flag(self, code: str, severity: Severity, description: str = "d") -> AttachmentFlag:
        return AttachmentFlag(code=code, severity=severity, description=description)

    def test_codes_and_severity(self) -> None:
        att = Attachment(filename="a.exe", size=1, flags=[self.flag("disguised_executable", S.CRITICAL)])
        (found,) = attachment_findings([att])
        assert (found.code, found.severity) == ("attachment_disguised_executable", S.CRITICAL)

    def test_same_flag_on_two_files_is_one_finding_with_two_evidence_lines(self) -> None:
        atts = [Attachment(filename=f"{n}.exe", size=1, flags=[self.flag("executable_extension", S.HIGH)])
                for n in ("a", "b")]
        (found,) = attachment_findings(atts)
        assert len(found.evidence) == 2

    def test_evidence_is_escaped_and_defanged(self) -> None:
        att = Attachment(
            filename="photo\u202egpj.exe", size=1,
            flags=[self.flag("remote_template", S.HIGH, "loads http://evil.example/t.dotm")],
        )
        (found,) = attachment_findings([att])
        text = " ".join(found.evidence)
        assert "\u202e" not in text and "\\u202e" in text
        assert "http://evil.example" not in text and "hxxp[://]evil[.]example" in text

    def test_no_flags_means_no_findings(self) -> None:
        assert attachment_findings([Attachment(filename="a.txt", size=1)]) == []


# ===================================================== intel conversion
class TestIntelFindings:
    def test_malicious_url(self) -> None:
        holder = url_ioc("hxxp[://]evil[.]example/a", intel("urlhaus", V.MALICIOUS, IOCType.URL, 95))
        (found,) = intel_findings([holder], [])
        assert (found.code, found.severity) == ("intel_malicious_url", S.CRITICAL)
        assert "urlhaus" in found.evidence[0] and "top score 95" in found.evidence[0]
        assert "hxxp[://]evil[.]example/a" in found.evidence[0]

    @pytest.mark.parametrize(
        ("ioc_type", "level", "code", "single", "double"),
        [
            (IOCType.DOMAIN, V.MALICIOUS, "intel_malicious_domain", S.HIGH, S.CRITICAL),
            (IOCType.IPV4, V.MALICIOUS, "intel_malicious_ip", S.HIGH, S.CRITICAL),
            (IOCType.URL, V.SUSPICIOUS, "intel_suspicious_url", S.MEDIUM, S.HIGH),
            (IOCType.IPV6, V.SUSPICIOUS, "intel_suspicious_ip", S.LOW, S.MEDIUM),
        ],
    )
    def test_severity_and_corroboration_bump(
        self, ioc_type: IOCType, level: IntelVerdict, code: str, single: Severity, double: Severity
    ) -> None:
        one = IOC(type=ioc_type, value="x", defanged="x", intel=[intel("p1", level, ioc_type)])
        two = IOC(type=ioc_type, value="x", defanged="x",
                  intel=[intel("p1", level, ioc_type), intel("p2", level, ioc_type)])
        (a,) = intel_findings([one], [])
        (b,) = intel_findings([two], [])
        assert (a.code, a.severity, b.severity) == (code, single, double)

    @pytest.mark.parametrize("verdict", [V.CLEAN, V.UNKNOWN, V.ERROR, V.SKIPPED])
    def test_non_detections_produce_nothing(self, verdict: IntelVerdict) -> None:
        assert intel_findings([url_ioc("u", intel("p", verdict, IOCType.URL))], []) == []

    def test_malicious_outranks_suspicious_on_the_same_indicator(self) -> None:
        holder = url_ioc("u", intel("a", V.SUSPICIOUS, IOCType.URL), intel("b", V.MALICIOUS, IOCType.URL))
        (found,) = intel_findings([holder], [])
        assert found.code == "intel_malicious_url" and "a, b" in found.evidence[0]

    def test_attachment_hash_verdicts(self) -> None:
        att = Attachment(filename="a\u202e.exe", size=1, sha256="aa" * 32,
                         intel=[intel("virustotal", V.MALICIOUS, IOCType.HASH, 91)])
        (found,) = intel_findings([], [att])
        assert (found.code, found.severity) == ("intel_malicious_hash", S.CRITICAL)
        assert "aa" * 32 in found.evidence[0] and "\u202e" not in found.evidence[0]

    def test_several_indicators_merge_into_one_finding(self) -> None:
        holders = [url_ioc(f"u{i}", intel("urlhaus", V.MALICIOUS, IOCType.URL)) for i in range(3)]
        (found,) = intel_findings(holders, [])
        assert len(found.evidence) == 3


# ====================================================== end to end policy
class TestPolicy:
    def score(self, *groups: list[Finding]) -> tuple[int, Verdict]:
        outcome = score_findings(merge_findings(*groups))
        return outcome.score, outcome.verdict

    def test_a_malicious_url_alone_is_malicious(self) -> None:
        holder = url_ioc("u", intel("urlhaus", V.MALICIOUS, IOCType.URL))
        assert self.score(intel_findings([holder], [])) == (85, Verdict.MALICIOUS)

    def test_a_malicious_domain_or_ip_alone_is_suspicious_not_malicious(self) -> None:
        domain = IOC(type=IOCType.DOMAIN, value="d", defanged="d", intel=[intel("p", V.MALICIOUS, IOCType.DOMAIN)])
        ip = IOC(type=IOCType.IPV4, value="i", defanged="i", intel=[intel("p", V.MALICIOUS, IOCType.IPV4)])
        assert self.score(intel_findings([domain], [])) == (60, Verdict.SUSPICIOUS)
        assert self.score(intel_findings([ip], [])) == (50, Verdict.SUSPICIOUS)

    def test_one_suspicious_intel_hit_alone_does_not_raise_the_verdict(self) -> None:
        holder = url_ioc("u", intel("urlhaus", V.SUSPICIOUS, IOCType.URL))
        assert self.score(intel_findings([holder], [])) == (10, Verdict.CLEAN)

    def test_authentication_failure_plus_impersonation_is_suspicious(self) -> None:
        findings = [finding("dmarc_fail", S.HIGH), finding("spf_fail", S.HIGH),
                    finding("lookalike_sender_domain", S.HIGH)]
        score, verdict = self.score(findings)
        assert score >= 40 and verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)

    def test_a_disguised_executable_is_always_malicious(self) -> None:
        att = Attachment(filename="r.pdf", size=1, flags=[
            AttachmentFlag(code="disguised_executable", severity=S.CRITICAL, description="d")])
        assert self.score(attachment_findings([att]))[1] is Verdict.MALICIOUS