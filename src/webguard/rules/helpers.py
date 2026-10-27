"""Result constructors. Rules build results only through these, so static metadata always comes
from the catalog and every reason code is one the rule declared."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from webguard.domain.enums import Confidence, FailureCode, Severity, Status
from webguard.domain.evidence import HopEvidence
from webguard.domain.results import EvidenceItem, RuleResult
from webguard.rules.catalog import BLOCKED_BY_TLS, HOP_FAILED, SCAN_DEADLINE, RuleMeta

Evidence = Sequence[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class RuleContext:
    started_at: datetime
    no_evidence_reason: str = HOP_FAILED
    """Reason used when a hop produced no headers: hop_failed, scan_deadline or scan_interrupted."""


def _build(
    meta: RuleMeta,
    status: Status,
    reason: str,
    subject: str | None,
    evidence: Evidence,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=meta.rule_id,
        rule_version=meta.version,
        title=meta.title,
        category=meta.category,
        subject=subject,
        status=status,
        severity=severity,
        confidence=confidence,
        reason_code=reason,
        message=meta.message(reason),
        evidence=[EvidenceItem(label=label, value=value) for label, value in evidence],
        remediation=meta.remediation,
        references=list(meta.references),
        limitations=list(meta.limitations),
    )


def pass_(
    meta: RuleMeta,
    reason: str,
    subject: str | None,
    evidence: Evidence = (),
    confidence: Confidence = Confidence.HIGH,
) -> RuleResult:
    return _build(meta, Status.PASS, reason, subject, evidence, confidence=confidence)


def finding(
    meta: RuleMeta,
    severity: Severity,
    confidence: Confidence,
    reason: str,
    subject: str | None,
    evidence: Evidence = (),
) -> RuleResult:
    return _build(meta, Status.FINDING, reason, subject, evidence, severity, confidence)


def inconclusive(
    meta: RuleMeta, reason: str, subject: str | None, evidence: Evidence = ()
) -> RuleResult:
    return _build(meta, Status.INCONCLUSIVE, reason, subject, evidence)


def not_applicable(
    meta: RuleMeta, reason: str, subject: str | None, evidence: Evidence = ()
) -> RuleResult:
    return _build(meta, Status.NOT_APPLICABLE, reason, subject, evidence)


def error(meta: RuleMeta, reason: str, subject: str | None, evidence: Evidence = ()) -> RuleResult:
    return _build(meta, Status.ERROR, reason, subject, evidence)


def hop_subject(hop: HopEvidence) -> str:
    return f"hop:{hop.index}"


def cookie_subject(name: str, hop: HopEvidence) -> str:
    return f"cookie:{name or '(unnamed)'}@hop:{hop.index}"


def no_http_reason(hop: HopEvidence, ctx: RuleContext) -> str:
    """Why a hop has no HTTP evidence, as a shared reason code."""
    if hop.tls_verify_failed:
        return BLOCKED_BY_TLS
    if hop.failure is not None and hop.failure.code is FailureCode.DEADLINE_EXCEEDED:
        return SCAN_DEADLINE
    return ctx.no_evidence_reason
