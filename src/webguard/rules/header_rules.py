"""WG-HDR-001 HSTS (every hop with headers), WG-HDR-002 CSP and WG-HDR-003 XCTO (terminal)."""

from __future__ import annotations

from webguard.domain.enums import Confidence, Severity
from webguard.domain.evidence import HopEvidence, HttpEvidence, ScanEvidence
from webguard.domain.results import RuleResult
from webguard.rules.applicability import Column, column
from webguard.rules.catalog import HDR_001, HDR_002, HDR_003, RuleMeta
from webguard.rules.helpers import (
    RuleContext,
    finding,
    hop_subject,
    inconclusive,
    no_http_reason,
    not_applicable,
    pass_,
)
from webguard.rules.parse import parse_hsts

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days


def hsts(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    results = []
    for hop in evidence.hops:
        subject = hop_subject(hop)
        if hop.http is None:
            results.append(inconclusive(HDR_001, no_http_reason(hop, ctx), subject))
            continue
        value = hop.http.first("strict-transport-security")
        if value is None:
            results.append(
                finding(HDR_001, Severity.MEDIUM, Confidence.HIGH, "header_absent", subject)
            )
            continue
        items = [("strict-transport-security", value)]
        parsed = parse_hsts(value)
        if not parsed.valid or parsed.max_age is None:
            results.append(
                finding(HDR_001, Severity.MEDIUM, Confidence.HIGH, "invalid", subject, items)
            )
            continue
        items += [
            ("max_age", str(parsed.max_age)),
            ("include_subdomains", str(parsed.include_subdomains).lower()),
            ("preload", str(parsed.preload).lower()),
        ]
        if parsed.max_age == 0:
            results.append(
                finding(HDR_001, Severity.MEDIUM, Confidence.HIGH, "disabled", subject, items)
            )
        elif parsed.max_age < HSTS_MIN_MAX_AGE:
            results.append(
                finding(
                    HDR_001, Severity.LOW, Confidence.HIGH, "max_age_below_minimum", subject, items
                )
            )
        else:
            results.append(pass_(HDR_001, "present", subject, items))
    return results


def _terminal_context(
    meta: RuleMeta, evidence: ScanEvidence, ctx: RuleContext
) -> tuple[HopEvidence, HttpEvidence, Confidence] | RuleResult:
    """Applicability for terminal-response header rules (Plan §14.2 HDR-002/003 rows)."""
    hop = evidence.terminal
    if hop is None or hop.http is None:
        last = evidence.hops[-1]
        return inconclusive(meta, no_http_reason(last, ctx), hop_subject(last))
    col = column(hop)
    if col is Column.REDIRECT:
        items = [("status", str(hop.http.status_code))]
        return not_applicable(meta, "redirect_response", hop_subject(hop), items)
    confidence = Confidence.MEDIUM if col is Column.ERROR_STATUS else Confidence.HIGH
    return hop, hop.http, confidence


def csp(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    resolved = _terminal_context(HDR_002, evidence, ctx)
    if isinstance(resolved, RuleResult):
        return [resolved]
    hop, http, confidence = resolved
    subject = hop_subject(hop)
    enforcing = http.headers.get("content-security-policy", [])
    report_only = http.headers.get("content-security-policy-report-only", [])
    items = [("content-security-policy", v) for v in enforcing] + [
        ("content-security-policy-report-only", v) for v in report_only
    ]
    if any(v.strip() for v in enforcing):
        return [pass_(HDR_002, "present", subject, items, confidence)]
    if enforcing:
        return [finding(HDR_002, Severity.LOW, confidence, "empty_policy", subject, items)]
    if report_only:
        return [finding(HDR_002, Severity.LOW, confidence, "report_only_only", subject, items)]
    return [finding(HDR_002, Severity.LOW, confidence, "header_absent", subject)]


def content_type_options(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    resolved = _terminal_context(HDR_003, evidence, ctx)
    if isinstance(resolved, RuleResult):
        return [resolved]
    hop, http, confidence = resolved
    subject = hop_subject(hop)
    value = http.first("x-content-type-options")
    if value is None:
        return [finding(HDR_003, Severity.LOW, confidence, "header_absent", subject)]
    items = [("x-content-type-options", value)]
    if value.strip().lower() == "nosniff":
        return [pass_(HDR_003, "nosniff", subject, items, confidence)]
    return [finding(HDR_003, Severity.LOW, confidence, "invalid_value", subject, items)]
