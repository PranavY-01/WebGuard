"""WG-TLS-001 certificate verification, WG-TLS-002 expiry horizon (one result per hop)."""

from __future__ import annotations

from webguard.domain.enums import Confidence, FailureCode, Severity
from webguard.domain.evidence import ScanEvidence
from webguard.domain.results import RuleResult
from webguard.rules.applicability import Column, column
from webguard.rules.catalog import BLOCKED_BY_TLS, TLS_001, TLS_002
from webguard.rules.helpers import (
    RuleContext,
    error,
    finding,
    hop_subject,
    inconclusive,
    no_http_reason,
    pass_,
)

# OpenSSL X509_V_ERR codes (P0, A-03).
_VERIFY_REASONS: dict[int, str] = {
    10: "expired",
    9: "not_yet_valid",
    2: "untrusted_chain",
    18: "untrusted_chain",
    19: "untrusted_chain",
    20: "untrusted_chain",
    21: "untrusted_chain",
    62: "hostname_mismatch",
}

_SECONDS_PER_DAY = 86400


def certificate_verification(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    results = []
    for hop in evidence.hops:
        subject = hop_subject(hop)
        tls = hop.tls
        if tls is not None and tls.verified:
            items: list[tuple[str, str]] = [("protocol", tls.protocol_version or "unknown")]
            results.append(pass_(TLS_001, "verified", subject, items))
        elif tls is not None:
            code = tls.verify_code
            reason = _VERIFY_REASONS.get(code or 0, "verification_failed_other")
            confidence = (
                Confidence.MEDIUM if reason == "verification_failed_other" else Confidence.HIGH
            )
            items = [("verify_code", str(code))] if code is not None else []
            if tls.verify_message:
                items.append(("verify_message", tls.verify_message))
            results.append(finding(TLS_001, Severity.HIGH, confidence, reason, subject, items))
        elif hop.failure is not None and hop.failure.code is FailureCode.TLS_HANDSHAKE_FAILED:
            results.append(error(TLS_001, "handshake_failed", subject))
        else:
            results.append(error(TLS_001, "tls_not_reached", subject))
    return results


def expiry_horizon(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    results = []
    for hop in evidence.hops:
        subject = hop_subject(hop)
        col = column(hop)
        if col is Column.TLS_VERIFY_FAILED:
            results.append(inconclusive(TLS_002, BLOCKED_BY_TLS, subject))
            continue
        if col is Column.HOP_FAILED:
            results.append(inconclusive(TLS_002, no_http_reason(hop, ctx), subject))
            continue
        cert = hop.tls.cert if hop.tls is not None else None
        if cert is None:
            results.append(inconclusive(TLS_002, BLOCKED_BY_TLS, subject))
            continue
        days = (cert.not_after - ctx.started_at).total_seconds() / _SECONDS_PER_DAY
        items = [("not_after", cert.not_after.isoformat()), ("days_remaining", f"{days:.1f}")]
        if days > 30:
            results.append(pass_(TLS_002, "expiry_beyond_30_days", subject, items))
        elif days >= 15:
            results.append(
                finding(
                    TLS_002, Severity.LOW, Confidence.HIGH, "expires_within_30_days", subject, items
                )
            )
        else:
            results.append(
                finding(
                    TLS_002,
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "expires_within_14_days",
                    subject,
                    items,
                )
            )
    return results
