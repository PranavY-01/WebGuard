"""WG-RDR-001 redirect downgrade (one result per hop)."""

from __future__ import annotations

from webguard.domain.enums import Confidence, Severity
from webguard.domain.evidence import ScanEvidence
from webguard.domain.results import RuleResult
from webguard.rules.applicability import Column, column
from webguard.rules.catalog import RDR_001
from webguard.rules.helpers import (
    RuleContext,
    finding,
    hop_subject,
    inconclusive,
    no_http_reason,
    not_applicable,
    pass_,
)


def redirect_downgrade(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    results = []
    for hop in evidence.hops:
        subject = hop_subject(hop)
        col = column(hop)
        if hop.http is None:
            results.append(inconclusive(RDR_001, no_http_reason(hop, ctx), subject))
            continue
        if col is not Column.REDIRECT:
            results.append(not_applicable(RDR_001, "not_redirect", subject))
            continue
        location = hop.http.location
        if location is None:
            results.append(not_applicable(RDR_001, "no_location", subject))
            continue
        if location.unparseable:
            items = [("location_length", str(location.raw_length))]
            results.append(inconclusive(RDR_001, "location_unparseable", subject, items))
            continue
        scheme = (location.scheme or "").lower()
        items = [("location_scheme", scheme or "(none)")]
        if location.host:
            items.append(("location_host", location.host))
        if scheme == "http":
            results.append(
                finding(
                    RDR_001,
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "https_to_http_redirect",
                    subject,
                    items,
                )
            )
        elif scheme == "https":
            results.append(pass_(RDR_001, "https_redirect", subject, items))
        else:
            results.append(inconclusive(RDR_001, "unexpected_scheme", subject, items))
    return results
