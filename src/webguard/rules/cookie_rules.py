"""WG-CK-001..004: one result per cookie per hop (Plan §14.1).

Hops without headers contribute one inconclusive result each; when no cookie was observed on
any hop with headers, each rule yields a single `not_applicable` (no_cookies_observed).
"""

from __future__ import annotations

from collections.abc import Callable

from webguard.domain.enums import Confidence, Severity
from webguard.domain.evidence import CookieEvidence, HopEvidence, ScanEvidence
from webguard.domain.results import RuleResult
from webguard.rules.catalog import CK_001, CK_002, CK_003, CK_004, RuleMeta
from webguard.rules.helpers import (
    RuleContext,
    cookie_subject,
    finding,
    hop_subject,
    inconclusive,
    no_http_reason,
    not_applicable,
    pass_,
)
from webguard.rules.parse import CookieAttributes, parse_cookie_attributes

CookieCheck = Callable[[CookieEvidence, CookieAttributes, str], RuleResult]


def _per_cookie(
    meta: RuleMeta, evidence: ScanEvidence, ctx: RuleContext, check: CookieCheck
) -> list[RuleResult]:
    results: list[RuleResult] = []
    saw_headers = False
    for hop in evidence.hops:
        if hop.http is None:
            results.append(inconclusive(meta, no_http_reason(hop, ctx), hop_subject(hop)))
            continue
        saw_headers = True
        for cookie in hop.http.cookies:
            attrs = parse_cookie_attributes(cookie.attributes_raw)
            results.append(check(cookie, attrs, cookie_subject(cookie.name, hop)))
    if saw_headers and not any(_cookies(h) for h in evidence.hops):
        results.append(not_applicable(meta, "no_cookies_observed", None))
    return results


def _cookies(hop: HopEvidence) -> list[CookieEvidence]:
    return hop.http.cookies if hop.http is not None else []


def _attrs_evidence(cookie: CookieEvidence) -> list[tuple[str, str]]:
    return [("attributes", cookie.attributes_raw)] if cookie.attributes_raw else []


def _secure(cookie: CookieEvidence, attrs: CookieAttributes, subject: str) -> RuleResult:
    items = _attrs_evidence(cookie)
    if attrs.has("secure"):
        return pass_(CK_001, "secure_present", subject, items)
    return finding(CK_001, Severity.MEDIUM, Confidence.HIGH, "secure_absent", subject, items)


def _httponly(cookie: CookieEvidence, attrs: CookieAttributes, subject: str) -> RuleResult:
    items = _attrs_evidence(cookie)
    if attrs.has("httponly"):
        return pass_(CK_002, "httponly_present", subject, items)
    return finding(CK_002, Severity.LOW, Confidence.LOW, "httponly_absent", subject, items)


def _samesite(cookie: CookieEvidence, attrs: CookieAttributes, subject: str) -> RuleResult:
    items = _attrs_evidence(cookie)
    if not attrs.has("samesite"):
        return finding(
            CK_003, Severity.INFORMATIONAL, Confidence.HIGH, "samesite_absent", subject, items
        )
    value = (attrs.get("samesite") or "").strip().lower()
    if value in ("strict", "lax"):
        return pass_(CK_003, "samesite_strict_or_lax", subject, items)
    if value == "none":
        if attrs.has("secure"):
            return pass_(CK_003, "none_with_secure", subject, items)
        return finding(
            CK_003, Severity.MEDIUM, Confidence.HIGH, "none_without_secure", subject, items
        )
    return finding(CK_003, Severity.LOW, Confidence.HIGH, "invalid_value", subject, items)


def _prefix(cookie: CookieEvidence, attrs: CookieAttributes, subject: str) -> RuleResult:
    items = _attrs_evidence(cookie)
    name = cookie.name.lower()
    if name.startswith("__host-"):
        ok = attrs.has("secure") and attrs.get("path") == "/" and not attrs.has("domain")
    elif name.startswith("__secure-"):
        ok = attrs.has("secure")
    else:
        return not_applicable(CK_004, "not_prefixed", subject)
    if ok:
        return pass_(CK_004, "prefix_requirements_met", subject, items)
    return finding(
        CK_004, Severity.MEDIUM, Confidence.HIGH, "prefix_requirements_unmet", subject, items
    )


def cookie_secure(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    return _per_cookie(CK_001, evidence, ctx, _secure)


def cookie_httponly(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    return _per_cookie(CK_002, evidence, ctx, _httponly)


def cookie_samesite(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    return _per_cookie(CK_003, evidence, ctx, _samesite)


def cookie_prefixes(evidence: ScanEvidence, ctx: RuleContext) -> list[RuleResult]:
    return _per_cookie(CK_004, evidence, ctx, _prefix)
