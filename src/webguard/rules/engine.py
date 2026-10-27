"""Rule engine (Plan §14.3): per-rule error isolation and coverage."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from webguard.domain.evidence import ScanEvidence
from webguard.domain.results import RuleResult
from webguard.rules import cookie_rules, header_rules, redirect_rules, tls_rules
from webguard.rules.catalog import BY_ID, CATALOG, INTERNAL_RULE_ERROR, RuleMeta
from webguard.rules.helpers import RuleContext, error

log = logging.getLogger("webguard.rules")

Rule = Callable[[ScanEvidence, RuleContext], list[RuleResult]]

RULES: Final[MappingProxyType[str, Rule]] = MappingProxyType(
    {
        "WG-CK-001": cookie_rules.cookie_secure,
        "WG-CK-002": cookie_rules.cookie_httponly,
        "WG-CK-003": cookie_rules.cookie_samesite,
        "WG-CK-004": cookie_rules.cookie_prefixes,
        "WG-HDR-001": header_rules.hsts,
        "WG-HDR-002": header_rules.csp,
        "WG-HDR-003": header_rules.content_type_options,
        "WG-RDR-001": redirect_rules.redirect_downgrade,
        "WG-TLS-001": tls_rules.certificate_verification,
        "WG-TLS-002": tls_rules.expiry_horizon,
    }
)


@dataclass
class EngineResult:
    results: list[RuleResult] = field(default_factory=list)
    internal_error_occurred: bool = False


def evaluate_rule(
    meta: RuleMeta, evidence: ScanEvidence, ctx: RuleContext
) -> tuple[list[RuleResult], bool]:
    """Run one rule. Any exception (or an empty or foreign result list) becomes a single
    `error` result for that rule and flags an internal error; KeyboardInterrupt propagates."""
    try:
        results = RULES[meta.rule_id](evidence, ctx)
        if not results or any(r.rule_id != meta.rule_id for r in results):
            raise ValueError("rule produced no results or results for another rule")
    except Exception:  # reason: per-rule isolation boundary (Plan §14.3)
        log.error("rule %s raised; recorded as error", meta.rule_id)
        return [error(meta, INTERNAL_RULE_ERROR, None)], True
    return results, False


def evaluate_all(evidence: ScanEvidence, ctx: RuleContext) -> EngineResult:
    out = EngineResult()
    for meta in CATALOG:
        results, failed = evaluate_rule(meta, evidence, ctx)
        out.results.extend(results)
        out.internal_error_occurred |= failed
    return out


def catalog_is_complete() -> bool:
    return set(RULES) == set(BY_ID)
