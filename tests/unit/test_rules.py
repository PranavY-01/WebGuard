"""U-20..U-35: rules (known answers per applicability column), parsers, engine, catalog parity."""

from __future__ import annotations

import re
from pathlib import Path
from types import MappingProxyType

import pytest

from tests.unit.builders import STARTED, failed_hop, http_hop, scan, tls_failed_hop
from tests.unit.known_answers import CASES, Case
from webguard.domain.enums import FailureCode, Status
from webguard.domain.results import RuleResult
from webguard.rules import engine
from webguard.rules.catalog import BY_ID, CATALOG
from webguard.rules.engine import evaluate_all, evaluate_rule
from webguard.rules.helpers import RuleContext
from webguard.rules.parse import parse_cookie_attributes, parse_hsts

ROOT = Path(__file__).resolve().parents[2]


def render(r: RuleResult) -> str:
    sev = r.severity.value if r.severity else "-"
    conf = r.confidence.value if r.confidence else "-"
    return f"{r.subject or '-'} {r.status.value} {sev} {conf} {r.reason_code}"


def run_case(case: Case) -> tuple[str, ...]:
    ctx = RuleContext(started_at=STARTED, no_evidence_reason=case.context_reason)
    results, failed = evaluate_rule(BY_ID[case.rule_id], case.evidence, ctx)
    assert not failed
    return tuple(render(r) for r in results)


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c.rule_id}:{c.name}")
def test_u20_u29_known_answers(case: Case) -> None:
    assert run_case(case) == case.expected


def test_u20_every_rule_has_known_answers_for_each_outcome_column() -> None:
    for meta in CATALOG:
        cases = [c for c in CASES if c.rule_id == meta.rule_id]
        statuses = {line.split()[1] for c in cases for line in c.expected}
        assert len(cases) >= 3, meta.rule_id
        assert "inconclusive" in statuses or meta.rule_id == "WG-TLS-001", meta.rule_id


# INV-11: missing evidence never yields pass ------------------------------------------------------

NO_HTTP_SCANS = [
    scan(failed_hop()),
    scan(failed_hop(code=FailureCode.CONNECT_TIMEOUT)),
    scan(failed_hop(code=FailureCode.DEADLINE_EXCEEDED)),
    scan(failed_hop(code=FailureCode.TLS_HANDSHAKE_FAILED)),
    scan(tls_failed_hop()),
]


@pytest.mark.parametrize("evidence", NO_HTTP_SCANS)
def test_inv11_no_pass_without_evidence(evidence: object) -> None:
    out = evaluate_all(evidence, RuleContext(started_at=STARTED))  # type: ignore[arg-type]  # reason: parametrized
    assert not out.internal_error_occurred
    assert [r for r in out.results if r.status is Status.PASS] == []
    assert {r.rule_id for r in out.results} == set(BY_ID)


def test_inv11_only_tls_rule_passes_when_hop_failed_after_tls() -> None:
    evidence = scan(failed_hop(code=FailureCode.READ_TIMEOUT, tls_reached=True))
    out = evaluate_all(evidence, RuleContext(started_at=STARTED))
    assert {r.rule_id for r in out.results if r.status is Status.PASS} == {"WG-TLS-001"}


# Engine ----------------------------------------------------------------------------------------


def test_engine_covers_every_rule_once_per_scan() -> None:
    out = evaluate_all(scan(http_hop()), RuleContext(started_at=STARTED))
    assert {r.rule_id for r in out.results} == set(BY_ID)
    assert not out.internal_error_occurred
    assert engine.catalog_is_complete()


def test_engine_isolates_a_failing_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: object) -> list[RuleResult]:
        raise RuntimeError("bug")

    def empty(*_: object) -> list[RuleResult]:
        return []

    rules = dict(engine.RULES)
    rules["WG-HDR-002"] = boom
    rules["WG-HDR-003"] = empty
    monkeypatch.setattr(engine, "RULES", MappingProxyType(rules))
    out = evaluate_all(scan(http_hop()), RuleContext(started_at=STARTED))
    assert out.internal_error_occurred
    errors = [r for r in out.results if r.status is Status.ERROR]
    assert {(r.rule_id, r.reason_code) for r in errors} == {
        ("WG-HDR-002", "internal_rule_error"),
        ("WG-HDR-003", "internal_rule_error"),
    }
    assert {r.rule_id for r in out.results} == set(BY_ID)


def test_engine_lets_keyboard_interrupt_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*_: object) -> list[RuleResult]:
        raise KeyboardInterrupt

    monkeypatch.setattr(engine, "RULES", MappingProxyType({**engine.RULES, "WG-CK-001": interrupt}))
    with pytest.raises(KeyboardInterrupt):
        evaluate_all(scan(http_hop()), RuleContext(started_at=STARTED))


def test_messages_are_static_and_declared() -> None:
    out = evaluate_all(scan(http_hop(cookies=[("a", "")])), RuleContext(started_at=STARTED))
    for r in out.results:
        assert r.message == BY_ID[r.rule_id].messages[r.reason_code]
    with pytest.raises(KeyError):
        BY_ID["WG-HDR-001"].message("made_up")


def test_no_rule_emits_critical_or_undeclared_severity() -> None:
    for case in CASES:
        ctx = RuleContext(started_at=STARTED)
        results, _ = evaluate_rule(BY_ID[case.rule_id], case.evidence, ctx)
        for r in results:
            if r.severity is not None:
                assert r.severity in BY_ID[r.rule_id].severities, (case.name, r.severity)


# U-30 catalog <-> docs parity ------------------------------------------------------------------


def test_u30_rules_doc_parity() -> None:
    doc = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
    assert set(re.findall(r"WG-[A-Z]+-\d{3}", doc)) == set(BY_ID)
    for meta in CATALOG:
        assert f"## {meta.rule_id}" in doc
        for reason in meta.messages:
            assert f"`{reason}`" in doc, (meta.rule_id, reason)


# U-31..U-34 parsers ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "valid", "max_age", "sub", "preload"),
    [
        ("max-age=31536000", True, 31536000, False, False),
        ("max-age=31536000; includeSubDomains; preload", True, 31536000, True, True),
        ('max-age="10"', True, 10, False, False),
        ("  max-age = 5 ; ", True, 5, False, False),
        ("max-age=1; unknown=x; another", True, 1, False, False),
        ("max-age=0", True, 0, False, False),
        ("", False, None, False, False),
        ("max-age", False, None, False, False),
        ("max-age=", False, None, False, False),
        ("max-age=1.5", False, None, False, False),
        ("max-age=-1", False, None, False, False),
        ('max-age="10', False, None, False, False),
        ("max-age=1; Max-Age=2", False, None, False, False),
        ("includeSubDomains; includesubdomains; max-age=1", False, None, False, False),
        ("max-age=١٢", False, None, False, False),
    ],
)
def test_u31_hsts_parser(
    value: str, valid: bool, max_age: int | None, sub: bool, preload: bool
) -> None:
    got = parse_hsts(value)
    assert got.valid is valid
    if valid:
        assert (got.max_age, got.include_subdomains, got.preload) == (max_age, sub, preload)


def test_u32_cookie_parser_case_and_last_wins() -> None:
    attrs = parse_cookie_attributes(
        " Secure ; PATH=/a ; path=/ ; SameSite = Lax ; Foo=bar; ; HttpOnly"
    )
    assert attrs.has("secure")
    assert attrs.has("httponly")
    assert attrs.get("path") == "/"
    assert attrs.get("samesite") == "Lax"
    assert attrs.unknown == ("Foo",)


def test_u33_cookie_parser_commas_in_expires() -> None:
    attrs = parse_cookie_attributes("Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure")
    assert attrs.get("expires") == "Wed, 21 Oct 2026 07:28:00 GMT"
    assert attrs.has("secure")


def test_u34_cookie_parser_malformed_inputs() -> None:
    assert parse_cookie_attributes("").values == {}
    assert parse_cookie_attributes(";;;").values == {}
    weird = parse_cookie_attributes("=x; Secure=1; Domain")
    assert weird.get("secure") == "1"
    assert weird.has("domain")
    assert weird.get("domain") is None
    assert weird.unknown == ("",)


def test_known_answers_record_is_current() -> None:
    from tests.unit.render_docs import (
        KNOWN_ANSWERS_MD,
        RULES_MD,
        render_known_answers_md,
        render_rules_md,
    )

    assert "MISMATCH" not in render_known_answers_md()
    assert KNOWN_ANSWERS_MD.read_text(encoding="utf-8") == render_known_answers_md()
    assert RULES_MD.read_text(encoding="utf-8") == render_rules_md()
