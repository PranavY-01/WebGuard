"""U-40: outcome_to_exit_code across status x finding x error x interrupt combinations."""

from __future__ import annotations

import itertools
from dataclasses import replace

import pytest

from tests.unit.builders import STARTED, http_hop, scan, sts, tls_failed_hop
from webguard.app.assemble import assemble_report
from webguard.app.state import Rejection, ScanOutcome
from webguard.cli.exitcodes import ExitCode, exit_reason, outcome_to_exit_code
from webguard.domain.config import ScanConfig
from webguard.domain.enums import FailOn, ScanStatus
from webguard.domain.report import Report
from webguard.policy.url import CanonicalTarget, canonicalize_url
from webguard.rules.engine import evaluate_all
from webguard.rules.helpers import RuleContext

TARGET = canonicalize_url("https://webguard.test/")
assert isinstance(TARGET, CanonicalTarget)


def report_for(kind: str, status: ScanStatus = ScanStatus.COMPLETED) -> Report:
    """kind: 'clean' (no findings), 'medium' (HSTS absent etc.), 'high' (expired certificate)."""
    headers = {
        "strict-transport-security": ["max-age=31536000"],
        "content-security-policy": ["default-src 'self'"],
        "x-content-type-options": ["nosniff"],
    }
    evidence = {
        "clean": scan(http_hop(headers=headers)),
        "medium": scan(http_hop(headers={**headers, **sts("max-age=0")})),
        "high": scan(tls_failed_hop(code=10)),
    }[kind]
    results = evaluate_all(evidence, RuleContext(started_at=STARTED)).results
    return assemble_report(
        scan_id="0" * 32,
        started_at=STARTED,
        finished_at=STARTED,
        status=status,
        target=TARGET,
        config=ScanConfig(target="https://webguard.test/"),
        notes=[],
        hops=list(evidence.hops),
        results=results,
    )


def outcome(
    status: ScanStatus | None = ScanStatus.COMPLETED,
    kind: str | None = "clean",
    fail_on: FailOn = FailOn.HIGH,
    **kw: object,
) -> ScanOutcome:
    rep = report_for(kind, status) if kind is not None and status is not None else None
    base = ScanOutcome(status=status, fail_on=fail_on, report=rep)
    return replace(base, **kw)  # type: ignore[arg-type]  # reason: test override of dataclass fields


@pytest.mark.parametrize(
    ("o", "code"),
    [
        (outcome(kind="clean"), ExitCode.OK),
        (outcome(kind="medium"), ExitCode.OK),
        (outcome(kind="medium", fail_on=FailOn.MEDIUM), ExitCode.FINDINGS),
        (outcome(kind="medium", fail_on=FailOn.LOW), ExitCode.FINDINGS),
        (outcome(kind="high"), ExitCode.FINDINGS),
        (outcome(kind="high", fail_on=FailOn.NONE), ExitCode.OK),
        (outcome(ScanStatus.PARTIAL, "clean"), ExitCode.SCAN_FAILED),
        (outcome(ScanStatus.PARTIAL, "high"), ExitCode.FINDINGS),
        (outcome(ScanStatus.PARTIAL, "high", FailOn.NONE), ExitCode.SCAN_FAILED),
        (outcome(ScanStatus.FAILED, "clean"), ExitCode.SCAN_FAILED),
        (outcome(ScanStatus.FAILED, "high"), ExitCode.SCAN_FAILED),
        (outcome(ScanStatus.INTERRUPTED, "clean"), ExitCode.INTERRUPTED),
        (outcome(kind="high", sink_error="write_failed"), ExitCode.PERSISTENCE_FAILED),
        (
            outcome(ScanStatus.FAILED, "clean", sink_error="output_exists"),
            ExitCode.PERSISTENCE_FAILED,
        ),
        (outcome(kind="high", internal_error=True), ExitCode.INTERNAL_ERROR),
        (outcome(kind="high", internal_error=True, sink_error="x"), ExitCode.INTERNAL_ERROR),
        (outcome(kind="high", internal_error=True, interrupted=True), ExitCode.INTERRUPTED),
        (outcome(None, None, rejection=Rejection("url_illegal_chars", True)), ExitCode.USAGE),
        (outcome(None, None, rejection=Rejection("scheme_not_https", False)), ExitCode.REJECTED),
        (
            outcome(None, None, rejection=Rejection("x", False), internal_error=True),
            ExitCode.INTERNAL_ERROR,
        ),
        (outcome(None, None), ExitCode.INTERNAL_ERROR),
    ],
)
def test_u40_exit_codes(o: ScanOutcome, code: ExitCode) -> None:
    assert outcome_to_exit_code(o) is code
    assert exit_reason(o, code)


def test_u40_precedence_exhaustive() -> None:
    """For every flag combination the highest-precedence applicable code wins."""
    order = [130, 70, 2, 3, 5, 4, 1, 0]
    for interrupted, internal, sink, status, kind, fail_on in itertools.product(
        (False, True),
        (False, True),
        (None, "write_failed"),
        (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED),
        ("clean", "medium", "high"),
        tuple(FailOn),
    ):
        o = outcome(
            status, kind, fail_on, interrupted=interrupted, internal_error=internal, sink_error=sink
        )
        applicable = {0}
        if interrupted:
            applicable.add(130)
        if internal:
            applicable.add(70)
        if sink:
            applicable.add(5)
        if status is ScanStatus.FAILED or (status is ScanStatus.PARTIAL and not o.threshold_met):
            applicable.add(4)
        if status is not ScanStatus.FAILED and o.threshold_met:
            applicable.add(1)
        expected = next(c for c in order if c in applicable)
        assert int(outcome_to_exit_code(o)) == expected, (
            interrupted,
            internal,
            sink,
            status,
            kind,
            fail_on,
        )


def test_u40_pure() -> None:
    o = outcome(kind="high")
    assert {outcome_to_exit_code(o) for _ in range(5)} == {ExitCode.FINDINGS}
