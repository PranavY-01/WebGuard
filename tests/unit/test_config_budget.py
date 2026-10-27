"""U-13..U-15: ScanConfig bounds, ScanBudget and clamp arithmetic."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from webguard.app.budget import ScanBudget
from webguard.domain.budget import (
    MAX_REQUESTS_PER_SCAN,
    DeadlineExceededError,
    RequestLimitExceededError,
    clamp,
)
from webguard.domain.config import EgressConfig, ScanConfig
from webguard.domain.enums import FailOn, Severity


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize("deadline", [5, 30, 120])
def test_u13_deadline_bounds_accepted(deadline: int) -> None:
    assert ScanConfig(target="https://a.test", deadline_s=deadline).deadline_s == deadline


@pytest.mark.parametrize("deadline", [4, 121, 0, -1])
def test_u13_deadline_bounds_rejected(deadline: int) -> None:
    with pytest.raises(ValidationError):
        ScanConfig(target="https://a.test", deadline_s=deadline)


def test_u13_defaults_and_strictness() -> None:
    cfg = ScanConfig(target="https://a.test")
    assert (cfg.deadline_s, cfg.fail_on, cfg.follow_redirects, cfg.output_dir) == (
        30,
        FailOn.HIGH,
        False,
        Path("reports"),
    )
    with pytest.raises(ValidationError):
        ScanConfig(target="https://a.test", insecure=True)  # type: ignore[call-arg]  # reason: proves extra=forbid
    with pytest.raises(ValidationError):
        ScanConfig(target="")
    with pytest.raises(ValidationError):
        EgressConfig(ca_file=Path("x"), user_agent="")


def test_u14_budget_remaining_and_expiry() -> None:
    clock = FakeClock()
    b = ScanBudget(30, clock=clock)
    assert b.remaining() == 30
    clock.now += 29.5
    assert b.remaining() == pytest.approx(0.5)
    assert not b.expired()
    clock.now += 0.5
    assert b.expired()


@pytest.mark.parametrize("deadline", [4.9, 120.1])
def test_u14_budget_rejects_out_of_range(deadline: float) -> None:
    with pytest.raises(ValueError, match="range"):
        ScanBudget(deadline)


def test_u14_request_cap() -> None:
    b = ScanBudget(30, clock=FakeClock())
    for _ in range(MAX_REQUESTS_PER_SCAN):
        b.charge_request()
    with pytest.raises(RequestLimitExceededError):
        b.charge_request()
    assert b.requests == MAX_REQUESTS_PER_SCAN


def test_u15_clamp_takes_minimum_and_refuses_when_exhausted() -> None:
    clock = FakeClock()
    b = ScanBudget(30, clock=clock)
    assert clamp(5.0, b) == 5.0
    clock.now += 27.0
    assert clamp(5.0, b) == pytest.approx(3.0)
    clock.now += 3.0
    with pytest.raises(DeadlineExceededError):
        clamp(5.0, b)
    clock.now += 100
    with pytest.raises(DeadlineExceededError):
        clamp(10.0, b)


@pytest.mark.parametrize(
    ("fail_on", "severity", "met"),
    [
        (FailOn.NONE, Severity.HIGH, False),
        (FailOn.HIGH, Severity.HIGH, True),
        (FailOn.HIGH, Severity.MEDIUM, False),
        (FailOn.LOW, Severity.MEDIUM, True),
        (FailOn.LOW, Severity.INFORMATIONAL, False),
        (FailOn.INFORMATIONAL, Severity.INFORMATIONAL, True),
    ],
)
def test_u15_fail_on_threshold(fail_on: FailOn, severity: Severity, met: bool) -> None:
    assert fail_on.is_met_by(severity) is met
