"""Scan lifecycle state machine (Plan §8). It is the only constructor of ScanOutcome."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from webguard.domain.enums import FailOn, ScanStatus, Status
from webguard.domain.report import Report


class Phase(StrEnum):
    INIT = "init"
    VALIDATING = "validating"
    REJECTED = "rejected"
    FETCHING = "fetching"
    EVALUATING = "evaluating"
    FAILED = "failed"
    DEADLINE = "deadline"
    INTERRUPTED = "interrupted"
    ASSEMBLING = "assembling"
    RENDERING = "rendering"
    WRITING = "writing"
    DONE = "done"


_ALLOWED: dict[Phase, frozenset[Phase]] = {
    Phase.INIT: frozenset({Phase.VALIDATING}),
    Phase.VALIDATING: frozenset({Phase.REJECTED, Phase.FETCHING}),
    Phase.FETCHING: frozenset(
        {Phase.EVALUATING, Phase.FAILED, Phase.DEADLINE, Phase.INTERRUPTED, Phase.REJECTED}
    ),
    Phase.FAILED: frozenset({Phase.EVALUATING, Phase.ASSEMBLING}),
    Phase.DEADLINE: frozenset({Phase.EVALUATING, Phase.ASSEMBLING}),
    Phase.INTERRUPTED: frozenset({Phase.EVALUATING, Phase.ASSEMBLING}),
    Phase.EVALUATING: frozenset({Phase.ASSEMBLING, Phase.INTERRUPTED}),
    Phase.ASSEMBLING: frozenset({Phase.RENDERING, Phase.DONE}),
    Phase.RENDERING: frozenset({Phase.WRITING, Phase.DONE}),
    Phase.WRITING: frozenset({Phase.DONE}),
    Phase.REJECTED: frozenset(),
    Phase.DONE: frozenset(),
}


class IllegalTransitionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Rejection:
    """Target rejected before any report exists (exit 2 or 3, no report; D-23)."""

    code: str
    usage_error: bool
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    status: ScanStatus | None
    fail_on: FailOn
    rejection: Rejection | None = None
    report: Report | None = None
    internal_error: bool = False
    interrupted: bool = False
    report_paths: tuple[Path, ...] = ()
    sink_error: str | None = None
    render_error: str | None = None

    @property
    def threshold_met(self) -> bool:
        if self.report is None:
            return False
        return any(
            r.status is Status.FINDING
            and r.severity is not None
            and self.fail_on.is_met_by(r.severity)
            for r in self.report.results
        )


@dataclass
class ScanStateMachine:
    fail_on: FailOn
    phase: Phase = Phase.INIT
    history: list[Phase] = field(default_factory=list)

    def to(self, phase: Phase) -> None:
        if phase not in _ALLOWED[self.phase]:
            raise IllegalTransitionError(f"{self.phase} -> {phase}")
        self.history.append(self.phase)
        self.phase = phase

    def reject(self, rejection: Rejection) -> ScanOutcome:
        self.to(Phase.REJECTED)
        return ScanOutcome(status=None, fail_on=self.fail_on, rejection=rejection)

    def finish(
        self,
        *,
        status: ScanStatus | None,
        report: Report | None,
        internal_error: bool,
        interrupted: bool,
        report_paths: tuple[Path, ...] = (),
        sink_error: str | None = None,
        render_error: str | None = None,
    ) -> ScanOutcome:
        self.to(Phase.DONE)
        return ScanOutcome(
            status=status,
            fail_on=self.fail_on,
            report=report,
            internal_error=internal_error,
            interrupted=interrupted,
            report_paths=report_paths,
            sink_error=sink_error,
            render_error=render_error,
        )
