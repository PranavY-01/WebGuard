"""Exit codes (Plan §19.4). `outcome_to_exit_code` is the single, pure mapping (INV-15).

Precedence when several apply: 130 > 70 > 2 > 3 > 5 > 4 > 1 > 0.
"""

from __future__ import annotations

from enum import IntEnum

from webguard.app.state import ScanOutcome
from webguard.domain.enums import ScanStatus


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    USAGE = 2
    REJECTED = 3
    SCAN_FAILED = 4
    PERSISTENCE_FAILED = 5
    INTERNAL_ERROR = 70
    INTERRUPTED = 130


def outcome_to_exit_code(outcome: ScanOutcome) -> ExitCode:
    if outcome.interrupted or outcome.status is ScanStatus.INTERRUPTED:
        return ExitCode.INTERRUPTED
    if outcome.internal_error:
        return ExitCode.INTERNAL_ERROR
    if outcome.rejection is not None:
        return ExitCode.USAGE if outcome.rejection.usage_error else ExitCode.REJECTED
    if outcome.sink_error is not None:
        return ExitCode.PERSISTENCE_FAILED
    if outcome.report is None or outcome.status is None:
        return ExitCode.INTERNAL_ERROR
    if outcome.status is ScanStatus.FAILED:
        return ExitCode.SCAN_FAILED
    if outcome.threshold_met:
        return ExitCode.FINDINGS
    if outcome.status is ScanStatus.PARTIAL:
        return ExitCode.SCAN_FAILED
    return ExitCode.OK


def exit_reason(outcome: ScanOutcome, code: ExitCode) -> str:
    """One static line explaining the exit code."""
    if code is ExitCode.INTERRUPTED:
        return "interrupted"
    if code is ExitCode.INTERNAL_ERROR:
        return "internal error (a bug); see the report and --debug output"
    if code in (ExitCode.USAGE, ExitCode.REJECTED) and outcome.rejection is not None:
        return f"target rejected: {outcome.rejection.code}"
    if code is ExitCode.PERSISTENCE_FAILED:
        return f"report persistence failed: {outcome.sink_error}"
    if code is ExitCode.SCAN_FAILED:
        if outcome.status is ScanStatus.PARTIAL:
            return "partial scan (deadline reached); no finding at or above --fail-on"
        return "scan failed: no usable evidence"
    if code is ExitCode.FINDINGS:
        return f"finding(s) at or above --fail-on {outcome.fail_on.value}"
    status = outcome.status.value if outcome.status else "done"
    return f"scan {status}; no finding at or above --fail-on {outcome.fail_on.value}"
