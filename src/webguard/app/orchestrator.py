"""Scan orchestration (Plan §7-§8, §12).

`collect` runs VALIDATING -> FETCHING (redirect loop) -> EVALUATING -> ASSEMBLING and returns a
frozen Report (or a rejection). KeyboardInterrupt is caught here during fetch and evaluation
only; whatever evidence exists is still assembled into a report.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from webguard.app.assemble import AssemblyError, assemble_report
from webguard.app.budget import ScanBudget
from webguard.app.redirects import next_hop
from webguard.app.state import Phase, Rejection, ScanOutcome, ScanStateMachine
from webguard.domain.config import ScanConfig
from webguard.domain.enums import FailureCode, ScanNote, ScanStatus
from webguard.domain.evidence import HopEvidence, ScanEvidence
from webguard.domain.report import Report
from webguard.domain.results import RuleResult
from webguard.egress import EgressDeps, HopRequest, fetch_hop
from webguard.policy.url import CanonicalTarget, UrlRejection, canonicalize_url
from webguard.render.html_render import render_html
from webguard.render.json_render import render_json
from webguard.rules.catalog import (
    CATALOG,
    HOP_FAILED,
    SCAN_DEADLINE,
    SCAN_INTERRUPTED,
    RuleMeta,
)
from webguard.rules.engine import evaluate_rule
from webguard.rules.helpers import RuleContext, inconclusive
from webguard.sink.writer import ReportFile, SinkError, report_basename, write_reports

log = logging.getLogger("webguard.app")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_scan_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class ScanDeps:
    egress: EgressDeps
    now: Callable[[], datetime] = _utc_now
    new_scan_id: Callable[[], str] = _new_scan_id
    on_progress: Callable[[Phase, int | None], None] | None = None
    """Optional observer for the interface: receives only the phase and hop index (static data)."""

    def notify(self, phase: Phase, hop: int | None = None) -> None:
        if self.on_progress is not None:
            self.on_progress(phase, hop)


@dataclass
class Collected:
    """Result of `collect`: either a rejection or an assembled report (or an internal error)."""

    machine: ScanStateMachine
    rejection: Rejection | None = None
    report: Report | None = None
    status: ScanStatus | None = None
    internal_error: bool = False
    interrupted: bool = False


@dataclass
class _FetchState:
    hops: list[HopEvidence] = field(default_factory=list)
    notes: list[ScanNote] = field(default_factory=list)
    deadline_hit: bool = False
    interrupted: bool = False
    internal_error: bool = False


def _validate(config: ScanConfig, deps: ScanDeps) -> CanonicalTarget | Rejection:
    target = canonicalize_url(config.target)
    if isinstance(target, UrlRejection):
        return Rejection(code=target.code.value, usage_error=target.code.is_usage_error)
    decision = deps.egress.policy.check_literal(target.host_ip, target.port)
    if not decision.permitted:
        detail = (
            decision.reason
            if decision.offending is None
            else f"{decision.reason}:{decision.offending}"
        )
        return Rejection(code="policy_prohibited_address", usage_error=False, detail=detail)
    return target


def _fetch(
    target: CanonicalTarget, config: ScanConfig, deps: ScanDeps, budget: ScanBudget
) -> _FetchState | Rejection:
    state = _FetchState()
    visited = {target.visit_key}
    current = target
    index = 0
    try:
        while True:
            if budget.expired():
                state.deadline_hit = True
                state.notes.append(ScanNote.DEADLINE_REACHED)
                break
            deps.notify(Phase.FETCHING, index)
            outcome = fetch_hop(
                HopRequest(index=index, target=current),
                budget,
                deps.egress.policy,
                deps.egress.cfg,
                deps.egress.resolver,
            )
            hop = outcome.evidence
            code = hop.failure.code if hop.failure is not None else None
            if code is FailureCode.POLICY_PROHIBITED_ADDRESS:
                if index == 0:
                    detail = hop.failure.detail if hop.failure is not None else None
                    return Rejection(code=code.value, usage_error=False, detail=detail)
                state.notes.append(ScanNote.REDIRECT_BLOCKED_BY_POLICY)
                break
            state.hops.append(hop)
            if code is FailureCode.INTERNAL_ERROR:
                state.internal_error = True
            if code is not None and budget.expired():
                code = FailureCode.DEADLINE_EXCEEDED  # the failure consumed the scan deadline
            if code is FailureCode.DEADLINE_EXCEEDED:
                state.deadline_hit = True
                state.notes.append(ScanNote.DEADLINE_REACHED)
                break
            decision = next_hop(
                hop,
                outcome.next_target,
                follow=config.follow_redirects,
                visited=visited,
            )
            if decision.note is not None:
                state.notes.append(decision.note)
            if decision.follow is None:
                break
            visited.add(decision.follow.visit_key)
            current = decision.follow
            index += 1
    except KeyboardInterrupt:
        state.interrupted = True
        state.notes.append(ScanNote.INTERRUPTED)
    return state


def _has_evidence(hop: HopEvidence) -> bool:
    return hop.http is not None or hop.tls_verify_failed


def _final_status(state: _FetchState, evaluation_interrupted: bool) -> ScanStatus:
    if state.interrupted or evaluation_interrupted:
        return ScanStatus.INTERRUPTED
    if not any(_has_evidence(h) for h in state.hops):
        return ScanStatus.FAILED
    if state.deadline_hit:
        return ScanStatus.PARTIAL
    return ScanStatus.COMPLETED


def _no_evidence_reason(state: _FetchState) -> str:
    if state.interrupted:
        return SCAN_INTERRUPTED
    if state.deadline_hit:
        return SCAN_DEADLINE
    return HOP_FAILED


def _evaluate(state: _FetchState, ctx: RuleContext) -> tuple[list[RuleResult], bool, bool]:
    """Returns (results, internal_error, interrupted). Rules not reached because of an
    interrupt (or because no hop exists at all) become inconclusive with a static reason."""
    results: list[RuleResult] = []
    internal_error = False
    pending: list[RuleMeta] = list(CATALOG)
    interrupted = False
    if state.hops:
        with_http = [h.index for h in state.hops if h.http is not None]
        evidence = ScanEvidence(
            hops=state.hops, terminal_index=with_http[-1] if with_http else None
        )
        try:
            while pending:
                rule_results, failed = evaluate_rule(pending[0], evidence, ctx)
                results.extend(rule_results)
                internal_error |= failed
                pending.pop(0)
        except KeyboardInterrupt:
            interrupted = True
    reason = SCAN_INTERRUPTED if (interrupted or state.interrupted) else ctx.no_evidence_reason
    results.extend(inconclusive(meta, reason, None) for meta in pending)
    return results, internal_error, interrupted


def collect(config: ScanConfig, deps: ScanDeps) -> Collected:
    machine = ScanStateMachine(fail_on=config.fail_on)
    machine.to(Phase.VALIDATING)
    validated = _validate(config, deps)
    if isinstance(validated, Rejection):
        return Collected(machine=machine, rejection=validated)
    target = validated

    started_at = deps.now()
    scan_id = deps.new_scan_id()
    budget = ScanBudget(config.deadline_s)
    machine.to(Phase.FETCHING)
    fetched = _fetch(target, config, deps, budget)
    if isinstance(fetched, Rejection):
        return Collected(machine=machine, rejection=fetched)
    state = fetched

    if state.interrupted:
        machine.to(Phase.INTERRUPTED)
    elif not any(_has_evidence(h) for h in state.hops):
        machine.to(Phase.FAILED)
    elif state.deadline_hit:
        machine.to(Phase.DEADLINE)
    machine.to(Phase.EVALUATING)
    deps.notify(Phase.EVALUATING)
    ctx = RuleContext(started_at=started_at, no_evidence_reason=_no_evidence_reason(state))
    results, rule_error, eval_interrupted = _evaluate(state, ctx)
    if eval_interrupted:
        machine.to(Phase.INTERRUPTED)
        state.notes.append(ScanNote.INTERRUPTED)
    status = _final_status(state, eval_interrupted)

    machine.to(Phase.ASSEMBLING)
    internal_error = state.internal_error or rule_error
    try:
        report = assemble_report(
            scan_id=scan_id,
            started_at=started_at,
            finished_at=max(deps.now(), started_at),
            status=status,
            target=target,
            config=config,
            notes=state.notes,
            hops=state.hops,
            results=results,
        )
    except (AssemblyError, ValueError):
        log.error("report assembly failed; no report produced")
        return Collected(
            machine=machine,
            status=status,
            internal_error=True,
            interrupted=status is ScanStatus.INTERRUPTED,
        )
    log.debug(
        "scan %s: status=%s hops=%d results=%d requests=%d",
        scan_id,
        status.value,
        len(state.hops),
        len(report.results),
        budget.requests,
    )
    return Collected(
        machine=machine,
        report=report,
        status=status,
        internal_error=internal_error,
        interrupted=status is ScanStatus.INTERRUPTED,
    )


def run_scan(config: ScanConfig, deps: ScanDeps) -> ScanOutcome:
    """Full pipeline: collect -> RENDERING -> WRITING -> DONE.

    A report is written for every scan that passed validation (D-23). JSON is written first;
    if HTML rendering fails, the JSON is still written and the outcome records the failure.
    A KeyboardInterrupt while writing propagates; the sink removes its temporary files.
    """
    collected = collect(config, deps)
    machine = collected.machine
    if collected.rejection is not None:
        return machine.reject(collected.rejection)
    report = collected.report
    if report is None:
        return machine.finish(
            status=collected.status,
            report=None,
            internal_error=True,
            interrupted=collected.interrupted,
        )

    machine.to(Phase.RENDERING)
    deps.notify(Phase.RENDERING)
    files = [ReportFile("json", render_json(report))]
    render_error: str | None = None
    try:
        files.append(ReportFile("html", render_html(report)))
    except Exception:  # reason: F-22 boundary; JSON is kept and the outcome forces exit 70
        log.error("HTML rendering failed; JSON report only")
        render_error = "template_error"

    machine.to(Phase.WRITING)
    deps.notify(Phase.WRITING)
    sink_error: str | None = None
    try:
        paths = write_reports(
            config.output_dir, report_basename(report.scan.started_at, report.scan.scan_id), files
        )
    except SinkError as exc:
        sink_error = exc.code
        paths = list(exc.written)
        log.error("report persistence failed: %s", exc.code)
    return machine.finish(
        status=collected.status,
        report=report,
        internal_error=collected.internal_error or render_error is not None,
        interrupted=collected.interrupted,
        report_paths=tuple(paths),
        sink_error=sink_error,
        render_error=render_error,
    )
