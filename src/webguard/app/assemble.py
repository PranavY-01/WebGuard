"""Report assembly (Plan §13.4) with the INV-18 coverage and arithmetic assertions."""

from __future__ import annotations

from datetime import datetime

from webguard import __version__
from webguard.domain.config import ScanConfig
from webguard.domain.enums import ScanNote, ScanStatus
from webguard.domain.evidence import HopEvidence
from webguard.domain.report import (
    ConfigInfo,
    Report,
    ScanInfo,
    Summary,
    TargetInfo,
    ToolInfo,
)
from webguard.domain.results import RuleResult
from webguard.policy.url import CanonicalTarget
from webguard.rules.catalog import BY_ID


class AssemblyError(RuntimeError):
    """An assembly invariant failed; the scan ends as an internal error."""


def assemble_report(
    *,
    scan_id: str,
    started_at: datetime,
    finished_at: datetime,
    status: ScanStatus,
    target: CanonicalTarget,
    config: ScanConfig,
    notes: list[ScanNote],
    hops: list[HopEvidence],
    results: list[RuleResult],
) -> Report:
    missing = set(BY_ID) - {r.rule_id for r in results}
    if missing:
        raise AssemblyError("catalog rules without results")
    ordered = sorted(results, key=lambda r: r.sort_key)
    summary = Summary.of(ordered)
    if summary.checks_total != len(ordered):
        raise AssemblyError("summary does not cover every result")
    return Report(
        tool=ToolInfo(version=__version__),
        scan=ScanInfo(
            scan_id=scan_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            target=TargetInfo(
                display_url_redacted=target.display_url_redacted,
                host=target.host,
                port=target.port,
            ),
            config=ConfigInfo(
                follow_redirects=config.follow_redirects,
                deadline_s=config.deadline_s,
                fail_on=config.fail_on,
            ),
            notes=list(dict.fromkeys(notes)),
        ),
        hops=hops,
        results=ordered,
        summary=summary,
    )
