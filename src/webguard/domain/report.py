"""Report schema (Plan §13.4), schema_version "1.0"."""

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from webguard.domain.budget import DEADLINE_MAX_S, DEADLINE_MIN_S
from webguard.domain.enums import FailOn, ScanNote, ScanStatus, Severity, Status
from webguard.domain.evidence import HopEvidence, require_utc
from webguard.domain.results import RuleResult
from webguard.domain.safe_text import SafeText

SCHEMA_VERSION: Final = "1.0"

REPORT_LIMITATIONS: Final[tuple[str, ...]] = (
    "Passive configuration assessment; not a penetration test. "
    "Passing checks do not mean the site is secure.",
    "Only the response status line and headers are inspected; the body is never read, "
    "so <meta> CSP and page content are not assessed.",
    "TLS checks cover certificate verification and expiry only; protocol versions and cipher "
    "suites are not audited.",
    "Trust is evaluated against the certifi CA bundle, which may differ from your operating "
    "system or browser trust store.",
    "URL paths are reported as given and may contain tokens; query values are redacted.",
    "Results describe one moment from one network vantage point.",
)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolInfo(_Frozen):
    name: Literal["WebGuard"] = "WebGuard"
    version: str


class TargetInfo(_Frozen):
    display_url_redacted: SafeText
    host: SafeText
    port: int = Field(ge=1, le=65535)


class ConfigInfo(_Frozen):
    follow_redirects: bool
    deadline_s: int = Field(ge=DEADLINE_MIN_S, le=DEADLINE_MAX_S)
    fail_on: FailOn


class ScanInfo(_Frozen):
    scan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    started_at: AwareDatetime
    finished_at: AwareDatetime
    status: ScanStatus
    target: TargetInfo
    config: ConfigInfo
    notes: list[ScanNote] = Field(default_factory=list)

    _utc = field_validator("started_at", "finished_at")(require_utc)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        return self


class SeverityCounts(_Frozen):
    informational: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)


class Summary(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", validate_by_name=True, serialize_by_alias=True
    )

    checks_total: int = Field(ge=0)
    pass_: int = Field(ge=0, alias="pass")
    finding: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    error: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    findings_by_severity: SeverityCounts

    @model_validator(mode="after")
    def _arithmetic(self) -> Self:
        parts = self.pass_ + self.finding + self.inconclusive + self.error + self.not_applicable
        if self.checks_total != parts:
            raise ValueError("checks_total must equal the sum of status counts (INV-18)")
        sev = self.findings_by_severity
        if sev.informational + sev.low + sev.medium + sev.high != self.finding:
            raise ValueError("findings_by_severity must sum to finding")
        return self

    @classmethod
    def of(cls, results: list[RuleResult]) -> Summary:
        by_status = {s: sum(1 for r in results if r.status is s) for s in Status}
        by_sev = {s: sum(1 for r in results if r.severity is s) for s in Severity}
        return cls(
            checks_total=len(results),
            pass_=by_status[Status.PASS],
            finding=by_status[Status.FINDING],
            inconclusive=by_status[Status.INCONCLUSIVE],
            error=by_status[Status.ERROR],
            not_applicable=by_status[Status.NOT_APPLICABLE],
            findings_by_severity=SeverityCounts(
                informational=by_sev[Severity.INFORMATIONAL],
                low=by_sev[Severity.LOW],
                medium=by_sev[Severity.MEDIUM],
                high=by_sev[Severity.HIGH],
            ),
        )


class Report(_Frozen):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    tool: ToolInfo
    scan: ScanInfo
    hops: list[HopEvidence]
    results: list[RuleResult]
    summary: Summary
    limitations: list[str] = Field(default_factory=lambda: list(REPORT_LIMITATIONS))

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if [r.sort_key for r in self.results] != sorted(r.sort_key for r in self.results):
            raise ValueError("results must be sorted by (rule_id, subject)")
        if self.summary != Summary.of(self.results):
            raise ValueError("summary does not match results (INV-18)")
        if not self.limitations or self.limitations[0] != REPORT_LIMITATIONS[0]:
            raise ValueError("the passive-assessment limitation must come first")
        return self
