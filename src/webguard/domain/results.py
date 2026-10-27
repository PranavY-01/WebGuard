"""Rule results (Plan §13.3)."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webguard.domain.enums import Category, Confidence, Severity, Status
from webguard.domain.safe_text import SafeText

RULE_ID_PATTERN = r"^WG-(TLS|HDR|CK|RDR)-\d{3}$"
SUBJECT_PATTERN = r"^(hop:[0-3]|cookie:.+@hop:[0-3])$"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = Field(pattern=r"^[a-z0-9_.:-]{1,64}$")
    value: SafeText


class RuleResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    rule_version: int = Field(ge=1)
    title: str
    category: Category
    subject: SafeText | None = Field(default=None, pattern=SUBJECT_PATTERN)
    status: Status
    severity: Severity | None = None
    confidence: Confidence | None = None
    reason_code: str = Field(pattern=r"^[a-z0-9_:.-]{1,80}$")
    message: SafeText
    evidence: list[EvidenceItem] = Field(default_factory=list)
    remediation: str
    references: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _co_occurrence(self) -> Self:
        is_finding = self.status is Status.FINDING
        if is_finding != (self.severity is not None):
            raise ValueError("severity is required iff status == finding")
        needs_confidence = self.status in (Status.PASS, Status.FINDING)
        if needs_confidence != (self.confidence is not None):
            raise ValueError("confidence is required iff status in {pass, finding}")
        return self

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.subject or "")
