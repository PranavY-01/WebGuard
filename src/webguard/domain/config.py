"""Scan and egress configuration models."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from webguard.domain.budget import DEADLINE_DEFAULT_S, DEADLINE_MAX_S, DEADLINE_MIN_S
from webguard.domain.enums import FailOn


class ScanConfig(BaseModel):
    """Operator input after CLI parsing (boundary B1). The raw target is validated later by
    `policy.canonicalize_url`; it is never handed to the HTTP layer."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    target: str = Field(min_length=1)
    follow_redirects: bool = False
    deadline_s: int = Field(default=DEADLINE_DEFAULT_S, ge=DEADLINE_MIN_S, le=DEADLINE_MAX_S)
    fail_on: FailOn = FailOn.HIGH
    output_dir: Path = Path("reports")
    debug: bool = False


class EgressConfig(BaseModel):
    """Egress wiring. `ca_file` is the certifi bundle in production; tests inject a local CA
    through the Python API only (D-15). No CLI path reaches this model."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    ca_file: Path
    user_agent: str = Field(min_length=1, max_length=256)
