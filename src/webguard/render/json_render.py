"""JSON report rendering (Plan §16.1)."""

from __future__ import annotations

from webguard.domain.report import Report


def render_json(report: Report) -> str:
    """UTF-8 JSON, indent 2. Non-ASCII is kept as-is: SafeText already neutralized controls."""
    return report.model_dump_json(indent=2) + "\n"
