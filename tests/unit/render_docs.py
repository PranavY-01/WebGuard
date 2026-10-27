"""Render docs/RULES.md (from the catalog) and tests/fixtures/known_answers.md (from the
known-answer table with actual results). Run: python -m tests.unit.render_docs"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from tests.unit.builders import STARTED
from tests.unit.known_answers import CASES
from webguard.domain.results import RuleResult
from webguard.rules.catalog import CATALOG, RuleMeta
from webguard.rules.engine import evaluate_rule
from webguard.rules.helpers import RuleContext

ROOT = Path(__file__).resolve().parents[2]
RULES_MD = ROOT / "docs" / "RULES.md"
KNOWN_ANSWERS_MD = ROOT / "tests" / "fixtures" / "known_answers.md"

_SHARED = {
    "blocked_by:WG-TLS-001",
    "hop_failed",
    "scan_deadline",
    "scan_interrupted",
    "internal_rule_error",
}


def _line(r: RuleResult) -> str:
    sev = r.severity.value if r.severity else "-"
    conf = r.confidence.value if r.confidence else "-"
    return f"{r.subject or '-'} {r.status.value} {sev} {conf} {r.reason_code}"


def _rule_section(meta: RuleMeta) -> list[str]:
    out = [
        f"## {meta.rule_id} — {meta.title}",
        "",
        f"- Category: `{meta.category.value}`",
        f"- Possible finding severities: {', '.join(f'`{s.value}`' for s in meta.severities)}",
        f"- Version: {meta.version}",
        "",
        "| Reason code | Meaning |",
        "|---|---|",
    ]
    out += [f"| `{code}` | {text} |" for code, text in meta.messages.items() if code not in _SHARED]
    out += ["", f"**Remediation.** {meta.remediation}", "", "**References.**", ""]
    out += [f"- <{ref}>" for ref in meta.references]
    if meta.limitations:
        out += ["", "**Limitations.**", ""]
        out += [f"- {text}" for text in meta.limitations]
    return [*out, ""]


def render_rules_md() -> str:
    lines = [
        "# WebGuard rule catalog",
        "",
        "Generated from `webguard.rules.catalog`; a parity test keeps this file and the catalog "
        "identical in rule IDs and reason codes.",
        "",
        "Every rule can also report these shared reason codes:",
        "",
        "| Reason code | Meaning |",
        "|---|---|",
    ]
    common = CATALOG[0].messages
    lines += [f"| `{code}` | {common[code]} |" for code in sorted(_SHARED)]
    lines.append("")
    for meta in CATALOG:
        lines += _rule_section(meta)
    return "\n".join(lines).rstrip() + "\n"


def render_known_answers_md() -> str:
    rows = []
    counts: Counter[str] = Counter()
    for case in CASES:
        ctx = RuleContext(started_at=STARTED, no_evidence_reason=case.context_reason)
        results, _ = evaluate_rule(
            next(m for m in CATALOG if m.rule_id == case.rule_id), case.evidence, ctx
        )
        actual = tuple(_line(r) for r in results)
        verdict = "match" if actual == case.expected else "MISMATCH"
        counts[case.rule_id] += 1
        rows.append(
            f"| {case.rule_id} | {case.name} | {'<br>'.join(case.expected)} | "
            f"{'<br>'.join(actual)} | {verdict} |"
        )
    lines = [
        "# Known-answer record",
        "",
        "Rendered by `python -m tests.unit.render_docs` from `tests/unit/known_answers.py`; "
        "`test_known_answers_record_is_current` fails if this file is stale. Columns per result: "
        "subject, status, severity, confidence, reason.",
        "",
        "Precision/recall is not computed: no rule has 10 labelled positive and 10 labelled "
        "negative real-world cases. No real-world accuracy is claimed.",
        "",
        "| Rule | Cases |",
        "|---|---|",
    ]
    lines += [f"| {meta.rule_id} | {counts[meta.rule_id]} |" for meta in CATALOG]
    lines += ["", "| Rule | Case | Expected | Actual | Verdict |", "|---|---|---|---|---|", *rows]
    return "\n".join(lines) + "\n"


def main() -> None:
    RULES_MD.write_text(render_rules_md(), encoding="utf-8", newline="\n")
    KNOWN_ANSWERS_MD.write_text(render_known_answers_md(), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
