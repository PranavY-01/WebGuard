"""Safe terminal output (Plan §16.3, INV-13).

Every dynamic value is passed to Rich as a `Text` object, and both consoles are created with
markup, highlighting and emoji disabled, so target text can never become markup, hyperlinks
or styling. ESC and other controls never reach here: SafeText escaped them at capture.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from webguard.app.state import ScanOutcome
from webguard.domain.enums import Status

_STATUS_STYLE = {
    Status.PASS: "green",
    Status.FINDING: "bold red",
    Status.INCONCLUSIVE: "yellow",
    Status.ERROR: "magenta",
    Status.NOT_APPLICABLE: "dim",
}


def make_console(
    file: TextIO | None = None,
    *,
    stderr: bool = False,
    force_terminal: bool | None = None,
    width: int | None = None,
) -> Console:
    return Console(
        file=file,
        stderr=stderr,
        markup=False,
        highlight=False,
        emoji=False,
        soft_wrap=False,
        force_terminal=force_terminal,
        width=width,
    )


class SafeConsole:
    def __init__(self, out: Console | None = None, err: Console | None = None) -> None:
        self.out = out or make_console()
        self.err = err or make_console(stderr=True)

    def error(self, message: str, *details: str) -> None:
        line = Text(message, style="bold red")
        for detail in details:
            line.append(" ")
            line.append(Text(detail))
        self.err.print(line)

    def info(self, message: str) -> None:
        self.err.print(Text(message))

    def print_outcome(self, outcome: ScanOutcome, exit_code: int, exit_reason: str) -> None:
        report = outcome.report
        if report is not None:
            table = Table(title=Text("WebGuard results"), show_lines=False, expand=False)
            for column in ("Rule", "Subject", "Status", "Severity", "Message"):
                table.add_column(Text(column), overflow="fold")
            for r in report.results:
                table.add_row(
                    Text(r.rule_id),
                    Text(r.subject or "-"),
                    Text(r.status.value, style=_STATUS_STYLE[r.status]),
                    Text(r.severity.value if r.severity else "-"),
                    Text(r.message),
                )
            self.out.print(table)
            s = report.summary
            self.out.print(
                Text(
                    f"Status {report.scan.status.value}: {s.checks_total} checks, {s.pass_} pass, "
                    f"{s.finding} finding, {s.inconclusive} inconclusive, {s.error} error, "
                    f"{s.not_applicable} not applicable "
                    f"(high {s.findings_by_severity.high}, medium {s.findings_by_severity.medium}, "
                    f"low {s.findings_by_severity.low}, "
                    f"informational {s.findings_by_severity.informational})"
                )
            )
            self.out.print(Text(f"Target {report.scan.target.display_url_redacted}"))
            if report.scan.notes:
                self.out.print(Text("Notes " + ", ".join(n.value for n in report.scan.notes)))
        self._print_paths(outcome.report_paths)
        self.out.print(Text(f"Exit {exit_code}: {exit_reason}", style="bold"))

    def _print_paths(self, paths: Sequence[Path]) -> None:
        for path in paths:
            self.out.print(Text(f"Report written: {path}"))
