"""Terminal interface (Plan §16.3, INV-13).

Every dynamic value is passed to Rich as a `Text` object and only *styled* with static theme
values; both consoles run with markup, highlighting and emoji disabled, so target text can never
become markup, hyperlinks or styling. ESC and other controls never arrive here from the target
(SafeText escaped them at capture); operator-typed text is escaped by `_display` before printing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from rich import box
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webguard.app.state import Phase, Rejection, ScanOutcome
from webguard.cli import theme
from webguard.cli.theme import (
    ACCENT,
    ACCENT_2,
    BAD,
    BORDER,
    MUTED,
    OK,
    WARN,
    Glyphs,
    brand_line,
    glyphs_for,
    gradient,
    logo,
    scan_status_badge,
    severity_badge,
    status_cell,
)
from webguard.domain.config import ScanConfig
from webguard.domain.enums import Category, ScanNote, Severity, Status
from webguard.domain.report import Report
from webguard.domain.results import RuleResult
from webguard.policy.url import CanonicalTarget, canonicalize_url
from webguard.rules.catalog import RuleMeta

_CATEGORY_ORDER = (Category.TLS, Category.HEADERS, Category.COOKIES, Category.REDIRECTS)
_CATEGORY_STYLE = {
    Category.TLS: "bold bright_green",
    Category.HEADERS: "bold bright_cyan",
    Category.COOKIES: "bold gold1",
    Category.REDIRECTS: "bold bright_magenta",
}
_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL)
_MAX_FIX_FIRST = 6

_NOTE_TIPS: dict[ScanNote, str] = {
    ScanNote.REDIRECT_NOT_FOLLOWED: (
        "The URL redirects. Add --follow-redirects or scan the final URL "
        "to check the page's headers."
    ),
    ScanNote.REDIRECT_LIMIT_REACHED: "Stopped after 3 redirects.",
    ScanNote.REDIRECT_LOOP: "The redirect chain loops back to an address already visited.",
    ScanNote.REDIRECT_BLOCKED_BY_POLICY: "A redirect pointed to a non-public address and was not "
    "followed.",
    ScanNote.DEADLINE_REACHED: (
        "The deadline ran out. Raise --deadline (up to 120) for slow servers."
    ),
    ScanNote.INTERRUPTED: "Interrupted. Everything gathered so far was saved.",
}

_REJECTION_HINTS: dict[str, str] = {
    "scheme_not_https": "Use the site's https:// address. Plain HTTP is never scanned.",
    "port_not_permitted": "Only ports 443 and 8443 are scanned.",
    "userinfo_present": "Remove user:password@ from the URL. WebGuard never logs in.",
    "host_invalid": "Check the hostname; it is malformed.",
    "ipv4_ambiguous": (
        "Write the address as a full dotted quad (e.g. 203.0.113.7) or use the hostname."
    ),
    "url_illegal_chars": "Quote the URL and percent-encode spaces or non-ASCII characters.",
    "url_too_long": "Shorten the URL (2048 characters maximum).",
    "policy_prohibited_address": (
        "WebGuard scans public addresses only. Private, loopback, link-local and reserved ranges "
        "are always refused."
    ),
}

_PHASE_TEXT: dict[Phase, str] = {
    Phase.EVALUATING: "Evaluating 10 checks",
    Phase.RENDERING: "Rendering the JSON and HTML reports",
    Phase.WRITING: "Writing reports",
}

ProgressCallback = Callable[[Phase, int | None], None]


def make_console(
    file: TextIO | None = None,
    *,
    stderr: bool = False,
    force_terminal: bool | None = None,
    width: int | None = None,
    record: bool = False,
    color_system: str | None = "auto",
    force_interactive: bool | None = None,
    legacy_windows: bool | None = None,
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
        record=record,
        force_interactive=force_interactive,
        legacy_windows=legacy_windows,
        color_system=color_system,  # type: ignore[arg-type]  # reason: Rich's Literal of system names
    )


def _display(value: str) -> str:
    """Operator-typed text: make every non-printable character visible."""
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)


def _redacted_target(raw: str) -> str:
    """Show the target with query values redacted, exactly as reports do. A URL that fails
    validation is shown only up to its query string."""
    canonical = canonicalize_url(raw)
    if isinstance(canonical, CanonicalTarget):
        return canonical.display_url_redacted
    base, sep, _query = raw.partition("?")
    return _display(base) + ("?REDACTED" if sep else "")


def _panel(body: RenderableType, title: str, border: str) -> Panel:
    return Panel(
        body,
        title=Text(f" {title} ", style=f"bold {border}"),
        title_align="left",
        border_style=border,
        box=box.ROUNDED,
        padding=(0, 1),
    )


class SafeConsole:
    def __init__(self, out: Console | None = None, err: Console | None = None) -> None:
        self.out = out or make_console()
        self.err = err or make_console(stderr=True)

    @property
    def g(self) -> Glyphs:
        return glyphs_for(self.out)

    # --- generic messages ------------------------------------------------------------------

    def error(self, message: str, *details: str) -> None:
        g = glyphs_for(self.err)
        line = Text.assemble((f"{g.cross} ", f"bold {BAD}"), (message, f"bold {BAD}"))
        for detail in details:
            line.append(" ")
            line.append(Text(_display(detail)))
        self.err.print(line)

    def info(self, message: str) -> None:
        self.err.print(Text(message, style=MUTED))

    def usage_error(self, message: str) -> None:
        body = Group(
            Text(_display(message), style="bold"),
            Text("Run 'webguard --help' or 'webguard scan --help' for usage.", style=MUTED),
        )
        self.err.print(_panel(body, "Usage error", BAD))

    def interrupted(self) -> None:
        g = glyphs_for(self.err)
        self.err.print(Text(f"{g.warn} Interrupted.", style=f"bold {ACCENT_2}"))

    def unauthorized(self, message: str, hint: str) -> None:
        g = glyphs_for(self.err)
        body = Group(
            Text(message, style="bold"),
            Text(hint, style=WARN),
            Text(""),
            Text.assemble(
                ("$ ", MUTED),
                ("webguard scan ", f"bold {ACCENT}"),
                ("https://your-site.example/ ", ""),
                ("--i-am-authorized", f"bold {OK}"),
            ),
        )
        self.err.print(_panel(body, f"{g.warn} Authorization required", WARN))

    # --- welcome, version, rules -------------------------------------------------------------

    def welcome(self, version: str) -> None:
        g = self.g
        commands = Table(box=None, show_header=False, padding=(0, 2, 0, 0))
        commands.add_column(no_wrap=True)
        commands.add_column()
        for name, text in (
            (
                "scan URL --i-am-authorized",
                "Scan one https:// site you own or are authorized to assess",
            ),
            ("rules", "List the ten checks and their severities"),
            ("version", "Show version, schema and runtime details"),
        ):
            commands.add_row(Text(f"webguard {name}", style=f"bold {ACCENT}"), Text(text))

        examples = Group(
            Text.assemble(
                ("$ ", MUTED),
                ("webguard scan https://www.your-site.example/ --i-am-authorized", ""),
            ),
            Text.assemble(
                ("$ ", MUTED),
                (
                    "webguard scan https://your-site.example/ --i-am-authorized --follow-redirects "
                    "--fail-on medium",
                    "",
                ),
            ),
            Text.assemble(("$ ", MUTED), ("webguard scan --help", "")),
        )
        checks = Text()
        for index, meta_cat in enumerate(_CATEGORY_ORDER):
            if index:
                checks.append(f"  {g.bullet}  ", style=MUTED)
            checks.append(
                {
                    Category.TLS: "TLS certificate",
                    Category.HEADERS: "HSTS / CSP / nosniff",
                    Category.COOKIES: "cookie flags",
                    Category.REDIRECTS: "redirect downgrades",
                }[meta_cat],
                style=_CATEGORY_STYLE[meta_cat],
            )

        self.out.print()
        self.out.print(Padding(logo(g), (0, 0, 0, 2)))
        self.out.print(Padding(brand_line(version, g), (1, 0, 1, 2)))
        self.out.print(Padding(checks, (0, 0, 1, 2)))
        self.out.print(_panel(commands, "Commands", ACCENT))
        self.out.print(_panel(examples, "Quick start", ACCENT_2))
        self.out.print(
            Padding(
                Group(
                    Text.assemble(
                        (f"{g.warn} ", f"bold {WARN}"),
                        ("Only scan systems you own or are authorized to assess.", f"bold {WARN}"),
                    ),
                    Text(
                        "  Passive checks: at most 4 GET requests, response headers only.",
                        style=MUTED,
                    ),
                    Text(
                        "  Run 'webguard COMMAND --help' for options  |  "
                        "User guide: docs/USER_GUIDE.md",
                        style=MUTED,
                    ),
                ),
                (1, 0, 1, 1),
            )
        )

    def version(self, version: str, schema: str, details: Sequence[tuple[str, str]]) -> None:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=MUTED, no_wrap=True)
        grid.add_column()
        for label, value in details:
            grid.add_row(Text(label), Text(_display(value)))
        body = Group(gradient(f"WebGuard {version} (report schema {schema})"), Text(""), grid)
        self.out.print(_panel(body, "version", ACCENT))

    def rules(self, catalog: Sequence[RuleMeta]) -> None:
        table = Table(
            box=box.ROUNDED,
            border_style=BORDER,
            header_style=f"bold {ACCENT}",
            title=gradient("WebGuard checks"),
            title_justify="left",
        )
        table.add_column(Text("ID"), no_wrap=True)
        table.add_column(Text("Check"))
        table.add_column(Text("Area"), no_wrap=True)
        table.add_column(Text("Finding severities"))
        for category in _CATEGORY_ORDER:
            metas = [m for m in catalog if m.category is category]
            if not metas:
                continue
            if table.row_count:
                table.add_section()
            for meta in metas:
                severities = Text(" ").join(
                    severity_badge(s) for s in _SEVERITY_ORDER if s in meta.severities
                )
                table.add_row(
                    Text(meta.rule_id, style="bold"),
                    Text(meta.title),
                    Text(category.value, style=_CATEGORY_STYLE[category]),
                    severities,
                )
        self.out.print(table)
        self.out.print(
            Text(
                "Reason codes and fixes: docs/RULES.md and docs/USER_GUIDE.md (section 8)",
                style=MUTED,
            )
        )

    # --- scan --------------------------------------------------------------------------------

    def scan_plan(self, config: ScanConfig, version: str) -> None:
        g = self.g
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=MUTED, no_wrap=True)
        grid.add_column()
        grid.add_row(Text("Target"), Text(_redacted_target(config.target), style="bold"))
        grid.add_row(
            Text("Redirects"),
            Text("follow up to 3 (HTTPS only)" if config.follow_redirects else "not followed"),
        )
        grid.add_row(Text("Deadline"), Text(f"{config.deadline_s} s"))
        grid.add_row(Text("Fail on"), Text(f"{config.fail_on.value} and above"))
        grid.add_row(Text("Reports"), Text(_display(str(config.output_dir))))
        grid.add_row(
            Text("Authorized"), Text(f"{g.check} confirmed by --i-am-authorized", style=OK)
        )
        self.out.print(brand_line(version, g))
        self.out.print(_panel(grid, "Scan plan", ACCENT))

    @contextmanager
    def progress(self, enabled: bool) -> Iterator[ProgressCallback]:
        """A live spinner on interactive terminals; a no-op otherwise (pipes, CI logs, --debug)."""
        if not enabled or not self.out.is_interactive:
            yield lambda _phase, _hop: None
            return
        g = self.g
        spinner = "dots" if g.unicode else "line"
        with self.out.status(
            Text("Preparing scan", style=f"bold {ACCENT}"), spinner=spinner, spinner_style=ACCENT_2
        ) as status:

            def update(phase: Phase, hop: int | None) -> None:
                if phase is Phase.FETCHING and hop is not None:
                    text = (
                        f"Request {hop + 1} of up to 4 {g.arrow} resolving, connecting, "
                        "verifying TLS, reading headers"
                    )
                else:
                    text = _PHASE_TEXT.get(phase, "Working")
                status.update(Text(text, style=f"bold {ACCENT}"))

            yield update

    def rejection(self, rejection: Rejection, exit_code: int, exit_reason: str) -> None:
        g = glyphs_for(self.err)
        title = "Invalid URL" if rejection.usage_error else "Target refused"
        lines: list[RenderableType] = [
            Text.assemble(("Reason  ", MUTED), (rejection.code, f"bold {BAD}")),
        ]
        if rejection.detail:
            lines.append(Text.assemble(("Address ", MUTED), (_display(rejection.detail), "bold")))
        lines.append(Text("Nothing was sent: no request was made to the target.", style=OK))
        hint = _REJECTION_HINTS.get(rejection.code)
        if hint:
            tip = Table.grid(padding=(0, 1))
            tip.add_column(no_wrap=True)
            tip.add_column()
            tip.add_row(Text(g.arrow, style=f"bold {WARN}"), Text(hint, style=WARN))
            lines.append(tip)
        self.err.print(_panel(Group(*lines), f"{g.cross} {title}", BAD))
        self.err.print(self._exit_line(exit_code, exit_reason, g))

    def persistence_error(self, code: str) -> None:
        g = glyphs_for(self.err)
        self.err.print(
            _panel(
                Group(
                    Text.assemble(("Reason  ", MUTED), (code, f"bold {BAD}")),
                    Text("The results below were not saved. Check --output.", style=WARN),
                ),
                f"{g.cross} Reports not written",
                BAD,
            )
        )

    def print_outcome(self, outcome: ScanOutcome, exit_code: int, exit_reason: str) -> None:
        g = self.g
        report = outcome.report
        if report is not None:
            self.out.print(self._results_table(report, g))
            self.out.print(self._fix_first(report, g))
            self.out.print(self._summary(report, g))
        if outcome.report_paths:
            self.out.print(self._reports(outcome.report_paths))
        self.out.print(self._exit_line(exit_code, exit_reason, g))

    # --- scan output building blocks ------------------------------------------------------------

    def _results_table(self, report: Report, g: Glyphs) -> Table:
        table = Table(
            box=box.ROUNDED,
            border_style=BORDER,
            header_style=f"bold {ACCENT}",
            title=gradient("Results"),
            title_justify="left",
        )
        table.add_column(Text("Status"), no_wrap=True)
        table.add_column(Text("Check"), no_wrap=True)
        table.add_column(Text("Subject"), overflow="fold")
        table.add_column(Text("Severity"), no_wrap=True)
        table.add_column(Text("Details"), overflow="fold")
        for category in _CATEGORY_ORDER:
            rows = [r for r in report.results if r.category is category]
            if not rows:
                continue
            if table.row_count:
                table.add_section()
            previous_rule = ""
            for r in rows:
                check = Text(r.rule_id, style="bold")
                if r.rule_id != previous_rule:
                    check.append("\n")
                    check.append(r.title, style=_CATEGORY_STYLE[category])
                previous_rule = r.rule_id
                table.add_row(
                    status_cell(r.status, g),
                    check,
                    Text(r.subject or "-", style="" if r.subject else MUTED),
                    severity_badge(r.severity),
                    Text(r.message),
                )
        return table

    def _fix_first(self, report: Report, g: Glyphs) -> Panel:
        findings = sorted(
            (r for r in report.results if r.status is Status.FINDING and r.severity is not None),
            key=lambda r: (-(r.severity.rank if r.severity else 0), r.rule_id),
        )
        if not findings:
            text = Text.assemble(
                (f"{g.check} No findings. ", f"bold {OK}"),
                (
                    "These settings look right. A clean result does not mean the site is secure.",
                    MUTED,
                ),
            )
            return _panel(text, "What to fix first", OK)
        unique: list[RuleResult] = []
        seen: set[tuple[str, str]] = set()
        for r in findings:
            key = (r.rule_id, r.reason_code)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        lines: list[RenderableType] = []
        for r in unique[:_MAX_FIX_FIRST]:
            count = sum(
                1 for f in findings if (f.rule_id, f.reason_code) == (r.rule_id, r.reason_code)
            )
            head = Text.assemble(severity_badge(r.severity), " ", (r.rule_id, "bold"), "  ")
            head.append_text(Text(r.message))
            if count > 1:
                head.append(f"  (x{count})", style=MUTED)
            lines.append(head)
            fix = Text.assemble((f"{g.arrow} ", ACCENT_2), (r.remediation, MUTED))
            lines.append(Padding(fix, (0, 0, 0, 3)))
        if len(unique) > _MAX_FIX_FIRST:
            lines.append(Text(f"+ {len(unique) - _MAX_FIX_FIRST} more in the report", style=MUTED))
        return _panel(Group(*lines), "What to fix first", BAD)

    def _summary(self, report: Report, g: Glyphs) -> Panel:
        s = report.summary
        seconds = (report.scan.finished_at - report.scan.started_at).total_seconds()
        plural = "s" if len(report.hops) != 1 else ""
        top = Text.assemble(scan_status_badge(report.scan.status), "  ")
        top.append_text(Text(report.scan.target.display_url_redacted, style="bold"))
        top.append(
            f"   {len(report.hops)} request{plural}  |  {seconds:.1f}s",
            style=MUTED,
        )

        counts = Text()
        for status, value in (
            (Status.PASS, s.pass_),
            (Status.FINDING, s.finding),
            (Status.INCONCLUSIVE, s.inconclusive),
            (Status.ERROR, s.error),
            (Status.NOT_APPLICABLE, s.not_applicable),
        ):
            style = theme.STATUS_STYLE[status] if value else MUTED
            counts.append(f"{g.status[status]} {value} {theme.STATUS_LABEL[status]}", style=style)
            counts.append("    ")
        counts.append(f"{s.checks_total} checks", style=MUTED)

        by_sev = s.findings_by_severity
        severity_line = Text()
        for severity, value in (
            (Severity.HIGH, by_sev.high),
            (Severity.MEDIUM, by_sev.medium),
            (Severity.LOW, by_sev.low),
            (Severity.INFORMATIONAL, by_sev.informational),
        ):
            severity_line.append_text(severity_badge(severity))
            severity_line.append(f" {value} ", style="bold" if value else MUTED)
            severity_line.append(g.block * min(value, 12), style=theme.SEVERITY_COLOR[severity])
            severity_line.append("   ")

        parts: list[RenderableType] = [top, Text(""), counts, severity_line]
        for note in report.scan.notes:
            tip = _NOTE_TIPS.get(note)
            line = Text.assemble((f"{g.bullet} ", ACCENT_2), (note.value, f"bold {ACCENT_2}"))
            if tip:
                line.append(f"  {tip}", style=MUTED)
            parts.append(line)
        return _panel(Group(*parts), "Summary", ACCENT)

    def _reports(self, paths: Sequence[Path]) -> Panel:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(no_wrap=True)
        grid.add_column()
        for path in paths:
            kind = path.suffix.lstrip(".").upper() or "FILE"
            style = f"bold {ACCENT}" if kind == "JSON" else f"bold {ACCENT_2}"
            grid.add_row(Text(f" {kind} ", style=f"{style} reverse"), Text(_display(str(path))))
        return _panel(grid, "Reports", ACCENT_2)

    @staticmethod
    def _exit_line(code: int, reason: str, g: Glyphs) -> Text:
        if code == 0:
            icon, style = g.check, f"bold {OK}"
        elif code == 1:
            icon, style = g.cross, f"bold {BAD}"
        elif code == 130:
            icon, style = g.warn, f"bold {ACCENT_2}"
        else:
            icon, style = g.warn, f"bold {WARN}"
        line = Text.assemble((f"{icon} ", style), (f"Exit {code}: ", style))
        line.append_text(Text(reason, style=style))
        return line
