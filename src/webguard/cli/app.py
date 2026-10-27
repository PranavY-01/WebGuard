"""Typer commands: scan, rules, version (Plan §19.1-§19.2).

The CLI can only construct production wiring (D-15): PublicScopePolicy, the system resolver and
the certifi CA bundle, via `build_production_egress`. No flag, environment variable or config
field weakens verification, destination policy, budgets or escaping (P7).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table
from rich.text import Text

from webguard import __version__
from webguard.app.orchestrator import ScanDeps, run_scan
from webguard.cli.console import SafeConsole
from webguard.cli.exitcodes import ExitCode, exit_reason, outcome_to_exit_code
from webguard.domain.budget import DEADLINE_DEFAULT_S, DEADLINE_MAX_S, DEADLINE_MIN_S
from webguard.domain.config import ScanConfig
from webguard.domain.enums import FailOn
from webguard.domain.report import SCHEMA_VERSION
from webguard.egress import build_production_egress
from webguard.logging_setup import configure as configure_logging
from webguard.rules.catalog import CATALOG

AUTHORIZATION_MESSAGE = (
    "WebGuard only scans systems you own or are authorized to assess. "
    "Re-run with --i-am-authorized."
)

app = typer.Typer(
    name="webguard",
    help="Passive web security configuration auditor (TLS, security headers, cookies, redirects).",
    add_completion=False,
    pretty_exceptions_enable=False,
    no_args_is_help=True,
)


def console() -> SafeConsole:
    return SafeConsole()


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="One https:// URL you are authorized to assess.")],
    i_am_authorized: Annotated[
        bool,
        typer.Option(
            "--i-am-authorized",
            help="Required. Confirms you own the target or are authorized to assess it.",
        ),
    ] = False,
    follow_redirects: Annotated[
        bool,
        typer.Option(
            "--follow-redirects", help="Follow up to 3 HTTPS-only redirects, each re-validated."
        ),
    ] = False,
    deadline: Annotated[
        int,
        typer.Option(
            "--deadline",
            min=DEADLINE_MIN_S,
            max=DEADLINE_MAX_S,
            help=f"Overall scan deadline in seconds ({DEADLINE_MIN_S}-{DEADLINE_MAX_S}).",
        ),
    ] = DEADLINE_DEFAULT_S,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            case_sensitive=True,
            help="Exit 1 when a finding at or above this severity exists ('none' never does).",
        ),
    ] = FailOn.HIGH,
    output: Annotated[
        Path,
        typer.Option(
            "--output", help="Report directory (created if its parent exists; never overwritten)."
        ),
    ] = Path("reports"),
    debug: Annotated[
        bool, typer.Option("--debug", help="Verbose diagnostics on stderr (never secrets).")
    ] = False,
) -> int:
    """Run one passive scan and write JSON and HTML reports."""
    out = console()
    if not i_am_authorized:
        out.error(AUTHORIZATION_MESSAGE)
        return ExitCode.USAGE
    configure_logging(debug)
    config = ScanConfig(
        target=url,
        follow_redirects=follow_redirects,
        deadline_s=deadline,
        fail_on=fail_on,
        output_dir=output,
        debug=debug,
    )
    outcome = run_scan(config, ScanDeps(egress=build_production_egress()))
    code = outcome_to_exit_code(outcome)
    reason = exit_reason(outcome, code)
    if outcome.rejection is not None:
        details = [outcome.rejection.detail] if outcome.rejection.detail else []
        out.error(f"Target rejected ({outcome.rejection.code}); nothing was sent.", *details)
        out.info(f"Exit {int(code)}: {reason}")
        return code
    if outcome.sink_error is not None:
        out.error(f"Report persistence failed ({outcome.sink_error}).")
    out.print_outcome(outcome, int(code), reason)
    return code


@app.command()
def rules() -> int:
    """List the rule catalog. Makes no network connections."""
    table = Table(title=Text("WebGuard rules"))
    for column in ("ID", "Name", "Category", "Possible severities"):
        table.add_column(Text(column))
    for meta in CATALOG:
        table.add_row(
            Text(meta.rule_id),
            Text(meta.title),
            Text(meta.category.value),
            Text(", ".join(s.value for s in meta.severities)),
        )
    console().out.print(table)
    return ExitCode.OK


@app.command()
def version() -> int:
    """Print the tool and report schema versions."""
    console().out.print(Text(f"WebGuard {__version__} (report schema {SCHEMA_VERSION})"))
    return ExitCode.OK
