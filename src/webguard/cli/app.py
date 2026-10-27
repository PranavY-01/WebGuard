"""Typer commands: scan, rules, version, plus the welcome screen (Plan §19.1-§19.2).

The CLI can only construct production wiring (D-15): PublicScopePolicy, the system resolver and
the certifi CA bundle, via `build_production_egress`. No flag, environment variable or config
field weakens verification, destination policy, budgets or escaping (P7).
"""

from __future__ import annotations

import platform
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Annotated

import typer

from webguard import __version__
from webguard.app.orchestrator import ScanDeps, run_scan
from webguard.cli.console import SafeConsole
from webguard.cli.exitcodes import ExitCode, exit_reason, outcome_to_exit_code
from webguard.cli.theme import apply_typer_theme
from webguard.domain.budget import DEADLINE_DEFAULT_S, DEADLINE_MAX_S, DEADLINE_MIN_S
from webguard.domain.config import ScanConfig
from webguard.domain.enums import FailOn
from webguard.domain.report import SCHEMA_VERSION
from webguard.egress import build_production_egress
from webguard.logging_setup import configure as configure_logging
from webguard.rules.catalog import CATALOG

AUTHORIZATION_MESSAGE = "WebGuard only scans systems you own or are authorized to assess."
AUTHORIZATION_HINT = "Re-run with --i-am-authorized."

_REQUIRED = "Required"
_BEHAVIOUR = "Scan behaviour"
_OUTPUT = "Output"

apply_typer_theme()

app = typer.Typer(
    name="webguard",
    help=(
        "[bold bright_cyan]WebGuard[/] - passive web security configuration auditor.\n\n"
        "Checks a site's TLS certificate, HSTS, CSP, X-Content-Type-Options, cookie flags and "
        "redirect downgrades, then writes JSON and HTML reports."
    ),
    epilog="Run [bold bright_cyan]webguard[/] with no arguments for the welcome screen.",
    add_completion=False,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
)


def console() -> SafeConsole:
    return SafeConsole()


@app.callback(invoke_without_command=True)
def root(ctx: typer.Context) -> None:
    """Passive web security configuration auditor."""
    if ctx.invoked_subcommand is None:
        console().welcome(__version__)


@app.command(
    epilog=(
        "[bold]Examples[/]\n\n"
        "  [bright_cyan]webguard scan https://www.example.com/ --i-am-authorized[/]\n\n"
        "  [bright_cyan]webguard scan https://example.com/ --i-am-authorized "
        "--follow-redirects --fail-on medium --output ./reports[/]"
    ),
)
def scan(
    url: Annotated[
        str,
        typer.Argument(
            help="One [bold]https://[/] URL you own or are authorized to assess.",
            show_default=False,
        ),
    ],
    i_am_authorized: Annotated[
        bool,
        typer.Option(
            "--i-am-authorized",
            help="Confirms you own the target or are authorized to assess it.",
            rich_help_panel=_REQUIRED,
        ),
    ] = False,
    follow_redirects: Annotated[
        bool,
        typer.Option(
            "--follow-redirects",
            help="Follow up to 3 HTTPS-only redirects, each fully re-validated.",
            rich_help_panel=_BEHAVIOUR,
        ),
    ] = False,
    deadline: Annotated[
        int,
        typer.Option(
            "--deadline",
            min=DEADLINE_MIN_S,
            max=DEADLINE_MAX_S,
            help=f"Time limit for the whole scan in seconds ({DEADLINE_MIN_S}-{DEADLINE_MAX_S}).",
            rich_help_panel=_BEHAVIOUR,
        ),
    ] = DEADLINE_DEFAULT_S,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            case_sensitive=True,
            help="Exit 1 when a finding at or above this severity exists; 'none' never does.",
            rich_help_panel=_BEHAVIOUR,
        ),
    ] = FailOn.HIGH,
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Report directory; created if its parent exists. Files are never overwritten.",
            rich_help_panel=_OUTPUT,
        ),
    ] = Path("reports"),
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            help="Diagnostics on stderr (never cookie, header or query values).",
            rich_help_panel=_OUTPUT,
        ),
    ] = False,
) -> int:
    """Scan one site and write JSON and HTML reports."""
    out = console()
    if not i_am_authorized:
        out.unauthorized(AUTHORIZATION_MESSAGE, AUTHORIZATION_HINT)
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
    out.scan_plan(config, __version__)
    with out.progress(enabled=not debug) as on_progress:
        outcome = run_scan(
            config, ScanDeps(egress=build_production_egress(), on_progress=on_progress)
        )
    code = outcome_to_exit_code(outcome)
    reason = exit_reason(outcome, code)
    if outcome.rejection is not None:
        out.rejection(outcome.rejection, int(code), reason)
        return code
    if outcome.sink_error is not None:
        out.persistence_error(outcome.sink_error)
    out.print_outcome(outcome, int(code), reason)
    return code


@app.command()
def rules() -> int:
    """List the ten checks. Makes no network connections."""
    console().rules(CATALOG)
    return ExitCode.OK


def _dependency_version(name: str) -> str:
    try:
        return package_version(name)
    except PackageNotFoundError:
        return "not installed"


@app.command()
def version() -> int:
    """Show version, report schema and runtime details."""
    console().version(
        __version__,
        SCHEMA_VERSION,
        [
            ("Python", f"{platform.python_implementation()} {platform.python_version()}"),
            ("Platform", platform.platform(terse=True)),
            ("Trust store", f"certifi {_dependency_version('certifi')}"),
            ("HTTP stack", f"httpcore {_dependency_version('httpcore')} (HTTP/1.1 only)"),
        ],
    )
    return ExitCode.OK
