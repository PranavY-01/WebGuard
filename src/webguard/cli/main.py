"""Console entry point (Plan §19.3).

Typer runs with standalone_mode=False and this function maps outcomes itself. Typer 0.27 bundles
its own Click, so usage errors arrive as `typer.TyperException` subclasses, and a
KeyboardInterrupt inside a command is returned as 130 (P0, A-06).
"""

from __future__ import annotations

import sys
import traceback
from collections.abc import Sequence

import typer

from webguard.cli.app import app
from webguard.cli.console import SafeConsole
from webguard.cli.exitcodes import ExitCode


def _never_crash_on_encoding() -> None:
    """A console that cannot encode a glyph (e.g. cp1252 pipes on Windows) gets '?' instead of a
    UnicodeEncodeError. The theme already picks ASCII glyphs for such consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    debug = "--debug" in args
    _never_crash_on_encoding()
    out = SafeConsole()
    try:
        result = app(args=args, prog_name="webguard", standalone_mode=False)
    except (typer.Abort, KeyboardInterrupt):
        out.interrupted()
        return ExitCode.INTERRUPTED
    except typer.TyperException as exc:
        code = int(getattr(exc, "exit_code", ExitCode.USAGE))
        format_message = getattr(exc, "format_message", None)
        message = format_message() if callable(format_message) else "invalid usage"
        if code == 0:
            return ExitCode.OK
        if message:
            out.usage_error(str(message))
        return ExitCode.USAGE
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else ExitCode.USAGE
    except Exception as exc:  # reason: outermost boundary; one line, traceback only with --debug
        out.error("Internal error:", type(exc).__name__)
        if debug:
            traceback.print_exc()
        return ExitCode.INTERNAL_ERROR
    if result is None:
        return ExitCode.OK
    code = int(result)
    if code == ExitCode.INTERRUPTED:  # Typer returns 130 for an interrupt inside a command (A-06)
        out.interrupted()
    return code
