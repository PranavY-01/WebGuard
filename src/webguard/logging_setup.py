"""Logging configuration (Plan §18), applied once by the CLI.

Logs go to stderr. WebGuard records may carry only static message templates with int, float,
bool, enum or SafeText-valid string arguments; anything else is dropped by `SafeLogFilter`.
httpcore, h11 and jinja2 stay at WARNING even in debug mode (T-25).
"""

from __future__ import annotations

import logging
import sys
from enum import Enum
from typing import Final, TextIO

from webguard.domain.safe_text import is_safe

PINNED_LIBRARIES: Final = ("httpcore", "h11", "jinja2")
_FORMAT: Final = "webguard: %(levelname)s %(name)s: %(message)s"
_MAX_ARG_CHARS: Final = 2048


def _safe_arg(arg: object) -> bool:
    if isinstance(arg, Enum | bool | int | float) or arg is None:
        return True
    return isinstance(arg, str) and len(arg) <= _MAX_ARG_CHARS and is_safe(arg)


class SafeLogFilter(logging.Filter):
    """Drop records whose message is not a static string or whose args are not safe values.
    Tracebacks are stripped unless debug output was requested."""

    def __init__(self, keep_tracebacks: bool) -> None:
        super().__init__()
        self._keep_tracebacks = keep_tracebacks

    def filter(self, record: logging.LogRecord) -> bool:
        if not isinstance(record.msg, str) or not is_safe(record.msg):
            return False
        args = record.args
        values: tuple[object, ...]
        if args is None:
            values = ()
        elif isinstance(args, tuple):
            values = args
        else:
            values = tuple(args.values())
        if not all(_safe_arg(v) for v in values):
            return False
        if not self._keep_tracebacks:
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


def pin_library_loggers() -> None:
    names = [
        name
        for name in logging.root.manager.loggerDict
        if any(name == lib or name.startswith(f"{lib}.") for lib in PINNED_LIBRARIES)
    ]
    for name in (*PINNED_LIBRARIES, *names):
        logging.getLogger(name).setLevel(logging.WARNING)


def configure(debug: bool, stream: TextIO | None = None) -> logging.Handler:
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))
    handler.addFilter(SafeLogFilter(keep_tracebacks=debug))
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    logging.getLogger("webguard").setLevel(logging.DEBUG if debug else logging.WARNING)
    pin_library_loggers()
    return handler
