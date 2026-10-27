"""Visual theme for the terminal interface: palette, glyphs, badges and the logo.

Everything here is static. Target-derived text is never turned into markup: callers wrap it in
`rich.text.Text` and only *style* it with the values defined below (INV-13).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import typer.rich_utils as typer_rich
from rich.color import Color
from rich.console import Console
from rich.style import Style
from rich.text import Text

from webguard.domain.enums import ScanStatus, Severity, Status

# Palette -----------------------------------------------------------------------------------------
ACCENT: Final = "bright_cyan"
ACCENT_2: Final = "bright_magenta"
MUTED: Final = "grey62"
BORDER: Final = "grey42"
OK: Final = "bright_green"
BAD: Final = "bright_red"
WARN: Final = "bright_yellow"
INFO: Final = "bright_blue"

GRADIENT_START: Final = (0, 229, 255)  # cyan
GRADIENT_END: Final = (213, 0, 249)  # magenta

STATUS_STYLE: Final[dict[Status, str]] = {
    Status.PASS: f"bold {OK}",
    Status.FINDING: f"bold {BAD}",
    Status.INCONCLUSIVE: f"bold {WARN}",
    Status.ERROR: f"bold {ACCENT_2}",
    Status.NOT_APPLICABLE: MUTED,
}
STATUS_LABEL: Final[dict[Status, str]] = {
    Status.PASS: "pass",
    Status.FINDING: "finding",
    Status.INCONCLUSIVE: "inconclusive",
    Status.ERROR: "error",
    Status.NOT_APPLICABLE: "n/a",
}
SEVERITY_BADGE: Final[dict[Severity, tuple[str, str]]] = {
    Severity.HIGH: (" HIGH ", "bold white on red3"),
    Severity.MEDIUM: (" MEDIUM ", "bold black on dark_orange"),
    Severity.LOW: (" LOW ", "bold black on gold1"),
    Severity.INFORMATIONAL: (" INFO ", "bold white on dodger_blue2"),
}
SEVERITY_COLOR: Final[dict[Severity, str]] = {
    Severity.HIGH: "red3",
    Severity.MEDIUM: "dark_orange",
    Severity.LOW: "gold1",
    Severity.INFORMATIONAL: "dodger_blue2",
}
SCAN_STATUS_BADGE: Final[dict[ScanStatus, tuple[str, str]]] = {
    ScanStatus.COMPLETED: (" COMPLETED ", "bold black on bright_green"),
    ScanStatus.PARTIAL: (" PARTIAL ", "bold black on bright_yellow"),
    ScanStatus.FAILED: (" FAILED ", "bold white on red3"),
    ScanStatus.INTERRUPTED: (" INTERRUPTED ", "bold white on magenta"),
}


# Glyphs (with an ASCII fallback for consoles that cannot encode Unicode, e.g. cp1252 pipes) -------
@dataclass(frozen=True, slots=True)
class Glyphs:
    status: dict[Status, str]
    bullet: str
    arrow: str
    check: str
    cross: str
    warn: str
    block: str
    unicode: bool


_UNICODE = Glyphs(
    status={
        Status.PASS: "✔",
        Status.FINDING: "✘",
        Status.INCONCLUSIVE: "?",
        Status.ERROR: "!",
        Status.NOT_APPLICABLE: chr(0x2013),  # en dash
    },
    bullet="◆",
    arrow="→",
    check="✔",
    cross="✘",
    warn="▲",
    block="■",
    unicode=True,
)
_ASCII = Glyphs(
    status={
        Status.PASS: "+",
        Status.FINDING: "x",
        Status.INCONCLUSIVE: "?",
        Status.ERROR: "!",
        Status.NOT_APPLICABLE: "-",
    },
    bullet="*",
    arrow="->",
    check="+",
    cross="x",
    warn="!",
    block="#",
    unicode=False,
)


def glyphs_for(console: Console) -> Glyphs:
    return _UNICODE if (console.encoding or "").lower().startswith("utf") else _ASCII


# Logo --------------------------------------------------------------------------------------------
# "ANSI Shadow" letterforms; each letter is 6 rows of equal width.
_LETTERS: Final[dict[str, tuple[str, ...]]] = {
    "W": (
        "██╗    ██╗",
        "██║    ██║",
        "██║ █╗ ██║",
        "██║███╗██║",
        "╚███╔███╔╝",
        " ╚══╝╚══╝ ",
    ),
    "E": (
        "███████╗",
        "██╔════╝",
        "█████╗  ",
        "██╔══╝  ",
        "███████╗",
        "╚══════╝",
    ),
    "B": (
        "██████╗ ",
        "██╔══██╗",
        "██████╔╝",
        "██╔══██╗",
        "██████╔╝",
        "╚═════╝ ",
    ),
    "G": (
        " ██████╗ ",
        "██╔════╝ ",
        "██║  ███╗",
        "██║   ██║",
        "╚██████╔╝",
        " ╚═════╝ ",
    ),
    "U": (
        "██╗   ██╗",
        "██║   ██║",
        "██║   ██║",
        "██║   ██║",
        "╚██████╔╝",
        " ╚═════╝ ",
    ),
    "A": (
        " █████╗ ",
        "██╔══██╗",
        "███████║",
        "██╔══██║",
        "██║  ██║",
        "╚═╝  ╚═╝",
    ),
    "R": (
        "██████╗ ",
        "██╔══██╗",
        "██████╔╝",
        "██╔══██╗",
        "██║  ██║",
        "╚═╝  ╚═╝",
    ),
    "D": (
        "██████╗ ",
        "██╔══██╗",
        "██║  ██║",
        "██║  ██║",
        "██████╔╝",
        "╚═════╝ ",
    ),
}

LOGO_WIDTH: Final = sum(len(_LETTERS[ch][0]) for ch in "WEBGUARD")


def _blend(position: float) -> Color:
    r = round(GRADIENT_START[0] + (GRADIENT_END[0] - GRADIENT_START[0]) * position)
    g = round(GRADIENT_START[1] + (GRADIENT_END[1] - GRADIENT_START[1]) * position)
    b = round(GRADIENT_START[2] + (GRADIENT_END[2] - GRADIENT_START[2]) * position)
    return Color.from_rgb(r, g, b)


def gradient(text: str, bold: bool = True) -> Text:
    """Colour a static string left-to-right from cyan to magenta."""
    out = Text()
    span = max(len(text) - 1, 1)
    for index, ch in enumerate(text):
        out.append(ch, Style(color=_blend(index / span), bold=bold))
    return out


def logo(glyphs: Glyphs) -> Text:
    if not glyphs.unicode:
        return gradient("W E B G U A R D")
    rows = ["".join(_LETTERS[ch][row] for ch in "WEBGUARD") for row in range(6)]
    out = Text()
    for row_index, row in enumerate(rows):
        out.append_text(gradient(row))
        if row_index < len(rows) - 1:
            out.append("\n")
    return out


def brand_line(version: str, glyphs: Glyphs) -> Text:
    line = gradient(f"{glyphs.bullet} WebGuard")
    line.append(f"  v{version}", style=f"bold {ACCENT}")
    line.append("  passive web security configuration audit", style=MUTED)
    return line


# Badges ------------------------------------------------------------------------------------------
def severity_badge(severity: Severity | None) -> Text:
    if severity is None:
        return Text("-", style=MUTED)
    label, style = SEVERITY_BADGE[severity]
    return Text(label, style=style)


def status_cell(status: Status, glyphs: Glyphs) -> Text:
    style = STATUS_STYLE[status]
    return Text.assemble((f"{glyphs.status[status]} ", style), (STATUS_LABEL[status], style))


def scan_status_badge(status: ScanStatus) -> Text:
    label, style = SCAN_STATUS_BADGE[status]
    return Text(label, style=style)


# Typer help screens ----------------------------------------------------------------------------
def apply_typer_theme() -> None:
    """Restyle Typer's built-in --help output to match the WebGuard palette."""
    typer_rich.STYLE_OPTION = f"bold {ACCENT}"
    typer_rich.STYLE_SWITCH = f"bold {OK}"
    typer_rich.STYLE_TYPES = f"bold {WARN}"
    typer_rich.STYLE_USAGE = f"bold {ACCENT_2}"
    typer_rich.STYLE_USAGE_COMMAND = f"bold {ACCENT}"
    typer_rich.STYLE_HELPTEXT_FIRST_LINE = "bold"
    typer_rich.STYLE_HELPTEXT = ""
    typer_rich.STYLE_OPTION_DEFAULT = MUTED
    typer_rich.STYLE_REQUIRED_SHORT = f"bold {BAD}"
    typer_rich.STYLE_REQUIRED_LONG = BAD
    typer_rich.STYLE_OPTIONS_PANEL_BORDER = ACCENT
    typer_rich.STYLE_COMMANDS_PANEL_BORDER = ACCENT_2
    typer_rich.STYLE_COMMANDS_TABLE_FIRST_COLUMN = f"bold {ACCENT}"
    typer_rich.STYLE_ERRORS_PANEL_BORDER = BAD
