"""Terminal interface: non-Unicode glyph fallback and safe rendering of every screen."""

from __future__ import annotations

import io

import pytest

from webguard.cli import app as cli_app
from webguard.cli.console import SafeConsole, make_console
from webguard.cli.main import main
from webguard.cli.theme import LOGO_WIDTH, glyphs_for, logo


class _Cp1252Stream(io.TextIOWrapper):
    """A cp1252 text stream like a redirected stdout on Windows."""

    def __init__(self) -> None:
        super().__init__(io.BytesIO(), encoding="cp1252", errors="strict")

    def text(self) -> str:
        self.flush()
        buffer = self.buffer
        assert isinstance(buffer, io.BytesIO)
        return buffer.getvalue().decode("cp1252")


def test_ascii_glyphs_for_non_unicode_console() -> None:
    stream = _Cp1252Stream()
    g = glyphs_for(make_console(stream))
    assert not g.unicode
    for glyph in (*g.status.values(), g.bullet, g.arrow, g.check, g.cross, g.warn, g.block):
        assert glyph.isascii()
    assert logo(g).plain.isascii()


def test_unicode_glyphs_and_logo_for_utf8_console() -> None:
    g = glyphs_for(make_console(io.StringIO()))
    assert g.unicode
    rows = logo(g).plain.split("\n")
    assert len(rows) == 6
    assert {len(row) for row in rows} == {LOGO_WIDTH}


@pytest.mark.parametrize("argv", [[], ["version"], ["rules"], ["scan", "https://x.test/"]])
def test_screens_render_on_cp1252_without_crashing(
    argv: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    out, err = _Cp1252Stream(), _Cp1252Stream()
    monkeypatch.setattr(
        cli_app, "console", lambda: SafeConsole(make_console(out), make_console(err))
    )
    code = main(argv)
    assert code in (0, 2)
    assert (out.text() + err.text()).strip()
