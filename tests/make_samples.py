"""Generate samples/: reports, plain-text transcripts and SVG screenshots, from loopback fixtures
only (G-09, G-10).

Run: python -m tests.make_samples

Scans run the real CLI (`webguard.cli.main.main`) against the local fixture server with only the
wiring factory swapped in-process, as the CLI tests do. Rejection and listing transcripts use the
unmodified production wiring; they are rejected before any DNS lookup. Hostnames are
*.webguard.test and the only address is 127.0.0.1. Output paths are relative, so no local path
is recorded. The interface is recorded on a truecolor console and exported as SVG.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
from pathlib import Path

from rich.text import Text

from tests.fixtures.pki import EXPIRED, build_pki
from tests.fixtures.server import FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.cli import app as cli_app
from webguard.cli.console import SafeConsole, make_console
from webguard.cli.main import main
from webguard.domain.config import EgressConfig
from webguard.egress import USER_AGENT, EgressDeps

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
WIDTH = 110

SCANS = [
    ("clean", ["scan", "https://webguard.test:8443/", "--i-am-authorized"]),
    (
        "findings",
        ["scan", "https://webguard.test:8443/missing", "--i-am-authorized", "--fail-on", "medium"],
    ),
    (
        "redirect",
        [
            "scan",
            "https://webguard.test:8443/redirect?to=/cookies",
            "--i-am-authorized",
            "--follow-redirects",
        ],
    ),
    ("expired-cert", ["scan", f"https://{EXPIRED}:8443/", "--i-am-authorized"]),
]
SCREENS = [
    ("welcome", []),
    ("version", ["version"]),
    ("rules", ["rules"]),
    ("unauthorized", ["scan", "https://webguard.test/"]),
    ("rejected-http", ["scan", "http://webguard.test/", "--i-am-authorized"]),
    ("rejected-loopback", ["scan", "https://127.0.0.1/", "--i-am-authorized"]),
]
HELP = [("help", ["--help"]), ("help-scan", ["scan", "--help"])]


def _record(name: str, argv: list[str]) -> None:
    """Run the CLI on a recording console; write cli-<name>.txt and cli-<name>.svg."""
    console = make_console(
        io.StringIO(),
        width=WIDTH,
        record=True,
        force_terminal=True,
        force_interactive=False,
        legacy_windows=False,
        color_system="truecolor",
    )
    cli_app.console = lambda: SafeConsole(console, console)  # type: ignore[assignment]  # reason: recording console for samples
    prompt = f"$ webguard {' '.join(argv)}".rstrip()
    console.print(Text(prompt, style="bold"))
    code = main(argv)
    console.print(Text(f"(exit code {code})", style="grey62"))
    text = console.export_text(clear=False)
    (SAMPLES / f"cli-{name}.txt").write_text(
        "\n".join(line.rstrip() for line in text.splitlines()) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (SAMPLES / f"cli-{name}.svg").write_text(
        console.export_svg(title=prompt.removeprefix("$ ")), encoding="utf-8", newline="\n"
    )


def _help(name: str, argv: list[str]) -> None:
    """Typer renders --help on its own console; capture it as plain text."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    body = "\n".join(line.rstrip() for line in out.getvalue().splitlines())
    (SAMPLES / f"cli-{name}.txt").write_text(
        f"$ webguard {' '.join(argv)}\n{body}\n(exit code {code})\n", encoding="utf-8", newline="\n"
    )


def main_samples() -> None:
    os.environ["COLUMNS"] = str(WIDTH)  # stable Typer help width (this script only)
    original_console = cli_app.console
    production = cli_app.build_production_egress
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        pki = build_pki(work)
        server = FixtureServer(pki, "127.0.0.1", 8443).start()
        cfg = EgressConfig(ca_file=pki.ca_file, user_agent=USER_AGENT)
        previous_cwd = Path.cwd()
        os.chdir(work)
        try:
            SAMPLES.mkdir(exist_ok=True)
            for old in SAMPLES.glob("*"):
                old.unlink()
            cli_app.build_production_egress = lambda: EgressDeps(  # type: ignore[assignment]  # reason: fixture wiring for samples only
                policy=TestScopePolicy(), resolver=StubResolver(["127.0.0.1"]), cfg=cfg
            )
            for name, argv in SCANS:
                _record(f"scan-{name}", [*argv, "--output", name])
                for produced in (work / name).glob("webguard_*"):
                    shutil.copyfile(produced, SAMPLES / f"{name}{produced.suffix}")
            # Rejections, listings and help use real production wiring; none reaches the network.
            cli_app.build_production_egress = production  # type: ignore[assignment]  # reason: restore
            for name, argv in SCREENS:
                _record(name, argv)
            for name, argv in HELP:
                _help(name, argv)
        finally:
            cli_app.console = original_console  # type: ignore[assignment]  # reason: restore
            cli_app.build_production_egress = production  # type: ignore[assignment]  # reason: restore
            os.chdir(previous_cwd)
            server.stop()


if __name__ == "__main__":
    main_samples()
