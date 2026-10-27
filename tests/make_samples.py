"""Generate samples/ and the README CLI transcripts from loopback fixtures only (G-09, G-10).

Run: python -m tests.make_samples

Scans run the real CLI (`webguard.cli.main.main`) against the local fixture server with only the
wiring factory swapped in-process, as the CLI tests do. Rejection and listing transcripts use the
unmodified production wiring; they are rejected before any DNS lookup. Hostnames are
*.webguard.test and the only address is 127.0.0.1. Output paths are relative, so no local path
is recorded.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
from pathlib import Path

from tests.fixtures.pki import EXPIRED, build_pki
from tests.fixtures.server import FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.cli import app as cli_app
from webguard.cli.main import main
from webguard.domain.config import EgressConfig
from webguard.egress import USER_AGENT, EgressDeps

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

RUNS = [
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
TRANSCRIPTS = [
    ("version", ["version"]),
    ("rules", ["rules"]),
    ("unauthorized", ["scan", "https://webguard.test/"]),
    ("rejected-http", ["scan", "http://webguard.test/", "--i-am-authorized"]),
    ("rejected-loopback", ["scan", "https://127.0.0.1/", "--i-am-authorized"]),
]


def _run(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    text = f"$ webguard {' '.join(argv)}\n{out.getvalue()}{err.getvalue()}(exit code {code})\n"
    return code, text


def main_samples() -> None:
    os.environ["COLUMNS"] = "110"  # stable Rich table width for transcripts (this script only)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        pki = build_pki(work)
        server = FixtureServer(pki, "127.0.0.1", 8443).start()
        cfg = EgressConfig(ca_file=pki.ca_file, user_agent=USER_AGENT)
        production = cli_app.build_production_egress
        cli_app.build_production_egress = lambda: EgressDeps(  # type: ignore[assignment]  # reason: fixture wiring for samples only
            policy=TestScopePolicy(), resolver=StubResolver(["127.0.0.1"]), cfg=cfg
        )
        previous_cwd = Path.cwd()
        os.chdir(work)
        try:
            SAMPLES.mkdir(exist_ok=True)
            for old in SAMPLES.glob("*"):
                old.unlink()
            for name, argv in RUNS:
                out_dir = work / name
                _code, text = _run([*argv, "--output", name])
                (SAMPLES / f"cli-scan-{name}.txt").write_text(text, encoding="utf-8", newline="\n")
                for produced in out_dir.glob("webguard_*"):
                    shutil.copyfile(produced, SAMPLES / f"{name}{produced.suffix}")
            # Rejections and listings use the real production wiring; none reaches the network.
            cli_app.build_production_egress = production  # type: ignore[assignment]  # reason: restore
            for name, argv in TRANSCRIPTS:
                _code, text = _run(argv)
                (SAMPLES / f"cli-{name}.txt").write_text(text, encoding="utf-8", newline="\n")
        finally:
            os.chdir(previous_cwd)
            server.stop()


if __name__ == "__main__":
    main_samples()
