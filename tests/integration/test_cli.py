"""CLI behaviour: flags, exit codes, I-10 (no network for rules/version), help surface."""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.conftest import FIXTURE_PORT
from tests.fixtures import pki as certs
from tests.fixtures.server import SENTINEL, FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.cli import app as cli_app
from webguard.cli.main import main
from webguard.domain.config import EgressConfig
from webguard.egress import EgressDeps


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    """`scan` configures root logging on the captured stderr; undo it after each test."""
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    logging.getLogger("webguard").setLevel(logging.NOTSET)


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: object, **_k: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture
def fixture_wiring(monkeypatch: pytest.MonkeyPatch, egress_cfg: EgressConfig) -> None:
    """Test-only: swap the CLI's production wiring for loopback fixtures (never shipped)."""
    monkeypatch.setattr(
        cli_app,
        "build_production_egress",
        lambda: EgressDeps(
            policy=TestScopePolicy(), resolver=StubResolver(["127.0.0.1"]), cfg=egress_cfg
        ),
    )


def url(path: str = "/", host: str = "webguard.test") -> str:
    return f"https://{host}:{FIXTURE_PORT}{path}"


# --- I-10 ------------------------------------------------------------------------------------


def test_i10_rules_and_version_make_no_network_calls(
    no_network: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["version"]) == 0
    assert "WebGuard 1.0.0 (report schema 1.0)" in capsys.readouterr().out
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule_id in ("WG-TLS-001", "WG-TLS-002", "WG-HDR-001", "WG-CK-004", "WG-RDR-001"):
        assert rule_id in out


def test_python_m_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "webguard", "version"], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0
    assert "WebGuard 1.0.0" in proc.stdout


# --- usage and policy rejections (no network) -------------------------------------------------


def test_missing_authorization_is_exit_2(
    no_network: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", "https://example.test/"]) == 2
    err = capsys.readouterr().err
    assert "WebGuard only scans systems you own or are authorized to assess." in err
    assert "--i-am-authorized" in err


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["scan", "http://example.test/", "--i-am-authorized"], 3),
        (["scan", "https://example.test:22/", "--i-am-authorized"], 3),
        (["scan", "https://127.0.0.1/", "--i-am-authorized"], 3),
        (["scan", "https://10.1.2.3/", "--i-am-authorized"], 3),
        (["scan", "https://[::1]/", "--i-am-authorized"], 3),
        (["scan", "https://127.1/", "--i-am-authorized"], 3),
        (["scan", "https://exa mple.test/", "--i-am-authorized"], 2),
        (["scan", "https://example.test/", "--i-am-authorized", "--deadline", "4"], 2),
        (["scan", "https://example.test/", "--i-am-authorized", "--deadline", "121"], 2),
        (["scan", "https://example.test/", "--i-am-authorized", "--fail-on", "critical"], 2),
        (["scan", "https://example.test/", "--i-am-authorized", "--fail-on", "HIGH"], 2),
        (["scan", "https://example.test/", "--insecure"], 2),
        (["scan", "https://example.test/", "--format", "json"], 2),
        (["scan", "https://example.test/", "--proxy", "http://p"], 2),
        (["scan"], 2),
        (["bogus"], 2),
    ],
)
def test_rejections_and_usage_errors(
    no_network: None, argv: list[str], code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(argv) == code
    assert not (tmp_path / "reports").exists()  # D-23: no report for exit 2/3


def test_no_arguments_shows_welcome_screen(
    no_network: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    for text in ("webguard scan URL --i-am-authorized", "Quick start", "authorized to assess"):
        assert text in out


def test_scan_plan_never_shows_query_values(
    no_network: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", "http://example.test/?token=QUERYSECRET", "--i-am-authorized"]) == 3
    captured = capsys.readouterr()
    assert "QUERYSECRET" not in captured.out + captured.err
    assert "?REDACTED" in captured.out


def test_policy_rejection_names_address_class(
    no_network: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", "https://169.254.169.254/latest", "--i-am-authorized"]) == 3
    err = capsys.readouterr().err
    assert "policy_prohibited_address" in err
    assert "link-local" in err


# --- help surface (§19.2: no other flags exist) -----------------------------------------------


# ANSI CSI sequences. Typer forces colour when GITHUB_ACTIONS / FORCE_COLOR / PY_COLORS is set,
# and colours "-" and "-flag" separately, so help text must be stripped before matching flags.
_ANSI = re.compile(chr(27) + r"\[[0-9;?]*[A-Za-z]")


@pytest.mark.parametrize("force_colour", [False, True])
def test_scan_help_lists_exactly_the_allowed_flags(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, force_colour: bool
) -> None:
    import typer.rich_utils

    monkeypatch.setattr(typer.rich_utils, "FORCE_TERMINAL", True if force_colour else None)
    assert main(["scan", "--help"]) == 0
    flags = set(re.findall(r"--[a-z][a-z-]+", _ANSI.sub("", capsys.readouterr().out)))
    assert flags == {
        "--i-am-authorized",
        "--follow-redirects",
        "--deadline",
        "--fail-on",
        "--output",
        "--debug",
        "--help",
    }


# --- end to end through the CLI against loopback fixtures --------------------------------------


@pytest.mark.parametrize(
    ("path", "host", "extra", "code"),
    [
        ("/", "webguard.test", [], 0),
        ("/missing", "webguard.test", [], 0),
        ("/missing", "webguard.test", ["--fail-on", "medium"], 1),
        ("/missing", "webguard.test", ["--fail-on", "none"], 0),
        ("/", certs.EXPIRED, [], 1),
        ("/", certs.EXPIRED, ["--fail-on", "none"], 0),
        ("/redirect?to=/", "webguard.test", ["--follow-redirects"], 0),
    ],
)
def test_cli_end_to_end_exit_codes(
    fixture_wiring: None,
    server: FixtureServer,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    path: str,
    host: str,
    extra: list[str],
    code: int,
) -> None:
    out_dir = tmp_path / "reports"
    argv = ["scan", url(path, host), "--i-am-authorized", "--output", str(out_dir), *extra]
    assert main(argv) == code
    captured = capsys.readouterr()
    assert f"Exit {code}:" in captured.out
    assert len(list(out_dir.glob("webguard_*.json"))) == 1
    assert len(list(out_dir.glob("webguard_*.html"))) == 1


def test_cli_scan_failed_is_exit_4(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli_app,
        "build_production_egress",
        lambda: EgressDeps(policy=TestScopePolicy(), resolver=StubResolver([]), cfg=egress_cfg),
    )
    assert main(["scan", url(), "--i-am-authorized", "--output", str(tmp_path / "r")]) == 4
    assert (
        len(list((tmp_path / "r").glob("webguard_*.json"))) == 1
    )  # D-23: failed scans still report


def test_cli_bad_output_dir_is_exit_5(
    fixture_wiring: None, server: FixtureServer, tmp_path: Path
) -> None:
    target_file = tmp_path / "not-a-dir"
    target_file.write_text("x", encoding="utf-8")
    assert main(["scan", url(), "--i-am-authorized", "--output", str(target_file)]) == 5


def test_cli_debug_output_has_no_secrets(
    fixture_wiring: None, server: FixtureServer, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = [
        "scan",
        url("/cookies?token=QUERYSECRET"),
        "--i-am-authorized",
        "--debug",
        "--output",
        str(tmp_path / "r"),
    ]
    main(argv)
    captured = capsys.readouterr()
    assert "hop 0" in captured.err
    for blob in (captured.out, captured.err):
        assert "QUERYSECRET" not in blob
        assert SENTINEL not in blob
