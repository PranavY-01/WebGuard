"""S-13 runtime, S-20, S-21..S-25, S-27, U-50 and sink failure modes F-17, F-18, F-20, F-22."""

from __future__ import annotations

import io
import json
import logging
import os
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from tests.conftest import FIXTURE_PORT
from tests.fixtures.server import SENTINEL, FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard import logging_setup
from webguard.app.orchestrator import ScanDeps, run_scan
from webguard.app.state import ScanOutcome
from webguard.cli.console import SafeConsole, make_console
from webguard.domain.config import EgressConfig, ScanConfig
from webguard.domain.enums import ScanStatus
from webguard.egress import EgressDeps
from webguard.render import html_render
from webguard.render.html_render import REPORT_CSP, environment
from webguard.sink.writer import report_basename

FIXED_NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
FIXED_ID = "abcdef0123456789abcdef0123456789"


def scan(
    cfg: EgressConfig,
    out: Path,
    path: str = "/",
    *,
    fixed: bool = False,
    follow: bool = False,
) -> ScanOutcome:
    config = ScanConfig(
        target=f"https://webguard.test:{FIXTURE_PORT}{path}",
        output_dir=out,
        follow_redirects=follow,
    )
    egress = EgressDeps(policy=TestScopePolicy(), resolver=StubResolver(["127.0.0.1"]), cfg=cfg)
    deps = (
        ScanDeps(egress=egress, now=lambda: FIXED_NOW, new_scan_id=lambda: FIXED_ID)
        if fixed
        else ScanDeps(egress=egress)
    )
    return run_scan(config, deps)


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend((tag, name, value) for name, value in attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def parse_html(text: str) -> _Collector:
    c = _Collector()
    c.feed(text)
    return c


def files_in(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


# --- I-01 files + S-13 runtime ------------------------------------------------------------------


def test_i01_clean_scan_writes_both_files(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path
) -> None:
    out = tmp_path / "reports"
    outcome = scan(egress_cfg, out)
    assert outcome.status is ScanStatus.COMPLETED
    assert outcome.sink_error is None
    assert outcome.report is not None
    base = report_basename(outcome.report.scan.started_at, outcome.report.scan.scan_id)
    assert files_in(out) == [f"{base}.html", f"{base}.json"]
    assert [p.name for p in outcome.report_paths] == [f"{base}.json", f"{base}.html"]
    data = json.loads((out / f"{base}.json").read_text(encoding="utf-8"))
    assert data["scan"]["scan_id"] == outcome.report.scan.scan_id
    assert data["summary"]["checks_total"] == len(data["results"])
    if os.name != "nt":
        assert (out.stat().st_mode & 0o777) == 0o700
        assert ((out / f"{base}.json").stat().st_mode & 0o777) == 0o600


def test_s13_environment_autoescapes() -> None:
    env = environment()
    assert env.autoescape is True
    assert env.loader is not None
    assert "report.html.j2" in env.loader.list_templates()


# --- S-21 HTML injection ------------------------------------------------------------------------


def test_s21_html_report_is_inert(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path
) -> None:
    outcome = scan(egress_cfg, tmp_path / "r", "/malicious")
    html_path = next(p for p in outcome.report_paths if p.suffix == ".html")
    text = html_path.read_text(encoding="utf-8")
    doc = parse_html(text)
    assert "script" not in doc.tags
    assert "iframe" not in doc.tags
    assert "img" not in doc.tags
    forbidden = {"href", "src", "action", "style", "srcset", "formaction"}
    assert [a for a in doc.attrs if a[1] in forbidden or a[1].startswith("on")] == []
    assert ("meta", "content", REPORT_CSP) in doc.attrs
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<img src=x>" not in text
    joined = "".join(doc.text)
    assert "<script>alert(1)</script>" in joined  # visible as inert text
    for _tag, _name, value in doc.attrs:
        assert "evil.test" not in (value or "")


# --- S-20 / S-27: no secrets in any output -------------------------------------------------------


def test_s20_s27_no_secrets_in_reports_console_or_debug_logs(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path
) -> None:
    log_stream = io.StringIO()
    handler = logging_setup.configure(debug=True, stream=log_stream)
    try:
        outcomes = [
            scan(egress_cfg, tmp_path / "r", path)
            for path in ("/cookies?token=QUERYSECRET", "/malicious", "/created")
        ]
    finally:
        logging.getLogger().removeHandler(handler)
        logging.getLogger("webguard").setLevel(logging.NOTSET)
    out, err = io.StringIO(), io.StringIO()
    console = SafeConsole(make_console(out, width=300), make_console(err, width=300))
    for o in outcomes:
        console.print_outcome(o, 0, "test")
    blobs = {
        "debug log": log_stream.getvalue(),
        "stdout": out.getvalue(),
        "stderr": err.getvalue(),
        **{p.name: p.read_text(encoding="utf-8") for o in outcomes for p in o.report_paths},
    }
    assert "hop 0" in blobs["debug log"]  # debug logging was really on
    for name, blob in blobs.items():
        assert SENTINEL not in blob, name
        assert "QUERYSECRET" not in blob, name
    for secret in ("__Host-c", "__Secure-d", "default-src", "<script>", "max-age=1;"):
        assert secret not in blobs["debug log"]


# --- S-22 terminal injection -------------------------------------------------------------------


def test_s22_terminal_prints_target_text_literally(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path
) -> None:
    outcome = scan(egress_cfg, tmp_path / "r", "/malicious")
    buf = io.StringIO()
    console = SafeConsole(
        make_console(buf, force_terminal=True, width=400), make_console(io.StringIO())
    )
    console.print_outcome(outcome, 0, "[bold]reason[/bold]")
    printed = buf.getvalue()
    assert "cookie:[link@hop:0" in printed  # cookie names end at the first "="
    assert "cookie:[bold red]B[/bold red]\\x9b2J@hop:0" in printed
    assert "[bold]reason[/bold]" in printed
    assert "\x1b]8;" not in printed  # no OSC 8 hyperlink
    assert "\x1b[2J" not in printed
    assert "\x9b" not in printed


# --- S-23..S-25 sink ----------------------------------------------------------------------------


def test_s23_existing_file_never_overwritten(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path
) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    existing = out / f"{report_basename(FIXED_NOW, FIXED_ID)}.json"
    existing.write_text("original", encoding="utf-8")
    outcome = scan(egress_cfg, out, fixed=True)
    assert outcome.sink_error == "output_exists"
    assert outcome.report_paths == ()
    assert existing.read_text(encoding="utf-8") == "original"
    assert files_in(out) == [existing.name]


def _make_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import _winapi  # reason: Windows without symlink privilege; a junction is the equivalent

        _winapi.CreateJunction(str(target), str(link))


def test_s24_symlinked_output_dir_refused(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    _make_link(link, real)
    outcome = scan(egress_cfg, link)
    assert outcome.sink_error == "output_is_symlink"
    assert files_in(real) == []


def test_s25_failure_mid_write_leaves_nothing(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disk_full(_fd: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", disk_full)
    out = tmp_path / "reports"
    outcome = scan(egress_cfg, out)
    assert outcome.sink_error == "write_failed"
    assert files_in(out) == []


def test_f18_html_failure_keeps_json(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync
    calls = {"n": 0}

    def second_fails(fd: int) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError(28, "No space left on device")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", second_fails)
    out = tmp_path / "reports"
    outcome = scan(egress_cfg, out)
    assert outcome.sink_error == "write_failed"
    assert [p.suffix for p in outcome.report_paths] == [".json"]
    assert [Path(n).suffix for n in files_in(out)] == [".json"]


def test_f20_interrupt_during_write_cleans_up(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(_fd: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "fsync", interrupt)
    out = tmp_path / "reports"
    with pytest.raises(KeyboardInterrupt):
        scan(egress_cfg, out)
    assert files_in(out) == []


@pytest.mark.parametrize(
    ("setup", "code"),
    [
        ("missing_parent", "output_parent_missing"),
        ("is_file", "output_not_directory"),
    ],
)
def test_f17_bad_output_directory(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path, setup: str, code: str
) -> None:
    if setup == "missing_parent":
        out = tmp_path / "no" / "such" / "dir"
    else:
        out = tmp_path / "file"
        out.write_text("x", encoding="utf-8")
    outcome = scan(egress_cfg, out)
    assert outcome.sink_error == code
    assert outcome.report is not None  # the summary can still be printed
    assert not (tmp_path / "no").exists()


def test_f22_template_error_keeps_json(
    egress_cfg: EgressConfig, server: FixtureServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> object:
        raise RuntimeError("template bug")

    monkeypatch.setattr(html_render, "_template", broken)
    out = tmp_path / "reports"
    outcome = scan(egress_cfg, out)
    assert outcome.render_error == "template_error"
    assert outcome.internal_error
    assert [Path(n).suffix for n in files_in(out)] == [".json"]


# --- U-50 logging filter -----------------------------------------------------------------------


def _record(msg: object, *args: object) -> logging.LogRecord:
    return logging.LogRecord("webguard.x", logging.WARNING, __file__, 1, msg, args or None, None)


def test_u50_filter_keeps_safe_and_drops_unsafe() -> None:
    f = logging_setup.SafeLogFilter(keep_tracebacks=False)
    assert f.filter(_record("hop %d %s %s", 1, "ok-text", ScanStatus.PARTIAL))
    assert f.filter(_record("plain"))
    assert not f.filter(_record("value %s", "bad\x1b[2J"))
    assert not f.filter(_record("value %s", "x" + chr(0x202E)))
    assert not f.filter(_record("value %s", object()))
    assert not f.filter(_record("value %s", b"bytes"))
    assert not f.filter(_record(object()))
    assert not f.filter(_record("value %s", "x" * 5000))


def test_u50_tracebacks_stripped_unless_debug() -> None:
    try:
        raise ValueError("target text")
    except ValueError:
        import sys

        info = sys.exc_info()
    record = _record("failed")
    record.exc_info = info
    assert logging_setup.SafeLogFilter(keep_tracebacks=False).filter(record)
    assert record.exc_info is None


def test_u50_library_loggers_pinned_even_in_debug() -> None:
    for name in ("httpcore", "httpcore.http11", "h11", "jinja2"):
        logging.getLogger(name).setLevel(logging.DEBUG)
    handler = logging_setup.configure(debug=True, stream=io.StringIO())
    try:
        for name in ("httpcore", "httpcore.http11", "h11", "jinja2"):
            assert logging.getLogger(name).getEffectiveLevel() == logging.WARNING, name
        assert logging.getLogger("webguard").getEffectiveLevel() == logging.DEBUG
    finally:
        logging.getLogger().removeHandler(handler)
        logging.getLogger("webguard").setLevel(logging.NOTSET)
