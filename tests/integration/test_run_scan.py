"""I-09 end to end: a real SIGINT during fetch yields an interrupted scan with a written report."""

from __future__ import annotations

import json
import signal
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import FrameType

import pytest

from tests.conftest import FIXTURE_PORT
from tests.fixtures.server import FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.app.orchestrator import ScanDeps, run_scan
from webguard.domain.config import EgressConfig, ScanConfig
from webguard.domain.enums import ScanNote, ScanStatus
from webguard.egress import EgressDeps


@pytest.fixture
def armed_sigint() -> Iterator[threading.Event]:
    """SIGINT raises KeyboardInterrupt only while armed, so a late signal cannot abort pytest."""
    armed = threading.Event()

    def handler(_signum: int, _frame: FrameType | None) -> None:
        if armed.is_set():
            armed.clear()
            raise KeyboardInterrupt

    previous = signal.signal(signal.SIGINT, handler)
    try:
        yield armed
    finally:
        armed.clear()
        signal.signal(signal.SIGINT, previous)


@pytest.mark.slow
def test_i09_sigint_during_fetch_writes_partial_report(
    egress_cfg: EgressConfig,
    server: FixtureServer,
    tmp_path: Path,
    armed_sigint: threading.Event,
) -> None:
    out = tmp_path / "reports"
    config = ScanConfig(target=f"https://webguard.test:{FIXTURE_PORT}/stall", output_dir=out)
    deps = ScanDeps(
        egress=EgressDeps(
            policy=TestScopePolicy(), resolver=StubResolver(["127.0.0.1"]), cfg=egress_cfg
        )
    )
    armed_sigint.set()
    timer = threading.Timer(0.5, signal.raise_signal, args=(signal.SIGINT,))
    started = time.monotonic()
    timer.start()
    try:
        outcome = run_scan(config, deps)
    finally:
        timer.cancel()
    # POSIX delivers immediately; Windows only after the clamped recv timeout (A-12, <= 10 s).
    assert time.monotonic() - started <= 12
    assert outcome.status is ScanStatus.INTERRUPTED
    assert outcome.interrupted
    assert outcome.report is not None
    assert ScanNote.INTERRUPTED in outcome.report.scan.notes
    assert sorted(p.suffix for p in outcome.report_paths) == [".html", ".json"]
    data = json.loads(
        next(p for p in outcome.report_paths if p.suffix == ".json").read_text("utf-8")
    )
    assert data["scan"]["status"] == "interrupted"
    assert {r["reason_code"] for r in data["results"]} <= {"scan_interrupted", "verified"}
