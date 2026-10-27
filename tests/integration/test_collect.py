"""I-02..I-08, S-06, S-07, S-18 and interrupt handling at the orchestrator level (collect)."""

from __future__ import annotations

import time
from types import MappingProxyType

import pytest

from tests.conftest import FIXTURE_PORT
from tests.fixtures import pki as certs
from tests.fixtures.server import FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.app.orchestrator import Collected, ScanDeps, collect
from webguard.app.state import IllegalTransitionError, Phase, ScanStateMachine
from webguard.domain.config import EgressConfig, ScanConfig
from webguard.domain.enums import FailOn, ScanNote, ScanStatus, Status
from webguard.domain.report import Report
from webguard.domain.results import RuleResult
from webguard.egress import EgressDeps
from webguard.policy.scope import PublicScopePolicy, ScopePolicy
from webguard.rules import engine

LOOP4 = "127.0.0.1"
BASE = f"https://webguard.test:{FIXTURE_PORT}"


def run(
    cfg: EgressConfig,
    path: str = "/",
    *,
    host: str = "webguard.test",
    url: str | None = None,
    follow: bool = False,
    deadline: int = 30,
    resolver: StubResolver | None = None,
    policy: ScopePolicy | None = None,
) -> Collected:
    config = ScanConfig(
        target=url or f"https://{host}:{FIXTURE_PORT}{path}",
        follow_redirects=follow,
        deadline_s=deadline,
    )
    egress = EgressDeps(
        policy=policy or TestScopePolicy(), resolver=resolver or StubResolver([LOOP4]), cfg=cfg
    )
    return collect(config, ScanDeps(egress=egress))


def report_of(c: Collected) -> Report:
    assert c.report is not None, c
    return c.report


def results(c: Collected, rule_id: str) -> list[RuleResult]:
    return [r for r in report_of(c).results if r.rule_id == rule_id]


def lines(c: Collected, rule_id: str) -> list[str]:
    def line(r: RuleResult) -> str:
        sev = r.severity.value if r.severity else "-"
        return f"{r.subject or '-'} {r.status.value} {sev} {r.reason_code}"

    return [line(r) for r in results(c, rule_id)]


def test_i01_clean_fixture_completed(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg)
    rep = report_of(c)
    assert c.status is ScanStatus.COMPLETED
    assert not c.internal_error
    assert rep.summary.finding == 0
    assert {r.status for r in rep.results} <= {Status.PASS, Status.NOT_APPLICABLE}
    assert rep.scan.target.display_url_redacted == f"{BASE}/"
    assert len(rep.hops) == 1
    assert server.log.connections == 1


def test_i02_missing_headers(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, "/missing")
    assert c.status is ScanStatus.COMPLETED
    assert lines(c, "WG-HDR-001") == ["hop:0 finding medium header_absent"]
    assert lines(c, "WG-HDR-002") == ["hop:0 finding low header_absent"]
    assert lines(c, "WG-HDR-003") == ["hop:0 finding low header_absent"]
    assert lines(c, "WG-CK-001") == ["- not_applicable - no_cookies_observed"]


def test_i03_multiple_set_cookie(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, "/cookies")
    assert len(results(c, "WG-CK-001")) == 7
    assert "cookie:a@hop:0 pass - secure_present" in lines(c, "WG-CK-001")
    assert "cookie:b@hop:0 finding medium secure_absent" in lines(c, "WG-CK-001")
    assert "cookie:e@hop:0 finding medium none_without_secure" in lines(c, "WG-CK-003")
    assert "cookie:f@hop:0 pass - none_with_secure" in lines(c, "WG-CK-003")
    assert "cookie:g@hop:0 finding low invalid_value" in lines(c, "WG-CK-003")
    assert "cookie:__Host-c@hop:0 pass - prefix_requirements_met" in lines(c, "WG-CK-004")
    assert "cookie:__Secure-d@hop:0 finding medium prefix_requirements_unmet" in lines(
        c, "WG-CK-004"
    )


def test_i04_apex_redirect_not_followed(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, "/redirect?to=/")
    rep = report_of(c)
    assert len(rep.hops) == 1
    assert ScanNote.REDIRECT_NOT_FOLLOWED in rep.scan.notes
    assert lines(c, "WG-HDR-002") == ["hop:0 not_applicable - redirect_response"]
    assert lines(c, "WG-HDR-003") == ["hop:0 not_applicable - redirect_response"]
    assert lines(c, "WG-HDR-001") == ["hop:0 pass - present"]
    assert lines(c, "WG-RDR-001") == ["hop:0 pass - https_redirect"]
    assert server.log.connections == 1


def test_i05_apex_redirect_followed(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    resolver = StubResolver([LOOP4])
    c = run(egress_cfg, "/redirect?to=/", follow=True, resolver=resolver)
    rep = report_of(c)
    assert c.status is ScanStatus.COMPLETED
    assert [h.http.status_code for h in rep.hops if h.http] == [301, 200]
    assert lines(c, "WG-HDR-002") == ["hop:1 pass - present"]
    assert lines(c, "WG-HDR-001") == ["hop:0 pass - present", "hop:1 pass - present"]
    assert len(resolver.calls) == 2  # fresh resolution per hop
    assert server.log.connections == 2


def test_i06_redirect_loop_detected(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, "/loop/a", follow=True)
    rep = report_of(c)
    assert len(rep.hops) == 2
    assert ScanNote.REDIRECT_LOOP in rep.scan.notes
    assert server.log.connections == 2


def test_i06_redirect_limit(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, "/chain/6", follow=True)
    rep = report_of(c)
    assert len(rep.hops) == 4  # 1 + 3 redirects, never more (D-11)
    assert ScanNote.REDIRECT_LIMIT_REACHED in rep.scan.notes
    assert server.log.connections == 4
    assert [r.request_line for r in server.log.received] == [
        b"GET /chain/6 HTTP/1.1",
        b"GET /chain/5 HTTP/1.1",
        b"GET /chain/4 HTTP/1.1",
        b"GET /chain/3 HTTP/1.1",
    ]


@pytest.mark.parametrize(
    ("sni", "reason"),
    [
        (certs.EXPIRED, "expired"),
        (certs.NOT_YET_VALID, "not_yet_valid"),
        (certs.WRONG_HOST, "hostname_mismatch"),
        (certs.UNTRUSTED, "untrusted_chain"),
    ],
)
def test_i07_certificate_failures(
    egress_cfg: EgressConfig, server: FixtureServer, sni: str, reason: str
) -> None:
    c = run(egress_cfg, host=sni)
    assert c.status is ScanStatus.COMPLETED
    assert lines(c, "WG-TLS-001") == [f"hop:0 finding high {reason}"]
    for rule in ("WG-TLS-002", "WG-HDR-001", "WG-HDR-002", "WG-HDR-003", "WG-CK-001", "WG-RDR-001"):
        assert [r.reason_code for r in results(c, rule)] == ["blocked_by:WG-TLS-001"], rule
    assert server.log.received == []


@pytest.mark.parametrize(
    ("sni", "expected"),
    [
        (certs.EXPIRES_10D, "hop:0 finding medium expires_within_14_days"),
        (certs.EXPIRES_25D, "hop:0 finding low expires_within_30_days"),
        ("webguard.test", "hop:0 pass - expiry_beyond_30_days"),
    ],
)
def test_i07_expiry_horizon(
    egress_cfg: EgressConfig, server: FixtureServer, sni: str, expected: str
) -> None:
    assert lines(run(egress_cfg, host=sni), "WG-TLS-002") == [expected]


@pytest.mark.slow
def test_i08_stall_never_passes(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    started = time.monotonic()
    c = run(egress_cfg, "/stall", deadline=5)
    assert time.monotonic() - started <= 6
    assert c.status is ScanStatus.FAILED
    rep = report_of(c)
    assert [r for r in rep.results if r.status is Status.PASS and r.rule_id != "WG-TLS-001"] == []
    assert {r.rule_id for r in rep.results} == set(engine.RULES)


def test_failed_scan_dns(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, resolver=StubResolver([]))
    assert c.status is ScanStatus.FAILED
    assert lines(c, "WG-TLS-001") == ["hop:0 error - tls_not_reached"]
    assert server.log.connections == 0


# --- S-06 / S-07 / S-18 ----------------------------------------------------------------------


def test_s06_redirect_to_prohibited_host_blocked(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    resolver = StubResolver([LOOP4], ["10.0.0.1"])
    c = run(
        egress_cfg,
        f"/redirect?to=https://b.webguard.test:{FIXTURE_PORT}/",
        follow=True,
        resolver=resolver,
    )
    rep = report_of(c)
    assert c.rejection is None  # exit code is not changed to 3 at hop >= 1
    assert c.status is ScanStatus.COMPLETED
    assert ScanNote.REDIRECT_BLOCKED_BY_POLICY in rep.scan.notes
    assert len(rep.hops) == 1
    assert server.log.connections == 1


def test_s07_downgrade_never_fetched(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    c = run(egress_cfg, "/downgrade", follow=True)
    rep = report_of(c)
    assert lines(c, "WG-RDR-001") == ["hop:0 finding medium https_to_http_redirect"]
    assert ScanNote.REDIRECT_REJECTED_SCHEME_NOT_HTTPS in rep.scan.notes
    assert len(rep.hops) == 1
    assert server.log.connections == 1


@pytest.mark.slow
def test_s18_deadline_mid_redirect_is_partial(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    started = time.monotonic()
    c = run(egress_cfg, "/redirect?to=/slowdrip", follow=True, deadline=5)
    assert time.monotonic() - started <= 6
    rep = report_of(c)
    assert c.status is ScanStatus.PARTIAL
    assert ScanNote.DEADLINE_REACHED in rep.scan.notes
    assert len(rep.hops) == 2
    assert server.log.connections == 2
    assert [r.reason_code for r in results(c, "WG-HDR-002")] == ["redirect_response"]
    assert lines(c, "WG-HDR-001")[1] == "hop:1 inconclusive - scan_deadline"


# --- rejections (no report) ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "code", "usage"),
    [
        ("http://webguard.test/", "scheme_not_https", False),
        ("https://exa mple.test/", "url_illegal_chars", True),
        ("https://webguard.test:22/", "port_not_permitted", False),
        ("https://127.1/", "ipv4_ambiguous", False),
    ],
)
def test_s01_rejected_url_no_dns_no_connection(
    egress_cfg: EgressConfig, server: FixtureServer, url: str, code: str, usage: bool
) -> None:
    resolver = StubResolver([LOOP4])
    c = run(egress_cfg, url=url, resolver=resolver)
    assert c.rejection is not None
    assert (c.rejection.code, c.rejection.usage_error) == (code, usage)
    assert c.report is None
    assert resolver.calls == []
    assert server.log.connections == 0


def test_s02_public_policy_rejects_loopback_literal(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    resolver = StubResolver([LOOP4])
    c = run(egress_cfg, host=LOOP4, policy=PublicScopePolicy(), resolver=resolver)
    assert c.rejection is not None
    assert c.rejection.detail == "loopback:127.0.0.1"
    assert resolver.calls == []
    assert server.log.connections == 0


def test_f05_public_policy_rejects_private_answer_at_hop0(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    c = run(egress_cfg, policy=PublicScopePolicy(), resolver=StubResolver([LOOP4]))
    assert c.rejection is not None
    assert c.rejection.code == "policy_prohibited_address"
    assert c.report is None
    assert server.log.connections == 0


# --- interrupts (I-09 at collect level; the signal-driven variant runs end to end in P7) -----


class InterruptOnSecondHop(TestScopePolicy):
    def __init__(self) -> None:
        self.calls = 0

    def check_resolved(self, ips: object) -> object:  # type: ignore[override]  # reason: test double
        self.calls += 1
        if self.calls >= 2:
            raise KeyboardInterrupt
        return super().check_resolved(ips)  # type: ignore[arg-type]  # reason: passthrough


def test_i09_interrupt_during_fetch_keeps_evidence(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    c = run(egress_cfg, "/redirect?to=/", follow=True, policy=InterruptOnSecondHop())  # type: ignore[arg-type]  # reason: test double
    rep = report_of(c)
    assert c.status is ScanStatus.INTERRUPTED
    assert c.interrupted
    assert len(rep.hops) == 1
    assert ScanNote.INTERRUPTED in rep.scan.notes
    assert lines(c, "WG-HDR-001") == ["hop:0 pass - present"]


def test_i09_interrupt_before_any_hop(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    class Immediate(TestScopePolicy):
        def check_resolved(self, ips: object) -> object:  # type: ignore[override]  # reason: test double
            raise KeyboardInterrupt

    c = run(egress_cfg, policy=Immediate())  # type: ignore[arg-type]  # reason: test double
    rep = report_of(c)
    assert c.status is ScanStatus.INTERRUPTED
    assert rep.hops == []
    assert {r.reason_code for r in rep.results} == {"scan_interrupted"}
    assert {r.rule_id for r in rep.results} == set(engine.RULES)


def test_interrupt_during_evaluation(
    egress_cfg: EgressConfig, server: FixtureServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(*_: object) -> list[RuleResult]:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        engine, "RULES", MappingProxyType({**engine.RULES, "WG-HDR-001": interrupt})
    )
    c = run(egress_cfg)
    rep = report_of(c)
    assert c.status is ScanStatus.INTERRUPTED
    done = {r.rule_id for r in rep.results if r.reason_code != "scan_interrupted"}
    assert done == {"WG-CK-001", "WG-CK-002", "WG-CK-003", "WG-CK-004"}
    assert {r.rule_id for r in rep.results} == set(engine.RULES)


def test_rule_exception_flags_internal_error(
    egress_cfg: EgressConfig, server: FixtureServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> list[RuleResult]:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "RULES", MappingProxyType({**engine.RULES, "WG-RDR-001": boom}))
    c = run(egress_cfg)
    assert c.internal_error
    assert c.status is ScanStatus.COMPLETED
    assert lines(c, "WG-RDR-001") == ["- error - internal_rule_error"]


def test_state_machine_rejects_illegal_transitions() -> None:
    m = ScanStateMachine(fail_on=FailOn.HIGH)
    with pytest.raises(IllegalTransitionError):
        m.to(Phase.FETCHING)
    m.to(Phase.VALIDATING)
    m.to(Phase.FETCHING)
    with pytest.raises(IllegalTransitionError):
        m.to(Phase.WRITING)
