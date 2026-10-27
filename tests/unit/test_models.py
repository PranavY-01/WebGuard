"""U-35 and model invariants: result co-occurrence, evidence consistency, summary arithmetic."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address

import pytest
from pydantic import ValidationError

from webguard.domain.enums import (
    Category,
    Confidence,
    FailOn,
    FailureCode,
    ScanStatus,
    Severity,
    Status,
)
from webguard.domain.evidence import (
    CookieEvidence,
    HopEvidence,
    HopFailure,
    HttpEvidence,
    LocationEvidence,
    ScanEvidence,
    TlsEvidence,
)
from webguard.domain.report import (
    REPORT_LIMITATIONS,
    ConfigInfo,
    Report,
    ScanInfo,
    Summary,
    TargetInfo,
    ToolInfo,
)
from webguard.domain.results import RuleResult

T0 = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
IP = ip_address("127.0.0.1")


def result(
    status: Status, sev: Severity | None = None, conf: Confidence | None = None, **kw: object
) -> RuleResult:
    base: dict[str, object] = {
        "rule_id": "WG-HDR-001",
        "rule_version": 1,
        "title": "HSTS",
        "category": Category.HEADERS,
        "status": status,
        "severity": sev,
        "confidence": conf,
        "reason_code": "header_absent",
        "message": "m",
        "remediation": "r",
    }
    base.update(kw)
    return RuleResult.model_validate(base)


def http(**kw: object) -> HttpEvidence:
    base: dict[str, object] = {
        "status_code": 200,
        "http_version": "HTTP/1.1",
        "headers": {},
        "headers_total": 0,
        "cookies": [],
        "cookies_dropped": 0,
    }
    base.update(kw)
    return HttpEvidence.model_validate(base)


def hop(index: int = 0, **kw: object) -> HopEvidence:
    base: dict[str, object] = {
        "index": index,
        "url_redacted": "https://a.test/",
        "host": "a.test",
        "port": 443,
        "resolved_ips": [IP],
        "connected_ip": IP,
        "tls": TlsEvidence(verified=True),
        "http": http(),
    }
    base.update(kw)
    return HopEvidence.model_validate(base)


# --- RuleResult co-occurrence -------------------------------------------------------------


def test_result_valid_combinations() -> None:
    result(Status.PASS, conf=Confidence.HIGH)
    result(Status.FINDING, Severity.LOW, Confidence.HIGH)
    for s in (Status.INCONCLUSIVE, Status.ERROR, Status.NOT_APPLICABLE):
        result(s)


@pytest.mark.parametrize(
    ("status", "sev", "conf"),
    [
        (Status.FINDING, None, Confidence.HIGH),
        (Status.FINDING, Severity.LOW, None),
        (Status.PASS, Severity.LOW, Confidence.HIGH),
        (Status.PASS, None, None),
        (Status.INCONCLUSIVE, None, Confidence.HIGH),
        (Status.ERROR, Severity.HIGH, None),
    ],
)
def test_result_invalid_combinations(
    status: Status, sev: Severity | None, conf: Confidence | None
) -> None:
    with pytest.raises(ValidationError):
        result(status, sev, conf)


@pytest.mark.parametrize("subject", ["hop:0", "cookie:sid@hop:3", None])
def test_result_subject_ok(subject: str | None) -> None:
    result(Status.ERROR, subject=subject)


@pytest.mark.parametrize("subject", ["hop:4", "x", "cookie:@hop:0", "cookie:a\x1b@hop:0"])
def test_result_subject_bad(subject: str) -> None:
    with pytest.raises(ValidationError):
        result(Status.ERROR, subject=subject)


def test_result_rule_id_pattern() -> None:
    with pytest.raises(ValidationError):
        result(Status.ERROR, rule_id="WG-01")


def test_s19_raw_control_chars_rejected_in_evidence_models() -> None:
    with pytest.raises(ValidationError):
        CookieEvidence(name="sid\x1b[2J", attributes_raw="")
    with pytest.raises(ValidationError):
        http(headers={"content-type": ["text/a" + chr(0x202E) + "b"]})
    with pytest.raises(ValidationError):
        result(Status.ERROR, message="x\r\ny")


# --- Evidence consistency ------------------------------------------------------------------


@pytest.mark.parametrize("name", ["server", "set-cookie", "location", "Content-Type"])
def test_http_header_allowlist_enforced(name: str) -> None:
    with pytest.raises(ValidationError):
        http(headers={name: ["v"]})


def test_s09_model_http_requires_verified_tls() -> None:
    with pytest.raises(ValidationError):
        hop(tls=TlsEvidence(verified=False, verify_code=10, verify_message="expired"))
    with pytest.raises(ValidationError):
        hop(tls=None)


def test_hop_outcome_exactly_one() -> None:
    hop(http=None, failure=HopFailure(code=FailureCode.READ_TIMEOUT))
    hop(http=None, tls=TlsEvidence(verified=False, verify_code=62, verify_message="mismatch"))
    with pytest.raises(ValidationError):
        hop(http=None)
    with pytest.raises(ValidationError):
        hop(failure=HopFailure(code=FailureCode.READ_TIMEOUT))


def test_hop_failure_cannot_carry_tls_verification() -> None:
    with pytest.raises(ValidationError):
        HopFailure(code=FailureCode.TLS_VERIFICATION_FAILED)


def test_connected_ip_must_be_resolved() -> None:
    with pytest.raises(ValidationError):
        hop(connected_ip=ip_address("8.8.8.8"))


def test_unverified_tls_cannot_carry_cert() -> None:
    with pytest.raises(ValidationError):
        TlsEvidence(verified=False, protocol_version="TLSv1.3")


def test_location_unparseable_has_length_only() -> None:
    LocationEvidence(unparseable=True, raw_length=9)
    with pytest.raises(ValidationError):
        LocationEvidence(unparseable=True, raw_length=9, scheme="http")


def test_scan_evidence_terminal_index() -> None:
    h0 = hop(0, http=http(status_code=301))
    h1 = hop(1, http=None, failure=HopFailure(code=FailureCode.CONNECT_FAILED))
    ev = ScanEvidence(hops=[h0, h1], terminal_index=0)
    assert ev.terminal is h0
    with pytest.raises(ValidationError):
        ScanEvidence(hops=[h0, h1], terminal_index=1)
    with pytest.raises(ValidationError):
        ScanEvidence(hops=[h1], terminal_index=None)  # index must start at 0
    with pytest.raises(ValidationError):
        ScanEvidence(hops=[], terminal_index=None)


def test_models_are_frozen() -> None:
    h = hop()
    with pytest.raises(ValidationError):
        h.port = 8443  # type: ignore[misc]  # reason: proves immutability


# --- U-35 summary arithmetic and report invariants -----------------------------------------


def _results() -> list[RuleResult]:
    return [
        result(Status.PASS, conf=Confidence.HIGH, rule_id="WG-CK-001"),
        result(Status.FINDING, Severity.MEDIUM, Confidence.HIGH, rule_id="WG-HDR-001"),
        result(Status.FINDING, Severity.LOW, Confidence.HIGH, rule_id="WG-HDR-002"),
        result(Status.INCONCLUSIVE, rule_id="WG-TLS-002"),
        result(Status.NOT_APPLICABLE, rule_id="WG-RDR-001"),
    ]


def test_u35_summary_of() -> None:
    s = Summary.of(_results())
    assert (s.checks_total, s.pass_, s.finding, s.inconclusive, s.error, s.not_applicable) == (
        5,
        1,
        2,
        1,
        0,
        1,
    )
    assert s.findings_by_severity.medium == 1
    assert s.findings_by_severity.low == 1
    assert json.loads(s.model_dump_json())["pass"] == 1


def test_u35_summary_rejects_bad_arithmetic() -> None:
    good = Summary.of(_results()).model_dump(by_alias=True)
    with pytest.raises(ValidationError):
        Summary.model_validate({**good, "checks_total": 6})
    with pytest.raises(ValidationError):
        Summary.model_validate({**good, "findings_by_severity": {"high": 3}})


def _report(results: list[RuleResult], summary: Summary | None = None, **scan_kw: object) -> Report:
    scan: dict[str, object] = {
        "scan_id": "0" * 32,
        "started_at": T0,
        "finished_at": T0 + timedelta(seconds=2),
        "status": ScanStatus.COMPLETED,
        "target": TargetInfo(display_url_redacted="https://a.test/", host="a.test", port=443),
        "config": ConfigInfo(follow_redirects=False, deadline_s=30, fail_on=FailOn.HIGH),
    }
    scan.update(scan_kw)
    return Report(
        tool=ToolInfo(version="1.0.0"),
        scan=ScanInfo.model_validate(scan),
        hops=[hop()],
        results=results,
        summary=summary or Summary.of(results),
    )


def test_u35_report_valid_and_serializes_utc_z() -> None:
    rep = _report(sorted(_results(), key=lambda r: r.sort_key))
    data = json.loads(rep.model_dump_json())
    assert data["schema_version"] == "1.0"
    assert data["scan"]["started_at"] == "2026-10-27T12:00:00Z"
    assert data["summary"]["pass"] == 1
    assert data["limitations"][0] == REPORT_LIMITATIONS[0]
    assert data["hops"][0]["resolved_ips"] == ["127.0.0.1"]


def test_u35_report_rejects_unsorted_or_mismatched() -> None:
    rs = _results()
    with pytest.raises(ValidationError):
        _report(list(reversed(sorted(rs, key=lambda r: r.sort_key))))
    ordered = sorted(rs, key=lambda r: r.sort_key)
    with pytest.raises(ValidationError):
        _report(ordered, summary=Summary.of(ordered[:-1]))


def test_report_rejects_non_utc() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    with pytest.raises(ValidationError):
        _report([], started_at=T0.astimezone(ist), finished_at=T0.astimezone(ist))
    with pytest.raises(ValidationError):
        _report([], finished_at=T0 - timedelta(seconds=1))
