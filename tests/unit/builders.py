"""Evidence builders for pure rule tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from webguard.domain.enums import FailureCode
from webguard.domain.evidence import (
    CertFacts,
    CookieEvidence,
    HopEvidence,
    HopFailure,
    HttpEvidence,
    LocationEvidence,
    ScanEvidence,
    TlsEvidence,
)

STARTED = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
IP = ip_address("127.0.0.1")


def tls_ok(days: float = 365.0) -> TlsEvidence:
    cert = CertFacts(
        subject_cn="webguard.test",
        san_dns=["webguard.test"],
        issuer_cn="Test CA",
        issuer_o="Test",
        not_before=STARTED - timedelta(days=30),
        not_after=STARTED + timedelta(days=days),
    )
    return TlsEvidence(verified=True, protocol_version="TLSv1.3", cert=cert)


def _base(index: int) -> dict[str, object]:
    return {
        "index": index,
        "url_redacted": "https://webguard.test/",
        "host": "webguard.test",
        "port": 443,
        "resolved_ips": [IP],
    }


def http_hop(
    index: int = 0,
    status: int = 200,
    headers: dict[str, list[str]] | None = None,
    cookies: list[tuple[str, str]] | None = None,
    location: LocationEvidence | None = None,
    days: float = 365.0,
) -> HopEvidence:
    http = HttpEvidence(
        status_code=status,
        http_version="HTTP/1.1",
        headers=headers or {},
        headers_total=len(headers or {}),
        cookies=[CookieEvidence(name=n, attributes_raw=a) for n, a in cookies or []],
        cookies_dropped=0,
        location=location,
    )
    return HopEvidence.model_validate(
        {**_base(index), "connected_ip": IP, "tls": tls_ok(days), "http": http}
    )


def tls_failed_hop(index: int = 0, code: int | None = 10) -> HopEvidence:
    tls = TlsEvidence(verified=False, verify_code=code, verify_message="certificate has expired")
    return HopEvidence.model_validate({**_base(index), "connected_ip": IP, "tls": tls})


def failed_hop(
    index: int = 0, code: FailureCode = FailureCode.DNS_NO_ANSWER, tls_reached: bool = False
) -> HopEvidence:
    extra: dict[str, object] = {"connected_ip": IP, "tls": tls_ok()} if tls_reached else {}
    return HopEvidence.model_validate({**_base(index), **extra, "failure": HopFailure(code=code)})


def scan(*hops: HopEvidence) -> ScanEvidence:
    with_http = [h.index for h in hops if h.http is not None]
    return ScanEvidence(hops=list(hops), terminal_index=with_http[-1] if with_http else None)


def loc(scheme: str = "https", host: str = "webguard.test") -> LocationEvidence:
    return LocationEvidence(
        scheme=scheme, host=host, port=None, path_query_redacted="/", raw_length=20
    )


def sts(value: str | list[str]) -> dict[str, list[str]]:
    return {"strict-transport-security": value if isinstance(value, list) else [value]}
