"""Evidence captured at the egress boundary (Plan §13.2). Target-derived strings are SafeText."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from webguard.domain.budget import (
    MAX_COOKIES_PER_HOP,
    MAX_DNS_ANSWERS,
    MAX_HEADERS,
    MAX_REQUESTS_PER_SCAN,
    MAX_SAN_ENTRIES,
)
from webguard.domain.enums import FailureCode
from webguard.domain.safe_text import SafeText

IPAddress = IPv4Address | IPv6Address

CAPTURED_HEADERS: frozenset[str] = frozenset(
    {
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-type-options",
        "set-cookie",
        "location",
        "content-type",
    }
)

REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})


def require_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return value.astimezone(UTC)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CertFacts(_Frozen):
    subject_cn: SafeText | None
    san_dns: list[SafeText] = Field(max_length=MAX_SAN_ENTRIES)
    issuer_cn: SafeText | None
    issuer_o: SafeText | None
    not_before: AwareDatetime
    not_after: AwareDatetime

    _utc = field_validator("not_before", "not_after")(require_utc)


class TlsEvidence(_Frozen):
    verified: bool
    verify_code: int | None = None
    verify_message: SafeText | None = None
    protocol_version: Literal["TLSv1.2", "TLSv1.3"] | None = None
    cert: CertFacts | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.verified and (self.verify_code is not None or self.verify_message is not None):
            raise ValueError("verified TLS cannot carry a verification error")
        if not self.verified and (self.cert is not None or self.protocol_version is not None):
            raise ValueError("unverified TLS must not record certificate facts")
        return self


class CookieEvidence(_Frozen):
    """Cookie name and attribute segment only. The value is discarded at capture (INV-10)."""

    name: SafeText
    attributes_raw: SafeText


class LocationEvidence(_Frozen):
    scheme: SafeText | None = None
    host: SafeText | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    path_query_redacted: SafeText | None = None
    unparseable: bool = False
    raw_length: int = Field(ge=0)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.unparseable and any(
            v is not None for v in (self.scheme, self.host, self.port, self.path_query_redacted)
        ):
            raise ValueError("unparseable Location records its length only")
        return self


class HttpEvidence(_Frozen):
    status_code: int = Field(ge=100, le=599)
    http_version: Literal["HTTP/1.0", "HTTP/1.1"]
    headers: dict[str, list[SafeText]]
    headers_total: int = Field(ge=0, le=MAX_HEADERS)
    cookies: list[CookieEvidence] = Field(max_length=MAX_COOKIES_PER_HOP)
    cookies_dropped: int = Field(ge=0)
    location: LocationEvidence | None = None

    @field_validator("headers")
    @classmethod
    def _allowlisted(cls, value: dict[str, list[SafeText]]) -> dict[str, list[SafeText]]:
        unexpected = set(value) - CAPTURED_HEADERS
        if unexpected:
            raise ValueError("header outside the capture allowlist")
        return value

    @property
    def is_redirect(self) -> bool:
        return self.status_code in REDIRECT_STATUSES

    def first(self, name: str) -> str | None:
        values = self.headers.get(name)
        return values[0] if values else None


class HopFailure(_Frozen):
    code: FailureCode
    detail: SafeText | None = None

    @field_validator("code")
    @classmethod
    def _not_evidence(cls, value: FailureCode) -> FailureCode:
        if value is FailureCode.TLS_VERIFICATION_FAILED:
            raise ValueError("TLS verification failure is evidence (TlsEvidence), not HopFailure")
        return value


class HopEvidence(_Frozen):
    index: int = Field(ge=0, le=MAX_REQUESTS_PER_SCAN - 1)
    url_redacted: SafeText
    host: SafeText
    port: int = Field(ge=1, le=65535)
    resolved_ips: list[IPAddress] = Field(max_length=MAX_DNS_ANSWERS)
    connected_ip: IPAddress | None = None
    tls: TlsEvidence | None = None
    http: HttpEvidence | None = None
    failure: HopFailure | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        tls_verify_failed = self.tls is not None and not self.tls.verified
        if self.http is not None and (self.tls is None or not self.tls.verified):
            raise ValueError("HTTP evidence requires a verified TLS session (S-09)")
        outcomes = [self.http is not None, self.failure is not None, tls_verify_failed]
        if sum(outcomes) != 1:
            raise ValueError("a hop ends in exactly one of: http, failure, tls verify failure")
        if self.connected_ip is not None and self.connected_ip not in self.resolved_ips:
            raise ValueError("connected_ip must come from the hop's resolved set (INV-02)")
        return self

    @property
    def tls_verify_failed(self) -> bool:
        return self.tls is not None and not self.tls.verified


class ScanEvidence(_Frozen):
    hops: list[HopEvidence] = Field(min_length=1, max_length=MAX_REQUESTS_PER_SCAN)
    terminal_index: int | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if [h.index for h in self.hops] != list(range(len(self.hops))):
            raise ValueError("hop indexes must be 0..n-1 in order")
        with_http = [h.index for h in self.hops if h.http is not None]
        expected = with_http[-1] if with_http else None
        if self.terminal_index != expected:
            raise ValueError("terminal_index must be the last hop with HTTP evidence")
        return self

    @property
    def terminal(self) -> HopEvidence | None:
        return None if self.terminal_index is None else self.hops[self.terminal_index]
