"""Capture and sanitization at boundary B4 (Plan §9.7).

This module is the only caller of `from_untrusted` on target data. Raw header bytes, cookie
values and Location query values never leave it: cookie values are dropped at the split,
Location is stored redacted and the next hop is handed on as a validated CanonicalTarget.
"""

from __future__ import annotations

import ssl
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

from webguard.domain.budget import (
    MAX_COOKIE_NAME_CHARS,
    MAX_COOKIES_PER_HOP,
    MAX_DETAIL_CHARS,
    MAX_HEADER_VALUE_CHARS,
    MAX_HEADERS,
    MAX_SAN_ENTRIES,
)
from webguard.domain.evidence import (
    REDIRECT_STATUSES,
    STORED_HEADERS,
    CertFacts,
    CookieEvidence,
    HttpEvidence,
    LocationEvidence,
    TlsEvidence,
)
from webguard.domain.safe_text import from_untrusted
from webguard.egress.errors import MalformedResponseError
from webguard.policy.url import (
    CanonicalTarget,
    UrlRejection,
    canonicalize_host,
    redact_query,
    resolve_redirect,
)

_HTTP_VERSIONS = {b"HTTP/1.0": "HTTP/1.0", b"HTTP/1.1": "HTTP/1.1"}
_TLS_VERSIONS: dict[str, Literal["TLSv1.2", "TLSv1.3"]] = {
    "TLSv1.2": "TLSv1.2",
    "TLSv1.3": "TLSv1.3",
}
_MAX_SCHEME_CHARS = 32
_MAX_HOST_CHARS = 253


def _text(raw: str | bytes, max_len: int = MAX_HEADER_VALUE_CHARS) -> str:
    return from_untrusted(raw, max_len)


def capture_cookie(raw: bytes) -> CookieEvidence:
    """Keep only the cookie *name* and the attribute segment; the value is never retained.

    Per RFC 6265bis, a name-value pair without '=' has an empty name (the text is the value).
    """
    text = raw.decode("iso-8859-1")
    pair, _sep, attributes = text.partition(";")
    name = pair.split("=", 1)[0].strip() if "=" in pair else ""
    return CookieEvidence(
        name=_text(name, MAX_COOKIE_NAME_CHARS),
        attributes_raw=_text(attributes.strip()),
    )


def capture_location(
    raw: bytes, base: CanonicalTarget
) -> tuple[LocationEvidence, CanonicalTarget | UrlRejection]:
    """Return redacted Location evidence and the validated next-hop target (or rejection)."""
    text = raw.decode("iso-8859-1").strip()
    next_target = resolve_redirect(text, base)
    try:
        parts = urlsplit(urljoin(base.url, text))
        port = parts.port
    except ValueError:
        return LocationEvidence(unparseable=True, raw_length=len(text)), next_target
    host_text = parts.hostname or ""
    canonical = canonicalize_host(host_text, ":" in host_text) if host_text else None
    host = canonical[0] if isinstance(canonical, tuple) else host_text
    path_query = (parts.path or "/") + (f"?{redact_query(parts.query)}" if parts.query else "")
    evidence = LocationEvidence(
        scheme=_text(parts.scheme, _MAX_SCHEME_CHARS) if parts.scheme else None,
        host=_text(host, _MAX_HOST_CHARS) if host else None,
        port=port,
        path_query_redacted=_text(path_query),
        unparseable=False,
        raw_length=len(text),
    )
    return evidence, next_target


def capture_http(
    status: int,
    http_version: bytes,
    headers: Sequence[tuple[bytes, bytes]],
    base: CanonicalTarget,
) -> tuple[HttpEvidence, CanonicalTarget | UrlRejection | None]:
    if not 100 <= status <= 599:
        raise MalformedResponseError("status_out_of_range")
    version = _HTTP_VERSIONS.get(http_version)
    if version is None:
        raise MalformedResponseError("http_version")
    if len(headers) > MAX_HEADERS:
        raise MalformedResponseError("headers_excess")

    stored: dict[str, list[str]] = {}
    cookies: list[CookieEvidence] = []
    cookies_dropped = 0
    locations: list[bytes] = []
    for raw_name, raw_value in headers:
        name = raw_name.decode("ascii", "replace").lower()
        if name == "set-cookie":
            if len(cookies) < MAX_COOKIES_PER_HOP:
                cookies.append(capture_cookie(raw_value))
            else:
                cookies_dropped += 1
        elif name == "location":
            locations.append(raw_value)
        elif name in STORED_HEADERS:
            stored.setdefault(name, []).append(_text(raw_value))

    location: LocationEvidence | None = None
    next_target: CanonicalTarget | UrlRejection | None = None
    if len(set(locations)) > 1:
        # Conflicting Location headers: browsers refuse them; record length only.
        location = LocationEvidence(unparseable=True, raw_length=len(locations[0]))
    elif locations:
        location, resolved = capture_location(locations[0], base)
        if status in REDIRECT_STATUSES:
            next_target = resolved

    evidence = HttpEvidence(
        status_code=status,
        http_version=version,
        headers=stored,
        headers_total=len(headers),
        cookies=cookies,
        cookies_dropped=cookies_dropped,
        location=location,
    )
    return evidence, next_target


def _name_field(rdns: Any, key: str) -> str | None:
    for rdn in rdns or ():
        for attr in rdn:
            if isinstance(attr, tuple) and len(attr) == 2 and attr[0] == key:
                return str(attr[1])
    return None


def _cert_time(value: Any) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(str(value)), tz=UTC)


def capture_tls(tls_sock: ssl.SSLSocket) -> TlsEvidence:
    """TLS facts from the hop's own verified socket (D-14). No second connection exists."""
    protocol = _TLS_VERSIONS.get(tls_sock.version() or "")
    cert = tls_sock.getpeercert()
    facts: CertFacts | None = None
    if cert:
        sans = [
            str(p[1])
            for p in cert.get("subjectAltName", ())
            if isinstance(p, tuple) and len(p) == 2 and p[0] == "DNS"
        ][:MAX_SAN_ENTRIES]
        subject_cn = _name_field(cert.get("subject"), "commonName")
        issuer_cn = _name_field(cert.get("issuer"), "commonName")
        issuer_o = _name_field(cert.get("issuer"), "organizationName")
        facts = CertFacts(
            subject_cn=_text(subject_cn, MAX_DETAIL_CHARS) if subject_cn else None,
            san_dns=[_text(s, MAX_DETAIL_CHARS) for s in sans],
            issuer_cn=_text(issuer_cn, MAX_DETAIL_CHARS) if issuer_cn else None,
            issuer_o=_text(issuer_o, MAX_DETAIL_CHARS) if issuer_o else None,
            not_before=_cert_time(cert["notBefore"]),
            not_after=_cert_time(cert["notAfter"]),
        )
    return TlsEvidence(verified=True, protocol_version=protocol, cert=facts)


def capture_tls_failure(verify_code: int | None, verify_message: str | None) -> TlsEvidence:
    return TlsEvidence(
        verified=False,
        verify_code=verify_code,
        verify_message=_text(verify_message or "certificate verification failed", MAX_DETAIL_CHARS),
    )


def safe_detail(detail: str | None) -> str | None:
    """Static failure details pass through the same SafeText conversion as target data."""
    return None if detail is None else _text(detail, MAX_DETAIL_CHARS)
