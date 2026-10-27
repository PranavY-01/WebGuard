"""Known-answer cases for every rule (Plan §24.5). Each expectation line is
"<subject> <status> <severity|-> <confidence|-> <reason>"; subject "-" means null.

tests/fixtures/known_answers.md is rendered from this table by `python -m tests.unit.render_docs`.
"""

from __future__ import annotations

from dataclasses import dataclass

from tests.unit.builders import failed_hop, http_hop, loc, scan, sts, tls_failed_hop
from webguard.domain.enums import FailureCode
from webguard.domain.evidence import LocationEvidence, ScanEvidence

F = FailureCode
OK = {
    "strict-transport-security": ["max-age=31536000"],
    "content-security-policy": ["default-src 'self'"],
    "x-content-type-options": ["nosniff"],
}
GOOD_COOKIE = ("sid", "Secure; HttpOnly; SameSite=Lax; Path=/")


@dataclass(frozen=True)
class Case:
    name: str
    rule_id: str
    evidence: ScanEvidence
    expected: tuple[str, ...]
    context_reason: str = "hop_failed"


CASES: list[Case] = [
    # --- WG-TLS-001 ---------------------------------------------------------------------------
    Case("verified", "WG-TLS-001", scan(http_hop()), ("hop:0 pass - high verified",)),
    Case(
        "expired (10)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=10)),
        ("hop:0 finding high high expired",),
    ),
    Case(
        "not yet valid (9)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=9)),
        ("hop:0 finding high high not_yet_valid",),
    ),
    Case(
        "unknown CA (20)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=20)),
        ("hop:0 finding high high untrusted_chain",),
    ),
    Case(
        "self-signed in chain (19)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=19)),
        ("hop:0 finding high high untrusted_chain",),
    ),
    Case(
        "self-signed leaf (18)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=18)),
        ("hop:0 finding high high untrusted_chain",),
    ),
    Case(
        "hostname mismatch (62)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=62)),
        ("hop:0 finding high high hostname_mismatch",),
    ),
    Case(
        "other verify code (7)",
        "WG-TLS-001",
        scan(tls_failed_hop(code=7)),
        ("hop:0 finding high medium verification_failed_other",),
    ),
    Case(
        "verify code missing",
        "WG-TLS-001",
        scan(tls_failed_hop(code=None)),
        ("hop:0 finding high medium verification_failed_other",),
    ),
    Case(
        "handshake failure",
        "WG-TLS-001",
        scan(failed_hop(code=F.TLS_HANDSHAKE_FAILED)),
        ("hop:0 error - - handshake_failed",),
    ),
    Case("dns failure", "WG-TLS-001", scan(failed_hop()), ("hop:0 error - - tls_not_reached",)),
    Case(
        "read timeout after TLS",
        "WG-TLS-001",
        scan(failed_hop(code=F.READ_TIMEOUT, tls_reached=True)),
        ("hop:0 pass - high verified",),
    ),
    Case(
        "two hops",
        "WG-TLS-001",
        scan(http_hop(0, 301, location=loc()), http_hop(1)),
        ("hop:0 pass - high verified", "hop:1 pass - high verified"),
    ),
    # --- WG-TLS-002 ---------------------------------------------------------------------------
    Case(
        "365 days",
        "WG-TLS-002",
        scan(http_hop(days=365)),
        ("hop:0 pass - high expiry_beyond_30_days",),
    ),
    Case(
        "30.5 days",
        "WG-TLS-002",
        scan(http_hop(days=30.5)),
        ("hop:0 pass - high expiry_beyond_30_days",),
    ),
    Case(
        "30 days",
        "WG-TLS-002",
        scan(http_hop(days=30)),
        ("hop:0 finding low high expires_within_30_days",),
    ),
    Case(
        "25 days",
        "WG-TLS-002",
        scan(http_hop(days=25)),
        ("hop:0 finding low high expires_within_30_days",),
    ),
    Case(
        "15 days",
        "WG-TLS-002",
        scan(http_hop(days=15)),
        ("hop:0 finding low high expires_within_30_days",),
    ),
    Case(
        "14.9 days",
        "WG-TLS-002",
        scan(http_hop(days=14.9)),
        ("hop:0 finding medium high expires_within_14_days",),
    ),
    Case(
        "1 day",
        "WG-TLS-002",
        scan(http_hop(days=1)),
        ("hop:0 finding medium high expires_within_14_days",),
    ),
    Case(
        "tls verify failed",
        "WG-TLS-002",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case("dns failure", "WG-TLS-002", scan(failed_hop()), ("hop:0 inconclusive - - hop_failed",)),
    Case(
        "deadline",
        "WG-TLS-002",
        scan(failed_hop(code=F.DEADLINE_EXCEEDED)),
        ("hop:0 inconclusive - - scan_deadline",),
    ),
    Case(
        "interrupted",
        "WG-TLS-002",
        scan(failed_hop(code=F.CONNECT_FAILED)),
        ("hop:0 inconclusive - - scan_interrupted",),
        "scan_interrupted",
    ),
    # --- WG-HDR-001 ---------------------------------------------------------------------------
    Case("absent", "WG-HDR-001", scan(http_hop()), ("hop:0 finding medium high header_absent",)),
    Case(
        "one year",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=31536000"))),
        ("hop:0 pass - high present",),
    ),
    Case(
        "exactly 180 days",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=15552000"))),
        ("hop:0 pass - high present",),
    ),
    Case(
        "quoted max-age",
        "WG-HDR-001",
        scan(http_hop(headers=sts('max-age="31536000"'))),
        ("hop:0 pass - high present",),
    ),
    Case(
        "case-insensitive directives",
        "WG-HDR-001",
        scan(http_hop(headers=sts("MAX-AGE=31536000; INCLUDESUBDOMAINS; preload"))),
        ("hop:0 pass - high present",),
    ),
    Case(
        "max-age=0",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=0"))),
        ("hop:0 finding medium high disabled",),
    ),
    Case(
        "one day",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=86400"))),
        ("hop:0 finding low high max_age_below_minimum",),
    ),
    Case(
        "non-integer",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=abc"))),
        ("hop:0 finding medium high invalid",),
    ),
    Case(
        "negative",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=-1"))),
        ("hop:0 finding medium high invalid",),
    ),
    Case(
        "no max-age",
        "WG-HDR-001",
        scan(http_hop(headers=sts("includeSubDomains"))),
        ("hop:0 finding medium high invalid",),
    ),
    Case(
        "duplicate directive",
        "WG-HDR-001",
        scan(http_hop(headers=sts("max-age=1; max-age=31536000"))),
        ("hop:0 finding medium high invalid",),
    ),
    Case(
        "first instance only",
        "WG-HDR-001",
        scan(http_hop(headers=sts(["max-age=0", "max-age=31536000"]))),
        ("hop:0 finding medium high disabled",),
    ),
    Case(
        "on a 301",
        "WG-HDR-001",
        scan(http_hop(status=301, headers=sts("max-age=31536000"), location=loc())),
        ("hop:0 pass - high present",),
    ),
    Case(
        "on a 404",
        "WG-HDR-001",
        scan(http_hop(status=404)),
        ("hop:0 finding medium high header_absent",),
    ),
    Case(
        "tls verify failed",
        "WG-HDR-001",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case(
        "hop failed",
        "WG-HDR-001",
        scan(failed_hop(code=F.READ_TIMEOUT, tls_reached=True)),
        ("hop:0 inconclusive - - hop_failed",),
    ),
    Case(
        "per hop",
        "WG-HDR-001",
        scan(http_hop(0, 301, location=loc()), http_hop(1, headers=sts("max-age=31536000"))),
        ("hop:0 finding medium high header_absent", "hop:1 pass - high present"),
    ),
    # --- WG-HDR-002 ---------------------------------------------------------------------------
    Case("present", "WG-HDR-002", scan(http_hop(headers=OK)), ("hop:0 pass - high present",)),
    Case(
        "report-only only",
        "WG-HDR-002",
        scan(http_hop(headers={"content-security-policy-report-only": ["default-src 'self'"]})),
        ("hop:0 finding low high report_only_only",),
    ),
    Case("absent", "WG-HDR-002", scan(http_hop()), ("hop:0 finding low high header_absent",)),
    Case(
        "empty",
        "WG-HDR-002",
        scan(http_hop(headers={"content-security-policy": ["  "]})),
        ("hop:0 finding low high empty_policy",),
    ),
    Case(
        "terminal 301",
        "WG-HDR-002",
        scan(http_hop(status=301, location=loc())),
        ("hop:0 not_applicable - - redirect_response",),
    ),
    Case(
        "404 present",
        "WG-HDR-002",
        scan(http_hop(status=404, headers=OK)),
        ("hop:0 pass - medium present",),
    ),
    Case(
        "503 absent",
        "WG-HDR-002",
        scan(http_hop(status=503)),
        ("hop:0 finding low medium header_absent",),
    ),
    Case(
        "tls verify failed",
        "WG-HDR-002",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case("hop failed", "WG-HDR-002", scan(failed_hop()), ("hop:0 inconclusive - - hop_failed",)),
    Case(
        "terminal after redirect",
        "WG-HDR-002",
        scan(http_hop(0, 301, location=loc()), http_hop(1, headers=OK)),
        ("hop:1 pass - high present",),
    ),
    Case(
        "redirect target failed",
        "WG-HDR-002",
        scan(http_hop(0, 301, location=loc()), failed_hop(1, F.CONNECT_FAILED)),
        ("hop:0 not_applicable - - redirect_response",),
    ),
    # --- WG-HDR-003 ---------------------------------------------------------------------------
    Case("nosniff", "WG-HDR-003", scan(http_hop(headers=OK)), ("hop:0 pass - high nosniff",)),
    Case(
        "padded mixed case",
        "WG-HDR-003",
        scan(http_hop(headers={"x-content-type-options": [" NoSniff "]})),
        ("hop:0 pass - high nosniff",),
    ),
    Case(
        "wrong value",
        "WG-HDR-003",
        scan(http_hop(headers={"x-content-type-options": ["sniff"]})),
        ("hop:0 finding low high invalid_value",),
    ),
    Case(
        "first instance only",
        "WG-HDR-003",
        scan(http_hop(headers={"x-content-type-options": ["bogus", "nosniff"]})),
        ("hop:0 finding low high invalid_value",),
    ),
    Case("absent", "WG-HDR-003", scan(http_hop()), ("hop:0 finding low high header_absent",)),
    Case(
        "terminal 302",
        "WG-HDR-003",
        scan(http_hop(status=302, location=loc())),
        ("hop:0 not_applicable - - redirect_response",),
    ),
    Case(
        "404",
        "WG-HDR-003",
        scan(http_hop(status=404, headers=OK)),
        ("hop:0 pass - medium nosniff",),
    ),
    Case(
        "tls verify failed",
        "WG-HDR-003",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    # --- WG-CK-001 ----------------------------------------------------------------------------
    Case(
        "no cookies", "WG-CK-001", scan(http_hop()), ("- not_applicable - - no_cookies_observed",)
    ),
    Case(
        "secure",
        "WG-CK-001",
        scan(http_hop(cookies=[GOOD_COOKIE])),
        ("cookie:sid@hop:0 pass - high secure_present",),
    ),
    Case(
        "upper-case SECURE",
        "WG-CK-001",
        scan(http_hop(cookies=[("a", "SECURE")])),
        ("cookie:a@hop:0 pass - high secure_present",),
    ),
    Case(
        "not secure",
        "WG-CK-001",
        scan(http_hop(cookies=[("a", "Path=/")])),
        ("cookie:a@hop:0 finding medium high secure_absent",),
    ),
    Case(
        "two cookies",
        "WG-CK-001",
        scan(http_hop(cookies=[GOOD_COOKIE, ("b", "")])),
        (
            "cookie:sid@hop:0 pass - high secure_present",
            "cookie:b@hop:0 finding medium high secure_absent",
        ),
    ),
    Case(
        "unnamed cookie",
        "WG-CK-001",
        scan(http_hop(cookies=[("", "Secure")])),
        ("cookie:(unnamed)@hop:0 pass - high secure_present",),
    ),
    Case(
        "tls verify failed",
        "WG-CK-001",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case(
        "cookies on two hops, second failed",
        "WG-CK-001",
        scan(
            http_hop(0, 301, cookies=[("a", "Secure")], location=loc()),
            failed_hop(1, F.READ_TIMEOUT),
        ),
        ("cookie:a@hop:0 pass - high secure_present", "hop:1 inconclusive - - hop_failed"),
    ),
    # --- WG-CK-002 ----------------------------------------------------------------------------
    Case(
        "httponly",
        "WG-CK-002",
        scan(http_hop(cookies=[GOOD_COOKIE])),
        ("cookie:sid@hop:0 pass - high httponly_present",),
    ),
    Case(
        "no httponly",
        "WG-CK-002",
        scan(http_hop(cookies=[("a", "Secure")])),
        ("cookie:a@hop:0 finding low low httponly_absent",),
    ),
    Case(
        "no cookies", "WG-CK-002", scan(http_hop()), ("- not_applicable - - no_cookies_observed",)
    ),
    Case(
        "tls verify failed",
        "WG-CK-002",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case(
        "deadline",
        "WG-CK-002",
        scan(failed_hop(code=F.DEADLINE_EXCEEDED)),
        ("hop:0 inconclusive - - scan_deadline",),
    ),
    # --- WG-CK-003 ----------------------------------------------------------------------------
    Case(
        "lax",
        "WG-CK-003",
        scan(http_hop(cookies=[GOOD_COOKIE])),
        ("cookie:sid@hop:0 pass - high samesite_strict_or_lax",),
    ),
    Case(
        "strict upper",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "SameSite=STRICT")])),
        ("cookie:a@hop:0 pass - high samesite_strict_or_lax",),
    ),
    Case(
        "none + secure",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "SameSite=None; Secure")])),
        ("cookie:a@hop:0 pass - high none_with_secure",),
    ),
    Case(
        "none without secure",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "SameSite=None")])),
        ("cookie:a@hop:0 finding medium high none_without_secure",),
    ),
    Case(
        "invalid",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "SameSite=bogus")])),
        ("cookie:a@hop:0 finding low high invalid_value",),
    ),
    Case(
        "empty value",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "SameSite")])),
        ("cookie:a@hop:0 finding low high invalid_value",),
    ),
    Case(
        "absent",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "Secure")])),
        ("cookie:a@hop:0 finding informational high samesite_absent",),
    ),
    Case(
        "last occurrence wins",
        "WG-CK-003",
        scan(http_hop(cookies=[("a", "SameSite=None; SameSite=Lax")])),
        ("cookie:a@hop:0 pass - high samesite_strict_or_lax",),
    ),
    Case("hop failed", "WG-CK-003", scan(failed_hop()), ("hop:0 inconclusive - - hop_failed",)),
    # --- WG-CK-004 ----------------------------------------------------------------------------
    Case(
        "not prefixed",
        "WG-CK-004",
        scan(http_hop(cookies=[GOOD_COOKIE])),
        ("cookie:sid@hop:0 not_applicable - - not_prefixed",),
    ),
    Case(
        "__Host- ok",
        "WG-CK-004",
        scan(http_hop(cookies=[("__Host-a", "Secure; Path=/")])),
        ("cookie:__Host-a@hop:0 pass - high prefix_requirements_met",),
    ),
    Case(
        "__Host- with Domain",
        "WG-CK-004",
        scan(http_hop(cookies=[("__Host-a", "Secure; Path=/; Domain=webguard.test")])),
        ("cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet",),
    ),
    Case(
        "__Host- without Path",
        "WG-CK-004",
        scan(http_hop(cookies=[("__Host-a", "Secure")])),
        ("cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet",),
    ),
    Case(
        "__Host- Path=/x",
        "WG-CK-004",
        scan(http_hop(cookies=[("__Host-a", "Secure; Path=/x")])),
        ("cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet",),
    ),
    Case(
        "__Secure- without Secure",
        "WG-CK-004",
        scan(http_hop(cookies=[("__Secure-a", "")])),
        ("cookie:__Secure-a@hop:0 finding medium high prefix_requirements_unmet",),
    ),
    Case(
        "__secure- lower-case prefix",
        "WG-CK-004",
        scan(http_hop(cookies=[("__secure-a", "Secure")])),
        ("cookie:__secure-a@hop:0 pass - high prefix_requirements_met",),
    ),
    Case(
        "tls verify failed",
        "WG-CK-004",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case(
        "no cookies", "WG-CK-004", scan(http_hop()), ("- not_applicable - - no_cookies_observed",)
    ),
    # --- WG-RDR-001 ---------------------------------------------------------------------------
    Case("200", "WG-RDR-001", scan(http_hop()), ("hop:0 not_applicable - - not_redirect",)),
    Case(
        "404", "WG-RDR-001", scan(http_hop(status=404)), ("hop:0 not_applicable - - not_redirect",)
    ),
    Case(
        "301 to http",
        "WG-RDR-001",
        scan(http_hop(status=301, location=loc("http"))),
        ("hop:0 finding medium high https_to_http_redirect",),
    ),
    Case(
        "308 to https",
        "WG-RDR-001",
        scan(http_hop(status=308, location=loc())),
        ("hop:0 pass - high https_redirect",),
    ),
    Case(
        "302 no location",
        "WG-RDR-001",
        scan(http_hop(status=302)),
        ("hop:0 not_applicable - - no_location",),
    ),
    Case(
        "unparseable",
        "WG-RDR-001",
        scan(http_hop(status=302, location=LocationEvidence(unparseable=True, raw_length=9))),
        ("hop:0 inconclusive - - location_unparseable",),
    ),
    Case(
        "javascript scheme",
        "WG-RDR-001",
        scan(http_hop(status=302, location=loc("javascript", ""))),
        ("hop:0 inconclusive - - unexpected_scheme",),
    ),
    Case(
        "tls verify failed",
        "WG-RDR-001",
        scan(tls_failed_hop()),
        ("hop:0 inconclusive - - blocked_by:WG-TLS-001",),
    ),
    Case("hop failed", "WG-RDR-001", scan(failed_hop()), ("hop:0 inconclusive - - hop_failed",)),
]
