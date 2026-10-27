"""Static rule metadata (Plan §14.1). Every message is a fixed string per reason code; dynamic
values travel only as SafeText evidence items, never inside messages."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from webguard.domain.enums import Category, Severity

# Reason codes shared by every rule.
BLOCKED_BY_TLS = "blocked_by:WG-TLS-001"
HOP_FAILED = "hop_failed"
SCAN_DEADLINE = "scan_deadline"
SCAN_INTERRUPTED = "scan_interrupted"
INTERNAL_RULE_ERROR = "internal_rule_error"

_COMMON: Final = {
    BLOCKED_BY_TLS: "Not evaluated: the certificate could not be verified, so no HTTP exchange "
    "took place.",
    HOP_FAILED: "Not evaluated: the request failed before response headers were received.",
    SCAN_DEADLINE: "Not evaluated: the scan deadline expired before evidence was collected.",
    SCAN_INTERRUPTED: "Not evaluated: the scan was interrupted.",
    INTERNAL_RULE_ERROR: "The rule failed with an internal error; no conclusion was drawn.",
}

MDN = "https://developer.mozilla.org/en-US/docs/Web"
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets"
RFC = "https://datatracker.ietf.org/doc/html"


@dataclass(frozen=True, slots=True)
class RuleMeta:
    rule_id: str
    version: int
    title: str
    category: Category
    severities: tuple[Severity, ...]
    messages: MappingProxyType[str, str]
    remediation: str
    references: tuple[str, ...]
    limitations: tuple[str, ...]

    def message(self, reason: str) -> str:
        if reason not in self.messages:
            raise KeyError(f"{self.rule_id}: undeclared reason code {reason!r}")
        return self.messages[reason]


def _meta(
    rule_id: str,
    title: str,
    category: Category,
    severities: tuple[Severity, ...],
    messages: dict[str, str],
    remediation: str,
    references: tuple[str, ...],
    limitations: tuple[str, ...] = (),
) -> RuleMeta:
    return RuleMeta(
        rule_id=rule_id,
        version=1,
        title=title,
        category=category,
        severities=severities,
        messages=MappingProxyType({**_COMMON, **messages}),
        remediation=remediation,
        references=references,
        limitations=limitations,
    )


S = Severity
TLS_001 = _meta(
    "WG-TLS-001",
    "Certificate verification",
    Category.TLS,
    (S.HIGH,),
    {
        "verified": "The certificate chain and hostname verified against the trust store.",
        "expired": "The server certificate has expired.",
        "not_yet_valid": "The server certificate is not yet valid.",
        "untrusted_chain": "The certificate chain does not lead to a trusted root.",
        "hostname_mismatch": "The certificate is not valid for the requested hostname.",
        "verification_failed_other": "Certificate verification failed.",
        "handshake_failed": "The TLS handshake failed for a reason other than certificate "
        "verification.",
        "tls_not_reached": "The TLS stage was not reached, so the certificate was not examined.",
    },
    "Serve a certificate that is currently valid, issued by a publicly trusted CA, covers the "
    "hostname, and is sent with its full intermediate chain.",
    (
        f"{RFC}/rfc5280",
        f"{RFC}/rfc6125",
        f"{OWASP}/Transport_Layer_Security_Cheat_Sheet.html",
    ),
    (
        "Trust is evaluated against the certifi CA bundle, which may differ from operating-system "
        "and browser trust stores.",
    ),
)

TLS_002 = _meta(
    "WG-TLS-002",
    "Certificate expiry horizon",
    Category.TLS,
    (S.LOW, S.MEDIUM),
    {
        "expiry_beyond_30_days": "The certificate remains valid for more than 30 days.",
        "expires_within_30_days": "The certificate expires within 15 to 30 days.",
        "expires_within_14_days": "The certificate expires within 14 days.",
    },
    "Renew the certificate before it expires; automate renewal and alert on short horizons.",
    (f"{RFC}/rfc5280#section-4.1.2.5", f"{OWASP}/Transport_Layer_Security_Cheat_Sheet.html"),
    ("Measured against the scan start time from this vantage point only.",),
)

HDR_001 = _meta(
    "WG-HDR-001",
    "HTTP Strict Transport Security (HSTS)",
    Category.HEADERS,
    (S.LOW, S.MEDIUM),
    {
        "present": "HSTS is set with a max-age of at least 180 days.",
        "header_absent": "No Strict-Transport-Security header was returned.",
        "invalid": "The Strict-Transport-Security header could not be parsed (missing or "
        "invalid max-age, or a duplicated directive), so browsers ignore it.",
        "disabled": "Strict-Transport-Security sets max-age=0, which removes HSTS protection.",
        "max_age_below_minimum": "The HSTS max-age is below 180 days (15552000 seconds).",
    },
    "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS "
    "response once all subdomains serve HTTPS.",
    (
        f"{RFC}/rfc6797",
        f"{MDN}/HTTP/Headers/Strict-Transport-Security",
        f"{OWASP}/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    ),
    (
        "Only the first header instance is evaluated (RFC 6797 section 8.1).",
        "includeSubDomains and preload are recorded as evidence, not graded.",
    ),
)

HDR_002 = _meta(
    "WG-HDR-002",
    "Content Security Policy (enforcing)",
    Category.HEADERS,
    (S.LOW,),
    {
        "present": "An enforcing Content-Security-Policy header is present.",
        "report_only_only": "Only Content-Security-Policy-Report-Only is present; nothing is "
        "enforced.",
        "header_absent": "No Content-Security-Policy header was returned.",
        "empty_policy": "The Content-Security-Policy header is empty.",
        "redirect_response": "Not applicable to a redirect response. Rerun with "
        "--follow-redirects or target the final URL.",
    },
    "Deploy an enforcing Content-Security-Policy; start from a restrictive default-src and "
    "iterate using a report-only policy first.",
    (
        f"{MDN}/HTTP/CSP",
        f"{OWASP}/Content_Security_Policy_Cheat_Sheet.html",
    ),
    ("<meta> CSP not detectable without the body; policy quality not graded.",),
)

HDR_003 = _meta(
    "WG-HDR-003",
    "X-Content-Type-Options",
    Category.HEADERS,
    (S.LOW,),
    {
        "nosniff": "X-Content-Type-Options is set to nosniff.",
        "invalid_value": "X-Content-Type-Options is present but not set to nosniff.",
        "header_absent": "No X-Content-Type-Options header was returned.",
        "redirect_response": "Not applicable to a redirect response. Rerun with "
        "--follow-redirects or target the final URL.",
    },
    "Send `X-Content-Type-Options: nosniff` on every response.",
    (
        f"{MDN}/HTTP/Headers/X-Content-Type-Options",
        f"{OWASP}/HTTP_Headers_Cheat_Sheet.html",
    ),
)

_COOKIE_REFS = (
    f"{RFC}/rfc6265",
    f"{MDN}/HTTP/Headers/Set-Cookie",
    f"{OWASP}/Session_Management_Cheat_Sheet.html",
)
_NO_COOKIES = {"no_cookies_observed": "No Set-Cookie headers were observed."}

CK_001 = _meta(
    "WG-CK-001",
    "Cookie Secure attribute",
    Category.COOKIES,
    (S.MEDIUM,),
    {
        **_NO_COOKIES,
        "secure_present": "The cookie is marked Secure.",
        "secure_absent": "The cookie is not marked Secure and may be sent over plain HTTP.",
    },
    "Add the Secure attribute to every cookie set over HTTPS.",
    _COOKIE_REFS,
)

CK_002 = _meta(
    "WG-CK-002",
    "Cookie HttpOnly attribute",
    Category.COOKIES,
    (S.LOW,),
    {
        **_NO_COOKIES,
        "httponly_present": "The cookie is marked HttpOnly.",
        "httponly_absent": "The cookie is readable by page scripts (no HttpOnly).",
    },
    "Add HttpOnly to cookies that scripts do not need, especially session identifiers.",
    _COOKIE_REFS,
    ("Cookie purpose unknown.",),
)

CK_003 = _meta(
    "WG-CK-003",
    "Cookie SameSite attribute",
    Category.COOKIES,
    (S.INFORMATIONAL, S.LOW, S.MEDIUM),
    {
        **_NO_COOKIES,
        "samesite_strict_or_lax": "SameSite is Strict or Lax.",
        "none_with_secure": "SameSite=None is combined with Secure (cross-site use is explicit).",
        "none_without_secure": "SameSite=None without Secure; browsers reject this cookie.",
        "invalid_value": "SameSite has an unrecognized value.",
        "samesite_absent": "SameSite is not set; the browser default applies.",
    },
    "Set SameSite=Lax or Strict unless cross-site delivery is required; SameSite=None "
    "requires Secure.",
    _COOKIE_REFS,
    ("Cookie purpose unknown.",),
)

CK_004 = _meta(
    "WG-CK-004",
    "Cookie name prefixes",
    Category.COOKIES,
    (S.MEDIUM,),
    {
        **_NO_COOKIES,
        "prefix_requirements_met": "The cookie satisfies its __Secure-/__Host- prefix rules.",
        "prefix_requirements_unmet": "The cookie violates its __Secure-/__Host- prefix rules "
        "and browsers will reject it.",
        "not_prefixed": "The cookie name has no __Secure- or __Host- prefix.",
    },
    "__Secure- cookies need Secure; __Host- cookies need Secure, Path=/ and no Domain.",
    (f"{MDN}/HTTP/Headers/Set-Cookie#cookie_prefixes", f"{RFC}/rfc6265"),
)

RDR_001 = _meta(
    "WG-RDR-001",
    "Redirect downgrade to HTTP",
    Category.REDIRECTS,
    (S.MEDIUM,),
    {
        "https_redirect": "The redirect stays on HTTPS.",
        "https_to_http_redirect": "An HTTPS response redirects to a plain-HTTP URL.",
        "not_redirect": "The response is not a redirect.",
        "no_location": "The redirect response has no Location header.",
        "location_unparseable": "The Location header could not be parsed.",
        "unexpected_scheme": "The Location uses a scheme other than http or https.",
    },
    "Redirect only to https:// URLs and enable HSTS so browsers never request HTTP.",
    (f"{RFC}/rfc9110#section-15.4", f"{RFC}/rfc6797", f"{MDN}/HTTP/Redirections"),
)

CATALOG: Final[tuple[RuleMeta, ...]] = (
    CK_001,
    CK_002,
    CK_003,
    CK_004,
    HDR_001,
    HDR_002,
    HDR_003,
    RDR_001,
    TLS_001,
    TLS_002,
)

BY_ID: Final = MappingProxyType({meta.rule_id: meta for meta in CATALOG})
