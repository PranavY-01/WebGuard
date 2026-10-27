"""Closed vocabularies shared by every layer."""

from __future__ import annotations

from enum import StrEnum


class Status(StrEnum):
    PASS = "pass"  # noqa: S105  # reason: rule status value, not a credential
    FINDING = "finding"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(StrEnum):
    TLS = "tls"
    HEADERS = "headers"
    COOKIES = "cookies"
    REDIRECTS = "redirects"


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class FailOn(StrEnum):
    """`--fail-on` threshold. NONE never produces exit code 1."""

    NONE = "none"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def is_met_by(self, severity: Severity) -> bool:
        if self is FailOn.NONE:
            return False
        return severity.rank >= Severity(self.value).rank


class FailureCode(StrEnum):
    DNS_NO_ANSWER = "dns_no_answer"
    DNS_TIMEOUT = "dns_timeout"
    DNS_TOO_MANY_ANSWERS = "dns_too_many_answers"
    POLICY_PROHIBITED_ADDRESS = "policy_prohibited_address"
    CONNECT_FAILED = "connect_failed"
    CONNECT_TIMEOUT = "connect_timeout"
    TLS_VERIFICATION_FAILED = "tls_verification_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    READ_TIMEOUT = "read_timeout"
    RESPONSE_TOO_LARGE = "response_too_large"
    MALFORMED_RESPONSE = "malformed_response"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    INTERNAL_ERROR = "internal_error"


class ScanNote(StrEnum):
    """Static codes recorded in `scan.notes`."""

    REDIRECT_NOT_FOLLOWED = "redirect_not_followed"
    REDIRECT_LIMIT_REACHED = "redirect_limit_reached"
    REDIRECT_LOOP = "redirect_loop"
    REDIRECT_BLOCKED_BY_POLICY = "redirect_blocked_by_policy"
    REDIRECT_LOCATION_MISSING = "redirect_location_missing"
    REDIRECT_LOCATION_UNPARSEABLE = "redirect_location_unparseable"
    REDIRECT_REJECTED_URL_TOO_LONG = "redirect_rejected:url_too_long"
    REDIRECT_REJECTED_URL_ILLEGAL_CHARS = "redirect_rejected:url_illegal_chars"
    REDIRECT_REJECTED_SCHEME_NOT_HTTPS = "redirect_rejected:scheme_not_https"
    REDIRECT_REJECTED_USERINFO_PRESENT = "redirect_rejected:userinfo_present"
    REDIRECT_REJECTED_HOST_INVALID = "redirect_rejected:host_invalid"
    REDIRECT_REJECTED_IPV4_AMBIGUOUS = "redirect_rejected:ipv4_ambiguous"
    REDIRECT_REJECTED_PORT_NOT_PERMITTED = "redirect_rejected:port_not_permitted"
    DEADLINE_REACHED = "deadline_reached"
    INTERRUPTED = "interrupted"
    REPORT_HTML_FAILED = "report_html_failed"
