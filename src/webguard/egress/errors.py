"""Egress exceptions and the single exception -> FailureCode mapping (Plan §9.8).

Every exception raised inside egress carries a static `code`. `classify` is called only at
`fetch_hop`'s outer boundary. Exception messages are never used as evidence: they may
contain target-controlled text.
"""

from __future__ import annotations

import ssl

import h11
import httpcore
from pydantic import ValidationError

from webguard.domain.budget import DeadlineExceededError
from webguard.domain.enums import FailureCode


class EgressError(Exception):
    """Base for classified egress failures. `detail` is a static code, never target text."""

    code: FailureCode = FailureCode.INTERNAL_ERROR

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.code.value)
        self.detail = detail


class PolicyViolationError(EgressError):
    code = FailureCode.POLICY_PROHIBITED_ADDRESS


class DnsNoAnswerError(EgressError):
    code = FailureCode.DNS_NO_ANSWER


class DnsTimeoutError(EgressError):
    code = FailureCode.DNS_TIMEOUT


class DnsTooManyAnswersError(EgressError):
    code = FailureCode.DNS_TOO_MANY_ANSWERS


class ConnectFailedError(EgressError):
    code = FailureCode.CONNECT_FAILED


class ConnectTimeoutError(EgressError):
    code = FailureCode.CONNECT_TIMEOUT


class TlsHandshakeError(EgressError):
    code = FailureCode.TLS_HANDSHAKE_FAILED


class ReadTimeoutError(EgressError):
    code = FailureCode.READ_TIMEOUT


class ResponseTooLargeError(EgressError):
    code = FailureCode.RESPONSE_TOO_LARGE


class MalformedResponseError(EgressError):
    code = FailureCode.MALFORMED_RESPONSE


# h11 marks "receive buffer too long" (oversized header block) with this status hint (P0, A-10).
_H11_TOO_LARGE_HINT = 431


def _h11_cause(exc: BaseException) -> h11.ProtocolError | None:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, h11.ProtocolError):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def classify(exc: Exception) -> tuple[FailureCode, str | None]:
    """Map an exception escaping the HTTP exchange to (failure code, static detail)."""
    if isinstance(exc, EgressError):
        return exc.code, exc.detail
    if isinstance(exc, DeadlineExceededError):
        return FailureCode.DEADLINE_EXCEEDED, None
    if isinstance(exc, ValidationError):
        return FailureCode.INTERNAL_ERROR, "evidence_validation"
    if isinstance(
        exc, httpcore.RemoteProtocolError | httpcore.LocalProtocolError | h11.ProtocolError
    ):
        cause = _h11_cause(exc)
        if cause is not None and cause.error_status_hint == _H11_TOO_LARGE_HINT:
            return FailureCode.RESPONSE_TOO_LARGE, "h11_header_block"
        return FailureCode.MALFORMED_RESPONSE, "protocol_error"
    if isinstance(exc, ssl.SSLError):
        return FailureCode.MALFORMED_RESPONSE, "tls_record_error"
    if isinstance(exc, OSError):
        return FailureCode.MALFORMED_RESPONSE, "connection_error"
    return FailureCode.INTERNAL_ERROR, type(exc).__name__
