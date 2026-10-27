"""Redirect decisions (Plan §12). The HTTP layer never follows redirects; this module decides
whether the orchestrator fetches another hop. Every next hop is a validated CanonicalTarget
produced inside egress, fetched with a fresh pool, backend and resolution."""

from __future__ import annotations

from dataclasses import dataclass

from webguard.domain.budget import MAX_REDIRECT_HOPS
from webguard.domain.enums import ScanNote
from webguard.domain.evidence import HopEvidence
from webguard.policy.url import CanonicalTarget, RejectionCode, UrlRejection

_REJECTION_NOTES: dict[RejectionCode, ScanNote] = {
    RejectionCode.URL_TOO_LONG: ScanNote.REDIRECT_REJECTED_URL_TOO_LONG,
    RejectionCode.URL_ILLEGAL_CHARS: ScanNote.REDIRECT_REJECTED_URL_ILLEGAL_CHARS,
    RejectionCode.SCHEME_NOT_HTTPS: ScanNote.REDIRECT_REJECTED_SCHEME_NOT_HTTPS,
    RejectionCode.USERINFO_PRESENT: ScanNote.REDIRECT_REJECTED_USERINFO_PRESENT,
    RejectionCode.HOST_INVALID: ScanNote.REDIRECT_REJECTED_HOST_INVALID,
    RejectionCode.IPV4_AMBIGUOUS: ScanNote.REDIRECT_REJECTED_IPV4_AMBIGUOUS,
    RejectionCode.PORT_NOT_PERMITTED: ScanNote.REDIRECT_REJECTED_PORT_NOT_PERMITTED,
}


@dataclass(frozen=True, slots=True)
class RedirectDecision:
    follow: CanonicalTarget | None
    note: ScanNote | None


STOP = RedirectDecision(None, None)


def next_hop(
    hop: HopEvidence,
    next_target: CanonicalTarget | UrlRejection | None,
    *,
    follow: bool,
    visited: set[tuple[str, int, str]],
) -> RedirectDecision:
    http = hop.http
    if http is None or not http.is_redirect:
        return STOP
    if not follow:
        return RedirectDecision(None, ScanNote.REDIRECT_NOT_FOLLOWED)
    if hop.index >= MAX_REDIRECT_HOPS:
        return RedirectDecision(None, ScanNote.REDIRECT_LIMIT_REACHED)
    if http.location is None:
        return RedirectDecision(None, ScanNote.REDIRECT_LOCATION_MISSING)
    if http.location.unparseable or next_target is None:
        return RedirectDecision(None, ScanNote.REDIRECT_LOCATION_UNPARSEABLE)
    if isinstance(next_target, UrlRejection):
        return RedirectDecision(None, _REJECTION_NOTES[next_target.code])
    if next_target.visit_key in visited:
        return RedirectDecision(None, ScanNote.REDIRECT_LOOP)
    return RedirectDecision(next_target, None)
