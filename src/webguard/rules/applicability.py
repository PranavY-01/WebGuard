"""Rule applicability matrix (Plan §14.2): the response context a hop represents."""

from __future__ import annotations

from enum import StrEnum

from webguard.domain.evidence import HopEvidence


class Column(StrEnum):
    SUCCESS = "2xx"
    REDIRECT = "3xx"
    ERROR_STATUS = "4xx/5xx"
    TLS_VERIFY_FAILED = "tls_verify_failed"
    HOP_FAILED = "hop_failed"


def column(hop: HopEvidence) -> Column:
    if hop.tls_verify_failed:
        return Column.TLS_VERIFY_FAILED
    if hop.http is None:
        return Column.HOP_FAILED
    status = hop.http.status_code
    if 300 <= status < 400:
        return Column.REDIRECT
    if status >= 400:
        return Column.ERROR_STATUS
    return Column.SUCCESS
