"""Fixed scan limits (Plan §11) and the Budget protocol shared by egress and app.

The concrete `ScanBudget` lives in `webguard.app.budget`; egress depends only on this
protocol so the layering (egress below app) holds.
"""

from __future__ import annotations

from typing import Final, Protocol

DEADLINE_DEFAULT_S: Final = 30
DEADLINE_MIN_S: Final = 5
DEADLINE_MAX_S: Final = 120

DNS_TIMEOUT_S: Final = 5.0
CONNECT_TIMEOUT_S: Final = 5.0
CONNECT_ATTEMPTS_PER_HOP: Final = 2
TLS_WRITE_TIMEOUT_S: Final = 5.0
READ_TIMEOUT_S: Final = 10.0
POOL_TIMEOUT_S: Final = 5.0

MAX_BYTES_PER_HOP: Final = 128 * 1024
MAX_REQUESTS_PER_SCAN: Final = 4
MAX_REDIRECT_HOPS: Final = 3
MAX_DNS_ANSWERS: Final = 16
MAX_HEADERS: Final = 100
MAX_HEADER_VALUE_CHARS: Final = 4096
MAX_COOKIES_PER_HOP: Final = 50
MAX_COOKIE_NAME_CHARS: Final = 128
MAX_SAN_ENTRIES: Final = 20
MAX_URL_CHARS: Final = 2048
MAX_DETAIL_CHARS: Final = 512


class DeadlineExceededError(Exception):
    """The scan deadline is exhausted; the operation was not started."""


class RequestLimitExceededError(Exception):
    """More than MAX_REQUESTS_PER_SCAN requests were attempted."""


class Budget(Protocol):
    def remaining(self) -> float:
        """Seconds left before the overall deadline (may be <= 0)."""
        ...

    def charge_request(self) -> None:
        """Account for one request; raises RequestLimitExceededError past the cap."""
        ...


def clamp(phase_limit: float, budget: Budget) -> float:
    """Timeout for one blocking operation: min(phase_limit, remaining).

    Raises DeadlineExceededError instead of returning a non-positive timeout, so callers never
    start an operation once the deadline has passed (INV-08).
    """
    remaining = budget.remaining()
    if remaining <= 0:
        raise DeadlineExceededError
    return min(phase_limit, remaining)
