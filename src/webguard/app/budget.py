"""ScanBudget: the single per-scan deadline and request counter (Plan §11)."""

from __future__ import annotations

import time
from collections.abc import Callable

from webguard.domain.budget import (
    DEADLINE_MAX_S,
    DEADLINE_MIN_S,
    MAX_REQUESTS_PER_SCAN,
    RequestLimitExceededError,
)


class ScanBudget:
    """Monotonic deadline plus request accounting. Implements `domain.budget.Budget`."""

    def __init__(
        self,
        deadline_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not DEADLINE_MIN_S <= deadline_s <= DEADLINE_MAX_S:
            raise ValueError("deadline outside the permitted range")
        self._clock = clock
        self._deadline_at = clock() + deadline_s
        self._requests = 0

    def remaining(self) -> float:
        return self._deadline_at - self._clock()

    def expired(self) -> bool:
        return self.remaining() <= 0

    @property
    def requests(self) -> int:
        return self._requests

    def charge_request(self) -> None:
        if self._requests >= MAX_REQUESTS_PER_SCAN:
            raise RequestLimitExceededError
        self._requests += 1
