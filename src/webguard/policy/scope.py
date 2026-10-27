"""Scope policy (Plan §10.3, D-15).

`PublicScopePolicy` is the only implementation shipped in src/ (S-28). Permissive policies
for loopback fixtures exist only under tests/ and reach the scanner via the Python API.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from webguard.policy.address import IPAddress, classify_address
from webguard.policy.url import PERMITTED_PORTS


@dataclass(frozen=True, slots=True)
class Decision:
    permitted: bool
    reason: str
    """Static code: "permitted", "port_not_permitted" or an address class label."""
    offending: IPAddress | None = None


PERMITTED = Decision(True, "permitted")


class ScopePolicy(Protocol):
    def check_literal(self, host_ip: IPAddress | None, port: int) -> Decision:
        """Decide on the canonical target before any DNS lookup."""
        ...

    def check_resolved(self, ips: Sequence[IPAddress]) -> Decision:
        """Decide on every resolved answer; any prohibited answer rejects the hop."""
        ...


class PublicScopePolicy:
    """Production policy: ports {443, 8443}; every address must be public (D-07, D-08, D-09)."""

    def check_literal(self, host_ip: IPAddress | None, port: int) -> Decision:
        if port not in PERMITTED_PORTS:
            return Decision(False, "port_not_permitted")
        if host_ip is not None:
            return self.check_resolved([host_ip])
        return PERMITTED

    def check_resolved(self, ips: Sequence[IPAddress]) -> Decision:
        if not ips:
            return Decision(False, "no_addresses")
        for ip in ips:
            verdict = classify_address(ip)
            if not verdict.permitted:
                return Decision(False, verdict.reason, ip)
        return PERMITTED
