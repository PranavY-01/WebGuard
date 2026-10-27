"""Permitted test doubles (prompt §13.1): StubResolver and TestScopePolicy. Never shipped."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address

from webguard.policy.scope import Decision
from webguard.policy.url import PERMITTED_PORTS

IPAddress = IPv4Address | IPv6Address
LOOPBACK_V4 = ip_address("127.0.0.1")
LOOPBACK_V6 = ip_address("::1")


class StubResolver:
    """Scripted answers. `script` is consumed one entry per call (the last entry repeats);
    `hang=True` blocks until released, like a resolver that never answers."""

    def __init__(self, *script: Sequence[str], hang: bool = False) -> None:
        self.script = [[ip_address(a) for a in answers] for answers in script] or [[LOOPBACK_V4]]
        self.calls: list[tuple[str, int]] = []
        self.hang = hang
        self.release = threading.Event()

    def resolve(self, host: str, port: int, timeout_s: float) -> Sequence[IPAddress]:
        self.calls.append((host, port))
        if self.hang:
            self.release.wait(3600)
        index = min(len(self.calls) - 1, len(self.script) - 1)
        return list(self.script[index])


class TestScopePolicy:
    """Loopback fixture policy: permits 127.0.0.1 only; ::1 (and everything else) prohibited."""

    __test__ = False

    def check_literal(self, host_ip: IPAddress | None, port: int) -> Decision:
        if port not in PERMITTED_PORTS:
            return Decision(False, "port_not_permitted")
        return Decision(True, "permitted") if host_ip is None else self.check_resolved([host_ip])

    def check_resolved(self, ips: Sequence[IPAddress]) -> Decision:
        if not ips:
            return Decision(False, "no_addresses")
        for ip in ips:
            if ip != LOOPBACK_V4:
                return Decision(False, "test_policy_prohibited", ip)
        return Decision(True, "permitted")
