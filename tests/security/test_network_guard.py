"""S-29: the test suite cannot reach any non-loopback host (INV-05, amended rule 13)."""

from __future__ import annotations

import socket

import pytest

from tests.conftest import FIXTURE_PORT, target
from tests.fixtures.network_guard import NetworkGuard, OutboundNetworkBlockedError
from tests.fixtures.server import FixtureServer
from tests.fixtures.stubs import StubResolver
from webguard.app.budget import ScanBudget
from webguard.domain.config import EgressConfig
from webguard.egress import HopRequest, fetch_hop
from webguard.policy.scope import PublicScopePolicy


@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, ("192.0.2.1", 443)),
        (socket.AF_INET, ("1.1.1.1", 443)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0)),
        (socket.AF_INET6, ("::ffff:8.8.8.8", 443, 0, 0)),
    ],
)
def test_s29_socket_connect_to_non_loopback_is_blocked(
    network_guard: NetworkGuard, family: int, address: tuple[object, ...]
) -> None:
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        with pytest.raises(OutboundNetworkBlockedError):
            sock.connect(address)
        with pytest.raises(OutboundNetworkBlockedError):
            sock.connect_ex(address)
    finally:
        sock.close()
    assert len(network_guard.blocked) == 2
    network_guard.blocked.clear()


def test_s29_names_are_blocked_before_dns(network_guard: NetworkGuard) -> None:
    with pytest.raises(OutboundNetworkBlockedError):
        socket.create_connection(("example.com", 443), timeout=1)
    with pytest.raises(OutboundNetworkBlockedError):
        socket.getaddrinfo("example.com", 443)
    assert len(network_guard.blocked) == 2
    network_guard.blocked.clear()


def test_s29_loopback_is_allowed(network_guard: NetworkGuard, server: FixtureServer) -> None:
    with socket.create_connection(("127.0.0.1", FIXTURE_PORT), timeout=5):
        pass
    assert socket.getaddrinfo("localhost", FIXTURE_PORT)
    assert network_guard.blocked == []


def test_s29_egress_cannot_reach_a_public_address_from_tests(
    network_guard: NetworkGuard, egress_cfg: EgressConfig
) -> None:
    """Even a public answer that the production policy permits never leaves the machine, and
    the guard error is not absorbed into an egress failure code."""
    with pytest.raises(OutboundNetworkBlockedError):
        fetch_hop(
            HopRequest(0, target()),
            ScanBudget(30),
            PublicScopePolicy(),
            egress_cfg,
            StubResolver(["1.1.1.1"]),
        )
    assert network_guard.blocked == ["connect ('1.1.1.1', 8443)"]
    network_guard.blocked.clear()
