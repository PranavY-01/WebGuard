"""U-06..U-09: address classification table (Plan §10.2) and scope policy."""

from __future__ import annotations

from ipaddress import ip_address

import pytest

from webguard.policy.address import DENYLIST, classify_address
from webguard.policy.scope import PublicScopePolicy

# Every denylist range at both boundaries (U-06).
BOUNDARIES = sorted(
    {str(addr) for net, _ in DENYLIST for addr in (net.network_address, net.broadcast_address)}
)


@pytest.mark.parametrize("addr", BOUNDARIES)
def test_u06_denylist_boundaries_prohibited(addr: str) -> None:
    ip = ip_address(addr)
    containing = {label for net, label in DENYLIST if ip.version == net.version and ip in net}
    verdict = classify_address(ip)
    assert not verdict.permitted
    assert verdict.reason in containing | {"ipv4-mapped"}


# Addresses where is_global alone is wrong or version-dependent (U-07, A-07 findings).
GAPS = [
    ("64:ff9b::7f00:1", "nat64"),
    ("64:ff9b:1::a00:1", "nat64-local"),
    ("192.88.99.1", "6to4-relay-anycast"),
    ("192.0.0.9", "ietf-protocol-assignments"),
    ("192.0.0.10", "ietf-protocol-assignments"),
    ("::ffff:8.8.8.8", "ipv4-mapped"),
    ("::ffff:127.0.0.1", "ipv4-mapped"),
    ("::ffff:169.254.169.254", "ipv4-mapped"),
    ("::7f00:1", "ipv6-outside-global-unicast"),
    ("::a00:1", "ipv6-outside-global-unicast"),
    ("fec0::1", "site-local"),
    ("2002:7f00:1::", "6to4"),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "teredo"),
    ("224.0.0.1", "multicast"),
    ("239.255.255.250", "multicast"),
    ("ff02::1", "multicast"),
    ("ff0e::1", "multicast"),
    ("169.254.169.254", "link-local"),
    ("fd00:ec2::254", "unique-local"),
    ("100::1", "discard-only"),
    ("4000::1", "ipv6-outside-global-unicast"),
    ("2001:2::1", "not-global"),
    ("2001:10::1", "not-global"),
]


@pytest.mark.parametrize(("addr", "reason"), GAPS)
def test_u07_known_gaps_prohibited(addr: str, reason: str) -> None:
    verdict = classify_address(ip_address(addr))
    assert (verdict.permitted, verdict.reason) == (False, reason)


# Public addresses, including neighbours just outside each IPv4 range (U-08).
PUBLIC = [
    "1.1.1.1",
    "8.8.8.8",
    "9.255.255.255",
    "11.0.0.0",
    "100.63.255.255",
    "100.128.0.0",
    "126.255.255.255",
    "128.0.0.0",
    "169.253.255.255",
    "169.255.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.0.1.0",
    "192.0.3.0",
    "192.88.98.255",
    "192.88.100.0",
    "192.167.255.255",
    "192.169.0.0",
    "198.17.255.255",
    "198.20.0.0",
    "198.51.99.255",
    "198.51.101.0",
    "203.0.112.255",
    "203.0.114.0",
    "223.255.255.255",
    "2606:4700:4700::1111",
    "2620:4f:8000::1",
    "2a00:1450:4001:80b::200e",
    "2003::1",
    "2001:db9::1",
]


@pytest.mark.parametrize("addr", PUBLIC)
def test_u08_public_permitted(addr: str) -> None:
    verdict = classify_address(ip_address(addr))
    assert (verdict.permitted, verdict.reason) == (True, "public")


def test_u09_scope_literal_and_port() -> None:
    p = PublicScopePolicy()
    assert p.check_literal(None, 443).permitted
    assert p.check_literal(None, 8443).permitted
    assert p.check_literal(None, 80).reason == "port_not_permitted"
    d = p.check_literal(ip_address("127.0.0.1"), 443)
    assert (d.permitted, d.reason, d.offending) == (False, "loopback", ip_address("127.0.0.1"))
    assert p.check_literal(ip_address("1.1.1.1"), 443).permitted


def test_u09_scope_any_prohibited_answer_rejects() -> None:
    p = PublicScopePolicy()
    assert p.check_resolved([ip_address("1.1.1.1"), ip_address("8.8.8.8")]).permitted
    mixed = p.check_resolved([ip_address("1.1.1.1"), ip_address("10.0.0.1")])
    assert (mixed.permitted, mixed.offending) == (False, ip_address("10.0.0.1"))
    assert not p.check_resolved([]).permitted


def test_u09_case_count() -> None:
    """The plan requires >= 55 address table cases."""
    assert len(BOUNDARIES) + len(GAPS) + len(PUBLIC) >= 55
