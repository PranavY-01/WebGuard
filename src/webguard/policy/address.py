"""Destination address classification (Plan §10.2, D-08).

An address is permitted iff ALL hold:
  * `ip.is_global` is True,
  * it is not multicast,
  * it is not in the explicit denylist (either check alone denies; both must agree to permit),
  * it is not IPv4-mapped IPv6,
  * (stricter, recorded decision) IPv6 lies inside 2000::/3, the only block IANA allocates
    for global unicast. This also closes IPv4-compatible `::a.b.c.d` and the rest of ::/8.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import Final

IPAddress = IPv4Address | IPv6Address

_IPV4_DENY: Final[tuple[tuple[str, str], ...]] = (
    ("0.0.0.0/8", "this-network"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "shared-address-space"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "ietf-protocol-assignments"),
    ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "6to4-relay-anycast"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("255.255.255.255/32", "limited-broadcast"),
)

_IPV6_DENY: Final[tuple[tuple[str, str], ...]] = (
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("::ffff:0:0/96", "ipv4-mapped"),
    ("64:ff9b::/96", "nat64"),
    ("64:ff9b:1::/48", "nat64-local"),
    ("100::/64", "discard-only"),
    ("2001::/32", "teredo"),
    ("2001:db8::/32", "documentation"),
    ("2002::/16", "6to4"),
    ("fc00::/7", "unique-local"),
    ("fe80::/10", "link-local"),
    ("fec0::/10", "site-local"),
    ("ff00::/8", "multicast"),
)

DENYLIST: Final[tuple[tuple[IPv4Network | IPv6Network, str], ...]] = tuple(
    (ip_network(net), label) for net, label in (*_IPV4_DENY, *_IPV6_DENY)
)

_IPV6_GLOBAL_UNICAST: Final = IPv6Network("2000::/3")


@dataclass(frozen=True, slots=True)
class AddressVerdict:
    permitted: bool
    reason: str
    """Static class label, e.g. "loopback" or "not-global"; "public" when permitted."""


def classify_address(ip: IPAddress) -> AddressVerdict:
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return AddressVerdict(False, "ipv4-mapped")
    for net, label in DENYLIST:
        if ip.version == net.version and ip in net:
            return AddressVerdict(False, label)
    if ip.is_multicast:
        return AddressVerdict(False, "multicast")
    if isinstance(ip, IPv6Address) and ip not in _IPV6_GLOBAL_UNICAST:
        return AddressVerdict(False, "ipv6-outside-global-unicast")
    if not ip.is_global:
        return AddressVerdict(False, "not-global")
    return AddressVerdict(True, "public")
