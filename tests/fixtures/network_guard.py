"""Mechanical enforcement of the test-suite no-internet rule (S-29, INV-05).

Installed for every test by an autouse fixture in tests/conftest.py. Outbound connects and name
lookups are allowed only for loopback literals (and "localhost"); anything else raises before a
packet is sent. Never shipped.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from ipaddress import ip_address
from typing import Any

import pytest

_LOCAL_NAMES = frozenset({"localhost", b"localhost"})


class OutboundNetworkBlockedError(BaseException):
    """BaseException on purpose: egress's `except Exception` boundary must not absorb it and
    turn a forbidden connection into an ordinary failure code."""


def is_loopback_literal(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    try:
        return ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class NetworkGuard:
    def __init__(self) -> None:
        self.blocked: list[str] = []

    def check_address(self, family: int, address: object) -> None:
        if family == getattr(socket, "AF_UNIX", None):
            return  # local IPC, not a network host
        host = address[0] if isinstance(address, tuple) and address else address
        if not is_loopback_literal(host):
            self._block(f"connect {address!r}")

    def check_name(self, host: object) -> None:
        if host is None or host in _LOCAL_NAMES or is_loopback_literal(host):
            return
        self._block(f"resolve {host!r}")

    def _block(self, what: str) -> None:
        self.blocked.append(what)
        raise OutboundNetworkBlockedError(f"test suite may only contact loopback: {what}")

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_create_connection = socket.create_connection
        real_getaddrinfo = socket.getaddrinfo

        def connect(sock: socket.socket, address: Any) -> None:
            self.check_address(sock.family, address)
            real_connect(sock, address)

        def connect_ex(sock: socket.socket, address: Any) -> int:
            self.check_address(sock.family, address)
            return real_connect_ex(sock, address)

        def create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
            self.check_address(socket.AF_INET, address)
            return real_create_connection(address, *args, **kwargs)

        def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
            self.check_name(host)
            return real_getaddrinfo(host, *args, **kwargs)

        patches: list[tuple[object, str, Callable[..., Any]]] = [
            (socket.socket, "connect", connect),
            (socket.socket, "connect_ex", connect_ex),
            (socket, "create_connection", create_connection),
            (socket, "getaddrinfo", getaddrinfo),
        ]
        for owner, name, replacement in patches:
            monkeypatch.setattr(owner, name, replacement)
