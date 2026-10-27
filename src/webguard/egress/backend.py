"""GuardedNetworkBackend: connect only to pinned, classified addresses (Plan §9.3, INV-02/04).

httpcore hands us the URL host and port; we never resolve them. We dial the pinned IPs from
the hop's single resolution and assert the connected peer is one of them before returning a
stream, i.e. before a single request byte can be written.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable, Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address

from httpcore import NetworkBackend, NetworkStream

from webguard.domain.budget import (
    CONNECT_ATTEMPTS_PER_HOP,
    CONNECT_TIMEOUT_S,
    Budget,
    DeadlineExceededError,
    clamp,
)
from webguard.egress.errors import (
    ConnectFailedError,
    ConnectTimeoutError,
    EgressError,
    PolicyViolationError,
)
from webguard.egress.stream import GuardedStream, HopRecorder

IPAddress = IPv4Address | IPv6Address


class GuardedNetworkBackend(NetworkBackend):
    def __init__(
        self,
        *,
        expected_host: str,
        expected_port: int,
        pinned: Sequence[IPAddress],
        budget: Budget,
        recorder: HopRecorder,
        ssl_context: ssl.SSLContext,
    ) -> None:
        if not pinned:
            raise PolicyViolationError("no_pinned_addresses")
        self._expected_host = expected_host
        self._expected_port = expected_port
        self._pinned: tuple[IPAddress, ...] = tuple(pinned)
        self._budget = budget
        self._recorder = recorder
        self._ssl_context = ssl_context

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[object] | None = None,
    ) -> NetworkStream:
        if host != self._expected_host or port != self._expected_port:
            raise PolicyViolationError("connect_target_mismatch")
        if local_address is not None or socket_options:
            raise PolicyViolationError("unexpected_socket_options")
        last: EgressError = ConnectFailedError("no_attempt")
        for ip in self._pinned[:CONNECT_ATTEMPTS_PER_HOP]:
            try:
                sock = self._dial(ip, port)
            except EgressError as exc:
                last = exc
                continue
            self._verify_peer(sock)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return GuardedStream(
                sock,
                budget=self._budget,
                recorder=self._recorder,
                expected_host=self._expected_host,
                ssl_context=self._ssl_context,
            )
        raise last

    def _dial(self, ip: IPAddress, port: int) -> socket.socket:
        family = socket.AF_INET6 if isinstance(ip, IPv6Address) else socket.AF_INET
        self._recorder.connect_attempts += 1
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(clamp(CONNECT_TIMEOUT_S, self._budget))
            sock.connect((str(ip), port))
        except TimeoutError as exc:
            sock.close()
            if self._budget.remaining() <= 0:
                raise DeadlineExceededError from exc
            raise ConnectTimeoutError from exc
        except OSError as exc:
            sock.close()
            raise ConnectFailedError from exc
        except BaseException:
            sock.close()
            raise
        return sock

    def _verify_peer(self, sock: socket.socket) -> None:
        """INV-02: the connected peer must be one of this hop's pinned addresses."""
        try:
            peer = ip_address(str(sock.getpeername()[0]).split("%", 1)[0])
        except (OSError, ValueError) as exc:
            sock.close()
            raise PolicyViolationError("peer_unknown") from exc
        if peer not in self._pinned:
            sock.close()
            raise PolicyViolationError("peer_not_pinned")
        self._recorder.connected_ip = peer

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[object] | None = None,
    ) -> NetworkStream:
        raise PolicyViolationError("unix_socket_forbidden")

    def sleep(self, seconds: float) -> None:
        raise PolicyViolationError("retry_forbidden")
