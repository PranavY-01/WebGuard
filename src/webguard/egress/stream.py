"""GuardedStream: deadline clamp and byte cap on every socket operation (Plan §9.4).

Every read/write recomputes its timeout as min(phase_limit, budget.remaining()), so a
slow-drip peer can never stretch the scan past its deadline (INV-08). Bytes read are counted
per hop and capped at MAX_BYTES_PER_HOP regardless of what the HTTP parser allows (INV-07).
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from httpcore import NetworkStream

from webguard.domain.budget import (
    MAX_BYTES_PER_HOP,
    READ_TIMEOUT_S,
    TLS_WRITE_TIMEOUT_S,
    Budget,
    clamp,
)
from webguard.domain.evidence import TlsEvidence
from webguard.egress.capture import capture_tls
from webguard.egress.errors import (
    ConnectTimeoutError,
    MalformedResponseError,
    PolicyViolationError,
    ReadTimeoutError,
    ResponseTooLargeError,
    TlsHandshakeError,
)


@dataclass
class HopRecorder:
    """Mutable per-hop facts gathered below httpcore; read by fetch_hop after the exchange."""

    connected_ip: IPv4Address | IPv6Address | None = None
    tls_attempted: bool = False
    ssl_object: ssl.SSLSocket | None = None
    tls_evidence: TlsEvidence | None = None
    tls_verify_failed: bool = False
    verify_code: int | None = None
    verify_message: str | None = None
    bytes_read: int = 0
    bytes_written: int = 0
    connect_attempts: int = 0


class GuardedStream(NetworkStream):
    def __init__(
        self,
        sock: socket.socket,
        *,
        budget: Budget,
        recorder: HopRecorder,
        expected_host: str,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self._sock = sock
        self._budget = budget
        self._recorder = recorder
        self._expected_host = expected_host
        self._ssl_context = ssl_context

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        allowance = MAX_BYTES_PER_HOP - self._recorder.bytes_read
        if allowance < 0:
            raise ResponseTooLargeError("byte_cap")
        self._sock.settimeout(clamp(READ_TIMEOUT_S, self._budget))
        try:
            # Ask for at most one byte past the cap, so the overshoot is bounded by 1 byte.
            data = self._sock.recv(min(max_bytes, allowance + 1))
        except TimeoutError as exc:
            raise ReadTimeoutError from exc
        except ssl.SSLError as exc:
            raise MalformedResponseError("tls_record_error") from exc
        except OSError as exc:
            raise MalformedResponseError("connection_error") from exc
        self._recorder.bytes_read += len(data)
        if self._recorder.bytes_read > MAX_BYTES_PER_HOP:
            raise ResponseTooLargeError("byte_cap")
        return data

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if not buffer:
            return
        self._sock.settimeout(clamp(TLS_WRITE_TIMEOUT_S, self._budget))
        try:
            self._sock.sendall(buffer)
        except TimeoutError as exc:
            raise ReadTimeoutError("write_timeout") from exc
        except OSError as exc:
            raise MalformedResponseError("connection_error") from exc
        self._recorder.bytes_written += len(buffer)

    def close(self) -> None:
        self._sock.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> NetworkStream:
        if server_hostname != self._expected_host:
            self.close()
            raise PolicyViolationError("sni_host_mismatch")
        if ssl_context is not self._ssl_context:
            self.close()
            raise PolicyViolationError("unexpected_ssl_context")
        self._recorder.tls_attempted = True
        try:
            self._sock.settimeout(clamp(TLS_WRITE_TIMEOUT_S, self._budget))
            tls_sock = ssl_context.wrap_socket(self._sock, server_hostname=server_hostname)
        except ssl.SSLCertVerificationError as exc:
            # Captured at the source: httpcore's pool re-raises `from None` (P0, A-03).
            self._recorder.tls_verify_failed = True
            self._recorder.verify_code = exc.verify_code
            self._recorder.verify_message = exc.verify_message
            self.close()
            raise TlsHandshakeError("certificate_verification") from exc
        except TimeoutError as exc:
            self.close()
            raise ConnectTimeoutError("tls_handshake_timeout") from exc
        except ssl.SSLError as exc:
            self.close()
            raise TlsHandshakeError("handshake_error") from exc
        except OSError as exc:
            self.close()
            raise TlsHandshakeError("handshake_connection_error") from exc
        except BaseException:
            self.close()
            raise
        self._recorder.ssl_object = tls_sock
        # TLS facts are read now, from this hop's own socket, while it is open (D-14).
        self._recorder.tls_evidence = capture_tls(tls_sock)
        return GuardedStream(
            tls_sock,
            budget=self._budget,
            recorder=self._recorder,
            expected_host=self._expected_host,
            ssl_context=self._ssl_context,
        )

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object" and isinstance(self._sock, ssl.SSLSocket):
            return self._sock
        return None
