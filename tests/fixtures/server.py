"""Threaded local TLS fixture server (never shipped).

Listens on loopback only. Records TCP connections, SNI names, raw request bytes and handshake
errors. Behaviour is selected by request path, so redirect chains and loops need no state.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from tests.fixtures.pki import FixturePki

SENTINEL = "WG_SENTINEL_9f3c"
FULL_HEADERS = [
    (b"Strict-Transport-Security", b"max-age=31536000; includeSubDomains"),
    (b"Content-Security-Policy", b"default-src 'self'"),
    (b"X-Content-Type-Options", b"nosniff"),
    (b"Set-Cookie", b"sid=" + SENTINEL.encode() + b"; Secure; HttpOnly; SameSite=Lax; Path=/"),
    (b"Content-Type", b"text/html; charset=utf-8"),
]


@dataclass
class Received:
    sni: str | None
    raw: bytes

    @property
    def request_line(self) -> bytes:
        return self.raw.split(b"\r\n", 1)[0]

    @property
    def header_lines(self) -> list[bytes]:
        head = self.raw.split(b"\r\n\r\n", 1)[0]
        return head.split(b"\r\n")[1:]


@dataclass
class ServerLog:
    connections: int = 0
    received: list[Received] = field(default_factory=list)
    snis: list[str | None] = field(default_factory=list)
    handshake_errors: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def clear(self) -> None:
        with self.lock:
            self.connections = 0
            self.received.clear()
            self.snis.clear()
            self.handshake_errors.clear()


def response(status: bytes, headers: list[tuple[bytes, bytes]], body: bytes = b"") -> bytes:
    lines = [b"HTTP/1.1 " + status]
    lines += [name + b": " + value for name, value in headers]
    lines += [b"Content-Length: " + str(len(body)).encode(), b"", b""]
    return b"\r\n".join(lines) + body


def _redirect(status: bytes, location: bytes) -> bytes:
    return response(status, [(b"Location", location), *FULL_HEADERS[:1]])


class FixtureServer:
    def __init__(self, pki: FixturePki, host: str, port: int) -> None:
        self.pki = pki
        self.host = host
        self.port = port
        self.log = ServerLog()
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._listener = socket.socket(family, socket.SOCK_STREAM)
        self._listener.bind((host, port))
        self._listener.listen(32)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._default_ctx, self._contexts = pki.server_contexts()
        self._default_ctx.sni_callback = self._pick_context

    def start(self) -> FixtureServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(5)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            with self.log.lock:
                self.log.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _pick_context(
        self, sock: ssl.SSLSocket | ssl.SSLObject, name: str | None, _ctx: ssl.SSLContext
    ) -> None:
        with self.log.lock:
            self.log.snis.append(name)
        sock.wg_sni = name  # type: ignore[union-attr]  # reason: tag this connection with its SNI
        sock.context = self._contexts.get(name or "", self._default_ctx)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        try:
            tls = self._default_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            with self.log.lock:
                self.log.handshake_errors.append(type(exc).__name__)
            conn.close()
            return
        sni = getattr(tls, "wg_sni", None)
        try:
            raw = b""
            while b"\r\n\r\n" not in raw and len(raw) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                raw += chunk
            with self.log.lock:
                self.log.received.append(Received(sni, raw))
            target = raw.split(b"\r\n", 1)[0].split(b" ")[1].decode() if b" " in raw else "/"
            self._route(tls, target)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                tls.close()

    def _route(self, tls: ssl.SSLSocket, target: str) -> None:
        parts = urlsplit(target)
        path, query = parts.path, parse_qs(parts.query)
        handler = ROUTES.get(path)
        if handler is not None:
            handler(tls, query)
            return
        if path.startswith("/chain/"):
            n = int(path.rsplit("/", 1)[1])
            nxt = b"/" if n == 0 else b"/chain/" + str(n - 1).encode()
            tls.sendall(
                _redirect(b"302 Found", nxt) if n > 0 else response(b"200 OK", FULL_HEADERS)
            )
            return
        tls.sendall(response(b"404 Not Found", [(b"X-Content-Type-Options", b"nosniff")]))


def _send(data: bytes) -> Callable[[ssl.SSLSocket, dict[str, list[str]]], None]:
    def handler(tls: ssl.SSLSocket, _q: dict[str, list[str]]) -> None:
        tls.sendall(data)

    return handler


def _redirect_to(tls: ssl.SSLSocket, query: dict[str, list[str]]) -> None:
    status = query.get("status", ["301"])[0].encode()
    tls.sendall(_redirect(status + b" Redirect", query["to"][0].encode()))


def _slowdrip(tls: ssl.SSLSocket, _q: dict[str, list[str]]) -> None:
    for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 64:
        tls.sendall(bytes([byte]))
        time.sleep(2)


def _stall(tls: ssl.SSLSocket, _q: dict[str, list[str]]) -> None:
    tls.sendall(b"HTTP/1.1 200 OK\r\n")
    time.sleep(60)


def _bigheaders(tls: ssl.SSLSocket, _q: dict[str, list[str]]) -> None:
    tls.sendall(b"HTTP/1.1 200 OK\r\n")
    for i in range(3300):  # ~200 KiB of header lines
        tls.sendall(b"X-Pad-%05d: " % i + b"a" * 50 + b"\r\n")


def _bigbody(tls: ssl.SSLSocket, _q: dict[str, list[str]]) -> None:
    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 50000000\r\n\r\n")
    for _ in range(800):
        tls.sendall(b"x" * 65536)


COOKIES = [
    (b"Set-Cookie", b"a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure"),
    (b"Set-Cookie", b"b=" + SENTINEL.encode() + b"; HttpOnly"),
    (b"Set-Cookie", b"__Host-c=3; Secure; Path=/"),
    (b"Set-Cookie", b"__Secure-d=4"),
    (b"Set-Cookie", b"e=5; SameSite=None"),
    (b"Set-Cookie", b"f=6; SameSite=None; Secure"),
    (b"Set-Cookie", b"g=7; SameSite=bogus; Secure; HttpOnly"),
]

MALICIOUS = [
    (b"Content-Security-Policy", b"<script>alert(1)</script>"),
    (b"X-Content-Type-Options", b"[link=https://evil.test]x[/link] [bold]B[/bold]"),
    (b"Content-Type", b"text/html\x9b2J \xe2\x80\xae-bidi"),
    (b"Set-Cookie", b"<img src=x>=" + SENTINEL.encode() + b"; Path=/\x9b31m"),
    (b"Strict-Transport-Security", b"max-age=1; %0d%0aX-Injected: 1"),
]

ROUTES: dict[str, Callable[[ssl.SSLSocket, dict[str, list[str]]], None]] = {
    "/": _send(response(b"200 OK", FULL_HEADERS, b"hello")),
    "/missing": _send(response(b"200 OK", [])),
    "/cookies": _send(response(b"200 OK", COOKIES)),
    "/many-cookies": _send(response(b"200 OK", [(b"Set-Cookie", b"k%d=v" % i) for i in range(60)])),
    "/malicious": _send(response(b"200 OK", MALICIOUS)),
    "/redirect": _redirect_to,
    "/loop/a": _send(_redirect(b"302 Found", b"/loop/b")),
    "/loop/b": _send(_redirect(b"302 Found", b"/loop/a")),
    "/downgrade": _send(_redirect(b"301 Moved", b"http://webguard.test/")),
    "/dup-location": _send(response(b"302 Found", [(b"Location", b"/a"), (b"Location", b"/b")])),
    "/created": _send(
        response(b"201 Created", [(b"Location", b"/thing?secret=" + SENTINEL.encode())])
    ),
    "/notfound": _send(response(b"404 Not Found", [(b"X-Content-Type-Options", b"nosniff")])),
    "/error": _send(
        response(b"503 Unavailable", [(b"Content-Security-Policy", b"default-src 'none'")])
    ),
    "/many-headers": _send(response(b"200 OK", [(b"X-H%d" % i, b"v") for i in range(150)])),
    "/bad-status": _send(b"HTTP/1.1 2x0 NOPE\r\n\r\n"),
    "/http10": _send(b"HTTP/1.0 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n"),
    "/slowdrip": _slowdrip,
    "/stall": _stall,
    "/bigheaders": _bigheaders,
    "/bigbody": _bigbody,
}


class ProxyTrap:
    """A plain TCP listener that only counts connections (S-14 proxy-environment poisoning)."""

    def __init__(self) -> None:
        self.connections = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self._sock.close()
