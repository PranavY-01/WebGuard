"""Name resolution (Plan §9.2): exactly once per hop, bounded by a daemon-thread join.

The timeout is enforced around *any* Resolver implementation, so a resolver that never returns
(a hung system resolver or a test stub) still ends in `dns_timeout` within the clamp.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Protocol

from webguard.domain.budget import MAX_DNS_ANSWERS
from webguard.egress.errors import (
    DnsNoAnswerError,
    DnsTimeoutError,
    DnsTooManyAnswersError,
    EgressError,
)

IPAddress = IPv4Address | IPv6Address


class Resolver(Protocol):
    def resolve(self, host: str, port: int, timeout_s: float) -> Sequence[IPAddress]:
        """Return every A/AAAA answer for `host`. May block; the caller bounds it."""
        ...


class SystemResolver:
    """Production resolver: one getaddrinfo call, TCP stream answers of any family."""

    def resolve(self, host: str, port: int, timeout_s: float) -> Sequence[IPAddress]:
        del timeout_s  # getaddrinfo is not cancellable; resolve_bounded enforces the bound.
        try:
            infos = socket.getaddrinfo(
                host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP
            )
        except (OSError, UnicodeError) as exc:
            raise DnsNoAnswerError("resolver_error") from exc
        answers: list[IPAddress] = []
        for family, _type, _proto, _canon, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            answers.append(ip_address(str(sockaddr[0]).split("%", 1)[0]))
        return answers


def resolve_bounded(resolver: Resolver, host: str, port: int, timeout_s: float) -> list[IPAddress]:
    """Run one resolution in a daemon thread joined with `timeout_s`; dedupe, preserve order.

    An abandoned thread cannot block interpreter exit (A-11) and its result is discarded.
    """
    box: dict[str, object] = {}

    def run() -> None:
        try:
            box["answers"] = list(resolver.resolve(host, port, timeout_s))
        except EgressError as exc:
            box["error"] = exc
        except Exception as exc:  # reason: thread boundary; mapped to dns_no_answer below
            box["error"] = DnsNoAnswerError(f"resolver_{type(exc).__name__}")

    worker = threading.Thread(target=run, name="webguard-dns", daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive():
        raise DnsTimeoutError
    error = box.get("error")
    if isinstance(error, EgressError):
        raise error
    raw = box.get("answers")
    if not isinstance(raw, list):
        raise DnsNoAnswerError("no_result")
    answers: list[IPAddress] = []
    for item in raw:
        if not isinstance(item, IPv4Address | IPv6Address):
            raise DnsNoAnswerError("non_address_answer")
        if item not in answers:
            answers.append(item)
    if not answers:
        raise DnsNoAnswerError
    if len(answers) > MAX_DNS_ANSWERS:
        raise DnsTooManyAnswersError
    return answers
