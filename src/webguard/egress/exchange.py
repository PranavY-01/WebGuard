"""fetch_hop: the only network entry point in WebGuard (Plan §9.1, §9.6).

One hop = resolve once -> classify every answer -> pin -> connect -> assert peer -> verified
TLS -> one GET with the fixed header set -> status line + headers -> close without reading the
body. Exceptions are caught only here, and only to map them to a FailureCode; KeyboardInterrupt
is a BaseException and propagates untouched to the orchestrator.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import httpcore

from webguard import __version__
from webguard.domain.budget import (
    CONNECT_ATTEMPTS_PER_HOP,
    CONNECT_TIMEOUT_S,
    DNS_TIMEOUT_S,
    POOL_TIMEOUT_S,
    READ_TIMEOUT_S,
    TLS_WRITE_TIMEOUT_S,
    Budget,
    clamp,
)
from webguard.domain.config import EgressConfig
from webguard.domain.enums import FailureCode
from webguard.domain.evidence import HopEvidence, HopFailure, HttpEvidence, TlsEvidence
from webguard.egress.backend import GuardedNetworkBackend
from webguard.egress.capture import (
    capture_http,
    capture_tls_failure,
    safe_detail,
)
from webguard.egress.errors import PolicyViolationError, TlsHandshakeError, classify
from webguard.egress.resolver import IPAddress, Resolver, resolve_bounded
from webguard.egress.stream import HopRecorder
from webguard.egress.tls_context import get_ssl_context
from webguard.policy.scope import Decision, ScopePolicy
from webguard.policy.url import CanonicalTarget, UrlRejection

log = logging.getLogger("webguard.egress")

USER_AGENT = (
    f"WebGuard/{__version__} (+passive configuration audit; https://github.com/PranavY-01/WebGuard)"
)


_LIBRARY_LOGGERS = ("httpcore", "h11")


def pin_library_loggers() -> None:
    """httpcore's DEBUG trace logs raw request/response headers, including cookie values
    (T-25). Pin it and h11, with every child logger, to WARNING before any I/O. Done here as
    well as in the CLI's logging setup so Python API callers are protected too."""
    names = [
        name
        for name in logging.root.manager.loggerDict
        if any(name == lib or name.startswith(f"{lib}.") for lib in _LIBRARY_LOGGERS)
    ]
    for name in (*_LIBRARY_LOGGERS, *names):
        logger = logging.getLogger(name)
        if logger.level == logging.NOTSET or logger.level < logging.WARNING:
            logger.setLevel(logging.WARNING)


@dataclass(frozen=True, slots=True)
class HopRequest:
    index: int
    target: CanonicalTarget


@dataclass(frozen=True, slots=True)
class HopOutcome:
    evidence: HopEvidence
    next_target: CanonicalTarget | UrlRejection | None = None
    """Validated redirect target (3xx only). Never raw Location text (INV-09)."""
    bytes_read: int = 0
    connect_attempts: int = field(default=0)


def request_headers(target: CanonicalTarget, user_agent: str) -> list[tuple[bytes, bytes]]:
    """Exactly the D-05 set, in a fixed order. Nothing else is ever sent (INV-16)."""
    return [
        (b"Host", target.host_header.encode("ascii")),
        (b"User-Agent", user_agent.encode("ascii")),
        (b"Accept", b"*/*"),
        (b"Accept-Encoding", b"identity"),
        (b"Connection", b"close"),
    ]


def _policy_detail(decision: Decision) -> str:
    return (
        decision.reason if decision.offending is None else f"{decision.reason}:{decision.offending}"
    )


def _exchange(
    request: HopRequest,
    budget: Budget,
    policy: ScopePolicy,
    cfg: EgressConfig,
    resolver: Resolver,
    recorder: HopRecorder,
    resolved: list[IPAddress],
) -> tuple[HttpEvidence, TlsEvidence, CanonicalTarget | UrlRejection | None]:
    target = request.target
    literal = policy.check_literal(target.host_ip, target.port)
    if not literal.permitted:
        raise PolicyViolationError(_policy_detail(literal))
    budget.charge_request()
    if target.host_ip is not None:
        answers: list[IPAddress] = [target.host_ip]
    else:
        answers = resolve_bounded(resolver, target.host, target.port, clamp(DNS_TIMEOUT_S, budget))
    resolved.extend(answers)
    decision = policy.check_resolved(answers)
    if not decision.permitted:
        raise PolicyViolationError(_policy_detail(decision))

    ssl_context = get_ssl_context(cfg)
    backend = GuardedNetworkBackend(
        expected_host=target.host,
        expected_port=target.port,
        pinned=answers[:CONNECT_ATTEMPTS_PER_HOP],
        budget=budget,
        recorder=recorder,
        ssl_context=ssl_context,
    )
    timeouts = {
        "connect": clamp(CONNECT_TIMEOUT_S, budget),
        "read": clamp(READ_TIMEOUT_S, budget),
        "write": clamp(TLS_WRITE_TIMEOUT_S, budget),
        "pool": clamp(POOL_TIMEOUT_S, budget),
    }
    url = httpcore.URL(
        scheme=b"https",
        host=target.host.encode("ascii"),
        port=target.port,
        target=target.request_target.encode("ascii"),
    )
    with (
        httpcore.ConnectionPool(
            ssl_context=ssl_context,
            http1=True,
            http2=False,
            retries=0,
            max_connections=1,
            keepalive_expiry=0,
            network_backend=backend,
        ) as pool,
        pool.stream(
            "GET",
            url,
            headers=request_headers(target, cfg.user_agent),
            extensions={"timeout": timeouts},
        ) as response,
    ):
        # Status line and headers only; leaving the block closes without reading the body.
        http_evidence, next_target = capture_http(
            response.status,
            response.extensions.get("http_version", b""),
            response.headers,
            target,
        )
        if recorder.tls_evidence is None:
            raise TlsHandshakeError("no_tls_session")
        tls_evidence = recorder.tls_evidence
    return http_evidence, tls_evidence, next_target


def fetch_hop(
    request: HopRequest,
    budget: Budget,
    policy: ScopePolicy,
    cfg: EgressConfig,
    resolver: Resolver,
) -> HopOutcome:
    pin_library_loggers()
    target = request.target
    recorder = HopRecorder()
    resolved: list[IPAddress] = []
    started = time.monotonic()
    base = {
        "index": request.index,
        "url_redacted": target.display_url_redacted,
        "host": target.host,
        "port": target.port,
    }
    try:
        http_evidence, tls_evidence, next_target = _exchange(
            request, budget, policy, cfg, resolver, recorder, resolved
        )
        evidence = HopEvidence(
            **base,
            resolved_ips=resolved,
            connected_ip=recorder.connected_ip,
            tls=tls_evidence,
            http=http_evidence,
        )
        code: FailureCode | None = None
    except Exception as exc:  # reason: the single egress catch boundary (Plan §9.8)
        code, detail = classify(exc)
        next_target = None
        evidence = _failure_evidence(base, resolved, recorder, code, detail)
    log.debug(
        "hop %d %s: answers=%d connected=%s bytes_read=%d elapsed=%.3fs outcome=%s",
        request.index,
        target.display_url_redacted,
        len(resolved),
        str(recorder.connected_ip),
        recorder.bytes_read,
        time.monotonic() - started,
        code.value if code else "http",
    )
    return HopOutcome(
        evidence=evidence,
        next_target=next_target,
        bytes_read=recorder.bytes_read,
        connect_attempts=recorder.connect_attempts,
    )


def _failure_evidence(
    base: dict[str, object],
    resolved: list[IPAddress],
    recorder: HopRecorder,
    code: FailureCode,
    detail: str | None,
) -> HopEvidence:
    connected = recorder.connected_ip if recorder.connected_ip in resolved else None
    try:
        if recorder.tls_verify_failed:
            return HopEvidence.model_validate(
                {
                    **base,
                    "resolved_ips": resolved,
                    "connected_ip": connected,
                    "tls": capture_tls_failure(recorder.verify_code, recorder.verify_message),
                }
            )
        tls = recorder.tls_evidence
        return HopEvidence.model_validate(
            {
                **base,
                "resolved_ips": resolved,
                "connected_ip": connected,
                "tls": tls,
                "failure": HopFailure(code=code, detail=safe_detail(detail)),
            }
        )
    except Exception:  # reason: evidence construction must not leak raw exceptions (F-16)
        return HopEvidence.model_validate(
            {
                **base,
                "resolved_ips": [],
                "failure": HopFailure(code=FailureCode.INTERNAL_ERROR, detail="evidence_build"),
            }
        )
