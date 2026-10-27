"""Egress security tests on real loopback sockets.

No mocks of the backend, stream, SSL context or fetch_hop; only the permitted doubles.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import socket
import ssl
import threading
import time
from ipaddress import ip_address
from pathlib import Path

import certifi
import pytest

from tests.conftest import FIXTURE_PORT, target
from tests.fixtures import pki as certs
from tests.fixtures.pki import FixturePki
from tests.fixtures.server import SENTINEL, FixtureServer, ProxyTrap
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.app.budget import ScanBudget
from webguard.domain.budget import MAX_BYTES_PER_HOP
from webguard.domain.config import EgressConfig
from webguard.domain.enums import FailureCode
from webguard.egress import USER_AGENT, HopOutcome, HopRequest, build_production_egress, fetch_hop
from webguard.egress.backend import GuardedNetworkBackend
from webguard.egress.errors import PolicyViolationError, ResponseTooLargeError
from webguard.egress.stream import GuardedStream, HopRecorder
from webguard.egress.tls_context import build_ssl_context, get_ssl_context
from webguard.policy.scope import PublicScopePolicy, ScopePolicy
from webguard.policy.url import CanonicalTarget

LOOP4 = "127.0.0.1"


def fetch(
    cfg: EgressConfig,
    path: str = "/",
    *,
    host: str = "webguard.test",
    resolver: StubResolver | None = None,
    policy: ScopePolicy | None = None,
    budget: ScanBudget | None = None,
    tgt: CanonicalTarget | None = None,
    index: int = 0,
) -> HopOutcome:
    return fetch_hop(
        HopRequest(index=index, target=tgt or target(path, host)),
        budget or ScanBudget(30),
        policy or TestScopePolicy(),
        cfg,
        resolver or StubResolver([LOOP4]),
    )


def failure_code(outcome: HopOutcome) -> FailureCode | None:
    failure = outcome.evidence.failure
    return failure.code if failure else None


# --- baseline ---------------------------------------------------------------------------------


def test_clean_hop_captures_headers_cookies_and_tls(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    out = fetch(egress_cfg)
    ev = out.evidence
    assert ev.failure is None
    assert ev.http is not None
    assert ev.tls is not None
    assert ev.http.status_code == 200
    assert ev.http.first("strict-transport-security") == "max-age=31536000; includeSubDomains"
    assert [c.name for c in ev.http.cookies] == ["sid"]
    assert ev.tls.verified
    assert ev.tls.protocol_version in {"TLSv1.2", "TLSv1.3"}
    assert ev.tls.cert is not None
    assert "webguard.test" in ev.tls.cert.san_dns
    assert ev.connected_ip == ip_address(LOOP4)
    assert server.log.connections == 1
    assert out.next_target is None


# --- S-01 / S-02 / S-03: policy before any resolution or connection --------------------------


def test_s01_literal_policy_rejection_makes_no_dns_and_no_connection(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    resolver = StubResolver([LOOP4])
    bad_port = dataclasses.replace(target(), port=22)
    out = fetch(egress_cfg, resolver=resolver, tgt=bad_port)
    assert failure_code(out) is FailureCode.POLICY_PROHIBITED_ADDRESS
    assert resolver.calls == []
    assert server.log.connections == 0


def test_s02_prohibited_literal_ip_makes_zero_connections(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    resolver = StubResolver([LOOP4])
    out = fetch(egress_cfg, host="127.0.0.1", resolver=resolver, policy=PublicScopePolicy())
    assert failure_code(out) is FailureCode.POLICY_PROHIBITED_ADDRESS
    assert out.evidence.failure is not None
    assert out.evidence.failure.detail == "loopback:127.0.0.1"
    assert resolver.calls == []
    assert server.log.connections == 0


def test_s02_prohibited_v6_literal_under_test_policy(
    egress_cfg: EgressConfig, server: FixtureServer, server6: FixtureServer | None
) -> None:
    out = fetch(egress_cfg, host="[::1]")
    assert failure_code(out) is FailureCode.POLICY_PROHIBITED_ADDRESS
    assert server.log.connections == 0
    if server6 is not None:
        assert server6.log.connections == 0


def test_s03_mixed_answers_rejected_with_zero_connections(
    egress_cfg: EgressConfig, server: FixtureServer, server6: FixtureServer | None
) -> None:
    out = fetch(egress_cfg, resolver=StubResolver([LOOP4, "::1"]))
    assert failure_code(out) is FailureCode.POLICY_PROHIBITED_ADDRESS
    assert out.evidence.resolved_ips == [ip_address(LOOP4), ip_address("::1")]
    assert out.evidence.connected_ip is None
    assert server.log.connections == 0
    if server6 is not None:
        assert server6.log.connections == 0


def test_s03_public_policy_rejects_any_private_answer(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    out = fetch(egress_cfg, resolver=StubResolver(["1.1.1.1", LOOP4]), policy=PublicScopePolicy())
    assert failure_code(out) is FailureCode.POLICY_PROHIBITED_ADDRESS
    assert server.log.connections == 0


# --- S-04 / S-05: one resolution, pinned connect, peer assertion -------------------------------


def test_s04_rebinding_resolver_is_called_exactly_once(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    resolver = StubResolver([LOOP4], ["10.0.0.1"])
    out = fetch(egress_cfg, resolver=resolver)
    assert len(resolver.calls) == 1
    assert out.evidence.connected_ip == ip_address(LOOP4)
    assert out.evidence.http is not None
    assert server.log.connections == 1


def test_s04_second_hop_resolves_afresh(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    resolver = StubResolver([LOOP4], ["10.0.0.1"])
    budget = ScanBudget(30)
    first = fetch(egress_cfg, resolver=resolver, budget=budget)
    second = fetch(egress_cfg, resolver=resolver, budget=budget, index=1)
    assert first.evidence.http is not None
    assert failure_code(second) is FailureCode.POLICY_PROHIBITED_ADDRESS
    assert len(resolver.calls) == 2
    assert server.log.connections == 1


def test_s05_peer_not_in_pinned_set_is_refused_before_any_byte(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    recorder = HopRecorder()
    backend = GuardedNetworkBackend(
        expected_host="webguard.test",
        expected_port=FIXTURE_PORT,
        pinned=[ip_address("1.1.1.1")],
        budget=ScanBudget(30),
        recorder=recorder,
        ssl_context=get_ssl_context(egress_cfg),
    )
    sock = socket.create_connection((LOOP4, FIXTURE_PORT), timeout=5)
    with pytest.raises(PolicyViolationError):
        backend._verify_peer(sock)
    assert sock.fileno() == -1  # closed by the backend
    assert recorder.connected_ip is None
    time.sleep(0.3)
    assert server.log.received == []


def test_s05_backend_refuses_unexpected_host_port_and_unix(egress_cfg: EgressConfig) -> None:
    backend = GuardedNetworkBackend(
        expected_host="webguard.test",
        expected_port=FIXTURE_PORT,
        pinned=[ip_address(LOOP4)],
        budget=ScanBudget(30),
        recorder=HopRecorder(),
        ssl_context=get_ssl_context(egress_cfg),
    )
    with pytest.raises(PolicyViolationError):
        backend.connect_tcp("evil.test", FIXTURE_PORT)
    with pytest.raises(PolicyViolationError):
        backend.connect_tcp("webguard.test", 443)
    with pytest.raises(PolicyViolationError):
        backend.connect_unix_socket("/tmp/x.sock")


def test_s05_tls_start_refuses_other_hostname_or_context(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    ctx = get_ssl_context(egress_cfg)
    for hostname, context in (("evil.test", ctx), ("webguard.test", build_ssl_context(egress_cfg))):
        sock = socket.create_connection((LOOP4, FIXTURE_PORT), timeout=5)
        stream = GuardedStream(
            sock,
            budget=ScanBudget(30),
            recorder=HopRecorder(),
            expected_host="webguard.test",
            ssl_context=ctx,
        )
        with pytest.raises(PolicyViolationError):
            stream.start_tls(context, server_hostname=hostname)
    time.sleep(0.3)
    assert server.log.received == []


# --- S-08 / S-09 / S-10 / S-11: TLS ------------------------------------------------------------

BAD_CERTS = [
    (certs.EXPIRED, 10),
    (certs.NOT_YET_VALID, 9),
    (certs.WRONG_HOST, 62),
    (certs.UNTRUSTED, 20),
]


@pytest.mark.parametrize(("sni", "code"), BAD_CERTS)
def test_s08_s09_bad_certificates_refused_without_http(
    egress_cfg: EgressConfig, server: FixtureServer, sni: str, code: int
) -> None:
    out = fetch(egress_cfg, host=sni)
    tls = out.evidence.tls
    assert tls is not None
    assert not tls.verified
    assert tls.verify_code == code
    assert tls.cert is None
    assert out.evidence.http is None
    assert out.evidence.failure is None
    time.sleep(0.2)
    assert server.log.received == []  # no HTTP bytes exchanged


def test_s10_context_properties(egress_cfg: EgressConfig) -> None:
    ctx = get_ssl_context(egress_cfg)
    assert ctx is get_ssl_context(egress_cfg)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.keylog_filename is None
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT
    assert ctx.get_ca_certs()  # only the injected CA is loaded


def test_s10_production_wiring_uses_certifi_and_public_policy() -> None:
    prod = build_production_egress()
    assert isinstance(prod.policy, PublicScopePolicy)
    assert prod.cfg.ca_file == Path(certifi.where())
    assert prod.cfg.user_agent == USER_AGENT


def test_s11_sni_is_canonical_hostname(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    fetch(egress_cfg, host="WebGuard.Test")
    assert server.log.snis == ["webguard.test"]
    assert server.log.received[0].sni == "webguard.test"


def test_s11_ip_literal_sends_no_sni(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    out = fetch(egress_cfg, host=LOOP4)
    assert out.evidence.http is not None
    assert server.log.snis == [None]


# --- S-14: environment cannot influence egress -------------------------------------------------


def test_s14_hostile_environment_has_no_effect(
    egress_cfg: EgressConfig,
    server: FixtureServer,
    pki: FixturePki,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trap = ProxyTrap()
    keylog = tmp_path / "keys.log"
    netrc = tmp_path / "netrc"
    netrc.write_text("machine webguard.test login u password p\n")
    try:
        proxy = f"http://127.0.0.1:{trap.port}"
        for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(var, proxy)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("SSL_CERT_FILE", str(pki.other_ca_file))
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(pki.other_ca_file))
        monkeypatch.setenv("NETRC", str(netrc))
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
        cfg = EgressConfig(ca_file=pki.ca_file, user_agent=USER_AGENT)  # fresh context under env
        good = fetch_hop(
            HopRequest(0, target()), ScanBudget(30), TestScopePolicy(), cfg, StubResolver([LOOP4])
        )
        bad = fetch_hop(
            HopRequest(0, target(host=certs.UNTRUSTED)),
            ScanBudget(30),
            TestScopePolicy(),
            cfg,
            StubResolver([LOOP4]),
        )
        assert build_ssl_context(cfg).keylog_filename is None
    finally:
        trap.close()
    assert good.evidence.http is not None
    assert bad.evidence.tls is not None
    assert not bad.evidence.tls.verified
    assert trap.connections == 0
    assert not keylog.exists()
    headers = b"\r\n".join(server.log.received[0].header_lines).lower()
    assert b"authorization" not in headers
    assert b"proxy" not in headers


# --- S-15: byte cap / oversized headers --------------------------------------------------------


def test_s15_oversized_header_block(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    out = fetch(egress_cfg, "/bigheaders")
    assert failure_code(out) is FailureCode.RESPONSE_TOO_LARGE
    assert out.bytes_read <= MAX_BYTES_PER_HOP + 64 * 1024


def test_s15_stream_byte_cap_is_authoritative(egress_cfg: EgressConfig) -> None:
    a, b = socket.socketpair()
    recorder = HopRecorder()
    stream = GuardedStream(
        a,
        budget=ScanBudget(30),
        recorder=recorder,
        expected_host="x",
        ssl_context=get_ssl_context(egress_cfg),
    )
    payload = b"x" * (MAX_BYTES_PER_HOP + 70_000)
    sender = threading.Thread(target=b.sendall, args=(payload,), daemon=True)
    sender.start()

    def drain() -> None:
        while True:
            stream.read(65536)

    with pytest.raises(ResponseTooLargeError):
        drain()
    assert recorder.bytes_read <= MAX_BYTES_PER_HOP + 1
    a.close()
    b.close()


def test_s15_too_many_headers_is_malformed(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    out = fetch(egress_cfg, "/many-headers")
    assert failure_code(out) is FailureCode.MALFORMED_RESPONSE
    assert out.evidence.failure is not None
    assert out.evidence.failure.detail == "headers_excess"


def test_s15_body_never_read(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    started = time.monotonic()
    out = fetch(egress_cfg, "/bigbody")
    assert out.evidence.http is not None
    assert out.bytes_read < 128 * 1024
    assert time.monotonic() - started < 3


@pytest.mark.parametrize("path", ["/bad-status"])
def test_malformed_status_line(egress_cfg: EgressConfig, server: FixtureServer, path: str) -> None:
    assert failure_code(fetch(egress_cfg, path)) is FailureCode.MALFORMED_RESPONSE


# --- S-16 / S-17: deadlines --------------------------------------------------------------------


@pytest.mark.slow
def test_s16_slow_drip_bounded_by_deadline(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    started = time.monotonic()
    out = fetch(egress_cfg, "/slowdrip", budget=ScanBudget(5))
    elapsed = time.monotonic() - started
    assert failure_code(out) in {FailureCode.DEADLINE_EXCEEDED, FailureCode.READ_TIMEOUT}
    assert elapsed <= 5 + 1
    assert out.evidence.tls is not None  # TLS stage was reached and recorded
    assert out.evidence.http is None


@pytest.mark.slow
def test_s17_hanging_resolver_times_out(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    resolver = StubResolver([LOOP4], hang=True)
    started = time.monotonic()
    try:
        out = fetch(egress_cfg, resolver=resolver)
    finally:
        resolver.release.set()
    assert failure_code(out) is FailureCode.DNS_TIMEOUT
    assert time.monotonic() - started <= 5 + 1
    assert server.log.connections == 0


def test_deadline_already_spent_starts_nothing(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    now = [0.0]
    budget = ScanBudget(5, clock=lambda: now[0])
    now[0] = 10.0
    resolver = StubResolver([LOOP4])
    out = fetch(egress_cfg, resolver=resolver, budget=budget)
    assert failure_code(out) is FailureCode.DEADLINE_EXCEEDED
    assert resolver.calls == []
    assert server.log.connections == 0


def test_dns_failures(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    assert failure_code(fetch(egress_cfg, resolver=StubResolver([]))) is FailureCode.DNS_NO_ANSWER
    many = [f"127.0.0.{i}" for i in range(1, 18)]
    assert (
        failure_code(fetch(egress_cfg, resolver=StubResolver(many)))
        is FailureCode.DNS_TOO_MANY_ANSWERS
    )
    assert server.log.connections == 0


def test_connect_refused(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    closed_port = dataclasses.replace(target(), port=443)  # nothing listens on loopback:443
    out = fetch(egress_cfg, tgt=closed_port)
    assert failure_code(out) in {FailureCode.CONNECT_FAILED, FailureCode.CONNECT_TIMEOUT}


# --- S-19 / S-20 / S-26: capture boundary and request shape -----------------------------------


def test_s19_malicious_values_are_neutralized(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    out = fetch(egress_cfg, "/malicious")
    http = out.evidence.http
    assert http is not None
    assert http.first("content-security-policy") == "<script>alert(1)</script>"
    ctype = http.first("content-type")
    assert ctype is not None
    assert "\\x9b" in ctype
    assert "\\x80" in ctype  # UTF-8 bidi override bytes decoded as Latin-1 then escaped
    assert all(
        ord(ch) >= 0x20 and not 0x7F <= ord(ch) <= 0x9F for ch in out.evidence.model_dump_json()
    )


def test_s20_cookie_value_never_captured(
    egress_cfg: EgressConfig, server: FixtureServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    for name in ("httpcore", "httpcore.http11", "h11"):
        logging.getLogger(name).setLevel(logging.DEBUG)  # a hostile embedding application
    dumps = [
        fetch(egress_cfg, path).evidence.model_dump_json()
        for path in ("/", "/cookies", "/malicious", "/created")
    ]
    for dump in dumps:
        assert SENTINEL not in dump
    assert SENTINEL not in caplog.text


def test_s26_request_headers_are_exactly_d05(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    fetch(egress_cfg, "/missing?a=1")
    received = server.log.received[0]
    assert received.request_line == b"GET /missing?a=1 HTTP/1.1"
    assert received.header_lines == [
        f"Host: webguard.test:{FIXTURE_PORT}".encode(),
        f"User-Agent: {USER_AGENT}".encode(),
        b"Accept: */*",
        b"Accept-Encoding: identity",
        b"Connection: close",
    ]


# --- capture details ---------------------------------------------------------------------------


def test_cookies_split_on_first_semicolon_not_commas(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    http = fetch(egress_cfg, "/cookies").evidence.http
    assert http is not None
    names = [c.name for c in http.cookies]
    assert names == ["a", "b", "__Host-c", "__Secure-d", "e", "f", "g"]
    assert http.cookies[0].attributes_raw == "Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure"


def test_cookie_cap(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    http = fetch(egress_cfg, "/many-cookies").evidence.http
    assert http is not None
    assert (len(http.cookies), http.cookies_dropped) == (50, 10)


def test_redirect_location_redacted_and_next_target_validated(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    out = fetch(egress_cfg, "/redirect?to=/next%3Fk%3Dsecret")
    http = out.evidence.http
    assert http is not None
    assert http.location is not None
    assert http.location.path_query_redacted == "/next?k=REDACTED"
    assert "location" not in http.headers
    assert isinstance(out.next_target, CanonicalTarget)
    assert out.next_target.request_target == "/next?k=secret"


def test_downgrade_location_recorded_and_not_followable(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    out = fetch(egress_cfg, "/downgrade")
    http = out.evidence.http
    assert http is not None
    assert http.location is not None
    assert http.location.scheme == "http"
    assert not isinstance(out.next_target, CanonicalTarget)


def test_conflicting_locations_unparseable(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    out = fetch(egress_cfg, "/dup-location")
    assert out.evidence.http is not None
    assert out.evidence.http.location is not None
    assert out.evidence.http.location.unparseable
    assert out.next_target is None


def test_non_redirect_location_has_no_next_target(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    out = fetch(egress_cfg, "/created")
    assert out.evidence.http is not None
    assert out.evidence.http.status_code == 201
    assert out.next_target is None


def test_http10_response_accepted(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    http = fetch(egress_cfg, "/http10").evidence.http
    assert http is not None
    assert http.http_version == "HTTP/1.0"


def test_keyboard_interrupt_propagates_untouched(
    egress_cfg: EgressConfig, server: FixtureServer
) -> None:
    class InterruptingPolicy(TestScopePolicy):
        def check_resolved(self, ips: object) -> object:  # type: ignore[override]  # reason: raises only
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        fetch(egress_cfg, policy=InterruptingPolicy())  # type: ignore[arg-type]  # reason: test double
    assert server.log.connections == 0


def test_request_cap_is_enforced(egress_cfg: EgressConfig, server: FixtureServer) -> None:
    budget = ScanBudget(30)
    outcomes = [fetch(egress_cfg, budget=budget, index=min(i, 3)) for i in range(5)]
    assert [o.evidence.http is not None for o in outcomes[:4]] == [True] * 4
    assert failure_code(outcomes[4]) is FailureCode.INTERNAL_ERROR
    assert server.log.connections == 4


def test_env_var_not_read_for_ca(monkeypatch: pytest.MonkeyPatch, pki: FixturePki) -> None:
    monkeypatch.setitem(os.environ, "SSL_CERT_FILE", str(pki.ca_file))
    ctx = build_ssl_context(EgressConfig(ca_file=Path(certifi.where()), user_agent=USER_AGENT))
    subjects = {str(c.get("subject")) for c in ctx.get_ca_certs()}
    assert not any("Testing CA" in s for s in subjects)
