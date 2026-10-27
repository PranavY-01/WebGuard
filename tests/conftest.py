"""Shared fixtures: test PKI, loopback TLS servers on port 8443, egress wiring for tests."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from tests.fixtures.pki import FixturePki, build_pki
from tests.fixtures.server import FixtureServer
from tests.fixtures.stubs import StubResolver, TestScopePolicy
from webguard.domain.config import EgressConfig
from webguard.egress import USER_AGENT, EgressDeps
from webguard.policy.url import CanonicalTarget, canonicalize_url

FIXTURE_PORT = 8443


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> FixturePki:
    return build_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture(scope="session")
def _server_v4(pki: FixturePki) -> Iterator[FixtureServer]:
    server = FixtureServer(pki, "127.0.0.1", FIXTURE_PORT).start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def _server_v6(pki: FixturePki) -> Iterator[FixtureServer | None]:
    if not socket.has_ipv6:
        yield None
        return
    try:
        server = FixtureServer(pki, "::1", FIXTURE_PORT).start()
    except OSError:
        yield None
        return
    yield server
    server.stop()


@pytest.fixture
def server(_server_v4: FixtureServer) -> FixtureServer:
    _server_v4.log.clear()
    return _server_v4


@pytest.fixture
def server6(_server_v6: FixtureServer | None) -> FixtureServer | None:
    if _server_v6 is not None:
        _server_v6.log.clear()
    return _server_v6


@pytest.fixture
def egress_cfg(pki: FixturePki) -> EgressConfig:
    return EgressConfig(ca_file=pki.ca_file, user_agent=USER_AGENT)


@pytest.fixture
def deps(egress_cfg: EgressConfig) -> EgressDeps:
    return EgressDeps(policy=TestScopePolicy(), resolver=StubResolver(), cfg=egress_cfg)


def target(path: str = "/", host: str = "webguard.test") -> CanonicalTarget:
    got = canonicalize_url(f"https://{host}:{FIXTURE_PORT}{path}")
    assert isinstance(got, CanonicalTarget), got
    return got
