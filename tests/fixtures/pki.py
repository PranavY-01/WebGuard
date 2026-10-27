"""Test PKI (never shipped): one trustme CA and per-SNI certificate variants."""

from __future__ import annotations

import datetime as dt
import ssl
from dataclasses import dataclass
from pathlib import Path

import trustme

VALID_NAMES = ("webguard.test", "a.webguard.test", "b.webguard.test", "127.0.0.1", "::1")

# SNI name -> variant. The fixture server picks the certificate by the SNI it receives.
EXPIRED = "expired.webguard.test"
NOT_YET_VALID = "notyet.webguard.test"
WRONG_HOST = "wronghost.webguard.test"
UNTRUSTED = "untrusted.webguard.test"
EXPIRES_10D = "exp10.webguard.test"
EXPIRES_25D = "exp25.webguard.test"


@dataclass
class FixturePki:
    ca: trustme.CA
    ca_file: Path
    other_ca_file: Path
    leaves: dict[str, trustme.LeafCert]
    valid_leaf: trustme.LeafCert

    def server_contexts(self) -> tuple[ssl.SSLContext, dict[str, ssl.SSLContext]]:
        """Fresh server contexts per fixture server (each installs its own SNI callback)."""
        return _server_context(self.valid_leaf), {
            name: _server_context(leaf) for name, leaf in self.leaves.items()
        }


def _server_context(leaf: trustme.LeafCert) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    leaf.configure_cert(ctx)
    return ctx


def build_pki(directory: Path) -> FixturePki:
    now = dt.datetime.now(dt.UTC)
    ca = trustme.CA()
    other = trustme.CA()
    leaves = {
        EXPIRED: ca.issue_cert(
            EXPIRED, not_before=now - dt.timedelta(days=60), not_after=now - dt.timedelta(days=1)
        ),
        NOT_YET_VALID: ca.issue_cert(
            NOT_YET_VALID,
            not_before=now + dt.timedelta(days=5),
            not_after=now + dt.timedelta(days=90),
        ),
        WRONG_HOST: ca.issue_cert("other.test"),
        UNTRUSTED: other.issue_cert(UNTRUSTED),
        EXPIRES_10D: ca.issue_cert(EXPIRES_10D, not_after=now + dt.timedelta(days=10, hours=1)),
        EXPIRES_25D: ca.issue_cert(EXPIRES_25D, not_after=now + dt.timedelta(days=25, hours=1)),
    }
    ca_file = directory / "test-ca.pem"
    other_ca_file = directory / "other-ca.pem"
    ca.cert_pem.write_to_path(str(ca_file))
    other.cert_pem.write_to_path(str(other_ca_file))
    return FixturePki(
        ca=ca,
        ca_file=ca_file,
        other_ca_file=other_ca_file,
        leaves=leaves,
        valid_leaf=ca.issue_cert(*VALID_NAMES),
    )
