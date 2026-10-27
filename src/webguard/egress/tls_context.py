"""The only SSLContext factory in WebGuard (Plan §9.5, D-13, INV-03).

`ssl.SSLContext(PROTOCOL_TLS_CLIENT)` is built directly instead of via the stdlib convenience
factory, because that factory reads SSLKEYLOGFILE from the environment (P0 finding, INV-05).
No system/default trust store is ever loaded: only the configured CA file.
"""

from __future__ import annotations

import functools
import ssl

from webguard.domain.config import EgressConfig


class TlsContextError(RuntimeError):
    """The built context does not have the mandatory properties."""


@functools.cache
def get_ssl_context(cfg: EgressConfig) -> ssl.SSLContext:
    """One context per EgressConfig per process (production has exactly one)."""
    return build_ssl_context(cfg)


def build_ssl_context(cfg: EgressConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Python >= 3.13 defaults; set explicitly so every supported version behaves the same.
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cafile=str(cfg.ca_file))
    ctx.set_alpn_protocols(["http/1.1"])
    verify_ssl_context(ctx)
    return ctx


def verify_ssl_context(ctx: ssl.SSLContext) -> None:
    """Refuse any context that could weaken verification or leak key material."""
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise TlsContextError("verification disabled")
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        raise TlsContextError("minimum TLS version below 1.2")
    if ctx.keylog_filename is not None:
        raise TlsContextError("key logging enabled")
