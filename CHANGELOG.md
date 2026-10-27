# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-28

First release.

### Added

- `webguard scan URL --i-am-authorized`: passive scan of one public `https://` target (ports 443/8443) with at
  most 4 `GET` requests. Optional `--follow-redirects` (≤3 HTTPS-only hops, each re-validated), plus
  `--deadline`, `--fail-on`, `--output` and `--debug`.
- `webguard rules` and `webguard version`.
- 10 rules: WG-TLS-001/002, WG-HDR-001/002/003, WG-CK-001..004 and WG-RDR-001, with an applicability matrix
  and severity/confidence rubric.
- JSON report (schema 1.0) and a self-contained HTML report (autoescaped, no scripts, own CSP); Rich terminal
  summary; fixed exit codes 0/1/2/3/4/5/70/130.
- Egress hardening:
  - every answer of a single DNS resolution is classified, and the connection is pinned to one of them with a
    peer assertion;
  - verified TLS only (certifi, TLS ≥ 1.2);
  - per-operation deadline clamp, 128 KiB per hop and a fixed request header set;
  - capture-time sanitization (SafeText), with cookie values dropped and query values redacted.
- Sink: generated file names, exclusive creation, no overwrite, no partial files, symlinks refused.
- Test suite: unit, integration and security tests on loopback TLS fixtures; import-architecture contracts;
  CI on Linux, macOS and Windows × Python 3.12–3.14; `pip-audit`.

### Security

- `certifi >= 2026.10.19` is required (GHSA-6q48-6c7w-9gw2 / PYSEC-2026-4320, compromised emSign
  intermediates).
- The TLS context is built without `ssl.create_default_context()` so `SSLKEYLOGFILE` cannot enable key logging.
- httpcore/h11 debug tracing is pinned to WARNING inside egress, because it would log raw headers including
  cookie values.

[1.0.0]: https://github.com/PranavY-01/WebGuard/releases/tag/v1.0.0
