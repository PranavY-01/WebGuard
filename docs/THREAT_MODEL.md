# WebGuard threat model

The adversary is the **scan target**: its DNS answers, TLS endpoint, certificate, status line, headers, cookies,
redirects, timing and byte volume. The operator who runs the CLI and chooses the target and output directory is
trusted, and so is code calling the Python API.

## Trust boundaries

| Boundary | What crosses it | Control |
|---|---|---|
| B1 operator → config | URL, flags | Typer parsing, `ScanConfig` validation, URL canonicalization |
| B2 DNS | answers | one resolution per hop, timeout, every answer classified, any prohibited answer rejects the hop |
| B3 target → bytes | TCP/TLS/HTTP | pinned IP, peer assertion, verified TLS, byte cap, deadline clamp |
| B4 capture → evidence | header and cert text | allowlist, SafeText at capture, cookie values dropped, URL redaction |
| B5 reports | files | generated names, exclusive create, autoescaped HTML with its own CSP |
| B6 terminal and logs | text | Rich `Text` only, markup off; safe log filter; library loggers pinned |
| B7 supply chain | dependencies | `uv.lock` with hashes, `pip-audit` in CI, minimal dependencies, two-week cooling-off |

## Threat register

| ID | Threat | Mitigation | Verified by |
|---|---|---|---|
| T-01 | SSRF / internal destinations | Public-only policy (D-07/D-08) with `is_global`, denylist, IPv4-mapped refusal and `2000::/3`; ports 443/8443 | U-06..U-09, S-02, S-03 |
| T-02 | DNS rebinding / resolution race | Resolve once, pin, assert peer (INV-02/04) | S-04, S-05 |
| T-03 | Unsafe redirects | Orchestrator-only redirects, HTTPS only, ≤3, loop detection, full re-validation per hop | I-05, I-06, S-06, S-07 |
| T-04 | TLS verification bypass | Single context factory, `CERT_REQUIRED` and `check_hostname`, no flag to disable | S-08..S-12 |
| T-05 | Oversized or malformed response | 128 KiB cap, h11 431 mapping, 100-header limit, status range check | S-15 |
| T-06 | Slow response / exhaustion | Clamp on every blocking operation; DNS thread join | S-16, S-17, S-18 |
| T-07 | HTML injection in report | SafeText, explicit autoescape, no URL/script/style contexts, report CSP | S-13, S-21 |
| T-08 | Unsafe report path / overwrite | Directory only, generated names, `O_EXCL`, link/rename without replace, symlinks refused | S-23, S-24, S-25 |
| T-09 | Sensitive data leakage | Cookie values dropped at capture; query values redacted; safe logging | S-20, S-27 |
| T-10 | URL parsing bypass | Canonical reconstruction; the raw string never reaches httpcore | U-01..U-05 |
| T-11 | False positives/negatives | Applicability matrix; default inconclusive; known-answer table | U-20..U-29 |
| T-12 | Dependency compromise | Hash-locked dependencies, `pip-audit`, cooling-off window | CI audit job |
| T-13 | Exception leakage | Closed `FailureCode` enum; static details; one-line CLI errors | S-19, CLI tests |
| T-14 | Proxy / environment influence | httpcore used directly; explicit CA file; `SSLKEYLOGFILE` neutralized | S-14 |
| T-15 | Unauthorized or disruptive scan | `--i-am-authorized`; ≤4 GETs; ports 443/8443 | CLI tests, I-06 |
| T-16 | Test coverage gaps | S/U/I suites; release gates | CI |
| T-17 | Credential forwarding | Fixed D-05 header set; no cookies or auth ever | S-26 |
| T-18 | Log injection | SafeText; `SafeLogFilter` drops unsafe args | U-50 |
| T-19 | Temporary-file exposure | Temp files `0600`, `O_EXCL`, removed on any failure | S-25 |
| T-20 | Misread severity | Rubric; banner "not a penetration test"; confidence levels | report tests |
| T-21 | Terminal markup / ANSI injection | SafeText escapes ESC/C1; Rich `Text` with markup off | S-22 |
| T-22 | A second unguarded network path | One egress package; TLS facts from the same socket | `lint-imports` |
| T-23 | Parser differential | Request rebuilt from canonical components as a structured `httpcore.URL` | U-01..U-05 |
| T-24 | A shipped test hook becomes a bypass | DI only; permissive policy exists only under `tests/` | S-28 |
| T-25 | Library logging leaks headers | httpcore/h11/jinja2 pinned to WARNING in the CLI **and** in every `fetch_hop` | S-20, U-50 |
| T-26 | Unicode bidi / zero-width spoofing | SafeText rejection set; Trojan-Source static test on the codebase | U-10, static tests |
| T-27 | Mapped / NAT64 / 6to4 / Teredo addresses smuggling IPv4 | Explicit denylist, mapped refusal, `2000::/3` | U-06, U-07 |
| T-28 | Numeric-shorthand IPv4 | Strict dotted-quad, re-checked after IDNA mapping | U-02 |
| T-29 | Compromised CA in the bundled trust store | certifi pinned ≥ 2026.10.19 (GHSA-6q48-6c7w-9gw2); `pip-audit` gate | trust-store test |

## Residual risk (accepted for V1)

| Risk | Why it is accepted |
|---|---|
| URL paths may contain tokens and are reported unredacted. | Documented limitation; query values are redacted. |
| A non-cancellable `getaddrinfo` thread can outlive its deadline until the process exits. | Bounded by process lifetime; the result is discarded. |
| Ctrl+C on Windows can take up to 10 s to take effect. | Bounded by the clamped read timeout (A-12). |
| The certifi trust store may differ from OS and browser stores. | Documented; deterministic across platforms. |
| OpenSSL reads `OPENSSL_CONF` at library initialization (outside Python's control). | The operator controls their own environment. The context explicitly pins verify mode, CA file and minimum version. |
| The Python API trusts its caller (custom policy, resolver, CA). | By design (D-15). The CLI can only build production wiring. |
