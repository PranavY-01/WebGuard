# WebGuard architecture

Condensed from the build plan (*WebGuard Architecture & Build Plan v2*). This file records how v1.0.0 is
built, every implementation decision taken where the plan was silent, and how each plan conflict was resolved.

## Governing rule

> Nothing the target sends, whether DNS answers, certificates, status, headers, cookies, redirects, timing or
> volume, is trusted, reused as code, used as a path, or allowed to leave the egress boundary in raw form. Every
> bound is enforced where the bytes arrive, every result is `pass` only on evidence, and every failure is named.

The **adversary is the target**. The operator running the CLI is trusted to choose the target and the output
directory. Python API callers are trusted code.

## Layers

```text
L5  webguard.cli      Typer commands, flag validation, production wiring, safe Rich console, exit codes
L4  webguard.app      collect/run_scan, state machine, ScanBudget, redirect loop, interrupts, assembly
L3  webguard.egress   the ONLY network I/O         webguard.rules   pure: evidence -> results
    webguard.render   pure: report -> JSON/HTML     webguard.sink    the ONLY report file I/O
L2  webguard.policy   pure: URL canonicalization, address classification, scope policy
L1  webguard.domain   frozen Pydantic models, SafeText, enums, configs, limits, Budget protocol
    webguard.logging_setup (configured once by the CLI)
```

Import contracts in `.importlinter` are checked in CI:

- `domain` imports nothing from WebGuard, and the layer order holds.
- The four L3 packages are mutually independent.
- `socket`, `ssl`, `httpcore`, `h11` and `certifi` appear only in `egress`; `jinja2` only in `render`;
  `rich` and `typer` only in `cli`.
- `http`, `asyncio`, `pickle` and `subprocess` appear nowhere.
- `cli` reaches egress only through `build_production_egress`, and only `cli` imports `logging_setup`.

## One hop (egress)

```text
fetch_hop(HopRequest{index, CanonicalTarget}, budget, policy, cfg, resolver) -> HopOutcome
  pin httpcore/h11 loggers to WARNING                       (T-25)
  policy.check_literal(host_ip, port)  -- reject: no DNS, no request charged
  budget.charge_request()                                   (<= 4 per scan)
  answers = [ip literal] | resolve_bounded(resolver, ...)   exactly once; daemon thread joined with clamp(5 s)
  dedupe; 0 -> dns_no_answer; >16 -> dns_too_many_answers
  policy.check_resolved(answers)       -- ANY prohibited answer rejects the hop
  ConnectionPool(ssl_context, http1 only, retries=0, max 1, keepalive 0, GuardedNetworkBackend)
    connect_tcp(host, port): assert host/port == expected; dial pinned IPs (<= 2 attempts);
                             assert getpeername() in pinned BEFORE returning a stream     (INV-02)
    start_tls: assert SNI host == expected and context is the process context;
               verify chain + hostname; capture TlsEvidence from THIS socket               (D-14)
  GET <request_target> with the fixed D-05 header set; status line + headers only
  capture: allowlist, SafeText, cookie value dropped, Location redacted + next hop validated
  leave the `with` blocks: close without reading the body                                   (INV-07)
  any Exception -> classify() -> HopEvidence(failure=...); KeyboardInterrupt propagates
```

`GuardedStream` recomputes `min(phase_limit, budget.remaining())` on every read and write. It caps bytes read per
hop at 128 KiB, asking the socket for at most one byte past the cap. The request URL is a structured
`httpcore.URL(scheme, host, port, target)` built from canonical components, so httpcore never parses a URL
string.

## Invariants and where they are enforced

| ID | Enforcement | Tests |
|---|---|---|
| INV-01 egress-only I/O | `.importlinter` | CI `lint-imports` |
| INV-02 pinned connect, peer asserted | `GuardedNetworkBackend._verify_peer` | S-03, S-04, S-05 |
| INV-03 verified TLS, one factory | `egress.tls_context` + static scan | S-08..S-10, S-12 |
| INV-04 one resolution per hop | pinned backend never resolves | S-04 |
| INV-05 no environment influence (and no internet from tests) | no httpx; `SSLContext` built directly; explicit CA file; autouse loopback-only network guard in `tests/conftest.py` | S-14, S-29 |
| INV-06 orchestrator-only redirects | `app.redirects.next_hop` | I-05, I-06, S-06, S-07 |
| INV-07 no body, ≤128 KiB | `GuardedStream` cap; close after headers | S-15 |
| INV-08 clamped blocking ops | `clamp()` in stream, backend, resolver | S-16, S-17, S-18 |
| INV-09 no raw target text outside egress | `SafeText` rejecting validator; `capture` only | U-10..U-12, S-19 |
| INV-10 cookie values never kept | `capture_cookie` keeps the name only | S-20, S-27 |
| INV-11 pass only on evidence | catalog helpers; applicability; default inconclusive | U-20..U-29, I-08 |
| INV-12 inert HTML + CSP | explicit autoescape, template rules | S-13, S-21 |
| INV-13 inert terminal | `Text` objects + markup/highlight/emoji off | S-22 |
| INV-14 no overwrite/partial/target names | `sink.writer` | S-23..S-25 |
| INV-15 pure exit mapping | `cli.exitcodes.outcome_to_exit_code` | U-40 |
| INV-16 exact request headers | `exchange.request_headers` | S-26 |
| INV-17 safe logging | `SafeLogFilter`, pinned library loggers | U-50, S-27 |
| INV-18 summary arithmetic, rule coverage | `Summary`/`Report` validators, `assemble_report` | U-35 |

## Phase 0 assumption outcomes

Verified against the locked versions (httpcore 1.0.9, h11 0.16.0, Typer 0.27.3, Rich 15.0.0, Jinja2 3.1.6,
trustme 1.2.1) on CPython 3.12.16, 3.13.18 and 3.14.10 (OpenSSL 3.5.9), on loopback only.

| ID | Outcome |
|---|---|
| A-01 | Confirmed. `connect_tcp` receives the URL host and port. `start_tls(server_hostname=<URL host>)`. SNI is sent for names; IP literals send no SNI and verify against IP SANs. Egress **option A** (httpcore + custom backend) adopted. |
| A-02 | Confirmed. Headers are available after 53 bytes were read; closing reset the connection without draining a 50 MB body. |
| A-03 | Confirmed, with a stricter capture. Codes: expired 10, not yet valid 9, hostname 62, unknown CA 20. The pool re-raises `from None`, so `GuardedStream.start_tls` records the error at the source instead of walking chains. |
| A-04 | Confirmed. `getpeercert()` is populated; `version()` returns `TLSv1.3` or `TLSv1.2`. |
| A-05 | Confirmed. Autoescape defaults to off; `True` escapes `& < > " '`. |
| A-06 | Fallback adapted. Typer 0.27 bundles its own Click: usage errors are `typer.TyperException` subclasses (`exit_code` 2), and a `KeyboardInterrupt` inside a command is *returned* as 130. `main()` maps those. |
| A-07 | Identical on all three versions. `is_global` is True for `64:ff9b::7f00:1`, `192.88.99.1`, `192.0.0.9`, `192.0.0.10`, `fec0::1`, `::ffff:8.8.8.8` and multicast, so the denylist, mapped and multicast checks are load-bearing. |
| A-08 | Confirmed. `Text` prints markup literally and `escape` neutralizes `[`. `Text` does **not** strip ESC; SafeText does. |
| A-09 | Confirmed on Windows (`os.rename`/`os.link` raise `FileExistsError`). POSIX `os.link` is covered by S-23 on the Linux and macOS CI cells. |
| A-10 | Confirmed. Malformed status → `h11.RemoteProtocolError` (hint 400). Oversized header block → hint 431 after about 100 KiB. |
| A-11 | Confirmed. A daemon thread blocked in a GIL-releasing call does not delay exit. |
| A-12 | Confirmed. On Windows, SIGINT is delivered only after the blocking `recv` times out (≤10 s here). |
| A-13 | Confirmed. `trustme.issue_cert(not_before=, not_after=)` plus arbitrary DNS and IP SANs. |

## Plan conflicts and how they were resolved (stricter interpretation)

1. **`ssl.create_default_context()` reads `SSLKEYLOGFILE`**, which would write TLS session keys to a file named by
   the environment, violating INV-05/P7. `tls_context` builds `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` directly with
   identical settings and refuses any context with `keylog_filename` set. The S-12 static scan bans the factory
   name, and S-14 sets `SSLKEYLOGFILE`.
2. **httpcore DEBUG traces print raw response headers**, including cookie values (T-25). The CLI pins library
   loggers, and `fetch_hop` also re-pins `httpcore`/`h11` and their children before every hop, so Python-API
   callers are protected too.
3. **Typer bundles its own Click** (see A-06): `main()` catches `typer.TyperException`, not Click's classes.
4. **h11's 100 KiB header-block limit fires before the 128 KiB byte cap.** Both map to `response_too_large`:
   h11 is identified by `error_status_hint == 431`, not by message text. The cap remains the independent backstop
   and is tested directly.
5. **`ScanBudget` is in `app` (L4), but egress (L3) needs it.** A `Budget` protocol, `clamp()` and all fixed
   limits live in `domain/budget.py`.
6. **I-01 and I-09 need the renderer and sink (P7)**, but are listed for P6. Orchestration is split into
   `collect()` (P6) and `run_scan()` (P7), and the file assertions run in P7.
7. **httpcore calls `ssl_context.set_alpn_protocols(["http/1.1"])` on every connect**, mutating the shared context
   to the value D-13 already sets. This is harmless and recorded.
8. **certifi 2026.7.22 trusted a root with compromised intermediates** (GHSA-6q48-6c7w-9gw2), which `pip-audit`
   found during P9. certifi is now ≥ 2026.10.19 via a scoped `exclude-newer-package` exemption from the two-week
   cooling-off, with a regression test on the installed bundle.

## Implementation decisions (where the plan is silent)

**Process and tests**
- Build-prompt rule 13 is amended (ratified by the project owner, 2026-10-28) to: *"WebGuard's runtime and its
  test suite MUST NOT contact any host other than local fixtures. Build tooling MAY contact package indexes,
  uv's Python distribution sources, and vulnerability databases for locking, installing, and auditing."*
- **S-29, mechanical no-internet enforcement for tests.** The autouse `network_guard` fixture in
  `tests/conftest.py` (implementation in `tests/fixtures/network_guard.py`) patches `socket.socket.connect`,
  `socket.socket.connect_ex` and `socket.create_connection`. Any address that is not a loopback IP literal raises
  before a packet is sent.
  - Stricter addition: `socket.getaddrinfo` is guarded too, so a DNS query can't leave the machine; only
    loopback literals, `localhost` and `None` resolve.
  - `AF_UNIX` sockets are local IPC and are allowed.
  - The guard raises `OutboundNetworkBlockedError`, a `BaseException` subclass. egress's `except Exception`
    boundary therefore cannot turn a forbidden connection into an ordinary failure code.
  - Each blocked attempt is also recorded, and the fixture fails the test at teardown if any remain. Tests that
    trigger the guard on purpose clear the record after asserting on it.
  - S-29 is listed under INV-05.
- **Install paths and reader-facing docs.** The README and `docs/USER_GUIDE.md` (the instruction manual) are
  written for users; build and design material lives in `CONTRIBUTING.md` and this file. End users install with
  `pip install .` or `pipx install .` and need no uv; pip resolves the
  ranges in `pyproject.toml`. Contributors use `uv sync --locked` for the exact hash-pinned set. uv-managed
  Pythons are optional and only useful for local multi-version testing; CI covers the matrix.

**Policy and URL**
- Rejection codes `url_too_long` and `url_illegal_chars` map to exit 2; all other rejections map to exit 3.
  "Illegal characters" also covers C1 controls, Unicode whitespace, bidi and invisible characters, and any
  non-ASCII character outside the host (operators percent-encode).
- `urlsplit` failures map to `host_invalid` for https URLs and `scheme_not_https` otherwise. Empty, signed,
  leading-zero or out-of-range ports map to `port_not_permitted`. A numeric host with a trailing dot maps to
  `ipv4_ambiguous`.
- The WHATWG numeric-host check is re-applied **after** UTS-46 mapping, because fullwidth digits and ideographic
  full stops map to `127.0.0.1`.
- Bare query items without `=` are redacted entirely, since they may be tokens.
- IPv6 is permitted only inside `2000::/3`, the global unicast block. This also closes IPv4-compatible
  `::a.b.c.d` addresses and the rest of `::/8`.
- `resolve_redirect` validates the raw `Location` before `urljoin`, because `urljoin` strips some characters.

**Egress**
- `fetch_hop` returns `HopOutcome(evidence, next_target, bytes_read, connect_attempts)`. The next hop is a
  validated `CanonicalTarget`, never raw `Location` text.
- The DNS timeout wraps *any* resolver, so a hanging test stub exercises the real enforcement.
- A timeout that consumed the remaining budget is classified as `deadline_exceeded`, not as a phase timeout.
- A TLS handshake timeout maps to `connect_timeout`, a write timeout to `read_timeout` (detail `write_timeout`),
  and a post-handshake TLS record error or reset to `malformed_response` with a static detail.
- `Set-Cookie` and `Location` never enter the stored header map (enforced by the domain model). A name-less
  `Set-Cookie` has an empty name (RFC 6265bis); the text is a value and is discarded. Conflicting duplicate
  `Location` headers are treated as unparseable and not followed.
- The TLS context additionally sets `VERIFY_X509_STRICT | VERIFY_X509_PARTIAL_CHAIN` on every Python version
  (the 3.13+ defaults).

**Domain, rules and app**
- SafeText also rejects U+200E, U+200F and U+061C (bidi marks), U+2028/U+2029 and lone surrogates. Truncation
  never splits an escape.
- A TLS verification failure is `TlsEvidence(verified=False)`, never a `HopFailure`. A hop ends in exactly one of:
  HTTP evidence, a failure, or a TLS verification failure. HTTP evidence without verified TLS cannot be
  represented.
- Messages are static per reason code; dynamic values appear only as SafeText evidence items.
- Terminal-response rules use subject `hop:<terminal>`. A cookie without a name is `cookie:(unnamed)@hop:n`.
- Additional reason codes:
  - `empty_policy` (HDR-002)
  - `no_location`, `location_unparseable` and `unexpected_scheme` (RDR-001); `javascript:` is never a pass
  - `tls_not_reached` (TLS-001, the matrix's "else error")
- Cookie prefixes are matched case-insensitively. Expiry is in fractional days: >30 pass, 15–30 low, <15 medium.
- An empty or foreign result list from a rule is treated like a rule exception.
- A scan is `partial` only when the deadline ended it after at least one evidence hop. Other failures on a
  redirect hop leave it `completed`, with that hop's rules inconclusive. A redirect hop blocked by policy is not
  recorded as a hop, only as a note.
- If the scan is interrupted before any hop, the report has no hops and every rule is inconclusive
  (`scan_interrupted`).

**Output and CLI**
- Windows directory junctions are refused like symlinks. `O_NOFOLLOW` is used where available, and `O_BINARY` on
  Windows.
- `SafeLogFilter` drops non-string messages and string arguments over 2048 characters, and strips tracebacks
  unless `--debug` is set.
- Running `webguard` with no arguments shows the welcome screen and exits 0 (an unknown command still exits 2).
  `--fail-on` values are case-sensitive.
- **Terminal interface** (`cli/theme.py`, `cli/console.py`): a branded Rich design with a gradient logo, panels,
  severity badges, a grouped results table, "What to fix first", a summary with severity bars, and themed Typer
  help screens (options grouped into Required / Scan behaviour / Output). Safety is unchanged: every dynamic value
  is a `Text` object styled only with static theme values, and markup, highlighting and emoji stay disabled.
  - Operator-typed text is shown with non-printable characters escaped.
  - The scan plan shows the canonical **redacted** target; an invalid URL is shown only up to its query string.
  - Glyphs fall back to ASCII when the console encoding isn't UTF (for example cp1252 pipes on Windows), and
    `main()` sets `errors="replace"` on stdout/stderr, so output encoding can never crash a scan (tested).
  - The live spinner runs only on interactive terminals and never with `--debug`. It is driven by
    `ScanDeps.on_progress`, an optional callback that receives only the phase and hop index, so `app` stays free
    of Rich.
- A partial scan with a finding at or above the threshold exits 1; without one it exits 4.
- `uv` `exclude-newer` enforces a two-week cooling-off for dependencies (certifi is exempt; see conflict 8).
