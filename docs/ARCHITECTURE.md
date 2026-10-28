# WebGuard architecture

How WebGuard is built and why its less obvious design choices were made. For using the tool, see the
[user guide](USER_GUIDE.md); for threats and mitigations, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Security model

> Nothing the target sends, whether DNS answers, certificates, status, headers, cookies, redirects, timing or
> volume, is trusted, reused as code, used as a path, or allowed to leave the egress boundary in raw form. Every
> bound is enforced where the bytes arrive, every result is `pass` only on evidence, and every failure is named.

The **adversary is the target**. The operator running the CLI is trusted to choose the target and the output
directory. Code calling the Python API is trusted.

## Layers

```text
cli      Typer commands, flag validation, production wiring, terminal interface, exit codes
app      collect/run_scan, state machine, ScanBudget, redirect loop, interrupts, report assembly
egress   the ONLY network I/O          rules    pure: evidence -> results
render   pure: report -> JSON/HTML     sink     the ONLY report file I/O
policy   pure: URL canonicalization, address classification, scope policy
domain   frozen Pydantic models, SafeText, enums, configuration, limits, Budget protocol
```

Each layer imports only from layers below it. The import contracts in `.importlinter` are checked in CI:

- `domain` imports nothing else from WebGuard; `egress`, `rules`, `render` and `sink` are mutually independent.
- `socket`, `ssl`, `httpcore`, `h11` and `certifi` are imported only in `egress`; `jinja2` only in `render`;
  `rich` and `typer` only in `cli`. `http`, `asyncio`, `pickle` and `subprocess` are not imported at all.
- `cli` reaches egress only through `build_production_egress`, and only `cli` configures logging.

## One request (egress)

```text
fetch_hop(HopRequest, budget, policy, cfg, resolver) -> HopOutcome
  pin httpcore/h11 loggers to WARNING
  policy.check_literal(host_ip, port)        reject -> no DNS, no request counted
  budget.charge_request()                    at most 4 per scan
  answers = ip literal | resolve once        bounded by a daemon-thread join (<= 5 s)
  policy.check_resolved(answers)             ANY prohibited answer rejects the hop
  connect only to those answers (<= 2 attempts); assert the peer is one of them before any byte is sent
  TLS: assert SNI host and context; verify chain + hostname; capture certificate facts from this socket
  GET with the fixed header set; read status line + headers only
  capture: header allowlist, SafeText, cookie values dropped, Location redacted, next hop validated
  close without reading the body
  any Exception -> a named failure code; KeyboardInterrupt propagates
```

Every socket read and write uses a timeout of `min(phase limit, time left in the scan)`. Bytes read per request
are capped at 128 KiB. The request URL is built from validated components (`httpcore.URL(scheme, host, port,
target)`), so the HTTP library never parses a URL string.

## Invariants and where they are enforced

| ID | Guarantee | Enforced by | Tests |
|---|---|---|---|
| INV-01 | Only egress does network I/O | `.importlinter` | CI `lint-imports` |
| INV-02 | Connect only to the hop's classified addresses; peer checked first | `GuardedNetworkBackend._verify_peer` | S-03, S-04, S-05 |
| INV-03 | TLS always verified; one context factory | `egress.tls_context`, static scan | S-08..S-10, S-12 |
| INV-04 | One DNS resolution per hop | backend never resolves | S-04 |
| INV-05 | No environment influence; tests never reach the internet | context built directly; explicit CA file; loopback-only test guard | S-14, S-29 |
| INV-06 | Redirects followed only by the orchestrator, HTTPS only, ≤3 | `app.redirects.next_hop` | I-05, I-06, S-06, S-07 |
| INV-07 | Body never read; ≤128 KiB per hop | `GuardedStream` cap; close after headers | S-15 |
| INV-08 | Every blocking call bounded by the deadline | `clamp()` in stream, backend, resolver | S-16, S-17, S-18 |
| INV-09 | No raw target text outside egress | `SafeText` validator; `capture` only | U-10..U-12, S-19 |
| INV-10 | Cookie values never kept | `capture_cookie` keeps the name only | S-20, S-27 |
| INV-11 | `pass` only on evaluated evidence | catalog helpers; applicability; default inconclusive | U-20..U-29, I-08 |
| INV-12 | Inert HTML with its own CSP | explicit autoescape, template rules | S-13, S-21 |
| INV-13 | Target text can't steer the terminal | `Text` objects; markup, highlighting, emoji off | S-22 |
| INV-14 | Reports never overwritten, partial or target-named | `sink.writer` | S-23..S-25 |
| INV-15 | Exit code is a pure function of the outcome | `cli.exitcodes.outcome_to_exit_code` | U-40 |
| INV-16 | Request headers are exactly the fixed set | `exchange.request_headers` | S-26 |
| INV-17 | Logging can't leak target data | `SafeLogFilter`, pinned library loggers | U-50, S-27 |
| INV-18 | Summary arithmetic holds; every rule reports | `Summary`/`Report` validators | U-35 |

## Design decisions

**TLS and dependencies**
- The TLS context is built with `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` rather than `ssl.create_default_context()`,
  because the latter reads `SSLKEYLOGFILE` and would write TLS session keys to a file named by the environment.
  Contexts with key logging enabled are refused, and a static test bans the helper.
- `VERIFY_X509_STRICT | VERIFY_X509_PARTIAL_CHAIN` are set on every Python version, so 3.12 behaves like 3.13+.
- Only the configured CA file is loaded (certifi in production), never the system store.
- `certifi >= 2026.10.19` is required: older bundles trust a root whose intermediates' keys were compromised
  (GHSA-6q48-6c7w-9gw2). A test checks the installed bundle.
- Dependencies are locked with hashes and must be at least two weeks old (`exclude-newer`), with a scoped
  exception when a security fix is newer.

**Network**
- httpcore's DEBUG logging prints raw response headers, including cookie values, so `fetch_hop` pins `httpcore` and
  `h11` loggers to WARNING before every request, protecting Python-API callers too, not only the CLI.
- Certificate verification errors are captured inside `GuardedStream.start_tls`, because httpcore's pool re-raises
  exceptions in a way that loses the original cause.
- h11 rejects header blocks over about 100 KiB before the 128 KiB cap is reached; both map to `response_too_large`
  (h11's error is identified by its status hint, not its message). The cap stays as an independent backstop.
- The DNS timeout wraps any resolver, so a hanging test resolver exercises the real enforcement.
- A timeout that used up the remaining scan time is reported as `deadline_exceeded`, not as a slow phase.
- `Set-Cookie` and `Location` never enter the stored header map. Cookie values are dropped at capture, and a
  redirect target leaves egress only as a validated `CanonicalTarget`, never as raw text.

**Addresses and URLs**
- `ipaddress.is_global` alone is not enough: it is True for NAT64 (`64:ff9b::7f00:1`), the 6to4 relay
  (`192.88.99.1`) and IPv4-mapped addresses. An explicit denylist and a mapped-address check close those gaps.
- IPv6 is allowed only inside `2000::/3` (global unicast), which also excludes IPv4-compatible `::a.b.c.d`.
- The numeric-host check is repeated after IDNA mapping, because fullwidth digits and ideographic full stops map
  to `127.0.0.1`.
- A redirect `Location` is validated before `urljoin`, because `urljoin` silently strips some characters.
- Bare query items without `=` are redacted entirely, since they may be tokens.

**Results**
- A certificate verification failure is evidence (`TlsEvidence(verified=False)`), not a failed request; HTTP
  evidence without verified TLS can't be represented.
- Rule messages are fixed per reason code; dynamic values appear only as escaped evidence items.
- A scan is `partial` only when the deadline ended it after at least one response; other failures on a redirect
  hop leave it `completed`, with that hop's checks inconclusive.

**Interface and output**
- The terminal interface styles every dynamic value as a `Text` object with fixed theme styles; markup parsing is
  off, operator-typed text is escaped, and the scan plan shows the redacted target.
- Glyphs fall back to ASCII when the console can't encode Unicode (for example cp1252 pipes on Windows), and
  stdout/stderr use `errors="replace"`, so output encoding can never crash a scan.
- The progress spinner gets only the phase and hop number through an optional callback, so `app` stays free of Rich.
- Report directories that are symlinks or Windows junctions are refused; files are published with `os.link`
  (POSIX) or `os.rename` (Windows), neither of which replaces an existing file.
- Running `webguard` with no arguments shows the welcome screen and exits 0.

**Tests**
- Tests can reach only loopback: an autouse fixture blocks every other connect and DNS lookup before a packet is
  sent. It raises a `BaseException` subclass so egress can't absorb it as an ordinary failure.
