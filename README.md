# WebGuard

WebGuard is a **passive**, single-target auditor of a website's transport and response-header security
configuration. Given one `https://` URL, it makes at most four tightly controlled `GET` requests, reads only the
status line and headers, and checks TLS certificate verification and expiry, HSTS, CSP, `X-Content-Type-Options`,
cookie attributes and HTTPS-to-HTTP redirect downgrades against 10 fixed rules. It writes evidence-backed JSON and
HTML reports and prints a terminal summary.

> **Authorization.** WebGuard only scans systems you own or are authorized to assess. Every scan requires the
> `--i-am-authorized` flag.
>
> **Passive, not a penetration test.** WebGuard sends ordinary `GET` requests with a fixed, minimal header set and
> never reads response bodies. Passing checks do not mean the site is secure.

Day 5 of the *7 Days – 7 Builds* series (after NetScope, TraceDNS, FileSift and AuthWatch).

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands and flags](#commands-and-flags)
- [Exit codes](#exit-codes)
- [Rules](#rules)
- [Severity and confidence](#severity-and-confidence)
- [What WebGuard sends, and what it refuses to do](#what-webguard-sends-and-what-it-refuses-to-do)
- [Reports](#reports)
- [Limitations](#limitations)
- [Development](#development)

## Install

Requires CPython 3.12, 3.13 or 3.14 on Linux, macOS or Windows.

```console
$ git clone https://github.com/PranavY-01/WebGuard
$ cd WebGuard
$ uv tool install .          # or: pipx install .   /   python -m pip install .
$ webguard version
WebGuard 1.0.0 (report schema 1.0)
```

`python -m webguard` works the same as `webguard`.

## Quick start

```console
$ webguard scan https://your-site.example/ --i-am-authorized
```

Real output from a scan of the local test fixture (`tests/fixtures`), whose response lacks the security headers:

```text
$ webguard scan https://webguard.test:8443/missing --i-am-authorized --fail-on medium --output findings
                                              WebGuard results
┌────────────┬─────────┬────────────────┬──────────┬────────────────────────────────────────────────────────┐
│ Rule       │ Subject │ Status         │ Severity │ Message                                                │
├────────────┼─────────┼────────────────┼──────────┼────────────────────────────────────────────────────────┤
│ WG-CK-001  │ -       │ not_applicable │ -        │ No Set-Cookie headers were observed.                   │
│ WG-CK-002  │ -       │ not_applicable │ -        │ No Set-Cookie headers were observed.                   │
│ WG-CK-003  │ -       │ not_applicable │ -        │ No Set-Cookie headers were observed.                   │
│ WG-CK-004  │ -       │ not_applicable │ -        │ No Set-Cookie headers were observed.                   │
│ WG-HDR-001 │ hop:0   │ finding        │ medium   │ No Strict-Transport-Security header was returned.      │
│ WG-HDR-002 │ hop:0   │ finding        │ low      │ No Content-Security-Policy header was returned.        │
│ WG-HDR-003 │ hop:0   │ finding        │ low      │ No X-Content-Type-Options header was returned.         │
│ WG-RDR-001 │ hop:0   │ not_applicable │ -        │ The response is not a redirect.                        │
│ WG-TLS-001 │ hop:0   │ pass           │ -        │ The certificate chain and hostname verified against    │
│            │         │                │          │ the trust store.                                       │
│ WG-TLS-002 │ hop:0   │ pass           │ -        │ The certificate remains valid for more than 30 days.   │
└────────────┴─────────┴────────────────┴──────────┴────────────────────────────────────────────────────────┘
Status completed: 10 checks, 2 pass, 3 finding, 0 inconclusive, 0 error, 5 not applicable (high 0, medium 1,
low 2, informational 0)
Target https://webguard.test:8443/missing
Report written: findings\webguard_20261027T184934Z_80ede724.json
Report written: findings\webguard_20261027T184934Z_80ede724.html
Exit 1: finding(s) at or above --fail-on medium
```

Targets that fail validation are refused before any DNS lookup or connection:

```text
$ webguard scan https://127.0.0.1/ --i-am-authorized
Target rejected (policy_prohibited_address); nothing was sent. loopback:127.0.0.1
Exit 3: target rejected: policy_prohibited_address

$ webguard scan http://webguard.test/ --i-am-authorized
Target rejected (scheme_not_https); nothing was sent.
Exit 3: target rejected: scheme_not_https

$ webguard scan https://webguard.test/
WebGuard only scans systems you own or are authorized to assess. Re-run with --i-am-authorized.
```

More transcripts and complete JSON/HTML sample reports, all generated from local fixtures, are in
[`samples/`](samples/).

## Commands and flags

| Command | What it does |
|---|---|
| `webguard scan URL --i-am-authorized [options]` | Runs one scan and writes a JSON and an HTML report. |
| `webguard rules` | Lists the 10 rules (ID, name, category, possible severities). Makes no network connections. |
| `webguard version` | Prints `WebGuard 1.0.0 (report schema 1.0)`. |

`scan` options. **No other options exist:** there is no way to disable TLS verification, allow plain HTTP or
private targets, use a proxy or custom CA, add headers or cookies, or overwrite reports.

| Flag | Default | Meaning |
|---|---|---|
| `--i-am-authorized` | *(required)* | Confirms you own the target or are authorized to assess it. Missing → exit 2. No prompt, so it is CI-safe. |
| `--follow-redirects` | off | Follow up to 3 redirects. Each must be `https://`, is re-validated from scratch (URL rules, fresh DNS resolution, address policy, new connection), and loops stop the chain. |
| `--deadline SECONDS` | `30` | Overall deadline for the whole scan, 5–120. Every DNS lookup, connect, handshake, read and write is bounded by what remains. |
| `--fail-on LEVEL` | `high` | `none`, `informational`, `low`, `medium` or `high`. Exit 1 when a finding at or above this severity exists. `none` never yields exit 1. |
| `--output DIR` | `./reports` | Report directory. Created only if its parent already exists; symlinks are refused; files are never overwritten. |
| `--debug` | off | Diagnostics on stderr: redacted URL, resolved and connected IPs, timings, failure codes. Never cookie names or values, raw header values or query values. |

No environment variable changes WebGuard's behaviour (proxy, CA bundle, netrc, key-log variables are all ignored).
Rich's own `NO_COLOR`/`TERM` handling affects presentation only.

### Target URL rules

The URL must be `https://`, at most 2048 characters, with no whitespace, control characters, backslashes or user
info. The host must be a DNS name (IDNA is converted to its ASCII form) or a strict dotted-quad IPv4 or bracketed
IPv6 literal. Ambiguous numeric hosts such as `127.1`, `0x7f.0.0.1` or `2130706433` are refused. Ports: 443
(default) or 8443. Fragments are dropped; query values are redacted in reports.

Every address the host resolves to must be public. If **any** answer is loopback, private, link-local, CGNAT,
documentation, benchmarking, multicast, reserved, IPv4-mapped, NAT64, 6to4, Teredo or otherwise non-global, the
target is refused (exit 3) and no connection is made.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; no finding at or above `--fail-on`. |
| 1 | Scan completed (or partial); at least one finding at or above `--fail-on`. |
| 2 | Usage or configuration error, malformed URL, or missing `--i-am-authorized`. |
| 3 | Target rejected by policy before any request: scheme, port, ambiguous host, or a non-public address. |
| 4 | Scan failed with no usable evidence (DNS, connect, handshake, read, malformed response), or a partial scan with no finding at or above the threshold. |
| 5 | Reports could not be written (output directory or write error). |
| 70 | Internal error (a bug), including any rule raising an exception. |
| 130 | Interrupted (Ctrl+C). |

When several apply, the first in this order wins: 130, 70, 2, 3, 5, 4, 1, 0. A report is written for every scan that
passes validation, including failed, partial and interrupted scans. No report is written for exit 2 or 3.

## Rules

Full details, every reason code, remediation and references: [`docs/RULES.md`](docs/RULES.md).

| ID | Checks | Finding severities |
|---|---|---|
| `WG-TLS-001` | Certificate verification per hop: expired, not yet valid, untrusted chain, hostname mismatch. | high |
| `WG-TLS-002` | Certificate expiry horizon: medium within 14 days, low within 15–30 days. | low, medium |
| `WG-HDR-001` | HSTS on every HTTPS response: absent, invalid or `max-age=0` (medium); `max-age` below 180 days (low). | low, medium |
| `WG-HDR-002` | Enforcing `Content-Security-Policy` on the final response (presence only; quality is not graded). | low |
| `WG-HDR-003` | `X-Content-Type-Options: nosniff` on the final response. | low |
| `WG-CK-001` | Every cookie has `Secure`. | medium |
| `WG-CK-002` | Every cookie has `HttpOnly` (low confidence: the cookie's purpose is unknown). | low |
| `WG-CK-003` | `SameSite` is Strict/Lax, or None together with Secure. | informational, low, medium |
| `WG-CK-004` | `__Secure-` / `__Host-` name-prefix requirements. | medium |
| `WG-RDR-001` | An HTTPS response redirecting to `http://`. | medium |

Rules know their context. Header rules on a redirect response report `not_applicable` and suggest
`--follow-redirects`. Header rules on 4xx/5xx responses lower their confidence to medium. When the certificate fails
verification, every rule that needs HTTP evidence reports `inconclusive` (`blocked_by:WG-TLS-001`). A rule reports
`pass` only after evaluating its condition on evidence that is actually present.

## Severity and confidence

| Severity | Meaning | V1 examples |
|---|---|---|
| high | Directly breaks the transport-security guarantee for users. | Certificate verification failures. |
| medium | Removes a protection, with a concrete and commonly exploitable consequence. | HSTS missing/disabled/invalid, cookie without `Secure`, `SameSite=None` without `Secure`, prefix violation, HTTPS→HTTP redirect, certificate expiring within 14 days. |
| low | Defence-in-depth gap with no consequence on its own. | CSP missing or report-only, `X-Content-Type-Options` missing/invalid, short HSTS `max-age`, cookie without `HttpOnly`, certificate expiring in 15–30 days. |
| informational | Context, not a weakness. | `SameSite` absent (browser default applies). |

No V1 rule reports `critical`: passive checks do not demonstrate direct exploitation.
**Confidence:** *high* means direct evidence meets the condition. *Medium* means evidence is present but its
context weakens it (for example a 4xx/5xx response). *Low* means the conclusion depends on unknown intent
(`HttpOnly`).

## What WebGuard sends, and what it refuses to do

Each request is a `GET` with exactly these headers and nothing else (no cookies, no credentials):

```text
Host: <target host>
User-Agent: WebGuard/1.0.0 (+passive configuration audit; https://github.com/PranavY-01/WebGuard)
Accept: */*
Accept-Encoding: identity
Connection: close
```

- **One way out.** All network I/O lives in one package. The hostname is resolved exactly once per request.
  Every answer is classified, and the connection goes only to one of those classified addresses. The connected
  peer is checked before any byte is sent, which defeats DNS rebinding.
- **Verified TLS only.** Certificates and hostnames are checked against the bundled `certifi` CA store, with
  TLS 1.2 minimum. There is no way to turn verification off. TLS facts come from the same connection, never a
  second one.
- **Bounded.** At most 4 requests per scan, 128 KiB read per request, 100 headers, 50 cookies. Every blocking
  operation is clamped to the remaining deadline, so a slow-drip server cannot stretch the scan.
- **Untrusted data stays inert.** Header values, certificate fields and cookie names are escaped as soon as they
  are captured (control, bidirectional and invisible characters become visible escapes). Cookie values are
  discarded immediately and never stored, logged or shown. Query values are redacted. The HTML report is
  autoescaped, has no scripts, links or external resources, and carries its own Content-Security-Policy. Terminal
  output never interprets target text as markup.
- **No surprises from the environment.** Proxy variables, `.netrc`, `SSL_CERT_FILE`/`SSL_CERT_DIR` and
  `SSLKEYLOGFILE` are ignored.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Reports

Each scan writes two files to `--output` (default `./reports`):

```text
webguard_<YYYYMMDDTHHMMSSZ>_<scan-id-prefix>.json
webguard_<YYYYMMDDTHHMMSSZ>_<scan-id-prefix>.html
```

File names are generated and never contain target text. Files are created exclusively with mode `0600` on POSIX,
are never overwritten, and a failed write leaves no partial or temporary file. WebGuard never deletes or rotates
reports; retention is up to you. Add `reports/` to your `.gitignore`.

The JSON report (`schema_version` `"1.0"`) contains:

- `tool` and `scan`: id, UTC timestamps, status `completed` / `partial` / `interrupted` / `failed`, redacted
  target, configuration, notes.
- `hops`: per-request evidence (resolved and connected IPs, TLS facts, allowlisted headers, cookie names and
  attributes, redacted `Location`).
- `results`: one entry per rule per subject, with status, severity, confidence, reason code, static message,
  evidence, remediation, references and limitations.
- `summary` (counts) and `limitations`.

The HTML report shows the same content as a self-contained page that works in light or dark mode and prints well.

## Limitations

- Passive configuration assessment; **not a penetration test**. Passing checks do not mean the site is secure.
- Only the status line and headers are inspected. The body is never read, so `<meta>` CSP and page content are
  not assessed, and CSP quality is not graded.
- TLS checks cover certificate verification and expiry only. Protocol versions and cipher suites are not audited.
- Trust is evaluated against the `certifi` CA bundle, which may differ from your operating system's or browser's
  trust store.
- URL **paths** are reported as given and may contain tokens; only query values are redacted.
- Only public `https://` targets on ports 443/8443. No plain HTTP, private networks, proxies or HTTP/2.
- On Windows, Ctrl+C can take up to 10 seconds to take effect while a socket read is blocked.
- A DNS lookup cannot be cancelled. If it hangs, WebGuard gives up after its timeout, but the background lookup
  thread lives until the process exits.
- Results describe one moment from one network vantage point.

## Development

```console
$ uv sync --locked                       # Python 3.12+; uv.lock pins every dependency with hashes
$ uv run ruff check && uv run ruff format --check
$ uv run mypy --strict src/
$ uv run lint-imports                    # architecture contracts (network I/O only in webguard.egress)
$ uv run pytest                          # unit, integration and security tests; loopback fixtures only
$ uv run python -m tests.unit.render_docs   # regenerate docs/RULES.md and the known-answer record
$ uv run python -m tests.make_samples       # regenerate samples/ from local fixtures
```

Tests never touch the internet. They run against a local TLS server on `127.0.0.1:8443` with a locally generated
CA. That CA, a permissive scope policy and a stub resolver are injected through the Python API and exist only
under `tests/`. CI runs the full suite on Linux, macOS and Windows × Python 3.12, 3.13 and 3.14, and audits the
locked dependencies with `pip-audit`.

Layout: `src/webguard/{domain,policy,egress,rules,render,sink,app,cli}`. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Security issues: see [`SECURITY.md`](SECURITY.md). Changes: [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
