# WebGuard user guide

This guide shows you how to install WebGuard, scan a website you are responsible for, read what it tells you, fix
what it finds, and use it in automated pipelines.

**Contents**

1. [What WebGuard does (and doesn't)](#1-what-webguard-does-and-doesnt)
2. [Before you scan](#2-before-you-scan)
3. [Installing](#3-installing)
4. [Your first scan](#4-your-first-scan)
5. [Choosing the URL to scan](#5-choosing-the-url-to-scan)
6. [Scan options](#6-scan-options)
7. [Reading the results](#7-reading-the-results)
8. [The ten checks and how to fix them](#8-the-ten-checks-and-how-to-fix-them)
9. [Working with reports](#9-working-with-reports)
10. [Using WebGuard in CI and scripts](#10-using-webguard-in-ci-and-scripts)
11. [Troubleshooting](#11-troubleshooting)
12. [Privacy: what WebGuard records](#12-privacy-what-webguard-records)
13. [FAQ](#13-faq)
14. [Quick reference](#14-quick-reference)

---

## 1. What WebGuard does (and doesn't)

WebGuard visits one HTTPS address the way a browser's first request would, and checks how the site is configured
for transport security:

- **TLS certificate:** is it trusted, valid for this hostname, and not about to expire?
- **Security headers:** HSTS, Content-Security-Policy, X-Content-Type-Options.
- **Cookies:** `Secure`, `HttpOnly`, `SameSite` and the `__Secure-`/`__Host-` name prefixes.
- **Redirects:** does an HTTPS page send visitors back to plain HTTP?

It prints a summary and saves two reports (JSON for machines, HTML for people).

What it does **not** do:

- It is **not a penetration test.** It does not attack, fuzz, log in, crawl or try to exploit anything.
- It reads only the **status line and headers** of each response, never the page body.
- It does not grade TLS versions or cipher suites, or judge how strong your CSP is.
- **A clean result does not mean the site is secure.** It means these ten settings look right.

## 2. Before you scan

**Only scan sites you own or are authorized to assess.** WebGuard asks you to confirm this on every scan with
the `--i-am-authorized` flag. Without it, nothing is sent.

What the site will see is very small. Each scan sends **at most 4 ordinary `GET` requests** (one, plus up to three
if you ask it to follow redirects). Every request carries exactly these headers:

```text
Host: <your host>
User-Agent: WebGuard/1.0.0 (+passive configuration audit; https://github.com/PranavY-01/WebGuard)
Accept: */*
Accept-Encoding: identity
Connection: close
```

WebGuard never sends cookies, credentials or custom headers, and it closes each connection as soon as the headers
arrive. If you run a WAF or monitor logs, you can recognise the scan by that `User-Agent`.

Requirements: Python **3.12, 3.13 or 3.14** on Linux, macOS or Windows, and network access to the site.

## 3. Installing

You need Python and pip. [pipx](https://pipx.pypa.io/) is recommended because it keeps WebGuard isolated from
your other Python packages.

```console
$ git clone https://github.com/PranavY-01/WebGuard
$ cd WebGuard
$ pipx install .
```

Or install into a virtual environment:

```console
$ python -m venv .venv
$ source .venv/bin/activate          # Windows: .venv\Scripts\activate
$ python -m pip install .
```

Check that it works:

```console
$ webguard version
WebGuard 1.0.0 (report schema 1.0)
```

If the `webguard` command isn't found, `python -m webguard` does the same thing.

To **upgrade**, pull the latest code and run `pipx install --force .` (or `pip install --upgrade .`). To
**uninstall**, run `pipx uninstall webguard` (or `pip uninstall webguard`).

## 4. Your first scan

```console
$ webguard scan https://www.your-site.example/ --i-am-authorized
```

A scan usually takes a second or two. Here is real output from a scan of WebGuard's local test server, whose page
is missing its security headers:

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

How to read it:

1. **The table** has one row per check per subject. Here the certificate is fine, cookies weren't set at all, and
   three headers are missing.
2. **The status line** counts the outcomes and the findings by severity.
3. **The report paths** point to your saved results. By default they go in a `reports` folder in the current
   directory. Open the `.html` file in a browser for the readable version.
4. **The exit line** gives the process exit code and the reason (see [section 10](#10-using-webguard-in-ci-and-scripts)).

Next step: look up each `finding` in [section 8](#8-the-ten-checks-and-how-to-fix-them) to see how to fix it.

## 5. Choosing the URL to scan

Give WebGuard one complete `https://` URL.

**Scan the page your visitors actually land on.** Many sites redirect `https://example.com/` to
`https://www.example.com/`. If you scan the address that redirects, the header checks report `not_applicable`,
because a redirect response isn't a page. Either scan the final URL directly or add `--follow-redirects`.

**What WebGuard accepts:**

- `https://` only, on port **443** (the default) or **8443**.
- A normal hostname (international names are fine), or a plain IPv4 address (`203.0.113.7`), or a bracketed IPv6
  address (`[2001:db8::1]`).
- Up to 2048 characters, with no spaces, control characters, backslashes or `user:password@` part.
- Anything after `#` is ignored. Query strings are allowed, but their values are hidden in reports.

**Public sites only.** Before connecting, WebGuard looks up the hostname. If **any** of the addresses is private,
loopback, link-local or otherwise not on the public internet, it refuses the scan and sends nothing. The same
applies to an IP address you type directly. This stops WebGuard from being pointed at internal systems, including
by a site that tries to trick it with DNS. There is no option to scan internal hosts.

If a target is refused, you'll see `Target rejected (<code>); nothing was sent.` and exit code 2 or 3:

| Code | What it means | What to do |
|---|---|---|
| `scheme_not_https` | The URL isn't `https://` (for example `http://` or no scheme at all). | Use the `https://` address. |
| `port_not_permitted` | A port other than 443 or 8443 was given. | Use the site's standard HTTPS port. |
| `userinfo_present` | The URL contains `user@` or `user:password@`. | Remove the credentials; WebGuard never logs in. |
| `host_invalid` | The hostname is malformed (bad characters, empty, too long, broken IPv6). | Check the spelling. |
| `ipv4_ambiguous` | A numeric host in a shorthand form such as `127.1`, `0x7f.0.0.1` or `2130706433`. | Write the full dotted address, or use the hostname. |
| `url_illegal_chars` | Spaces, control characters, backslashes or non-ASCII characters in the path. Exit 2. | Percent-encode the path; quote the URL in your shell. |
| `url_too_long` | Longer than 2048 characters. Exit 2. | Shorten the URL. |
| `policy_prohibited_address` | The host is, or resolves to, a non-public address. The message names which kind, for example `loopback:127.0.0.1` or `private:10.0.0.5`. | WebGuard can't scan it. Scan the public address of the site instead. |

## 6. Scan options

```text
webguard scan URL --i-am-authorized [--follow-redirects] [--deadline SECONDS]
                  [--fail-on LEVEL] [--output DIR] [--debug]
```

| Option | Default | Use it when |
|---|---|---|
| `--i-am-authorized` | required | Always. It confirms you may assess the site. |
| `--follow-redirects` | off | The URL redirects (for example apex → `www`, or `/` → `/login`) and you want the final page checked too. |
| `--deadline SECONDS` | 30 | The site is slow (raise it, up to 120), or you want a fast fail (lower it, at least 5). |
| `--fail-on LEVEL` | high | You use the exit code in CI and want to fail on less severe findings too. |
| `--output DIR` | `reports` | You want the reports somewhere else. |
| `--debug` | off | Something unexpected happened and you want to see what WebGuard did. |

There are deliberately **no** options to skip certificate checks, use plain HTTP, scan private networks, go through
a proxy, send cookies or headers, or overwrite reports. Environment variables such as `HTTPS_PROXY` or
`SSL_CERT_FILE` are ignored too.

### `--follow-redirects`

Without it, WebGuard checks the first response only. If that response is a redirect, the report includes the note
`redirect_not_followed`.

With it, WebGuard follows **up to 3** redirects. Each new address goes through the same checks as the original:
it must be `https://` on an allowed port, it is looked up again, every address must be public, and a fresh,
verified connection is made. Following stops, with a note in the report, when:

| Note | Why it stopped |
|---|---|
| `redirect_limit_reached` | Three redirects were already followed. |
| `redirect_loop` | The redirect points to an address already visited. |
| `redirect_blocked_by_policy` | The next host resolves to a non-public address. The scan still completes using the responses gathered so far. |
| `redirect_rejected:<code>` | The `Location` failed a URL rule; for example `redirect_rejected:scheme_not_https` for a redirect to `http://`. That redirect is **never** followed, and WG-RDR-001 reports it. |
| `redirect_location_missing` / `redirect_location_unparseable` | The redirect has no usable `Location` header. |

With redirects followed, the HSTS, cookie, certificate and redirect checks run on **every** response in the chain.
CSP and X-Content-Type-Options are checked on the **final** response.

### `--deadline`

This is the time limit for the **whole scan**, including every lookup, connection and read. If time runs out after
at least one response arrived, the scan ends as `partial` with the note `deadline_reached`; checks that never got
evidence report `inconclusive` with the reason `scan_deadline`. If it runs out before anything arrived, the scan is
`failed`.

### `--fail-on`

This sets which findings make WebGuard **exit with code 1**. It changes nothing about what is checked or reported.

| Value | Exit 1 when a finding is at least... |
|---|---|
| `high` (default) | high, which means certificate problems |
| `medium` | medium, which adds missing HSTS, insecure cookies, HTTPS→HTTP redirects, certificates expiring within 14 days |
| `low` | low, which adds missing CSP or X-Content-Type-Options, short HSTS, cookies without HttpOnly |
| `informational` | anything at all, including `SameSite` not set |
| `none` | never; useful when you only want the reports |

Values are lowercase.

### `--output`

Reports are written to this directory, which is created if it doesn't exist **and** its parent folder does.
WebGuard refuses to write into a symbolic link (or a Windows junction). It never overwrites an existing file and
never leaves half-written files behind.

### `--debug`

This prints diagnostic lines to stderr, such as:

```text
webguard: DEBUG webguard.egress: hop 0 https://www.your-site.example/: answers=2 connected=203.0.113.7 bytes_read=812 elapsed=0.214s outcome=http
```

Debug output shows the address with query values hidden, the IP addresses involved, timings and failure codes. It
never shows cookie names or values, header contents or query values, so it is safe to paste into a bug report.

## 7. Reading the results

### Columns

| Column | Meaning |
|---|---|
| **Rule** | Which check, for example `WG-HDR-001` (see [section 8](#8-the-ten-checks-and-how-to-fix-them)). |
| **Subject** | What was checked. `hop:0` is the first response, `hop:1` the next one after a redirect, and so on. `cookie:session@hop:0` is the cookie named `session` set by the first response. `-` means the result applies to the scan as a whole. |
| **Status** | The outcome, from the table below. |
| **Severity** | How serious a finding is. It appears only when the status is `finding`. |
| **Message** | A plain-language explanation. |

### Statuses

| Status | Meaning |
|---|---|
| `pass` | The check was evaluated against real evidence and the setting is correct. |
| `finding` | The check was evaluated and something should be fixed. |
| `not_applicable` | The check doesn't apply here, for example cookie checks when no cookies were set, or CSP on a redirect response. |
| `inconclusive` | There wasn't enough evidence to decide. The reason says why: `blocked_by:WG-TLS-001` (the certificate failed, so no page was fetched), `hop_failed`, `scan_deadline` or `scan_interrupted`. |
| `error` | The check could not run. For WG-TLS-001 this means the secure connection was never established (reasons `tls_not_reached`, `handshake_failed`). `internal_rule_error` means a bug in WebGuard (exit 70). |

WebGuard never reports `pass` without evidence. Anything it couldn't check shows up as `inconclusive` or `error`.

### Severity and confidence

| Severity | Meaning |
|---|---|
| **high** | Breaks the security of the connection for your users. Fix immediately. |
| **medium** | Removes a protection with a realistic, commonly exploited consequence. Fix soon. |
| **low** | A defence-in-depth gap; harmful mainly in combination with another weakness. |
| **informational** | Worth knowing; not a weakness on its own. |

Each `pass` or `finding` also carries a **confidence**, shown in the HTML and JSON reports:

- **high:** the evidence directly shows it.
- **medium:** the evidence is there, but the context weakens it. Header checks on an error page (4xx/5xx), for
  example, may not reflect your real pages.
- **low:** the answer depends on something WebGuard can't know. A cookie without `HttpOnly` may be intentionally
  readable by your JavaScript.

### Scan status

| Scan status | Meaning |
|---|---|
| `completed` | Every response needed was received and every check ran. |
| `partial` | The deadline ran out after at least one response arrived; some checks are `inconclusive`. |
| `failed` | No usable response at all (lookup failure, refused connection, broken TLS handshake, malformed reply). |
| `interrupted` | You pressed Ctrl+C. Whatever was gathered is still saved. |

A certificate that fails verification is a `finding`, not a failed scan. The scan is `completed`, and the checks
that needed the page are `inconclusive`.

## 8. The ten checks and how to fix them

Run `webguard rules` for the list. [`docs/RULES.md`](RULES.md) has every reason code with references. The header
examples below are in standard HTTP form; set them in your web server, CDN or application framework.

### WG-TLS-001: Certificate verification (high)

Checks that the certificate is trusted, currently valid and issued for the exact hostname you scanned.

| Reason | Typical cause | Fix |
|---|---|---|
| `expired` | Renewal didn't happen. | Renew it, and automate renewal (for example ACME/Let's Encrypt). |
| `not_yet_valid` | A new certificate was deployed early, or the server clock is wrong. | Check the certificate dates and the server time. |
| `untrusted_chain` | Most often the server doesn't send the **intermediate** certificate. Also self-signed or private-CA certificates. | Configure the full chain (leaf + intermediates). Use a publicly trusted CA for public sites. |
| `hostname_mismatch` | The certificate doesn't cover this name (for example only `www` but you scanned the apex). | Add every hostname you serve to the certificate's SAN list. |

> "But it works in my browser." Browsers can sometimes repair a missing intermediate on their own; WebGuard (like
> most API clients) cannot. WebGuard trusts the widely used `certifi` root store, which can also differ slightly
> from your operating system's store.

### WG-TLS-002: Certificate expiry horizon (medium / low)

A **medium** finding means the certificate expires within 14 days; **low** means within 15–30 days; more than
30 days passes. Fix: renew now, and set up renewal monitoring.

### WG-HDR-001: Strict-Transport-Security, HSTS (medium / low)

HSTS tells browsers to use HTTPS for your site, every time. It is checked on every HTTPS response in the chain.

| Reason | Severity | Meaning |
|---|---|---|
| `header_absent` | medium | No HSTS header. |
| `invalid` | medium | Malformed: missing or non-numeric `max-age`, or a directive repeated. Browsers ignore it. |
| `disabled` | medium | `max-age=0` switches HSTS off. |
| `max_age_below_minimum` | low | Shorter than 180 days. |

Fix, once your whole site (and any subdomains you include) works over HTTPS:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

nginx: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
Apache: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`

### WG-HDR-002: Content-Security-Policy (low)

A CSP limits where scripts and other content may load from, which reduces the damage of cross-site scripting.
WebGuard checks that an **enforcing** policy exists on the final page; it does not grade how strict it is.

| Reason | Meaning |
|---|---|
| `header_absent` | No CSP header. |
| `report_only_only` | Only `Content-Security-Policy-Report-Only` is present, which enforces nothing. |
| `empty_policy` | The header is present but empty. |
| `redirect_response` | `not_applicable`: the scanned URL is a redirect. Use `--follow-redirects` or scan the final URL. |

Fix: start with a report-only policy, watch the reports, then switch to enforcing. A strict starting point:

```text
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'
```

WebGuard can't see a CSP set in an HTML `<meta>` tag, because it doesn't read page bodies.

### WG-HDR-003: X-Content-Type-Options (low)

This stops browsers from guessing ("sniffing") content types, which can turn an uploaded file into executable
script. It is checked on the final page. Fix:

```text
X-Content-Type-Options: nosniff
```

nginx: `add_header X-Content-Type-Options "nosniff" always;`

### WG-CK-001: Cookie `Secure` (medium)

A cookie without `Secure` can be sent over unencrypted HTTP and stolen on the network. Add `Secure` to every
cookie set by an HTTPS site.

### WG-CK-002: Cookie `HttpOnly` (low, low confidence)

A cookie without `HttpOnly` can be read by JavaScript, so an XSS bug can steal it. Add `HttpOnly` to every cookie
your scripts don't need, and always to session cookies. Some cookies (like a CSRF token read by your front end)
are intentionally script-readable, so this check has low confidence.

### WG-CK-003: Cookie `SameSite` (medium / low / informational)

`SameSite` controls whether the cookie is sent on cross-site requests, which helps against CSRF.

| Reason | Severity | Fix |
|---|---|---|
| `none_without_secure` | medium | Browsers reject `SameSite=None` without `Secure`. Add `Secure`. |
| `invalid_value` | low | Use `Strict`, `Lax` or `None`. |
| `samesite_absent` | informational | Set it explicitly instead of relying on browser defaults. |

`SameSite=Lax` suits most cookies. Use `Strict` for sensitive cookies, and `None; Secure` only for cookies that
truly must work cross-site.

### WG-CK-004: Cookie name prefixes (medium)

Cookie names beginning with `__Secure-` or `__Host-` promise extra protections, and browsers reject cookies that
break the promise:

- `__Secure-name` must have `Secure`.
- `__Host-name` must have `Secure`, `Path=/`, and **no** `Domain` attribute.

A well-formed session cookie:

```text
Set-Cookie: __Host-session=<value>; Secure; HttpOnly; SameSite=Lax; Path=/
```

### WG-RDR-001: Redirect downgrade to HTTP (medium)

An HTTPS page that redirects to an `http://` address sends your visitor back onto an unencrypted connection, where
the next request can be intercepted. WebGuard reports it and never follows it. Fix: make every redirect target
`https://`, and enable HSTS (WG-HDR-001) so browsers upgrade automatically.

## 9. Working with reports

Every scan that gets past target validation writes two files, even when the scan failed, was partial or was
interrupted:

```text
reports/webguard_20261027T184934Z_80ede724.json
reports/webguard_20261027T184934Z_80ede724.html
```

The name holds the UTC start time and the first 8 characters of the scan ID. It never contains anything from the
website. Existing files are never overwritten. WebGuard never deletes old reports, so clean them up yourself. If
you scan from inside a code repository, add `reports/` to `.gitignore`.

**The HTML report** is a single self-contained page. It loads nothing from the internet and runs no scripts, so it
is safe to open and to email. It shows the summary, every result (expand **evidence, remediation, references** for
details), the per-request evidence (addresses, TLS facts, status codes, redirect targets), and the limitations. It
works in light and dark mode and prints cleanly.

**The JSON report** holds the same data for tools. Its top-level keys:

| Key | Contents |
|---|---|
| `schema_version` | `"1.0"` |
| `tool` | `{name, version}` |
| `scan` | `scan_id`, `started_at`, `finished_at` (UTC), `status`, `target` (query values redacted), `config`, `notes` |
| `hops` | One entry per request: resolved and connected IPs, TLS facts, status code, selected headers, cookie names and attributes, redacted `Location`, or the failure code |
| `results` | One entry per check per subject: `rule_id`, `subject`, `status`, `severity`, `confidence`, `reason_code`, `message`, `evidence`, `remediation`, `references`, `limitations` |
| `summary` | Counts by status and by severity |
| `limitations` | What this kind of scan cannot tell you |

List just the findings with [jq](https://jqlang.github.io/jq/):

```console
$ jq -r '.results[] | select(.status=="finding") | "\(.severity)\t\(.rule_id)\t\(.subject)\t\(.message)"' reports/webguard_*.json
```

PowerShell:

```powershell
(Get-Content reports\webguard_*.json -Raw | ConvertFrom-Json).results |
  Where-Object status -eq 'finding' | Select-Object severity, rule_id, subject, message
```

Complete example reports are in [`samples/`](../samples/).

## 10. Using WebGuard in CI and scripts

WebGuard never prompts, so it runs unattended. Decide what should fail the build with `--fail-on`, then act on the
exit code:

| Exit code | Meaning | Suggested handling |
|---|---|---|
| 0 | Scan completed; nothing at or above `--fail-on`. | Pass. |
| 1 | At least one finding at or above `--fail-on`. | Fail the build. |
| 2 | Usage error: bad option, malformed URL, or missing `--i-am-authorized`. | Fix the pipeline configuration. |
| 3 | Target refused before anything was sent (scheme, port, host form, non-public address). | Fix the URL. |
| 4 | The scan failed (no usable response), or a partial scan with nothing at or above the threshold. | Retry or investigate connectivity. |
| 5 | The reports couldn't be written. | Fix the output directory or disk. |
| 70 | Internal error in WebGuard. | Report a bug (see `SECURITY.md` for security bugs). |
| 130 | Interrupted. | — |

If more than one applies, the first in this order wins: 130, 70, 2, 3, 5, 4, 1, 0.

**GitHub Actions example**

```yaml
- name: Install WebGuard
  run: pipx install git+https://github.com/PranavY-01/WebGuard
- name: Scan staging
  run: webguard scan https://staging.your-site.example/ --i-am-authorized --fail-on medium --output webguard-reports
- name: Keep the reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: webguard-reports
    path: webguard-reports/
```

**Shell example** (WebGuard scans one URL per run, so loop for several):

```bash
for url in https://www.your-site.example/ https://app.your-site.example/login; do
  webguard scan "$url" --i-am-authorized --fail-on medium --output reports
  rc=$?
  case $rc in
    0) echo "OK      $url" ;;
    1) echo "FIX     $url" ;;
    3) echo "REFUSED $url" ;;
    *) echo "ERROR   $url (exit $rc)" ;;
  esac
done
```

Always quote URLs in the shell; `?` and `&` are special characters.

## 11. Troubleshooting

**"WebGuard only scans systems you own or are authorized to assess."** Add `--i-am-authorized`.

**`Target rejected (policy_prohibited_address)` for my staging or internal site.** Its hostname resolves to a
private or local address. WebGuard scans public sites only and can't be configured otherwise. Scan a publicly
reachable environment instead.

**Every header check says `not_applicable` / `redirect_response`.** You scanned an address that redirects. Add
`--follow-redirects` or scan the final URL.

**`WG-TLS-001 untrusted_chain`, but the site loads in my browser.** Your server is probably not sending its
intermediate certificate. Configure the full chain. See [WG-TLS-001](#wg-tls-001-certificate-verification-high).

**Everything is `inconclusive` with `blocked_by:WG-TLS-001`.** The certificate failed verification, so WebGuard
deliberately didn't request the page over an untrusted connection. Fix the certificate first.

**Exit 4 / scan `failed`.** Open the HTML report's *Per-hop evidence* table (or `hops[].failure` in the JSON)
for the failure code:

| Failure code | Meaning |
|---|---|
| `dns_no_answer` | The hostname didn't resolve. Check the spelling and your DNS. |
| `dns_timeout` | The DNS lookup took longer than 5 seconds. |
| `dns_too_many_answers` | The name returned more than 16 addresses. |
| `connect_failed` / `connect_timeout` | Nothing accepted the connection on that port (firewall, wrong port, server down). |
| `tls_handshake_failed` | The secure connection couldn't be negotiated (for example the server only offers TLS below 1.2). |
| `read_timeout` | The server accepted the connection but didn't send headers in time. |
| `response_too_large` | The response headers exceeded WebGuard's size limit (about 100–128 KiB). |
| `malformed_response` | The reply wasn't valid HTTP/1.1, had more than 100 headers, or the connection broke mid-response. |
| `deadline_exceeded` | The overall `--deadline` ran out. Try a larger value. |

**Exit 5: `Report persistence failed (<code>)`.** The results are still printed.

| Code | Meaning |
|---|---|
| `output_parent_missing` | The folder that should contain `--output` doesn't exist. WebGuard creates only the last folder level. |
| `output_not_directory` | `--output` points to a file. |
| `output_is_symlink` | `--output` is a symbolic link or junction; give the real path. |
| `output_not_writable` | No permission to write there. |
| `output_exists` | A report with the same name already exists (extremely unlikely; run again). |
| `write_failed` | The disk is full or a write error occurred. Nothing partial is left behind. |

**Ctrl+C takes a few seconds on Windows.** While waiting on a slow server, Windows delivers Ctrl+C only when the
current network wait ends, which takes at most about 10 seconds. The partial report is still saved.

**`webguard: command not found`.** Use `python -m webguard`, or make sure pipx's bin directory is on your `PATH`
(`pipx ensurepath`).

## 12. Privacy: what WebGuard records

| Kept in reports | Never kept anywhere |
|---|---|
| The URL with **query values replaced by `REDACTED`** | Cookie **values** (discarded the moment they arrive) |
| Resolved and connected IP addresses | Response bodies (never read) |
| Certificate subject, issuer, SAN names, validity dates | Headers other than the security headers listed below |
| Values of `Strict-Transport-Security`, `Content-Security-Policy` (and `-Report-Only`), `X-Content-Type-Options`, `Content-Type` | Query values, in any output |
| Cookie **names** and their attributes (`Secure`, `Path`, …) | |
| Redirect targets, with query values redacted | |

**The URL path is kept as given.** If your path contains a token (for example `/reset/abc123`), don't scan that
URL, or treat the report as sensitive. Reports are created readable only by your user account on Linux and macOS.

Text from the website (header values, cookie names, certificate fields) is stored with control and
invisible characters made visible. It can never inject markup into the HTML report or styling into your terminal.

## 13. FAQ

**Is it safe to run against production?** Yes. A scan is at most four ordinary `GET` requests that close as soon
as the headers arrive, the same load as a few page views. Still, only scan sites you're authorized to assess.

**Does it log in or test authenticated pages?** No. It never sends cookies or credentials, so it sees what an
anonymous first-time visitor sees.

**Why HTTPS only? Why not my internal network?** WebGuard checks the HTTPS configuration of public sites. Refusing
plain HTTP and non-public addresses keeps it from being misused to probe internal systems.

**Can it use a proxy, my company's CA, or skip certificate checks?** No, by design. Results are based on the
public `certifi` trust store with full verification.

**Why are cookie checks `not_applicable`?** The response set no cookies. Many sites set cookies only after login
or on specific pages. Scan those URLs (if you're authorized) to check them.

**My site passed everything. Is it secure?** It means these ten settings are right. WebGuard doesn't look at your
application logic, page content, server software, TLS ciphers or anything behind a login.

**Can I scan several sites at once?** One URL per run; use a loop (see [section 10](#10-using-webguard-in-ci-and-scripts)).

## 14. Quick reference

```text
webguard scan URL --i-am-authorized      run one scan (reports in ./reports)
    --follow-redirects                   follow up to 3 HTTPS redirects
    --deadline 5..120                    whole-scan time limit in seconds (default 30)
    --fail-on none|informational|low|medium|high   exit 1 threshold (default high)
    --output DIR                         report directory (default reports)
    --debug                              diagnostics on stderr (no secrets)
webguard rules                           list the ten checks
webguard version                         show versions

Exit: 0 ok · 1 findings ≥ threshold · 2 usage · 3 target refused · 4 scan failed/partial
      5 reports not written · 70 internal error · 130 interrupted
```
