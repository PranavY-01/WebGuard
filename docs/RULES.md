# WebGuard rule catalog

Generated from `webguard.rules.catalog`; a parity test keeps this file and the catalog identical in rule IDs and reason codes.

Every rule can also report these shared reason codes:

| Reason code | Meaning |
|---|---|
| `blocked_by:WG-TLS-001` | Not evaluated: the certificate could not be verified, so no HTTP exchange took place. |
| `hop_failed` | Not evaluated: the request failed before response headers were received. |
| `internal_rule_error` | The rule failed with an internal error; no conclusion was drawn. |
| `scan_deadline` | Not evaluated: the scan deadline expired before evidence was collected. |
| `scan_interrupted` | Not evaluated: the scan was interrupted. |

## WG-CK-001 — Cookie Secure attribute

- Category: `cookies`
- Possible finding severities: `medium`
- Version: 1

| Reason code | Meaning |
|---|---|
| `no_cookies_observed` | No Set-Cookie headers were observed. |
| `secure_present` | The cookie is marked Secure. |
| `secure_absent` | The cookie is not marked Secure and may be sent over plain HTTP. |

**Remediation.** Add the Secure attribute to every cookie set over HTTPS.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc6265>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
- <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

## WG-CK-002 — Cookie HttpOnly attribute

- Category: `cookies`
- Possible finding severities: `low`
- Version: 1

| Reason code | Meaning |
|---|---|
| `no_cookies_observed` | No Set-Cookie headers were observed. |
| `httponly_present` | The cookie is marked HttpOnly. |
| `httponly_absent` | The cookie is readable by page scripts (no HttpOnly). |

**Remediation.** Add HttpOnly to cookies that scripts do not need, especially session identifiers.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc6265>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
- <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

**Limitations.**

- Cookie purpose unknown.

## WG-CK-003 — Cookie SameSite attribute

- Category: `cookies`
- Possible finding severities: `informational`, `low`, `medium`
- Version: 1

| Reason code | Meaning |
|---|---|
| `no_cookies_observed` | No Set-Cookie headers were observed. |
| `samesite_strict_or_lax` | SameSite is Strict or Lax. |
| `none_with_secure` | SameSite=None is combined with Secure (cross-site use is explicit). |
| `none_without_secure` | SameSite=None without Secure; browsers reject this cookie. |
| `invalid_value` | SameSite has an unrecognized value. |
| `samesite_absent` | SameSite is not set; the browser default applies. |

**Remediation.** Set SameSite=Lax or Strict unless cross-site delivery is required; SameSite=None requires Secure.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc6265>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>
- <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

**Limitations.**

- Cookie purpose unknown.

## WG-CK-004 — Cookie name prefixes

- Category: `cookies`
- Possible finding severities: `medium`
- Version: 1

| Reason code | Meaning |
|---|---|
| `no_cookies_observed` | No Set-Cookie headers were observed. |
| `prefix_requirements_met` | The cookie satisfies its __Secure-/__Host- prefix rules. |
| `prefix_requirements_unmet` | The cookie violates its __Secure-/__Host- prefix rules and browsers will reject it. |
| `not_prefixed` | The cookie name has no __Secure- or __Host- prefix. |

**Remediation.** __Secure- cookies need Secure; __Host- cookies need Secure, Path=/ and no Domain.

**References.**

- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes>
- <https://datatracker.ietf.org/doc/html/rfc6265>

## WG-HDR-001 — HTTP Strict Transport Security (HSTS)

- Category: `headers`
- Possible finding severities: `low`, `medium`
- Version: 1

| Reason code | Meaning |
|---|---|
| `present` | HSTS is set with a max-age of at least 180 days. |
| `header_absent` | No Strict-Transport-Security header was returned. |
| `invalid` | The Strict-Transport-Security header could not be parsed (missing or invalid max-age, or a duplicated directive), so browsers ignore it. |
| `disabled` | Strict-Transport-Security sets max-age=0, which removes HSTS protection. |
| `max_age_below_minimum` | The HSTS max-age is below 180 days (15552000 seconds). |

**Remediation.** Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response once all subdomains serve HTTPS.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc6797>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security>
- <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html>

**Limitations.**

- Only the first header instance is evaluated (RFC 6797 section 8.1).
- includeSubDomains and preload are recorded as evidence, not graded.

## WG-HDR-002 — Content Security Policy (enforcing)

- Category: `headers`
- Possible finding severities: `low`
- Version: 1

| Reason code | Meaning |
|---|---|
| `present` | An enforcing Content-Security-Policy header is present. |
| `report_only_only` | Only Content-Security-Policy-Report-Only is present; nothing is enforced. |
| `header_absent` | No Content-Security-Policy header was returned. |
| `empty_policy` | The Content-Security-Policy header is empty. |
| `redirect_response` | Not applicable to a redirect response. Rerun with --follow-redirects or target the final URL. |

**Remediation.** Deploy an enforcing Content-Security-Policy; start from a restrictive default-src and iterate using a report-only policy first.

**References.**

- <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>
- <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>

**Limitations.**

- <meta> CSP not detectable without the body; policy quality not graded.

## WG-HDR-003 — X-Content-Type-Options

- Category: `headers`
- Possible finding severities: `low`
- Version: 1

| Reason code | Meaning |
|---|---|
| `nosniff` | X-Content-Type-Options is set to nosniff. |
| `invalid_value` | X-Content-Type-Options is present but not set to nosniff. |
| `header_absent` | No X-Content-Type-Options header was returned. |
| `redirect_response` | Not applicable to a redirect response. Rerun with --follow-redirects or target the final URL. |

**Remediation.** Send `X-Content-Type-Options: nosniff` on every response.

**References.**

- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>
- <https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>

## WG-RDR-001 — Redirect downgrade to HTTP

- Category: `redirects`
- Possible finding severities: `medium`
- Version: 1

| Reason code | Meaning |
|---|---|
| `https_redirect` | The redirect stays on HTTPS. |
| `https_to_http_redirect` | An HTTPS response redirects to a plain-HTTP URL. |
| `not_redirect` | The response is not a redirect. |
| `no_location` | The redirect response has no Location header. |
| `location_unparseable` | The Location header could not be parsed. |
| `unexpected_scheme` | The Location uses a scheme other than http or https. |

**Remediation.** Redirect only to https:// URLs and enable HSTS so browsers never request HTTP.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc9110#section-15.4>
- <https://datatracker.ietf.org/doc/html/rfc6797>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections>

## WG-TLS-001 — Certificate verification

- Category: `tls`
- Possible finding severities: `high`
- Version: 1

| Reason code | Meaning |
|---|---|
| `verified` | The certificate chain and hostname verified against the trust store. |
| `expired` | The server certificate has expired. |
| `not_yet_valid` | The server certificate is not yet valid. |
| `untrusted_chain` | The certificate chain does not lead to a trusted root. |
| `hostname_mismatch` | The certificate is not valid for the requested hostname. |
| `verification_failed_other` | Certificate verification failed. |
| `handshake_failed` | The TLS handshake failed for a reason other than certificate verification. |
| `tls_not_reached` | The TLS stage was not reached, so the certificate was not examined. |

**Remediation.** Serve a certificate that is currently valid, issued by a publicly trusted CA, covers the hostname, and is sent with its full intermediate chain.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc5280>
- <https://datatracker.ietf.org/doc/html/rfc6125>
- <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>

**Limitations.**

- Trust is evaluated against the certifi CA bundle, which may differ from operating-system and browser trust stores.

## WG-TLS-002 — Certificate expiry horizon

- Category: `tls`
- Possible finding severities: `low`, `medium`
- Version: 1

| Reason code | Meaning |
|---|---|
| `expiry_beyond_30_days` | The certificate remains valid for more than 30 days. |
| `expires_within_30_days` | The certificate expires within 15 to 30 days. |
| `expires_within_14_days` | The certificate expires within 14 days. |

**Remediation.** Renew the certificate before it expires; automate renewal and alert on short horizons.

**References.**

- <https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5>
- <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>

**Limitations.**

- Measured against the scan start time from this vantage point only.
