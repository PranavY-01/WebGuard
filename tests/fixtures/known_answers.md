# Known-answer record

Rendered by `python -m tests.unit.render_docs` from `tests/unit/known_answers.py`; `test_known_answers_record_is_current` fails if this file is stale. Columns per result: subject, status, severity, confidence, reason.

Precision/recall is not computed: no rule has 10 labelled positive and 10 labelled negative real-world cases. No real-world accuracy is claimed.

| Rule | Cases |
|---|---|
| WG-CK-001 | 8 |
| WG-CK-002 | 5 |
| WG-CK-003 | 9 |
| WG-CK-004 | 9 |
| WG-HDR-001 | 17 |
| WG-HDR-002 | 11 |
| WG-HDR-003 | 8 |
| WG-RDR-001 | 9 |
| WG-TLS-001 | 13 |
| WG-TLS-002 | 11 |

| Rule | Case | Expected | Actual | Verdict |
|---|---|---|---|---|
| WG-TLS-001 | verified | hop:0 pass - high verified | hop:0 pass - high verified | match |
| WG-TLS-001 | expired (10) | hop:0 finding high high expired | hop:0 finding high high expired | match |
| WG-TLS-001 | not yet valid (9) | hop:0 finding high high not_yet_valid | hop:0 finding high high not_yet_valid | match |
| WG-TLS-001 | unknown CA (20) | hop:0 finding high high untrusted_chain | hop:0 finding high high untrusted_chain | match |
| WG-TLS-001 | self-signed in chain (19) | hop:0 finding high high untrusted_chain | hop:0 finding high high untrusted_chain | match |
| WG-TLS-001 | self-signed leaf (18) | hop:0 finding high high untrusted_chain | hop:0 finding high high untrusted_chain | match |
| WG-TLS-001 | hostname mismatch (62) | hop:0 finding high high hostname_mismatch | hop:0 finding high high hostname_mismatch | match |
| WG-TLS-001 | other verify code (7) | hop:0 finding high medium verification_failed_other | hop:0 finding high medium verification_failed_other | match |
| WG-TLS-001 | verify code missing | hop:0 finding high medium verification_failed_other | hop:0 finding high medium verification_failed_other | match |
| WG-TLS-001 | handshake failure | hop:0 error - - handshake_failed | hop:0 error - - handshake_failed | match |
| WG-TLS-001 | dns failure | hop:0 error - - tls_not_reached | hop:0 error - - tls_not_reached | match |
| WG-TLS-001 | read timeout after TLS | hop:0 pass - high verified | hop:0 pass - high verified | match |
| WG-TLS-001 | two hops | hop:0 pass - high verified<br>hop:1 pass - high verified | hop:0 pass - high verified<br>hop:1 pass - high verified | match |
| WG-TLS-002 | 365 days | hop:0 pass - high expiry_beyond_30_days | hop:0 pass - high expiry_beyond_30_days | match |
| WG-TLS-002 | 30.5 days | hop:0 pass - high expiry_beyond_30_days | hop:0 pass - high expiry_beyond_30_days | match |
| WG-TLS-002 | 30 days | hop:0 finding low high expires_within_30_days | hop:0 finding low high expires_within_30_days | match |
| WG-TLS-002 | 25 days | hop:0 finding low high expires_within_30_days | hop:0 finding low high expires_within_30_days | match |
| WG-TLS-002 | 15 days | hop:0 finding low high expires_within_30_days | hop:0 finding low high expires_within_30_days | match |
| WG-TLS-002 | 14.9 days | hop:0 finding medium high expires_within_14_days | hop:0 finding medium high expires_within_14_days | match |
| WG-TLS-002 | 1 day | hop:0 finding medium high expires_within_14_days | hop:0 finding medium high expires_within_14_days | match |
| WG-TLS-002 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-TLS-002 | dns failure | hop:0 inconclusive - - hop_failed | hop:0 inconclusive - - hop_failed | match |
| WG-TLS-002 | deadline | hop:0 inconclusive - - scan_deadline | hop:0 inconclusive - - scan_deadline | match |
| WG-TLS-002 | interrupted | hop:0 inconclusive - - scan_interrupted | hop:0 inconclusive - - scan_interrupted | match |
| WG-HDR-001 | absent | hop:0 finding medium high header_absent | hop:0 finding medium high header_absent | match |
| WG-HDR-001 | one year | hop:0 pass - high present | hop:0 pass - high present | match |
| WG-HDR-001 | exactly 180 days | hop:0 pass - high present | hop:0 pass - high present | match |
| WG-HDR-001 | quoted max-age | hop:0 pass - high present | hop:0 pass - high present | match |
| WG-HDR-001 | case-insensitive directives | hop:0 pass - high present | hop:0 pass - high present | match |
| WG-HDR-001 | max-age=0 | hop:0 finding medium high disabled | hop:0 finding medium high disabled | match |
| WG-HDR-001 | one day | hop:0 finding low high max_age_below_minimum | hop:0 finding low high max_age_below_minimum | match |
| WG-HDR-001 | non-integer | hop:0 finding medium high invalid | hop:0 finding medium high invalid | match |
| WG-HDR-001 | negative | hop:0 finding medium high invalid | hop:0 finding medium high invalid | match |
| WG-HDR-001 | no max-age | hop:0 finding medium high invalid | hop:0 finding medium high invalid | match |
| WG-HDR-001 | duplicate directive | hop:0 finding medium high invalid | hop:0 finding medium high invalid | match |
| WG-HDR-001 | first instance only | hop:0 finding medium high disabled | hop:0 finding medium high disabled | match |
| WG-HDR-001 | on a 301 | hop:0 pass - high present | hop:0 pass - high present | match |
| WG-HDR-001 | on a 404 | hop:0 finding medium high header_absent | hop:0 finding medium high header_absent | match |
| WG-HDR-001 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-HDR-001 | hop failed | hop:0 inconclusive - - hop_failed | hop:0 inconclusive - - hop_failed | match |
| WG-HDR-001 | per hop | hop:0 finding medium high header_absent<br>hop:1 pass - high present | hop:0 finding medium high header_absent<br>hop:1 pass - high present | match |
| WG-HDR-002 | present | hop:0 pass - high present | hop:0 pass - high present | match |
| WG-HDR-002 | report-only only | hop:0 finding low high report_only_only | hop:0 finding low high report_only_only | match |
| WG-HDR-002 | absent | hop:0 finding low high header_absent | hop:0 finding low high header_absent | match |
| WG-HDR-002 | empty | hop:0 finding low high empty_policy | hop:0 finding low high empty_policy | match |
| WG-HDR-002 | terminal 301 | hop:0 not_applicable - - redirect_response | hop:0 not_applicable - - redirect_response | match |
| WG-HDR-002 | 404 present | hop:0 pass - medium present | hop:0 pass - medium present | match |
| WG-HDR-002 | 503 absent | hop:0 finding low medium header_absent | hop:0 finding low medium header_absent | match |
| WG-HDR-002 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-HDR-002 | hop failed | hop:0 inconclusive - - hop_failed | hop:0 inconclusive - - hop_failed | match |
| WG-HDR-002 | terminal after redirect | hop:1 pass - high present | hop:1 pass - high present | match |
| WG-HDR-002 | redirect target failed | hop:0 not_applicable - - redirect_response | hop:0 not_applicable - - redirect_response | match |
| WG-HDR-003 | nosniff | hop:0 pass - high nosniff | hop:0 pass - high nosniff | match |
| WG-HDR-003 | padded mixed case | hop:0 pass - high nosniff | hop:0 pass - high nosniff | match |
| WG-HDR-003 | wrong value | hop:0 finding low high invalid_value | hop:0 finding low high invalid_value | match |
| WG-HDR-003 | first instance only | hop:0 finding low high invalid_value | hop:0 finding low high invalid_value | match |
| WG-HDR-003 | absent | hop:0 finding low high header_absent | hop:0 finding low high header_absent | match |
| WG-HDR-003 | terminal 302 | hop:0 not_applicable - - redirect_response | hop:0 not_applicable - - redirect_response | match |
| WG-HDR-003 | 404 | hop:0 pass - medium nosniff | hop:0 pass - medium nosniff | match |
| WG-HDR-003 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-CK-001 | no cookies | - not_applicable - - no_cookies_observed | - not_applicable - - no_cookies_observed | match |
| WG-CK-001 | secure | cookie:sid@hop:0 pass - high secure_present | cookie:sid@hop:0 pass - high secure_present | match |
| WG-CK-001 | upper-case SECURE | cookie:a@hop:0 pass - high secure_present | cookie:a@hop:0 pass - high secure_present | match |
| WG-CK-001 | not secure | cookie:a@hop:0 finding medium high secure_absent | cookie:a@hop:0 finding medium high secure_absent | match |
| WG-CK-001 | two cookies | cookie:sid@hop:0 pass - high secure_present<br>cookie:b@hop:0 finding medium high secure_absent | cookie:sid@hop:0 pass - high secure_present<br>cookie:b@hop:0 finding medium high secure_absent | match |
| WG-CK-001 | unnamed cookie | cookie:(unnamed)@hop:0 pass - high secure_present | cookie:(unnamed)@hop:0 pass - high secure_present | match |
| WG-CK-001 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-CK-001 | cookies on two hops, second failed | cookie:a@hop:0 pass - high secure_present<br>hop:1 inconclusive - - hop_failed | cookie:a@hop:0 pass - high secure_present<br>hop:1 inconclusive - - hop_failed | match |
| WG-CK-002 | httponly | cookie:sid@hop:0 pass - high httponly_present | cookie:sid@hop:0 pass - high httponly_present | match |
| WG-CK-002 | no httponly | cookie:a@hop:0 finding low low httponly_absent | cookie:a@hop:0 finding low low httponly_absent | match |
| WG-CK-002 | no cookies | - not_applicable - - no_cookies_observed | - not_applicable - - no_cookies_observed | match |
| WG-CK-002 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-CK-002 | deadline | hop:0 inconclusive - - scan_deadline | hop:0 inconclusive - - scan_deadline | match |
| WG-CK-003 | lax | cookie:sid@hop:0 pass - high samesite_strict_or_lax | cookie:sid@hop:0 pass - high samesite_strict_or_lax | match |
| WG-CK-003 | strict upper | cookie:a@hop:0 pass - high samesite_strict_or_lax | cookie:a@hop:0 pass - high samesite_strict_or_lax | match |
| WG-CK-003 | none + secure | cookie:a@hop:0 pass - high none_with_secure | cookie:a@hop:0 pass - high none_with_secure | match |
| WG-CK-003 | none without secure | cookie:a@hop:0 finding medium high none_without_secure | cookie:a@hop:0 finding medium high none_without_secure | match |
| WG-CK-003 | invalid | cookie:a@hop:0 finding low high invalid_value | cookie:a@hop:0 finding low high invalid_value | match |
| WG-CK-003 | empty value | cookie:a@hop:0 finding low high invalid_value | cookie:a@hop:0 finding low high invalid_value | match |
| WG-CK-003 | absent | cookie:a@hop:0 finding informational high samesite_absent | cookie:a@hop:0 finding informational high samesite_absent | match |
| WG-CK-003 | last occurrence wins | cookie:a@hop:0 pass - high samesite_strict_or_lax | cookie:a@hop:0 pass - high samesite_strict_or_lax | match |
| WG-CK-003 | hop failed | hop:0 inconclusive - - hop_failed | hop:0 inconclusive - - hop_failed | match |
| WG-CK-004 | not prefixed | cookie:sid@hop:0 not_applicable - - not_prefixed | cookie:sid@hop:0 not_applicable - - not_prefixed | match |
| WG-CK-004 | __Host- ok | cookie:__Host-a@hop:0 pass - high prefix_requirements_met | cookie:__Host-a@hop:0 pass - high prefix_requirements_met | match |
| WG-CK-004 | __Host- with Domain | cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet | cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet | match |
| WG-CK-004 | __Host- without Path | cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet | cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet | match |
| WG-CK-004 | __Host- Path=/x | cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet | cookie:__Host-a@hop:0 finding medium high prefix_requirements_unmet | match |
| WG-CK-004 | __Secure- without Secure | cookie:__Secure-a@hop:0 finding medium high prefix_requirements_unmet | cookie:__Secure-a@hop:0 finding medium high prefix_requirements_unmet | match |
| WG-CK-004 | __secure- lower-case prefix | cookie:__secure-a@hop:0 pass - high prefix_requirements_met | cookie:__secure-a@hop:0 pass - high prefix_requirements_met | match |
| WG-CK-004 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-CK-004 | no cookies | - not_applicable - - no_cookies_observed | - not_applicable - - no_cookies_observed | match |
| WG-RDR-001 | 200 | hop:0 not_applicable - - not_redirect | hop:0 not_applicable - - not_redirect | match |
| WG-RDR-001 | 404 | hop:0 not_applicable - - not_redirect | hop:0 not_applicable - - not_redirect | match |
| WG-RDR-001 | 301 to http | hop:0 finding medium high https_to_http_redirect | hop:0 finding medium high https_to_http_redirect | match |
| WG-RDR-001 | 308 to https | hop:0 pass - high https_redirect | hop:0 pass - high https_redirect | match |
| WG-RDR-001 | 302 no location | hop:0 not_applicable - - no_location | hop:0 not_applicable - - no_location | match |
| WG-RDR-001 | unparseable | hop:0 inconclusive - - location_unparseable | hop:0 inconclusive - - location_unparseable | match |
| WG-RDR-001 | javascript scheme | hop:0 inconclusive - - unexpected_scheme | hop:0 inconclusive - - unexpected_scheme | match |
| WG-RDR-001 | tls verify failed | hop:0 inconclusive - - blocked_by:WG-TLS-001 | hop:0 inconclusive - - blocked_by:WG-TLS-001 | match |
| WG-RDR-001 | hop failed | hop:0 inconclusive - - hop_failed | hop:0 inconclusive - - hop_failed | match |
