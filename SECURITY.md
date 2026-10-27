# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting:
<https://github.com/PranavY-01/WebGuard/security/advisories/new>. Do not open a public issue.

Include the WebGuard version (`webguard version`), your Python version and OS, and a reproduction. If you can,
use a local server rather than a third-party site. You can expect an acknowledgement within 7 days.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## In scope

Anything that breaks a property WebGuard promises, for example:

- connecting to an address that is not public, or to an address other than the one that was validated
  (SSRF, DNS rebinding, redirect tricks);
- accepting an unverified certificate, or reporting `pass` without evidence;
- reading more than the documented limits, or exceeding the scan deadline;
- target-controlled text that executes or changes styling or links in the HTML report, the terminal or the logs;
- cookie values, query values or raw header values appearing in any output;
- writing outside the output directory, overwriting a file, or leaving partial files;
- any environment variable or flag that changes network or verification behaviour.

Findings that WebGuard reports about *other* websites are not WebGuard vulnerabilities.

## Dependency audit

CI runs `pip-audit --strict` against the hash-locked runtime dependencies exported from `uv.lock`.
Known-vulnerability exceptions: **none**.

v1.0.0 resolved GHSA-6q48-6c7w-9gw2 (PYSEC-2026-4320) before release by requiring `certifi >= 2026.10.19`. The
affected certifi trusted a root whose intermediates' private keys were compromised.

## Design summary

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
