"""HTML report rendering (Plan §16.2).

The environment is built once with explicit autoescaping (Jinja2's default is off, A-05) and
StrictUndefined. The template is package data; nothing is loaded from the working directory.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass

from jinja2 import Environment, PackageLoader, StrictUndefined, Template

from webguard.domain.report import Report

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
BANNER = (
    "Passive configuration assessment — not a penetration test; passing checks do not mean "
    "the site is secure."
)


@functools.cache
def environment() -> Environment:
    return Environment(
        loader=PackageLoader("webguard.render", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _template() -> Template:
    return environment().get_template("report.html.j2")


@dataclass(frozen=True, slots=True)
class HopRow:
    index: int
    url: str
    endpoint: str
    resolved: str
    connected: str
    tls: str
    certificate: str
    http: str
    outcome: str


def _hop_rows(report: Report) -> list[HopRow]:
    rows = []
    for hop in report.hops:
        tls = hop.tls
        if tls is None:
            tls_text, cert_text = "not reached", "-"
        elif tls.verified:
            tls_text = f"verified ({tls.protocol_version or 'unknown'})"
            cert = tls.cert
            cert_text = (
                f"{cert.subject_cn or '-'}; issuer {cert.issuer_cn or '-'}; "
                f"expires {cert.not_after.date().isoformat()}"
                if cert is not None
                else "-"
            )
        else:
            tls_text = f"verification failed (code {tls.verify_code})"
            cert_text = tls.verify_message or "-"
        http = hop.http
        http_text = f"{http.status_code} {http.http_version}" if http is not None else "-"
        if hop.failure is not None:
            outcome = hop.failure.code.value + (
                f" ({hop.failure.detail})" if hop.failure.detail else ""
            )
        elif http is not None and http.location is not None and not http.location.unparseable:
            loc = http.location
            outcome = (
                f"Location: {loc.scheme or ''}://{loc.host or ''}{loc.path_query_redacted or ''}"
            )
        else:
            outcome = "headers captured" if http is not None else "-"
        rows.append(
            HopRow(
                index=hop.index,
                url=hop.url_redacted,
                endpoint=f"{hop.host}:{hop.port}",
                resolved=", ".join(str(ip) for ip in hop.resolved_ips) or "-",
                connected=str(hop.connected_ip) if hop.connected_ip else "-",
                tls=tls_text,
                certificate=cert_text,
                http=http_text,
                outcome=outcome,
            )
        )
    return rows


def render_html(report: Report) -> str:
    return _template().render(
        report=report,
        hops=_hop_rows(report),
        csp=REPORT_CSP,
        banner=BANNER,
    )
