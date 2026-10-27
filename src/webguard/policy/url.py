"""URL canonicalization (Plan §10.1).

The request is always rebuilt from validated components; the raw string never reaches the HTTP
layer. Rules apply in order and the first failure rejects. The same function validates every
redirect `Location` after it is resolved against the current hop URL (`resolve_redirect`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Final
from urllib.parse import urljoin, urlsplit

import idna

from webguard.domain.budget import MAX_URL_CHARS
from webguard.domain.safe_text import is_safe

IPAddress = IPv4Address | IPv6Address

PERMITTED_PORTS: Final = frozenset({443, 8443})
DEFAULT_PORT: Final = 443
REDACTED: Final = "REDACTED"

_ASCII_DIGITS = re.compile(r"[0-9]+")
_DNS_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_PORT_TEXT = re.compile(r"[1-9][0-9]{0,4}")


class RejectionCode(StrEnum):
    URL_TOO_LONG = "url_too_long"
    URL_ILLEGAL_CHARS = "url_illegal_chars"
    SCHEME_NOT_HTTPS = "scheme_not_https"
    USERINFO_PRESENT = "userinfo_present"
    HOST_INVALID = "host_invalid"
    IPV4_AMBIGUOUS = "ipv4_ambiguous"
    PORT_NOT_PERMITTED = "port_not_permitted"

    @property
    def is_usage_error(self) -> bool:
        """Malformed-syntax rejections map to exit 2; policy rejections map to exit 3."""
        return self in (RejectionCode.URL_TOO_LONG, RejectionCode.URL_ILLEGAL_CHARS)


@dataclass(frozen=True, slots=True)
class UrlRejection:
    code: RejectionCode


@dataclass(frozen=True, slots=True)
class CanonicalTarget:
    """A validated https target. Every string field is ASCII without controls or whitespace."""

    host: str
    """Lowercase IDNA A-label DNS name, or the compressed IP literal without brackets."""
    host_ip: IPAddress | None
    port: int
    path: str
    query: str
    request_target: str
    display_url_redacted: str

    scheme: str = "https"

    @property
    def host_for_url(self) -> str:
        return f"[{self.host}]" if isinstance(self.host_ip, IPv6Address) else self.host

    @property
    def host_header(self) -> str:
        suffix = "" if self.port == DEFAULT_PORT else f":{self.port}"
        return f"{self.host_for_url}{suffix}"

    @property
    def url(self) -> str:
        """Full request URL (unredacted query). Used only as the urljoin base and the request."""
        return f"https://{self.host_header}{self.request_target}"

    @property
    def visit_key(self) -> tuple[str, int, str]:
        return (self.host, self.port, self.request_target)


def redact_query(query: str) -> str:
    """Replace every query value with REDACTED, keep keys. A bare item (no '=') could itself be
    a token, so it is redacted entirely (stricter, recorded decision)."""
    if not query:
        return ""
    items = []
    for item in query.split("&"):
        if "=" in item:
            items.append(f"{item.split('=', 1)[0]}={REDACTED}")
        elif item:
            items.append(REDACTED)
        else:
            items.append("")
    return "&".join(items)


def _split_netloc(netloc: str) -> tuple[str, str | None, bool] | RejectionCode:
    """Return (host_text, port_text, bracketed) from a netloc without userinfo."""
    if netloc.startswith("["):
        close = netloc.find("]")
        if close == -1:
            return RejectionCode.HOST_INVALID
        host, rest = netloc[1:close], netloc[close + 1 :]
        if rest == "":
            return host, None, True
        if not rest.startswith(":"):
            return RejectionCode.HOST_INVALID
        return host, rest[1:], True
    if "]" in netloc:
        return RejectionCode.HOST_INVALID
    host, sep, port = netloc.rpartition(":")
    if not sep:
        return netloc, None, False
    return host, port, False


def _looks_numeric(host: str) -> bool:
    """WHATWG 'ends in a number': the last label (ignoring one trailing dot) is all ASCII digits
    or starts with 0x/0X."""
    labels = host.split(".")
    last = labels[-1] if labels[-1] or len(labels) == 1 else labels[-2]
    return bool(_ASCII_DIGITS.fullmatch(last)) or last[:2] in ("0x", "0X")


def canonicalize_host(
    host_text: str, bracketed: bool
) -> tuple[str, IPAddress | None] | RejectionCode:
    """Rules 5-8 for a host already split from its netloc."""
    if not host_text or "%" in host_text:
        return RejectionCode.HOST_INVALID
    if bracketed:
        try:
            ip6 = IPv6Address(host_text)
        except AddressValueError:
            return RejectionCode.HOST_INVALID
        return ip6.compressed, ip6
    if ":" in host_text:
        return RejectionCode.HOST_INVALID
    if _looks_numeric(host_text):
        try:
            ip4 = IPv4Address(host_text)
        except AddressValueError:
            return RejectionCode.IPV4_AMBIGUOUS
        return str(ip4), ip4
    name = host_text[:-1] if host_text.endswith(".") else host_text
    if not name:
        return RejectionCode.HOST_INVALID
    try:
        ascii_name = idna.encode(name, uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return RejectionCode.HOST_INVALID
    # UTS-46 maps fullwidth digits and dots, so the mapped name gets the numeric check again.
    if _looks_numeric(ascii_name):
        return RejectionCode.IPV4_AMBIGUOUS
    if len(ascii_name) > 253:
        return RejectionCode.HOST_INVALID
    if not all(_DNS_LABEL.fullmatch(label) for label in ascii_name.split(".")):
        return RejectionCode.HOST_INVALID
    return ascii_name, None


def _precheck(raw: str) -> RejectionCode | None:
    """Rules 1-2. Also rejects C1 controls, bidi/invisible characters (stricter)."""
    if len(raw) > MAX_URL_CHARS:
        return RejectionCode.URL_TOO_LONG
    if not is_safe(raw) or any(ch.isspace() or ch == "\\" for ch in raw):
        return RejectionCode.URL_ILLEGAL_CHARS
    return None


def canonicalize_url(raw: str) -> CanonicalTarget | UrlRejection:
    pre = _precheck(raw)
    if pre is not None:
        return UrlRejection(pre)
    try:
        parts = urlsplit(raw)
    except ValueError:
        is_https = raw[:8].lower() == "https://"
        return UrlRejection(
            RejectionCode.HOST_INVALID if is_https else RejectionCode.SCHEME_NOT_HTTPS
        )
    if parts.scheme.lower() != "https":
        return UrlRejection(RejectionCode.SCHEME_NOT_HTTPS)
    if "@" in parts.netloc:
        return UrlRejection(RejectionCode.USERINFO_PRESENT)
    split = _split_netloc(parts.netloc)
    if isinstance(split, RejectionCode):
        return UrlRejection(split)
    host_text, port_text, bracketed = split
    host = canonicalize_host(host_text, bracketed)
    if isinstance(host, RejectionCode):
        return UrlRejection(host)
    canonical_host, host_ip = host

    if port_text is None:
        port = DEFAULT_PORT
    elif _PORT_TEXT.fullmatch(port_text) and int(port_text) in PERMITTED_PORTS:
        port = int(port_text)
    else:
        return UrlRejection(RejectionCode.PORT_NOT_PERMITTED)

    # Outside the host only ASCII is accepted; the operator percent-encodes (stricter).
    if not (parts.path + parts.query).isascii():
        return UrlRejection(RejectionCode.URL_ILLEGAL_CHARS)
    path = parts.path or "/"
    query = parts.query
    request_target = f"{path}?{query}" if query else path
    host_for_url = f"[{canonical_host}]" if isinstance(host_ip, IPv6Address) else canonical_host
    port_part = "" if port == DEFAULT_PORT else f":{port}"
    redacted_query = redact_query(query)
    display = f"https://{host_for_url}{port_part}{path}" + (f"?{redacted_query}" if query else "")
    return CanonicalTarget(
        host=canonical_host,
        host_ip=host_ip,
        port=port,
        path=path,
        query=query,
        request_target=request_target,
        display_url_redacted=display,
    )


def resolve_redirect(location: str, base: CanonicalTarget) -> CanonicalTarget | UrlRejection:
    """Resolve a raw Location against the hop URL, then apply every canonicalization rule.

    Rules 1-2 run on the raw Location first, because urljoin silently strips some characters.
    """
    pre = _precheck(location)
    if pre is not None:
        return UrlRejection(pre)
    try:
        joined = urljoin(base.url, location)
    except ValueError:
        return UrlRejection(RejectionCode.HOST_INVALID)
    return canonicalize_url(joined)
