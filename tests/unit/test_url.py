"""U-01..U-05: URL canonicalization table (Plan §10.1) and redirect resolution."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from webguard.policy.url import (
    CanonicalTarget,
    RejectionCode,
    UrlRejection,
    canonicalize_url,
    redact_query,
    resolve_redirect,
)

R = RejectionCode


def fullwidth(text: str) -> str:
    """Map printable ASCII to its fullwidth form (UTS-46 maps it back)."""
    return "".join(chr(ord(c) + 0xFEE0) for c in text)


# (raw, host, port, request_target, display_url_redacted)
ACCEPT = [
    ("https://example.com", "example.com", 443, "/", "https://example.com/"),
    ("HTTPS://EXAMPLE.COM/A", "example.com", 443, "/A", "https://example.com/A"),
    ("https://example.com:8443/x", "example.com", 8443, "/x", "https://example.com:8443/x"),
    ("https://example.com:443/", "example.com", 443, "/", "https://example.com/"),
    ("https://example.com./", "example.com", 443, "/", "https://example.com/"),
    (
        "https://bücher.example/",
        "xn--bcher-kva.example",
        443,
        "/",
        "https://xn--bcher-kva.example/",
    ),
    (
        "https://xn--bcher-kva.example/",
        "xn--bcher-kva.example",
        443,
        "/",
        "https://xn--bcher-kva.example/",
    ),
    ("https://" + fullwidth("EXAMPLE") + ".com/", "example.com", 443, "/", "https://example.com/"),
    ("https://1.1.1.1/", "1.1.1.1", 443, "/", "https://1.1.1.1/"),
    (
        "https://[2606:4700:4700::1111]/",
        "2606:4700:4700::1111",
        443,
        "/",
        "https://[2606:4700:4700::1111]/",
    ),
    (
        "https://[2606:4700:4700:0:0:0:0:1111]:8443/",
        "2606:4700:4700::1111",
        8443,
        "/",
        "https://[2606:4700:4700::1111]:8443/",
    ),
    (
        "https://example.com/p?a=1&b=2",
        "example.com",
        443,
        "/p?a=1&b=2",
        "https://example.com/p?a=REDACTED&b=REDACTED",
    ),
    ("https://example.com/?token", "example.com", 443, "/?token", "https://example.com/?REDACTED"),
    ("https://example.com/p#frag", "example.com", 443, "/p", "https://example.com/p"),
    ("https://example.com?x=1", "example.com", 443, "/?x=1", "https://example.com/?x=REDACTED"),
    (
        "https://example.com/%2e%2e/a",
        "example.com",
        443,
        "/%2e%2e/a",
        "https://example.com/%2e%2e/a",
    ),
    ("https://a-b.example/", "a-b.example", 443, "/", "https://a-b.example/"),
    ("https://localhost/", "localhost", 443, "/", "https://localhost/"),
    ("https://example.com/a/../b", "example.com", 443, "/a/../b", "https://example.com/a/../b"),
    (
        "https://example.com/?a=1&&b",
        "example.com",
        443,
        "/?a=1&&b",
        "https://example.com/?a=REDACTED&&REDACTED",
    ),
    ("https://example.com/?a==b", "example.com", 443, "/?a==b", "https://example.com/?a=REDACTED"),
    (
        "https://EXAMPLE.com/Path?Q=V",
        "example.com",
        443,
        "/Path?Q=V",
        "https://example.com/Path?Q=REDACTED",
    ),
]


@pytest.mark.parametrize(("raw", "host", "port", "target", "display"), ACCEPT)
def test_u01_accept(raw: str, host: str, port: int, target: str, display: str) -> None:
    got = canonicalize_url(raw)
    assert isinstance(got, CanonicalTarget), got
    assert (got.host, got.port, got.request_target, got.display_url_redacted) == (
        host,
        port,
        target,
        display,
    )
    assert got.url.startswith("https://")
    assert got.display_url_redacted.isascii()


REJECT = [
    ("https://" + "a" * 2048, R.URL_TOO_LONG),
    ("https://exa mple.com", R.URL_ILLEGAL_CHARS),
    ("https://example.com/\tx", R.URL_ILLEGAL_CHARS),
    ("https://example.com\\@evil.test", R.URL_ILLEGAL_CHARS),
    ("https://example.com/\x00", R.URL_ILLEGAL_CHARS),
    ("https://example.com/\r\nX: y", R.URL_ILLEGAL_CHARS),
    ("https://example.com/" + chr(0x202E), R.URL_ILLEGAL_CHARS),
    ("https://example.com/" + chr(0x85), R.URL_ILLEGAL_CHARS),
    ("https://exa" + chr(0x200B) + "mple.com", R.URL_ILLEGAL_CHARS),
    ("https://example.com/" + chr(0x3000), R.URL_ILLEGAL_CHARS),
    ("https://example.com/café", R.URL_ILLEGAL_CHARS),
    ("http://example.com", R.SCHEME_NOT_HTTPS),
    ("ftp://example.com", R.SCHEME_NOT_HTTPS),
    ("example.com", R.SCHEME_NOT_HTTPS),
    ("javascript:alert(1)", R.SCHEME_NOT_HTTPS),
    ("http://[::1", R.SCHEME_NOT_HTTPS),
    ("https://user@example.com", R.USERINFO_PRESENT),
    ("https://user:pw@example.com", R.USERINFO_PRESENT),
    ("https://example.com@evil.test/", R.USERINFO_PRESENT),
    ("https://example.com%2F.evil.test/", R.HOST_INVALID),
    ("https://exa%mple.com", R.HOST_INVALID),
    ("https:///path", R.HOST_INVALID),
    ("https:example.com", R.HOST_INVALID),
    ("https://[::1%25eth0]/", R.HOST_INVALID),
    ("https://[::1/", R.HOST_INVALID),
    ("https://[not-ip]/", R.HOST_INVALID),
    ("https://[1.2.3.4]/", R.HOST_INVALID),
    ("https://::1/", R.HOST_INVALID),
    ("https://a.test]/", R.HOST_INVALID),
    ("https://exa_mple.com/", R.HOST_INVALID),
    ("https://-a.example/", R.HOST_INVALID),
    ("https://a-.example/", R.HOST_INVALID),
    ("https://" + "a" * 64 + ".com/", R.HOST_INVALID),
    ("https://" + ".".join(["a" * 63] * 4) + "/", R.HOST_INVALID),
    ("https://a..b/", R.HOST_INVALID),
    ("https://./", R.HOST_INVALID),
    ("https://example.com:443:443/", R.HOST_INVALID),
    ("https://127.1/", R.IPV4_AMBIGUOUS),
    ("https://0x7f.0.0.1/", R.IPV4_AMBIGUOUS),
    ("https://0X7F.1/", R.IPV4_AMBIGUOUS),
    ("https://2130706433/", R.IPV4_AMBIGUOUS),
    ("https://017.0.0.1/", R.IPV4_AMBIGUOUS),
    ("https://127.0.0.1./", R.IPV4_AMBIGUOUS),
    ("https://1.2.3.4.5/", R.IPV4_AMBIGUOUS),
    ("https://example.0x10/", R.IPV4_AMBIGUOUS),
    ("https://example.123/", R.IPV4_AMBIGUOUS),
    ("https://" + fullwidth("127.0.0.1").replace(fullwidth("."), ".") + "/", R.IPV4_AMBIGUOUS),
    ("https://" + chr(0x3002).join(["127", "0", "0", "1"]) + "/", R.IPV4_AMBIGUOUS),
    ("https://example.com:80/", R.PORT_NOT_PERMITTED),
    ("https://example.com:22/", R.PORT_NOT_PERMITTED),
    ("https://example.com:0443/", R.PORT_NOT_PERMITTED),
    ("https://example.com:/", R.PORT_NOT_PERMITTED),
    ("https://example.com:65536/", R.PORT_NOT_PERMITTED),
    ("https://example.com:+443/", R.PORT_NOT_PERMITTED),
    ("https://[2606:4700:4700::1111]:80/", R.PORT_NOT_PERMITTED),
]


@pytest.mark.parametrize(("raw", "code"), REJECT)
def test_u02_reject(raw: str, code: RejectionCode) -> None:
    assert canonicalize_url(raw) == UrlRejection(code)


def test_u03_ip_literals_are_typed() -> None:
    v4 = canonicalize_url("https://1.1.1.1/")
    v6 = canonicalize_url("https://[2606:4700:4700::1111]/")
    name = canonicalize_url("https://example.com/")
    assert isinstance(v4, CanonicalTarget)
    assert isinstance(v6, CanonicalTarget)
    assert isinstance(name, CanonicalTarget)
    assert isinstance(v4.host_ip, IPv4Address)
    assert isinstance(v6.host_ip, IPv6Address)
    assert name.host_ip is None
    assert v6.host_header == "[2606:4700:4700::1111]"
    assert canonicalize_url("https://example.com:8443/") == canonicalize_url(
        "https://EXAMPLE.com:8443"
    )


def test_u03_exit_class_of_codes() -> None:
    usage = {c for c in RejectionCode if c.is_usage_error}
    assert usage == {R.URL_TOO_LONG, R.URL_ILLEGAL_CHARS}


@pytest.mark.parametrize(
    ("query", "redacted"),
    [
        ("", ""),
        ("a=1", "a=REDACTED"),
        ("a=1&b=", "a=REDACTED&b=REDACTED"),
        ("secret", "REDACTED"),
        ("a=1&", "a=REDACTED&"),
        ("=x", "=REDACTED"),
    ],
)
def test_u04_redact_query(query: str, redacted: str) -> None:
    assert redact_query(query) == redacted


BASE = canonicalize_url("https://a.test/dir/page?x=1")


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/next?y=2", "https://a.test/next?y=2"),
        ("next", "https://a.test/dir/next"),
        ("../up", "https://a.test/up"),
        ("?z=3", "https://a.test/dir/page?z=3"),
        ("//b.test/x", "https://b.test/x"),
        ("https://B.TEST:8443/", "https://b.test:8443/"),
        ("https://a.test/#frag", "https://a.test/"),
    ],
)
def test_u05_resolve_redirect_accept(location: str, expected: str) -> None:
    assert isinstance(BASE, CanonicalTarget)
    got = resolve_redirect(location, BASE)
    assert isinstance(got, CanonicalTarget), got
    assert got.url == expected


@pytest.mark.parametrize(
    ("location", "code"),
    [
        ("http://a.test/", R.SCHEME_NOT_HTTPS),
        (" /x", R.URL_ILLEGAL_CHARS),
        ("/x\r\nSet-Cookie: a=b", R.URL_ILLEGAL_CHARS),
        ("\\\\evil.test/", R.URL_ILLEGAL_CHARS),
        ("https://user@b.test/", R.USERINFO_PRESENT),
        ("https://127.1/", R.IPV4_AMBIGUOUS),
        ("https://b.test:22/", R.PORT_NOT_PERMITTED),
        ("javascript:alert(1)", R.SCHEME_NOT_HTTPS),
        ("data:text/html,x", R.SCHEME_NOT_HTTPS),
        ("https://[::1/", R.HOST_INVALID),
    ],
)
def test_u05_resolve_redirect_reject(location: str, code: RejectionCode) -> None:
    assert isinstance(BASE, CanonicalTarget)
    assert resolve_redirect(location, BASE) == UrlRejection(code)
