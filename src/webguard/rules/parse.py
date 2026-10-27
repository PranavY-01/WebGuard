"""Pure parsers for HSTS and cookie attributes (Plan §14.1). Inputs are SafeText strings.

The stdlib cookie parser is deliberately not used: it splits on commas inside Expires and
silently drops malformed cookies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_DIGITS = re.compile(r"[0-9]+")

COOKIE_ATTRIBUTES = frozenset(
    {"secure", "httponly", "samesite", "path", "domain", "expires", "max-age", "partitioned"}
)


@dataclass(frozen=True, slots=True)
class Hsts:
    valid: bool
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False


def parse_hsts(value: str) -> Hsts:
    """RFC 6797 §6.1: directives separated by ';', names case-insensitive, max-age required,
    each directive at most once. Unknown directives are ignored."""
    seen: set[str] = set()
    max_age: int | None = None
    for raw in value.split(";"):
        directive = raw.strip()
        if not directive:
            continue
        name, has_value, arg = directive.partition("=")
        name = name.strip().lower()
        if name in seen:
            return Hsts(valid=False)
        seen.add(name)
        if name == "max-age":
            text = arg.strip()
            if len(text) >= 2 and text[0] == text[-1] == '"':
                text = text[1:-1]
            if not has_value or not _DIGITS.fullmatch(text):
                return Hsts(valid=False)
            max_age = int(text)
    if max_age is None:
        return Hsts(valid=False)
    return Hsts(
        valid=True,
        max_age=max_age,
        include_subdomains="includesubdomains" in seen,
        preload="preload" in seen,
    )


@dataclass(frozen=True, slots=True)
class CookieAttributes:
    values: dict[str, str | None] = field(default_factory=dict)
    """Recognized attributes, lowercased names; last occurrence wins (RFC 6265 §5.3)."""
    unknown: tuple[str, ...] = ()

    def has(self, name: str) -> bool:
        return name in self.values

    def get(self, name: str) -> str | None:
        return self.values.get(name)


def parse_cookie_attributes(segment: str) -> CookieAttributes:
    values: dict[str, str | None] = {}
    unknown: list[str] = []
    for raw in segment.split(";"):
        item = raw.strip()
        if not item:
            continue
        name, has_value, arg = item.partition("=")
        key = name.strip().lower()
        if key in COOKIE_ATTRIBUTES:
            values.pop(key, None)  # re-insert so the last occurrence wins
            values[key] = arg.strip() if has_value else None
        else:
            unknown.append(name.strip())
    return CookieAttributes(values=values, unknown=tuple(unknown))
