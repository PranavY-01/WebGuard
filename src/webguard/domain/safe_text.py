"""SafeText: type-level taint control for target-derived strings (Plan §13.1, INV-09).

`SafeText` is a plain `str` at runtime, but every model field typed `SafeText` runs a validator
that *rejects* (never repairs) control, bidi and invisible characters. The only way to turn
untrusted target data into an acceptable value is `from_untrusted`, which is called only in
`webguard.egress.capture`. A forgotten sanitization step therefore fails validation loudly
instead of leaking into logs, terminals or reports.

SafeText is not markup-safe: HTML autoescaping and Rich escaping still apply.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator

# Plan set: C0 + DEL, C1, bidi embeddings/overrides/isolates, zero-width + BOM.
# Stricter additions (recorded decision): LRM/RLM/ALM bidi marks (U+200E, U+200F, U+061C),
# line/paragraph separators (U+2028, U+2029) and lone surrogates (break UTF-8 encoding).
#
# Disallowed code-point ranges (inclusive). Written numerically on purpose: the source file
# itself must never contain invisible or bidi characters (see test_no_invisible_chars_in_source).
_DISALLOWED_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x001F),  # C0 controls
    (0x007F, 0x009F),  # DEL + C1 controls
    (0x061C, 0x061C),  # ARABIC LETTER MARK (bidi)
    (0x200B, 0x200F),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    (0x2028, 0x202E),  # LINE/PARAGRAPH SEPARATOR, LRE..RLO bidi embeddings/overrides
    (0x2060, 0x2060),  # WORD JOINER
    (0x2066, 0x2069),  # LRI..PDI bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / ZWNBSP
    (0xD800, 0xDFFF),  # lone surrogates
)
_DISALLOWED = re.compile(
    "["
    + "".join(f"{re.escape(chr(lo))}-{re.escape(chr(hi))}" for lo, hi in _DISALLOWED_RANGES)
    + "]"
)

TRUNCATION_SUFFIX = "…[+{n} chars]"


def _reject_unsafe(value: str) -> str:
    match = _DISALLOWED.search(value)
    if match is not None:
        raise ValueError(f"unsafe character U+{ord(match.group()):04X} in SafeText")
    return value


SafeText = Annotated[str, AfterValidator(_reject_unsafe)]


def is_safe(value: str) -> bool:
    return _DISALLOWED.search(value) is None


def _escape_char(ch: str) -> str:
    code = ord(ch)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def from_untrusted(raw: str | bytes, max_len: int) -> str:
    """Convert untrusted data into a SafeText-valid string.

    Bytes are decoded as ISO-8859-1 (HTTP octets; never fails). Each disallowed character is
    replaced by a visible `\\xNN` / `\\uNNNN` escape. If the escaped text would exceed
    `max_len` characters it is cut at a character boundary (never inside an escape) and the
    suffix `…[+N chars]` records how many *input* characters were dropped.
    """
    if max_len < 1:
        raise ValueError("max_len must be positive")
    text = raw.decode("iso-8859-1") if isinstance(raw, bytes) else raw
    out: list[str] = []
    used = 0
    for index, ch in enumerate(text):
        piece = _escape_char(ch) if _DISALLOWED.match(ch) else ch
        if used + len(piece) > max_len:
            out.append(TRUNCATION_SUFFIX.format(n=len(text) - index))
            break
        out.append(piece)
        used += len(piece)
    return _reject_unsafe("".join(out))
