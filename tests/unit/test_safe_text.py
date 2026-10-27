"""U-10..U-12: SafeText rejection set, escaping, truncation, bytes decoding; S-19 at model level."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from webguard.domain.safe_text import SafeText, from_untrusted, is_safe


class _M(BaseModel):
    v: SafeText


REJECTED = (
    [chr(c) for c in range(0x00, 0x20)]
    + [chr(0x7F)]
    + [chr(c) for c in range(0x80, 0xA0)]
    + [chr(c) for c in range(0x202A, 0x202F)]  # bidi embeddings/overrides
    + [chr(c) for c in range(0x2066, 0x206A)]  # bidi isolates
    + [chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)]  # invisible
    + [chr(c) for c in (0x200E, 0x200F, 0x061C, 0x2028, 0x2029, 0xD800, 0xDFFF)]  # stricter set
)


@pytest.mark.parametrize("ch", REJECTED, ids=lambda c: f"U+{ord(c):04X}")
def test_u10_validator_rejects_every_unsafe_char(ch: str) -> None:
    with pytest.raises(ValidationError):
        _M(v=f"a{ch}b")
    assert not is_safe(ch)


@pytest.mark.parametrize("ok", ["", "plain", "café", "日本語", "<script>", "[link=x]", "a\\x1b"])
def test_u10_validator_accepts_printable(ok: str) -> None:
    assert _M(v=ok).v == ok


@pytest.mark.parametrize("ch", REJECTED, ids=lambda c: f"U+{ord(c):04X}")
def test_u11_from_untrusted_escapes_and_validates(ch: str) -> None:
    out = from_untrusted(f"x{ch}y", 100)
    assert is_safe(out)
    assert _M(v=out).v == out
    code = ord(ch)
    expected = f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"
    assert out == f"x{expected}y"


def test_u11_ansi_and_crlf_neutralized() -> None:
    assert from_untrusted("\x1b[2J\r\nSet-Cookie: x", 100) == "\\x1b[2J\\x0d\\x0aSet-Cookie: x"


def test_u12_bytes_decoded_as_latin1() -> None:
    assert from_untrusted(b"caf\xe9", 10) == "café"
    assert from_untrusted(b"\xff\x85", 20) == "ÿ\\x85"


def test_u12_truncation_suffix_counts_dropped_input_chars() -> None:
    assert from_untrusted("abcdefghij", 4) == "abcd…[+6 chars]"
    assert from_untrusted("abc", 3) == "abc"


def test_u12_truncation_never_splits_an_escape() -> None:
    out = from_untrusted("ab\x1bcdef", 4)
    assert out == "ab…[+5 chars]"


def test_u12_max_len_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        from_untrusted("x", 0)
