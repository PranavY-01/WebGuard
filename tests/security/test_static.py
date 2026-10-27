"""Static source scans: S-12, S-13, S-28 and shipped-code hygiene (prompt rules 14 and 15)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "webguard"
RENDER = SRC / "render"


def _py_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _all_src_files() -> list[Path]:
    return sorted(
        p
        for p in SRC.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix in {".py", ".j2", ".html"}
    )


# S-12: forbidden security-weakening patterns anywhere in src/ (code, comments and docstrings).
S12_PATTERNS = [
    r"CERT_NONE",
    r"check_hostname\s*=\s*False",
    r"_create_unverified_context",
    r"create_default_context",  # reads SSLKEYLOGFILE from the environment (P0 finding)
    r"verify\s*=\s*False",
    r"allow_redirects",
    r"trust_env",
    r"shell\s*=\s*True",
    r"\beval\(",
    r"\bexec\(",
    r"\bpickle\b",
    r"os\.replace\(",
    r"shutil\.move\(",
    r"SimpleCookie",
    r"^\s*(import|from)\s+(httpx|requests|aiohttp|urllib3)\b",
    r"urllib\.request",
    r"http\.client",
]


@pytest.mark.parametrize("pattern", S12_PATTERNS)
def test_s12_no_forbidden_patterns(pattern: str) -> None:
    rx = re.compile(pattern)
    hits = [
        f"{p.relative_to(SRC)}:{n}"
        for p in _all_src_files()
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if rx.search(line)
    ]
    assert hits == [], f"forbidden pattern {pattern!r} found: {hits}"


# S-13: templates and render code never bypass autoescaping.
S13_PATTERNS = [r"\|\s*safe\b", r"Markup\(", r"autoescape\s+false", r"autoescape\s*=\s*False"]


@pytest.mark.parametrize("pattern", S13_PATTERNS)
def test_s13_no_escape_bypass(pattern: str) -> None:
    rx = re.compile(pattern, re.IGNORECASE)
    hits = [
        f"{p.relative_to(SRC)}:{n}"
        for p in sorted(RENDER.rglob("*"))
        if p.is_file() and p.suffix in {".py", ".j2", ".html"}
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if rx.search(line)
    ]
    assert hits == [], f"escape bypass {pattern!r} found: {hits}"


def test_s13_templates_only_include_packaged_paths() -> None:
    rx = re.compile(r"{%-?\s*(include|import|extends|from)\b")
    for p in RENDER.rglob("*.j2"):
        assert not rx.search(p.read_text(encoding="utf-8")), f"{p.name} pulls in another template"


# S-28: the only ScopePolicy implementation shipped in src/ is PublicScopePolicy.
def test_s28_only_public_scope_policy_in_src() -> None:
    implementations: list[str] = []
    for p in _py_files(SRC):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            methods = {n.name for n in node.body if isinstance(n, ast.FunctionDef)}
            bases = {ast.unparse(b) for b in node.bases}
            looks_like_policy = {"check_literal", "check_resolved"} <= methods
            if looks_like_policy or any("ScopePolicy" in b for b in bases):
                implementations.append(node.name)
    allowed = {"ScopePolicy", "PublicScopePolicy"}
    assert set(implementations) <= allowed, implementations


# Prompt rule 14: no placeholders in shipped code.
@pytest.mark.parametrize("pattern", [r"\bTODO\b", r"\bFIXME\b", r"\bXXX\b", r"NotImplementedError"])
def test_no_placeholders_in_src(pattern: str) -> None:
    rx = re.compile(pattern)
    hits = [
        f"{p.relative_to(SRC)}:{n}"
        for p in _all_src_files()
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if rx.search(line)
    ]
    assert hits == [], hits


def _is_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """A body that is only `pass` / `...` (after an optional docstring)."""
    body = fn.body[1:] if ast.get_docstring(fn) is not None else fn.body
    if len(body) != 1:
        return False
    stmt = body[0]
    return isinstance(stmt, ast.Pass) or (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


def test_no_stub_function_bodies() -> None:
    """Protocol method declarations are the only permitted `...` bodies."""
    for p in _py_files(SRC):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        protocol_methods = {
            id(fn)
            for cls in ast.walk(tree)
            if isinstance(cls, ast.ClassDef)
            and any("Protocol" in ast.unparse(b) for b in cls.bases)
            for fn in cls.body
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_stub(node):
                assert id(node) in protocol_methods, (
                    f"{p.relative_to(SRC)}:{node.lineno} {node.name} has a stub body"
                )


# Prompt rule 15: suppressions need an inline justification after them.
def test_suppressions_are_justified() -> None:
    rx = re.compile(r"#\s*(type:\s*ignore|noqa)\b[^#]*$")
    hits = [
        f"{p.relative_to(SRC)}:{n}"
        for p in _py_files(SRC)
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if rx.search(line)
    ]
    assert hits == [], f"unjustified suppression (add '# reason: ...'): {hits}"


def test_no_assert_statements_in_src() -> None:
    """Security checks must not use `assert` (stripped under python -O)."""
    for p in _py_files(SRC):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            assert not isinstance(node, ast.Assert), f"{p.relative_to(SRC)}:{node.lineno}"


def test_no_fstring_or_format_in_log_calls() -> None:
    log_methods = {"debug", "info", "warning", "error", "exception", "critical", "log"}
    for p in _py_files(SRC):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in log_methods
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"log", "logger", "_log", "LOG"}
                and node.args
            ):
                first = node.args[0]
                where = f"{p.relative_to(SRC)}:{node.lineno} log message must be a static string"
                assert isinstance(first, ast.Constant), where
                assert isinstance(first.value, str), where


def test_s12_no_http_library_redirect_following() -> None:
    """`follow_redirects` may only appear as WebGuard's own config field, never as an HTTP kwarg."""
    allowed_callers = {"ScanConfig", "ConfigInfo"}
    for p in _py_files(SRC):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and any(
                k.arg == "follow_redirects" for k in node.keywords
            ):
                callee = ast.unparse(node.func).rsplit(".", 1)[-1]
                assert callee in allowed_callers, f"{p.relative_to(SRC)}:{node.lineno}"


# Trojan-Source guard: no invisible, bidi or control characters in any source or template file.
_INVISIBLE_RANGES = (
    (0x0000, 0x0008),
    (0x000B, 0x000C),
    (0x000E, 0x001F),
    (0x007F, 0x009F),
    (0x061C, 0x061C),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x2069),
    (0xFEFF, 0xFEFF),
)


def test_no_invisible_chars_in_source() -> None:
    root = SRC.parents[1]
    files = [
        p
        for base in (root / "src", root / "tests", root / "docs")
        if base.exists()
        for p in base.rglob("*")
        if p.is_file() and p.suffix in {".py", ".j2", ".html", ".md", ".toml"}
    ]
    hits = [
        f"{p.relative_to(root)}:{n}:U+{ord(ch):04X}"
        for p in files
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        for ch in line
        if any(lo <= ord(ch) <= hi for lo, hi in _INVISIBLE_RANGES)
    ]
    assert hits == [], hits


def test_threat_model_covers_register() -> None:
    """G-11: THREAT_MODEL.md lists every plan threat T-01..T-28 (it may add more)."""
    doc = (SRC.parents[1] / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    listed = set(re.findall(r"^\| (T-\d{2}) \|", doc, flags=re.MULTILINE))
    assert {f"T-{n:02d}" for n in range(1, 29)} <= listed
