"""Report persistence (Plan §17): the only file I/O for reports.

Guarantees (INV-14): never overwrites, never leaves partial or temporary files, never writes
outside the output directory, and file names never contain target-derived text.
"""

from __future__ import annotations

import contextlib
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

_IS_WINDOWS = os.name == "nt"
_FILE_MODE = 0o600
_DIR_MODE = 0o700


class SinkError(Exception):
    """Persistence failed. `code` is static; `written` lists files that were published."""

    def __init__(self, code: str, written: Sequence[Path] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.written = tuple(written)


@dataclass(frozen=True, slots=True)
class ReportFile:
    suffix: str
    content: str


def report_basename(started_at: datetime, scan_id: str) -> str:
    """webguard_<YYYYMMDDTHHMMSSZ>_<scan_id[:8]> — generated only (INV-14)."""
    return f"webguard_{started_at.strftime('%Y%m%dT%H%M%SZ')}_{scan_id[:8]}"


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if callable(is_junction) else False


def prepare_directory(directory: Path) -> Path:
    """Directory policy (Plan §17.1); returns the directory to write into."""
    if _is_link_or_junction(directory):
        raise SinkError("output_is_symlink")
    if not directory.exists():
        parent = directory.parent
        if not parent.is_dir():
            raise SinkError("output_parent_missing")
        try:
            os.mkdir(directory, _DIR_MODE)  # final component only; never parents=True
        except FileExistsError as exc:
            raise SinkError("output_raced") from exc
        except OSError as exc:
            raise SinkError("output_create_failed") from exc
    try:
        info = os.lstat(directory)
    except OSError as exc:
        raise SinkError("output_unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or _is_link_or_junction(directory):
        raise SinkError("output_is_symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise SinkError("output_not_directory")
    if not os.access(directory, os.W_OK | os.X_OK):
        raise SinkError("output_not_writable")
    return directory


def _publish(tmp: Path, final: Path) -> None:
    """Make `final` visible without ever replacing an existing file (A-09)."""
    if _IS_WINDOWS:
        os.rename(tmp, final)  # raises FileExistsError if final exists
    else:
        os.link(tmp, final)  # raises FileExistsError if final exists
        os.unlink(tmp)


def _write_one(directory: Path, name: str, content: str) -> Path:
    final = directory / name
    tmp = directory / f".{name}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(tmp, flags, _FILE_MODE)
        created = True
        with os.fdopen(fd, "wb") as handle:
            handle.write(content.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        _publish(tmp, final)
    except BaseException as exc:
        if created:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        if isinstance(exc, KeyboardInterrupt):
            raise
        if isinstance(exc, FileExistsError):
            raise SinkError("output_exists") from exc
        if isinstance(exc, OSError):
            raise SinkError("write_failed") from exc
        raise
    return final


def write_reports(directory: Path, basename: str, files: Sequence[ReportFile]) -> list[Path]:
    """Write each file in order (JSON first). On failure, files already published are kept and
    reported through SinkError.written; the failing file leaves nothing behind."""
    target = prepare_directory(directory)
    written: list[Path] = []
    for item in files:
        try:
            written.append(_write_one(target, f"{basename}.{item.suffix}", item.content))
        except SinkError as exc:
            raise SinkError(exc.code, written) from exc
    return written
