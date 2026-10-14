"""
Server logging.

By default the server logs to standard error, which is what systemd (Linux) collects and rotates.
On macOS the service is started by launchd, which opens its log files once and keeps writing to
them, so a file rotated from outside would go on growing in its old, renamed copy. There the
server rotates its own log: set VERITAS_LOG_DIR and it writes `veritas-app.log` in that folder,
10 MB at a time, keeping 5 compressed older files (VERITAS_LOG_MAX_MB, VERITAS_LOG_KEEP).

The files launchd writes (`veritas.log`, `veritas-error.log`) then only carry what the process
prints outside of logging, such as a crash traceback. A long-running service that restarts a
lot could still grow them, so any of them over the rotation size is emptied at start-up.
"""
from __future__ import annotations

import gzip
import logging
import logging.handlers
import os
import shutil
from pathlib import Path
from typing import Optional

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_NAME = "veritas-app.log"
LAUNCHD_FILES = ("veritas.log", "veritas-error.log")


def _int_env(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return max(low, min(high, value))


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotates by size, compresses what it rotates, and keeps every file private to the owner."""

    def __init__(self, filename, **kwargs):
        super().__init__(filename, **kwargs)
        self.namer = lambda name: name + ".gz"
        self.rotator = self._compress

    def _open(self):
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            pass
        return stream

    @staticmethod
    def _compress(source: str, dest: str) -> None:
        with open(source, "rb") as src, gzip.open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        os.chmod(dest, 0o600)
        os.remove(source)


def _empty_oversize_console_files(log_dir: Path, limit_bytes: int) -> None:
    for name in LAUNCHD_FILES:
        path = log_dir / name
        try:
            if path.is_file() and path.stat().st_size > limit_bytes:
                os.truncate(path, 0)
        except OSError:
            pass


def configure_logging(level: int = logging.INFO, log_dir: Optional[str] = None) -> Optional[Path]:
    """
    Set up the root logger. Returns the path of the rotating log file, or None when logging goes
    to standard error (the default, and the only mode when VERITAS_LOG_DIR is not set).
    """
    directory = log_dir if log_dir is not None else os.environ.get("VERITAS_LOG_DIR", "").strip()
    root = logging.getLogger()
    if not directory:
        logging.basicConfig(level=level, format=LOG_FORMAT)
        return None

    max_bytes = _int_env("VERITAS_LOG_MAX_MB", 10, 1, 1024) * 1024 * 1024
    keep = _int_env("VERITAS_LOG_KEEP", 5, 1, 100)
    folder = Path(directory)
    try:
        folder.mkdir(parents=True, exist_ok=True)
        _empty_oversize_console_files(folder, max_bytes)
        handler = _PrivateRotatingFileHandler(
            folder / LOG_NAME, maxBytes=max_bytes, backupCount=keep, encoding="utf-8"
        )
    except OSError:
        # A folder that cannot be written must not stop the service: fall back to standard error.
        logging.basicConfig(level=level, format=LOG_FORMAT)
        logging.getLogger("pipeline").warning("Cannot write logs to %s; logging to standard error", directory)
        return None

    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    return Path(handler.baseFilename)
