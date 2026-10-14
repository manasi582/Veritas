"""Server log rotation (used on macOS, where launchd cannot follow an externally rotated file)."""
import gzip
import logging
import os
import stat
import sys

import pytest

import log_setup


@pytest.fixture(autouse=True)
def _restore_root_logger():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    for h in handlers:
        root.addHandler(h)
    root.setLevel(level)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_without_a_log_dir_logging_stays_on_standard_error(monkeypatch):
    monkeypatch.delenv("VERITAS_LOG_DIR", raising=False)
    assert log_setup.configure_logging() is None


def test_rotates_at_the_size_limit_and_keeps_only_the_configured_number(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_LOG_MAX_MB", "1")
    monkeypatch.setenv("VERITAS_LOG_KEEP", "2")
    path = log_setup.configure_logging(log_dir=str(tmp_path))
    log = logging.getLogger("rotation-test")
    line = "x" * 1000
    for _ in range(4500):          # about 4.5 MB
        log.info(line)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert path.name == "veritas-app.log"
    assert names == ["veritas-app.log", "veritas-app.log.1.gz", "veritas-app.log.2.gz"], names
    assert os.path.getsize(path) < 1024 * 1024 + 2000


def test_rotated_files_are_compressed_and_readable(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_LOG_MAX_MB", "1")
    log_setup.configure_logging(log_dir=str(tmp_path))
    log = logging.getLogger("compress-test")
    for i in range(1500):
        log.info("line %d %s", i, "y" * 1000)
    with gzip.open(tmp_path / "veritas-app.log.1.gz", "rt") as f:
        assert "compress-test: line 0 " in f.readline()


@pytest.mark.skipif(sys.platform == "win32", reason="file modes are not meaningful on Windows")
def test_every_file_is_private_to_the_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_LOG_MAX_MB", "1")
    log_setup.configure_logging(log_dir=str(tmp_path))
    log = logging.getLogger("perm-test")
    for _ in range(1500):
        log.info("z" * 1000)
    files = list(tmp_path.iterdir())
    assert len(files) >= 2
    for p in files:
        assert _mode(p) == 0o600, (p.name, oct(_mode(p)))


def test_standard_error_handler_is_removed_so_nothing_is_written_twice(tmp_path):
    logging.getLogger().addHandler(logging.StreamHandler())
    log_setup.configure_logging(log_dir=str(tmp_path))
    kinds = [type(h).__name__ for h in logging.getLogger().handlers]
    assert kinds == ["_PrivateRotatingFileHandler"]


def test_oversize_launchd_files_are_emptied_at_start(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_LOG_MAX_MB", "1")
    big, small = tmp_path / "veritas.log", tmp_path / "veritas-error.log"
    big.write_bytes(b"a" * (2 * 1024 * 1024))
    small.write_bytes(b"short")
    log_setup.configure_logging(log_dir=str(tmp_path))
    assert big.stat().st_size == 0
    assert small.read_bytes() == b"short"


def test_an_unwritable_folder_does_not_stop_the_service(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a folder")
    assert log_setup.configure_logging(log_dir=str(blocker / "logs")) is None


def test_nonsense_settings_fall_back_to_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_LOG_MAX_MB", "lots")
    monkeypatch.setenv("VERITAS_LOG_KEEP", "-4")
    log_setup.configure_logging(log_dir=str(tmp_path))
    handler = logging.getLogger().handlers[0]
    assert handler.maxBytes == 10 * 1024 * 1024
    assert handler.backupCount == 1   # clamped to the minimum
