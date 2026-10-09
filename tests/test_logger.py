import io
import logging
import unittest

import pytest

from simple_socks5.config import ProxyConfiguration
from simple_socks5.logger import ColorFormatter, get_logger, update_loggers

CONSOLE_FORMAT = "%(levelname)s %(message)s"


class TTYStream(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def configure(monkeypatch, tmp_path):
    """Returns configure(level, stream=None): runs update_loggers() at that level, logging to stream."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SOCKS5_LOG_FILE", raising=False)

    class FreshConfig(ProxyConfiguration):
        pass

    monkeypatch.setattr("simple_socks5.logger.ProxyConfiguration", FreshConfig)

    def _configure(level: str, stream=None) -> io.StringIO:
        stream = stream if stream is not None else io.StringIO()
        FreshConfig.initialize("127.0.0.1", 1080, level)
        monkeypatch.setattr("sys.stderr", stream)
        update_loggers()
        return stream

    return _configure


def package_logger() -> logging.Logger:
    return logging.getLogger("simple_socks5")


def test_get_logger_returns_the_stdlib_logger():
    assert get_logger("simple_socks5.some.module") is logging.getLogger("simple_socks5.some.module")


def test_module_loggers_have_no_handlers_and_propagate(configure):
    configure("info")
    module_logger = get_logger("simple_socks5.handlers.tcp")

    assert module_logger.handlers == []
    assert module_logger.propagate
    assert module_logger.level == logging.NOTSET


def test_module_records_reach_the_package_handler(configure):
    stream = configure("info")

    get_logger("simple_socks5.a").info("hello")
    get_logger("simple_socks5.b").debug("hidden")

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert lines[0].endswith(" - [INFO] - hello")


def test_update_loggers_is_idempotent(configure, monkeypatch, tmp_path):
    configure("info")
    configure("info")
    assert len(package_logger().handlers) == 1

    monkeypatch.setenv("SOCKS5_LOG_FILE", str(tmp_path / "proxy.log"))
    configure("info")
    configure("info")
    assert len(package_logger().handlers) == 2


def test_configured_package_logger_does_not_propagate(configure):
    configure("info")
    assert not package_logger().propagate


def test_disabled_writes_nothing_and_creates_no_file(configure, monkeypatch, tmp_path):
    monkeypatch.setenv("SOCKS5_LOG_FILE", str(tmp_path / "proxy.log"))
    stream = configure("disabled")

    get_logger("simple_socks5.x").critical("boom")

    assert stream.getvalue() == ""
    assert list(tmp_path.iterdir()) == []


def test_no_errors_log_by_default(configure, tmp_path):
    configure("debug")

    get_logger("simple_socks5.x").error("boom")

    assert list(tmp_path.iterdir()) == []


def test_log_file_receives_errors_only(configure, monkeypatch, tmp_path):
    log_path = tmp_path / "proxy.log"
    monkeypatch.setenv("SOCKS5_LOG_FILE", str(log_path))
    configure("debug")

    get_logger("simple_socks5.x").warning("just a warning")
    get_logger("simple_socks5.x").error("boom")

    contents = log_path.read_text()
    assert "[simple_socks5.x] - [ERROR] - [boom]" in contents
    assert "just a warning" not in contents


def test_rotation_with_several_module_loggers(configure, monkeypatch, tmp_path):
    log_path = tmp_path / "proxy.log"
    monkeypatch.setenv("SOCKS5_LOG_FILE", str(log_path))
    monkeypatch.setattr("simple_socks5.logger.LOG_FILE_MAX_BYTES", 300)
    configure("error")

    for i in range(60):
        get_logger(f"simple_socks5.{'ab'[i % 2]}").error(f"record {i:02d}")

    files = sorted(tmp_path.iterdir())
    assert [f.name for f in files] == [f"proxy.log{suffix}" for suffix in ("", ".1", ".2", ".3", ".4", ".5")]
    record_size = len(log_path.read_text().splitlines()[0]) + 1
    assert all(f.stat().st_size <= 300 + record_size for f in files)
    # Newest records survive, each exactly once and in order
    kept = [line for f in reversed(files) for line in f.read_text().splitlines()]
    numbers = [int(line.split("record ")[1][:2]) for line in kept]
    assert numbers == list(range(numbers[0], 60))


def test_unwritable_log_file_logs_error_and_continues(configure, monkeypatch, tmp_path):
    missing = tmp_path / "missing-dir" / "proxy.log"
    monkeypatch.setenv("SOCKS5_LOG_FILE", str(missing))
    stream = configure("info")

    get_logger("simple_socks5.x").info("still running")

    output = stream.getvalue()
    assert "SOCKS5_LOG_FILE" in output and str(missing) in output
    assert "[ERROR]" in output
    assert "still running" in output
    assert len(package_logger().handlers) == 1


def test_colour_only_on_tty(configure):
    assert "\x1b[" not in _log_error(configure("info"))
    assert "\x1b[" in _log_error(configure("info", TTYStream()))


def _log_error(stream: io.StringIO) -> str:
    get_logger("simple_socks5.x").error("boom")
    return stream.getvalue()


class TestColorFormatter(unittest.TestCase):
    def record(self, level: int) -> logging.LogRecord:
        return logging.LogRecord("simple_socks5.x", level, __file__, 1, "message", None, None)

    def test_colour_wraps_message(self):
        formatted = ColorFormatter(CONSOLE_FORMAT, use_color=True).format(self.record(logging.ERROR))
        self.assertTrue(formatted.startswith("\x1b[91m"))
        self.assertTrue(formatted.endswith("\x1b[0m"))

    def test_no_colour_is_plain(self):
        formatted = ColorFormatter(CONSOLE_FORMAT, use_color=False).format(self.record(logging.ERROR))
        self.assertEqual(formatted, "ERROR message")


if __name__ == "__main__":
    unittest.main()
