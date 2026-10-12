import logging
from collections.abc import Mapping
from logging.handlers import RotatingFileHandler
from typing import Final

from .constants import LOG_FILE_BACKUP_COUNT, LOG_FILE_MAX_BYTES, log_file

CONSOLE_FORMAT: Final = "[%(asctime)s] - [%(levelname)s] - %(message)s"
FILE_FORMAT: Final = "[%(asctime)s] - [%(name)s] - [%(levelname)s] - [%(message)s]"

# What each level means, for every log call in the package:
#   ERROR    a server fault: an unexpected exception (with a traceback), failing to bind or to open SOCKS5_LOG_FILE
#   WARNING  something an operator should act on: the startup banners, the connection limit, a denied destination,
#            a relay write timeout, handshake timeouts, failed logins. Those a client can repeat are rate-limited.
#   INFO     the CONNECTION and CLOSED lines, and the reply code sent for a destination failure (refused, unreachable)
#   DEBUG    client protocol errors, clients hanging up, and per-datagram UDP detail
#
# Every module logger ("simple_socks5.server", "simple_socks5.relays.tcp_relay", ...) propagates to this one, which
# holds the only handlers. Until update_loggers() runs it just propagates, so library use and tests see records via
# the root logger.
_package_logger = logging.getLogger(__name__.rpartition(".")[0])
_package_logger.addHandler(logging.NullHandler())


class LogColors:
    RED: Final = "\033[91m"
    GREEN: Final = "\033[92m"
    YELLOW: Final = "\033[93m"
    WHITE: Final = "\033[97m"
    GREY: Final = "\033[90m"
    RESET: Final = "\033[0m"


class ColorFormatter(logging.Formatter):
    COLORS: Final[Mapping[int, str]] = {
        logging.ERROR: LogColors.RED,
        logging.WARNING: LogColors.YELLOW,
        logging.INFO: LogColors.WHITE,
        logging.DEBUG: LogColors.GREY,
    }

    def __init__(self, fmt: str, use_color: bool) -> None:
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        color = self.COLORS.get(record.levelno) if self.use_color else None
        if color:
            message = color + message + LogColors.RESET
        return message


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def update_loggers(logging_level: int) -> None:
    """
    Configures the package logger at logging_level (logging.NOTSET disables it) and from SOCKS5_LOG_FILE, replacing
    any earlier configuration.
    """
    for handler in list(_package_logger.handlers):
        _package_logger.removeHandler(handler)
        handler.close()
    # Records stop here, so an application that configures the root logger doesn't print them twice
    _package_logger.propagate = False

    if logging_level == logging.NOTSET:
        _package_logger.setLevel(logging.CRITICAL + 1)
        _package_logger.addHandler(logging.NullHandler())
        return

    _package_logger.setLevel(logging_level)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorFormatter(CONSOLE_FORMAT, use_color=console_handler.stream.isatty()))
    _package_logger.addHandler(console_handler)

    path = log_file()
    if path is None:
        return
    try:
        file_handler = RotatingFileHandler(path, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT)
    except OSError as e:
        _package_logger.error("Cannot open SOCKS5_LOG_FILE %s: %s. Logging to the console only.", path, e)
        return
    file_handler.setLevel(logging.ERROR)
    file_handler.setFormatter(logging.Formatter(FILE_FORMAT))
    _package_logger.addHandler(file_handler)
