import logging
from logging.handlers import RotatingFileHandler

from .config import ProxyConfiguration
from .constants import LOG_FILE_BACKUP_COUNT, LOG_FILE_MAX_BYTES, log_file

CONSOLE_FORMAT = "[%(asctime)s] - [%(levelname)s] - %(message)s"
FILE_FORMAT = "[%(asctime)s] - [%(name)s] - [%(levelname)s] - [%(message)s]"

# Every module logger ("src.server", "src.relays.tcp_relay", ...) propagates to this one, which holds the only
# handlers. Until update_loggers() runs it just propagates, so library use and tests see records via the root logger.
_package_logger = logging.getLogger(__name__.rpartition(".")[0])
_package_logger.addHandler(logging.NullHandler())


class LogColors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    RESET = "\033[0m"


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.ERROR: LogColors.RED,
        logging.WARNING: LogColors.YELLOW,
        logging.INFO: LogColors.WHITE,
        logging.DEBUG: LogColors.GREY,
    }

    def __init__(self, fmt: str, use_color: bool):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record):
        message = super().format(record)
        color = self.COLORS.get(record.levelno) if self.use_color else None
        if color:
            message = color + message + LogColors.RESET
        return message


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def update_loggers() -> None:
    """
    Configures the package logger from ProxyConfiguration and SOCKS5_LOG_FILE, replacing any earlier configuration.
    """
    for handler in list(_package_logger.handlers):
        _package_logger.removeHandler(handler)
        handler.close()
    # Records stop here, so an application that configures the root logger doesn't print them twice
    _package_logger.propagate = False

    logging_level = ProxyConfiguration.get_logging_level()
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
        _package_logger.error(f"Cannot open SOCKS5_LOG_FILE {path}: {e}. Logging to the console only.")
        return
    file_handler.setLevel(logging.ERROR)
    file_handler.setFormatter(logging.Formatter(FILE_FORMAT))
    _package_logger.addHandler(file_handler)
