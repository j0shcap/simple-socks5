import argparse
import os
from collections.abc import Mapping, Sequence
from importlib.metadata import PackageNotFoundError, version
from typing import Final

from .config import LOGGING_LEVELS, LoggingLevelName, ProxyConfiguration

try:
    __version__ = version("simple-socks5")
except PackageNotFoundError:  # a clone run as `python3 app.py` without `pip install -e .`
    __version__ = "0+unknown"

LOGGING_LEVEL_CHOICES: Final[tuple[LoggingLevelName, ...]] = tuple(LOGGING_LEVELS)
LOGGING_LEVEL_ENV: Final = "LOGGING_LEVEL"
DEFAULT_LOGGING_LEVEL: Final[LoggingLevelName] = "debug"


class _Arguments(argparse.Namespace):
    host: str
    port: int
    logging_level: str


def _logging_level_name(value: str) -> LoggingLevelName | None:
    for name in LOGGING_LEVEL_CHOICES:
        if name == value:
            return name
    return None


def parse_arguments(argv: Sequence[str] | None = None, environ: Mapping[str, str] = os.environ) -> ProxyConfiguration:
    """
    Parses command line arguments for the SOCKS5 Proxy Server.

    This parser configures the server's host, port and logging level. The logging level falls back to
    $LOGGING_LEVEL, then to debug, when -L/--logging-level is not given.
    """
    parser = argparse.ArgumentParser(
        description="SOCKS5 Proxy Server. A flexible and configurable proxy server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Server Configuration
    server_group = parser.add_argument_group("Server Configuration")
    server_group.add_argument(
        "-H",
        "--host",
        type=str,
        default="localhost",
        help="Host address for the SOCKS server.",
    )
    server_group.add_argument("-P", "--port", type=int, default=1080, help="Port number for the SOCKS server.")

    # Logging Configuration
    logging_group = parser.add_argument_group("Logging Configuration")
    logging_group.add_argument(
        "-L",
        "--logging-level",
        type=str,
        choices=LOGGING_LEVEL_CHOICES,
        default=environ.get(LOGGING_LEVEL_ENV) or DEFAULT_LOGGING_LEVEL,
        help=f"Set the logging level. Defaults to ${LOGGING_LEVEL_ENV}, else {DEFAULT_LOGGING_LEVEL}.",
    )

    # Version Information
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args(argv, namespace=_Arguments())
    # argparse validates choices only for values given on the command line, so an invalid value
    # here can only have come from the environment.
    logging_level = _logging_level_name(args.logging_level)
    if logging_level is None:
        parser.error(
            f"{LOGGING_LEVEL_ENV}: invalid choice: {args.logging_level!r} "
            f"(choose from {', '.join(LOGGING_LEVEL_CHOICES)})"
        )
    return ProxyConfiguration(host=args.host, port=args.port, logging_level=logging_level)
