import argparse
import os
from typing import Mapping, Optional, Sequence

__version__ = "2.0.0"

LOGGING_LEVEL_CHOICES: tuple[str, ...] = ("disabled", "debug", "info", "warning", "error", "critical")
LOGGING_LEVEL_ENV: str = "LOGGING_LEVEL"
DEFAULT_LOGGING_LEVEL: str = "debug"


def parse_arguments(
    argv: Optional[Sequence[str]] = None, environ: Mapping[str, str] = os.environ
) -> argparse.Namespace:
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
    server_group.add_argument(
        "-P", "--port", type=int, default=1080, help="Port number for the SOCKS server."
    )

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
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args(argv)
    # argparse validates choices only for values given on the command line, so an invalid value
    # here can only have come from the environment.
    if args.logging_level not in LOGGING_LEVEL_CHOICES:
        parser.error(
            f"{LOGGING_LEVEL_ENV}: invalid choice: {args.logging_level!r} "
            f"(choose from {', '.join(LOGGING_LEVEL_CHOICES)})"
        )
    return args
