import signal
import sys
import threading
import time
from argparse import Namespace
from collections.abc import Callable, Sequence

from .argument_parser import parse_arguments
from .config import ProxyConfiguration
from .constants import SHUTDOWN_FORCE_CLOSE_TIMEOUT, SHUTDOWN_GRACE_PERIOD
from .logger import get_logger, update_loggers
from .server import (
    TCPProxyServer,
    ThreadingTCPServer,
)
from .startup import collect_startup_advisories, validate_environment

logger = get_logger(__name__)


class GracefulShutdown:
    """
    Stops the server on SIGTERM or SIGINT and gives in-flight connections a grace period to finish.
    """

    SIGNALS = (signal.SIGTERM, signal.SIGINT)

    def __init__(
        self,
        server: ThreadingTCPServer,
        grace: float = SHUTDOWN_GRACE_PERIOD,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._server = server
        self._grace = grace
        self._clock = clock
        self._deadline: float | None = None
        self._previous_handlers: dict = {}

    def install(self) -> None:
        for signum in self.SIGNALS:
            self._previous_handlers[signum] = signal.signal(signum, self._handle)

    def restore(self) -> None:
        for signum, handler in self._previous_handlers.items():
            signal.signal(signum, handler)
        self._previous_handlers.clear()

    def _handle(self, _signum, _frame) -> None:
        if self._deadline is not None:
            return
        self._deadline = self._clock() + self._grace
        logger.info("Server shutting down...")
        # shutdown() waits for serve_forever() to return, so calling it on this (the serving) thread deadlocks.
        threading.Thread(target=self._server.shutdown, daemon=True).start()

    def drain(self) -> None:
        """
        Waits for in-flight connections until shortly before the deadline, then force-closes the rest.
        """
        deadline = self._deadline if self._deadline is not None else self._clock() + self._grace
        if not self._server.wait_for_connections(self._remaining(deadline - SHUTDOWN_FORCE_CLOSE_TIMEOUT)):
            closed = self._server.close_connections()
            logger.info("Closing %s connection(s) still active after the grace period", closed)
            self._server.wait_for_connections(self._remaining(deadline))
        logger.info("Server terminated.")

    def _remaining(self, until: float) -> float:
        return max(0.0, until - self._clock())


def main(args: Namespace):
    """
    Entry point of the program.
    Sets program configuration, starts the server, and handles server shutdown.
    """
    # Before loggers are configured, so -L disabled can't hide the error
    try:
        validate_environment()
    except ValueError as e:
        sys.exit(f"Invalid configuration: {e}")

    ProxyConfiguration.initialize(args.host, args.port, args.logging_level)

    update_loggers()

    for level, message in collect_startup_advisories(ProxyConfiguration.get_host()):
        logger.log(level, message)

    try:
        with ThreadingTCPServer(
            (ProxyConfiguration.get_host(), ProxyConfiguration.get_port()), TCPProxyServer
        ) as tcp_server:
            graceful_shutdown = GracefulShutdown(tcp_server)
            graceful_shutdown.install()
            logger.info("Server started on %s", ProxyConfiguration.get_address())

            try:
                tcp_server.serve_forever()
            finally:
                tcp_server.server_close()
                # Handlers stay installed while draining, so a repeated signal can't interrupt it.
                graceful_shutdown.drain()
                graceful_shutdown.restore()
    except OSError as e:
        logger.error("Error starting server: %s", e)
        sys.exit(1)


def cli(argv: Sequence[str] | None = None) -> None:
    """
    Console entry point: parses argv (default sys.argv[1:]) and runs main().
    """
    main(parse_arguments(argv))
