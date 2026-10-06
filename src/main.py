import signal
import threading
import time
from argparse import Namespace
from typing import Callable, Optional

from .server import (
    ThreadingTCPServer,
    TCPProxyServer,
)
from .logger import get_logger, update_loggers
from .config import ProxyConfiguration
from .constants import SHUTDOWN_FORCE_CLOSE_TIMEOUT, SHUTDOWN_GRACE_PERIOD
from .startup import collect_startup_advisories

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
        self._deadline: Optional[float] = None
        self._previous_handlers: dict = {}

    def install(self) -> None:
        for signum in self.SIGNALS:
            self._previous_handlers[signum] = signal.signal(signum, self._handle)

    def restore(self) -> None:
        for signum, handler in self._previous_handlers.items():
            signal.signal(signum, handler)
        self._previous_handlers.clear()

    def _handle(self, signum, frame) -> None:
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
            logger.info(f"Closing {closed} connection(s) still active after the grace period")
            self._server.wait_for_connections(self._remaining(deadline))
        logger.info("Server terminated.")

    def _remaining(self, until: float) -> float:
        return max(0.0, until - self._clock())


def main(args: Namespace):
    """
    Entry point of the program.
    Sets program configuration, starts the server, and handles server shutdown.
    """

    ProxyConfiguration.initialize(args.host, args.port, args.logging_level)

    update_loggers()

    for level, message in collect_startup_advisories(ProxyConfiguration.get_host()):
        logger.log(level, message)

    try:
        with ThreadingTCPServer(
            (ProxyConfiguration.get_host(), ProxyConfiguration.get_port()), TCPProxyServer
        ) as tcp_server:
            logger.info(f"Server started on {ProxyConfiguration.get_address()}")

            try:
                tcp_server.serve_forever()
            except KeyboardInterrupt:
                logger.info("Server shutting down...")
            finally:
                tcp_server.shutdown()
                tcp_server.server_close()
                logger.info("Server terminated.")
    except OSError as e:
        logger.error(f"Error starting server: {e}")
        exit(1)
