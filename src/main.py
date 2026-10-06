from argparse import Namespace

from .server import (
    ThreadingTCPServer,
    TCPProxyServer,
)
from .logger import get_logger, update_loggers
from .config import ProxyConfiguration
from .startup import collect_startup_advisories

logger = get_logger(__name__)


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
