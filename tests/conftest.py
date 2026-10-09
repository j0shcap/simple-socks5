import logging

import pytest


@pytest.fixture(autouse=True)
def _restore_package_logger():
    """
    update_loggers() reconfigures the process-wide "simple_socks5" logger; undo it so later tests still reach caplog.
    """
    logger = logging.getLogger("simple_socks5")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield
    for handler in logger.handlers:
        if handler not in handlers:
            handler.close()
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate
