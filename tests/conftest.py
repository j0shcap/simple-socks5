import logging

import pytest


@pytest.fixture(autouse=True)
def _restore_package_logger():
    """update_loggers() reconfigures the process-wide "src" logger; undo it so later tests still reach caplog."""
    logger = logging.getLogger("src")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield
    for handler in logger.handlers:
        if handler not in handlers:
            handler.close()
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate
