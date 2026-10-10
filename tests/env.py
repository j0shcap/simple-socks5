import os
import unittest
from unittest.mock import patch


def strip_socks5_env(test: unittest.TestCase, **environ: str) -> None:
    """Runs the test with no SOCKS5_* variables from the outer environment, plus the given ones."""
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_")}
    patcher = patch.dict(os.environ, {**clean, **environ}, clear=True)
    patcher.start()
    test.addCleanup(patcher.stop)
