"""
Runs app.py as a real process, for tests that need what only a process shows: exit codes, signals and its output.
"""

import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import pytest

from tests.e2e import socks_client as sc

APP = Path(__file__).resolve().parents[2] / "app.py"
STARTUP_TIMEOUT = 10.0  # seconds


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def socks_ready(address: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(address, timeout=1) as sock:
            return sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
    except (OSError, EOFError):
        return False


@contextmanager
def run_app(
    cwd: Path, *, logging_level: str = "info", env: Optional[dict[str, str]] = None
) -> Iterator[tuple[subprocess.Popen, tuple[str, int]]]:
    """
    Runs app.py on a free loopback port with no SOCKS5_* variables but SOCKS5_ALLOW_LOOPBACK=true (the origins
    listen on loopback) and those in env, and yields (process, address) once it accepts SOCKS5 connections. stdout
    and stderr are pipes, so the app sees no TTY.
    """
    if sys.platform == "win32":
        pytest.skip("POSIX signals only")
    address = ("127.0.0.1", free_port())
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("SOCKS5_") and k != "LOGGING_LEVEL"}
    proc = subprocess.Popen(
        [sys.executable, str(APP), "-H", address[0], "-P", str(address[1]), "-L", logging_level],
        cwd=cwd,
        env={**clean_env, "SOCKS5_ALLOW_LOOPBACK": "true", **(env or {})},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while not socks_ready(address):
            if proc.poll() is not None or time.monotonic() > deadline:
                proc.kill()
                pytest.fail(f"app.py did not start (exit code {proc.poll()}):\n{proc.communicate()[1]}")
            time.sleep(0.1)
        yield proc, address
    finally:
        proc.kill()
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()
