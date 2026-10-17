"""
The processes a benchmark runs besides its load generators: the origin servers and the proxy under test.
"""

import contextlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Final

from . import profiles

ROOT: Final = Path(__file__).resolve().parents[1]
START_TIMEOUT: Final = 15.0
STOP_TIMEOUT: Final = 15.0
STATS_TIMEOUT: Final = 120.0  # a tracemalloc snapshot of a thousand connections takes a while
PY_SPY_RATE: Final = 250
CREDENTIALS: Final = (b"bench-user", b"bench-password")  # what the proxy accepts for username/password auth


def _pythonpath(installed: bool) -> str:
    """Puts this checkout's benchmarks package, and unless installed is set its simple_socks5, on the path."""
    paths = [str(ROOT)] if installed else [str(ROOT), str(ROOT / "src")]
    return os.pathsep.join(paths)


class Origins:
    """The origin servers, in a child process that exits with this one."""

    def __init__(self, python: str = sys.executable) -> None:
        self._process = subprocess.Popen(
            [python, "-m", "benchmarks.origins"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": _pythonpath(installed=True)},
        )
        assert self._process.stdout is not None
        ports = json.loads(self._process.stdout.readline())
        self.tcp = ("127.0.0.1", int(ports["tcp"]))
        self.udp_port = int(ports["udp"])

    def close(self) -> None:
        if self._process.stdin is not None:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()

    def __enter__(self) -> "Origins":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True)
class ProxySettings:
    python: str = sys.executable
    log_level: str = "disabled"
    env: dict[str, str] = field(default_factory=dict)
    variant: str = ""
    profile: str = ""  # "", "cprofile", "sample" or "py-spy"
    tracemalloc: bool = False
    installed: bool = False  # run the simple_socks5 the interpreter has installed, not this checkout's src/


@dataclass
class ProcessStats:
    cpu_s: float
    threads: int
    rss_kib: float
    vsz_kib: float
    traced_bytes: int | None = None
    top_allocations: list[str] = field(default_factory=list)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def interpreter_version(python: str) -> str:
    out = subprocess.run(
        [python, "-c", "import platform; print(platform.python_version())"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def _memory_kib(pid: int) -> tuple[float, float]:
    """Current resident and virtual size of pid, from /proc on Linux and ps elsewhere."""
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        fields = dict(line.split(":", 1) for line in status.read_text().splitlines() if ":" in line)
        return float(fields["VmRSS"].split()[0]), float(fields["VmSize"].split()[0])
    out = subprocess.run(["ps", "-o", "rss=,vsz=", "-p", str(pid)], capture_output=True, text=True, check=True)
    rss, vsz = out.stdout.split()
    return float(rss), float(vsz)


class Proxy:
    """The proxy under test, run by benchmarks.launcher in a child process."""

    def __init__(self, settings: ProxySettings, label: str, out_dir: Path) -> None:
        self.settings = settings
        self.label = label
        self.out_dir = out_dir
        self.port = free_port()
        self.address = ("127.0.0.1", self.port)
        self._py_spy: subprocess.Popen[bytes] | None = None
        env = {
            **os.environ,
            "PYTHONPATH": _pythonpath(settings.installed),
            "PYTHONUNBUFFERED": "1",
            # The origins listen on loopback, which the proxy refuses by default
            "SOCKS5_ALLOW_LOOPBACK": "true",
            "SOCKS5_MAX_CONNECTIONS": "5000",
            "SOCKS5_USERNAME": CREDENTIALS[0].decode(),
            "SOCKS5_PASSWORD": CREDENTIALS[1].decode(),
            "BENCH_OUT": str(out_dir),
            "BENCH_LABEL": label,
            "BENCH_VARIANT": settings.variant,
            "BENCH_PROFILE": settings.profile if settings.profile != "py-spy" else "",
            **settings.env,
        }
        env.pop("LOGGING_LEVEL", None)
        if settings.tracemalloc:
            env["BENCH_TRACEMALLOC"] = "1"
        self.log_path = out_dir / f"{label}.log"
        with self.log_path.open("wb") as log:
            self._process = subprocess.Popen(
                [
                    settings.python,
                    "-m",
                    "benchmarks.launcher",
                    "-H",
                    "127.0.0.1",
                    "-P",
                    str(self.port),
                    "-L",
                    settings.log_level,
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )
        try:
            self._wait_until_listening()
            if settings.profile == "py-spy":
                self._start_py_spy()
        except BaseException:
            self.stop()
            raise

    @property
    def pid(self) -> int:
        return self._process.pid

    def _wait_until_listening(self) -> None:
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError(f"the proxy exited with {self._process.returncode}: {self._log_tail()}")
            with contextlib.suppress(OSError), socket.create_connection(self.address, timeout=1):
                return
            time.sleep(0.05)
        raise RuntimeError(f"the proxy didn't listen within {START_TIMEOUT} s: {self._log_tail()}")

    def _log_tail(self) -> str:
        return " | ".join(self.log_path.read_text(errors="replace").splitlines()[-5:])

    def _start_py_spy(self) -> None:
        py_spy = shutil.which("py-spy")
        if py_spy is None:
            raise RuntimeError("py-spy isn't installed: pip install -e '.[dev]'")
        command = [py_spy, "record", "--threads", "--rate", str(PY_SPY_RATE), "--format", "raw"]
        command += ["--output", str(self.out_dir / f"{self.label}.py-spy.collapsed"), "--pid", str(self.pid)]
        command += os.environ.get("BENCH_PY_SPY_ARGS", "").split()  # e.g. "--gil" or "--native"
        self._py_spy = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(1.0)  # attaching takes a moment
        if self._py_spy.poll() is not None:
            assert self._py_spy.stderr is not None
            error = self._py_spy.stderr.read().decode(errors="replace").strip()
            raise RuntimeError(f"py-spy couldn't attach (on macOS it needs sudo): {error}")

    def stats(self) -> ProcessStats:
        """Signals the launcher for its CPU time, thread count and traced memory, and reads its memory use."""
        path = self.out_dir / f"stats-{self.pid}.json"
        path.unlink(missing_ok=True)
        self._process.send_signal(signal.SIGUSR1)
        deadline = time.monotonic() + STATS_TIMEOUT
        while not path.exists():
            if time.monotonic() > deadline:
                raise RuntimeError("the proxy didn't write its stats")
            time.sleep(0.02)
        data = json.loads(path.read_text())
        path.unlink()
        rss, vsz = _memory_kib(self.pid)
        return ProcessStats(
            cpu_s=float(data["cpu_s"]),
            threads=int(data["threads"]),
            rss_kib=rss,
            vsz_kib=vsz,
            traced_bytes=data.get("traced_bytes"),
            top_allocations=list(data.get("top_allocations", [])),
        )

    def stop(self) -> None:
        if self._py_spy is not None:
            self._py_spy.send_signal(signal.SIGINT)
            try:
                self._py_spy.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._py_spy.kill()
            self._summarize_py_spy()
        if self._process.poll() is None:
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

    def _summarize_py_spy(self) -> None:
        collapsed = self.out_dir / f"{self.label}.py-spy.collapsed"
        if not collapsed.exists():
            return
        counts = profiles.read_collapsed(collapsed)
        summary = profiles.summarize_collapsed(counts, "py-spy (CPU, all threads)")
        (self.out_dir / f"{self.label}.py-spy.json").write_text(json.dumps(summary, indent=1))
        profiles.write_summary_text(summary, self.out_dir / f"{self.label}.py-spy.txt")
        profiles.render_flamegraph(counts, self.out_dir / f"{self.label}.py-spy.svg", f"{self.label}: CPU, py-spy")

    def __enter__(self) -> "Proxy":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.stop()
