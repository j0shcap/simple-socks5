"""
Runs the proxy for a benchmark: python -m benchmarks.launcher <simple-socks5 arguments>.

Before handing over to simple_socks5.main.cli() it applies BENCH_VARIANT (see variants.py), starts the profiler
BENCH_PROFILE names (cprofile, cprofile-cpu or sample), and starts tracemalloc if BENCH_TRACEMALLOC is set.
SIGUSR1 writes the process's CPU time, thread count and traced memory to BENCH_OUT/stats-<pid>.json. Profiles are
written to BENCH_OUT as BENCH_LABEL.* once the proxy exits on SIGTERM.
"""

import cProfile
import json
import os
import pstats
import resource
import signal
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from types import FrameType
from typing import Final

from . import profiles, variants

TRACEMALLOC_FRAMES: Final = 8


class _CProfiler:
    """
    One profiler per thread before Python 3.12, one for the process from 3.12 (see profiles.py).

    By default it times wall-clock time, so a call is charged for the time its thread waits to get the GIL back.
    With cpu, each thread's profiler times that thread's CPU time instead, which only works per thread.
    """

    def __init__(self, cpu: bool) -> None:
        self._profiles: list[cProfile.Profile] = []
        self._lock = threading.Lock()
        self._process_wide = sys.version_info >= (3, 12)
        self._cpu = cpu
        if cpu and self._process_wide:
            sys.exit("--profile cprofile-cpu needs the proxy on Python 3.10 or 3.11, e.g. --python python3.11")
        if not self._process_wide:
            run = threading.Thread.run
            add = self._add
            new = self._new

            def profiled_run(thread: threading.Thread) -> None:
                profile = new()
                add(profile)
                profile.enable()
                try:
                    run(thread)
                finally:
                    profile.disable()

            threading.Thread.run = profiled_run  # type: ignore[method-assign,assignment]
        self._main = self._new()
        self._add(self._main)
        self._main.enable()

    def _new(self) -> cProfile.Profile:
        return cProfile.Profile(time.thread_time_ns, 1e-9) if self._cpu else cProfile.Profile()

    def _add(self, profile: cProfile.Profile) -> None:
        with self._lock:
            self._profiles.append(profile)

    def finish(self, out: Path, label: str) -> None:
        self._main.disable()
        with self._lock:
            profiles_ = list(self._profiles)
        stats = pstats.Stats(profiles_[0])
        for profile in profiles_[1:]:
            # A thread still running has a profile that is still enabled; its counts so far are kept
            stats.add(profile)
        kind = "cprofile-cpu" if self._cpu else "cprofile"
        stats.dump_stats(out / f"{label}.{kind}.prof")
        summary = profiles.summarize_pstats(stats, "cProfile (CPU time)" if self._cpu else "cProfile (wall clock)")
        summary["python"] = sys.version.split()[0]
        summary["process_wide"] = self._process_wide
        (out / f"{label}.{kind}.json").write_text(json.dumps(summary, indent=1))
        profiles.write_summary_text(summary, out / f"{label}.{kind}.txt")


class _SampleProfiler:
    def __init__(self) -> None:
        self._sampler = profiles.Sampler()
        self._sampler.start()

    def finish(self, out: Path, label: str) -> None:
        counts = self._sampler.stop()
        profiles.write_collapsed(counts, out / f"{label}.sample.collapsed")
        summary = profiles.summarize_collapsed(counts, "stdlib sampler (wall clock, all threads)")
        (out / f"{label}.sample.json").write_text(json.dumps(summary, indent=1))
        profiles.write_summary_text(summary, out / f"{label}.sample.txt")
        profiles.render_flamegraph(counts, out / f"{label}.sample.svg", f"{label}: wall clock, all threads")


def _write_stats(out: Path) -> None:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    stats: dict[str, object] = {
        "cpu_s": usage.ru_utime + usage.ru_stime,
        "threads": threading.active_count(),
        "maxrss": usage.ru_maxrss,  # KiB on Linux, bytes on macOS
    }
    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        top = tracemalloc.take_snapshot().statistics("lineno")[:10]
        stats |= {
            "traced_bytes": current,
            "traced_peak_bytes": peak,
            "top_allocations": [f"{stat.size / 1024:.0f} KiB in {stat.count} blocks: {stat.traceback}" for stat in top],
        }
    path = out / f"stats-{os.getpid()}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(stats))
    tmp.replace(path)


def main() -> None:
    out = Path(os.environ["BENCH_OUT"])
    label = os.environ.get("BENCH_LABEL", "proxy")
    variants.apply(os.environ.get("BENCH_VARIANT", ""))
    if os.environ.get("BENCH_TRACEMALLOC"):
        tracemalloc.start(TRACEMALLOC_FRAMES)

    def on_usr1(_signum: int, _frame: FrameType | None) -> None:
        _write_stats(out)

    signal.signal(signal.SIGUSR1, on_usr1)

    kind = os.environ.get("BENCH_PROFILE", "")
    profiler: _CProfiler | _SampleProfiler | None = None
    if kind in {"cprofile", "cprofile-cpu"}:
        profiler = _CProfiler(cpu=kind == "cprofile-cpu")
    elif kind == "sample":
        profiler = _SampleProfiler()

    from simple_socks5.main import cli  # noqa: PLC0415 - after the profiler starts, so start-up is profiled too

    try:
        cli(sys.argv[1:])
    finally:
        if profiler is not None:
            profiler.finish(out, label)


if __name__ == "__main__":
    main()
