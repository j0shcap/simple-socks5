"""
The benchmark scenarios. Each runs its cases directly against the origin and through the proxy, so the proxy's
overhead is visible, and appends one Row per case and path.
"""

import contextlib
import math
import statistics
import sys
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final

from .client import Job, JobResult, Route, open_stream, run_job
from .origins import COMMAND
from .processes import CREDENTIALS, Origins, Proxy, ProxySettings, interpreter_version

MIB: Final = 1 << 20
GIB: Final = 1 << 30
SMALL_RESPONSE: Final = 100  # bytes, about an HTTP redirect or API error
DNS_QUERY: Final = 64  # bytes of UDP payload, about a DNS query
ROUND_TRIP_MESSAGE: Final = 512  # bytes per small request and answer, each sent in two writes


@dataclass
class Row:
    scenario: str
    case: str
    path: str  # "direct", "proxy", or "proxy" plus what differs from the default proxy
    metrics: dict[str, float]
    primary: str  # the metric the "vs direct" column compares
    notes: list[str] = field(default_factory=list)


@dataclass
class Bench:
    """What every scenario needs: settings, the origins, the load-generator pool and the rows so far."""

    proxy: ProxySettings
    variants: list[str]
    candidates: bool
    quick: bool
    workers: int
    out_dir: Path
    origins: Origins
    pool: ProcessPoolExecutor
    pythons: list[str]
    repeat: int = 1
    rows: list[Row] = field(default_factory=list)
    _errors: list[str] = field(default_factory=list)

    def size(self, normal: int, quick: int) -> int:
        return quick if self.quick else normal

    def add(self, row: Row) -> None:
        """Records row, with the first few distinct errors of the runs since the last row."""
        row.notes += sorted(set(self._errors))[:3]
        self._errors.clear()
        self.rows.append(row)
        print(f"  {row.scenario:<12} {row.case:<34} {row.path:<28} {format_metrics(row.metrics)}", flush=True)
        for note in row.notes:
            print(f"      {note}", flush=True)

    @contextlib.contextmanager
    def proxy_for(self, label: str, settings: ProxySettings | None = None) -> Iterator[Proxy]:
        with Proxy(settings or self.proxy, label, self.out_dir) as proxy:
            yield proxy

    def proxies(self, scenario: str, candidates: tuple[str, ...] = ()) -> Iterator[tuple[str, Proxy]]:
        """The default proxy, then one per --variant and (with --candidates) per candidate of this scenario."""
        variants = [*self.variants, *(candidates if self.candidates else ())]
        for variant in ["", *dict.fromkeys(variants)]:
            if variant == "splice" and sys.platform != "linux":
                continue
            settings = replace(self.proxy, variant=variant)
            path = f"proxy+{variant}" if variant else "proxy"
            with self.proxy_for(f"{scenario}-{path}", settings) as proxy:
                yield path, proxy

    def run(  # noqa: PLR0913 - the keyword-only knobs of one load
        self,
        op: str,
        route: Route,
        *,
        size: int,
        concurrency: int,
        count: int,
        proxy: Proxy | None,
    ) -> "Measurement":
        """
        Runs op count times on each of concurrency threads, spread over the worker processes, --repeat times.
        Returns the run with the median wall time.
        """
        processes = min(self.workers, concurrency)
        runs = []
        for _ in range(self.repeat):
            start_at = time.perf_counter() + 0.3
            jobs = [
                Job(op, route, size, count, concurrency // processes + (i < concurrency % processes), start_at)
                for i in range(processes)
            ]
            jobs = [replace(job, udp_port=self.origins.udp_port) for job in jobs]
            before = proxy.stats() if proxy else None
            results = list(self.pool.map(run_job, jobs))
            after = proxy.stats() if proxy else None
            self._errors += [e for r in results for e in r.errors]
            runs.append(Measurement(results, before.cpu_s if before else None, after.cpu_s if after else None))
        return sorted(runs, key=lambda m: m.wall)[len(runs) // 2]


@dataclass
class Measurement:
    results: list[JobResult]
    cpu_before: float | None
    cpu_after: float | None

    @property
    def wall(self) -> float:
        return max(r.ended for r in self.results) - min(r.started for r in self.results)

    @property
    def nbytes(self) -> int:
        return sum(r.nbytes for r in self.results)

    @property
    def latencies(self) -> list[float]:
        return [latency for r in self.results for latency in r.latencies]

    @property
    def marks(self) -> list[list[float]]:
        return [m for r in self.results for m in r.marks]

    @property
    def errors(self) -> list[str]:
        return [e for r in self.results for e in r.errors]

    def common(self) -> dict[str, float]:
        """Proxy CPU (100% is one core busy for the whole run) and errors, for every row."""
        metrics: dict[str, float] = {}
        if self.cpu_before is not None and self.cpu_after is not None:
            metrics["proxy CPU %"] = 100 * (self.cpu_after - self.cpu_before) / self.wall
        metrics["errors"] = len(self.errors)
        return metrics


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile."""
    if not values:
        return math.nan
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(pct / 100 * len(ordered)) - 1))]


def latency_metrics(latencies: list[float]) -> dict[str, float]:
    return {
        "p50 ms": 1000 * percentile(latencies, 50),
        "p95 ms": 1000 * percentile(latencies, 95),
        "p99 ms": 1000 * percentile(latencies, 99),
    }


def format_metrics(metrics: dict[str, float]) -> str:
    return "  ".join(f"{name} {format_value(value)}" for name, value in metrics.items())


def format_value(value: float | None) -> str:
    if value is None or math.isnan(value):
        return "-"
    if value == int(value):
        return f"{int(value):,}"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    if abs(value) >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def _human(n: int) -> str:
    if n >= GIB:
        return f"{n / GIB:.3g} GiB"
    return f"{n / MIB:.3g} MiB" if n >= MIB else f"{n:,} B"


def _paths(bench: Bench, scenario: str, candidates: tuple[str, ...] = ()) -> Iterator[tuple[str, Proxy | None]]:
    yield "direct", None
    yield from bench.proxies(scenario, candidates)


def _route(bench: Bench, proxy: Proxy | None) -> Route:
    return Route(bench.origins.tcp, proxy.address if proxy else None)


def bulk(bench: Bench) -> None:
    """Single-stream throughput, download then upload."""
    size = bench.size(GIB, 16 * MIB)
    for path, proxy in _paths(
        bench,
        "bulk",
        ("buf=16384", "buf=262144", "buf=1048576", "recv_into", "blocking", "blocking+recv_into", "pumps", "splice"),
    ):
        for op in ("download", "upload"):
            m = bench.run(op, _route(bench, proxy), size=size, concurrency=1, count=1, proxy=proxy)
            metrics = {"MB/s": m.nbytes / m.wall / 1e6, **m.common()}
            bench.add(Row("bulk", f"{op} {_human(size)}, 1 stream", path, metrics, "MB/s"))


def concurrency(bench: Bench) -> None:
    """Aggregate download throughput at 1/10/50/200 connections, the same total bytes at each level."""
    total = bench.size(2 * GIB, 32 * MIB)
    levels = (1, 4) if bench.quick else (1, 10, 50, 200)
    for path, proxy in _paths(bench, "concurrency", ("buf=262144", "blocking+recv_into", "pumps")):
        for level in levels:
            m = bench.run(
                "download", _route(bench, proxy), size=total // level, concurrency=level, count=1, proxy=proxy
            )
            metrics = {"MB/s": m.nbytes / m.wall / 1e6, "p50 ms": 1000 * percentile(m.latencies, 50), **m.common()}
            bench.add(Row("concurrency", f"{level} x {_human(total // level)}", path, metrics, "MB/s"))


def setup(bench: Bench) -> None:
    """Connection setup: a fresh connection per 100-byte response, without and with auth, by IP and by hostname."""
    cases = ((1, bench.size(500, 30)), (50, bench.size(5000, 200)))
    for path, proxy in _paths(bench, "setup"):
        routes = [("", _route(bench, proxy))]
        if proxy is not None:
            routes += [
                (" +auth", Route(bench.origins.tcp, proxy.address, CREDENTIALS)),
                (" +hostname", Route(bench.origins.tcp, proxy.address, hostname="localhost")),
            ]
        for suffix, route in routes:
            for level, requests in cases:
                m = bench.run(
                    "download", route, size=SMALL_RESPONSE, concurrency=level, count=requests // level, proxy=proxy
                )
                metrics = {"req/s": len(m.latencies) / m.wall, **latency_metrics(m.latencies), **m.common()}
                bench.add(Row("setup", f"{requests} requests, c={level}", path + suffix, metrics, "req/s"))


def first_byte(bench: Bench) -> None:
    """Time to first byte on a fresh connection, split into TCP connect, method reply and CONNECT reply."""
    requests = bench.size(300, 20)
    for path, proxy in _paths(bench, "first-byte"):
        m = bench.run(
            "first_byte", _route(bench, proxy), size=SMALL_RESPONSE, concurrency=1, count=requests, proxy=proxy
        )
        marks = m.marks
        metrics = {"TTFB p50 ms": 1000 * percentile([mk[-2] - mk[0] for mk in marks], 50)}
        metrics["TTFB p99 ms"] = 1000 * percentile([mk[-2] - mk[0] for mk in marks], 99)
        metrics["connect ms"] = 1000 * statistics.median(mk[1] - mk[0] for mk in marks)
        if proxy is not None:
            metrics["method reply ms"] = 1000 * statistics.median(mk[2] - mk[1] for mk in marks)
            metrics["CONNECT reply ms"] = 1000 * statistics.median(mk[3] - mk[2] for mk in marks)
        metrics["first byte ms"] = 1000 * statistics.median(mk[-2] - mk[-3] for mk in marks)
        metrics |= m.common()
        bench.add(Row("first-byte", f"{requests} sequential connections", path, metrics, "TTFB p50 ms"))


def small_writes(bench: Bench) -> None:
    """
    Request/response round trips over one connection where each message is written in two parts, which is where
    Nagle's algorithm on the proxy's sockets would add delay.
    """
    count = bench.size(300, 30)
    for path, proxy in _paths(bench, "small-writes", ("nodelay",)):
        m = bench.run(
            "round_trips", _route(bench, proxy), size=ROUND_TRIP_MESSAGE, concurrency=1, count=count, proxy=proxy
        )
        metrics = {"round trips/s": len(m.latencies) / m.wall, **latency_metrics(m.latencies)}
        metrics["max ms"] = 1000 * max(m.latencies, default=math.nan)
        metrics |= m.common()
        bench.add(Row("small-writes", f"{count} x {ROUND_TRIP_MESSAGE} B in 2 writes", path, metrics, "p50 ms"))


def idle(bench: Bench) -> None:
    """Memory and threads for established connections that carry no data."""
    levels = (10, 50) if bench.quick else (100, 1000)
    for path, proxy in bench.proxies("idle", ("stack=262144", "no_makefile", "pumps")):
        for level in levels:
            baseline = proxy.stats()
            sockets = []
            try:
                for _ in range(level):
                    sock = open_stream(_route(bench, proxy))
                    sock.sendall(COMMAND.pack(b"H", 0))
                    sockets.append(sock)
                time.sleep(1.0)
                loaded = proxy.stats()
            finally:
                for sock in sockets:
                    sock.close()
            metrics = {
                "RSS MiB": loaded.rss_kib / 1024,
                "RSS KiB/conn": (loaded.rss_kib - baseline.rss_kib) / level,
                "VSZ KiB/conn": (loaded.vsz_kib - baseline.vsz_kib) / level,
                "threads": loaded.threads,
                "threads/conn": (loaded.threads - baseline.threads) / level,
            }
            notes = []
            if loaded.traced_bytes is not None and baseline.traced_bytes is not None:
                metrics["traced KiB/conn"] = (loaded.traced_bytes - baseline.traced_bytes) / 1024 / level
                notes = loaded.top_allocations
            bench.add(Row("idle", f"{level} idle connections", path, metrics, "RSS KiB/conn", notes))
            _wait_for_threads(proxy, baseline.threads)


def _wait_for_threads(proxy: Proxy, threads: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while proxy.stats().threads > threads and time.monotonic() < deadline:
        time.sleep(0.1)


def udp(bench: Bench) -> None:
    """DNS-sized datagram round trips through a UDP association, one after another."""
    cases = ((1, bench.size(3000, 30)), (8, bench.size(500, 10)))
    for path, proxy in _paths(bench, "udp"):
        for level, count in cases:
            m = bench.run("udp", _route(bench, proxy), size=DNS_QUERY, concurrency=level, count=count, proxy=proxy)
            metrics = {"round trips/s": len(m.latencies) / m.wall, **latency_metrics(m.latencies), **m.common()}
            bench.add(Row("udp", f"{level} x {count} x {DNS_QUERY} B", path, metrics, "round trips/s"))


def logging(bench: Bench) -> None:
    """Connection setup and bulk throughput at log levels disabled, info and debug."""
    requests, total = bench.size(5000, 200), bench.size(GIB, 16 * MIB)
    direct = _route(bench, None)
    m = bench.run("download", direct, size=SMALL_RESPONSE, concurrency=50, count=requests // 50, proxy=None)
    bench.add(Row("logging", f"{requests} requests, c=50", "direct", {"req/s": len(m.latencies) / m.wall}, "req/s"))
    m = bench.run("download", direct, size=total // 10, concurrency=10, count=1, proxy=None)
    bench.add(Row("logging", f"10 x {_human(total // 10)}", "direct", {"MB/s": m.nbytes / m.wall / 1e6}, "MB/s"))
    for level in ("disabled", "info", "debug"):
        settings = replace(bench.proxy, log_level=level)
        with bench.proxy_for(f"logging-{level}", settings) as proxy:
            route = _route(bench, proxy)
            log_before = proxy.log_path.stat().st_size
            m = bench.run("download", route, size=SMALL_RESPONSE, concurrency=50, count=requests // 50, proxy=proxy)
            metrics = {"req/s": len(m.latencies) / m.wall, **latency_metrics(m.latencies), **m.common()}
            metrics["log B/conn"] = (proxy.log_path.stat().st_size - log_before) / (requests * bench.repeat)
            bench.add(Row("logging", f"{requests} requests, c=50", f"proxy -L {level}", metrics, "req/s"))
            m = bench.run("download", route, size=total // 10, concurrency=10, count=1, proxy=proxy)
            metrics = {"MB/s": m.nbytes / m.wall / 1e6, **m.common()}
            bench.add(Row("logging", f"10 x {_human(total // 10)}", f"proxy -L {level}", metrics, "MB/s"))


def pythons(bench: Bench) -> None:
    """Bulk, concurrent and setup throughput of the proxy on each interpreter given with --pythons."""
    size, requests = bench.size(GIB, 16 * MIB), bench.size(5000, 200)
    cases: list[tuple[str, Callable[[Route, Proxy | None], Row]]] = []

    def single(route: Route, proxy: Proxy | None) -> Row:
        m = bench.run("download", route, size=size, concurrency=1, count=1, proxy=proxy)
        return Row(
            "pythons", f"download {_human(size)}, 1 stream", "", {"MB/s": m.nbytes / m.wall / 1e6, **m.common()}, "MB/s"
        )

    def parallel(route: Route, proxy: Proxy | None) -> Row:
        m = bench.run("download", route, size=size // 50, concurrency=50, count=1, proxy=proxy)
        return Row("pythons", f"50 x {_human(size // 50)}", "", {"MB/s": m.nbytes / m.wall / 1e6, **m.common()}, "MB/s")

    def connections(route: Route, proxy: Proxy | None) -> Row:
        m = bench.run("download", route, size=SMALL_RESPONSE, concurrency=50, count=requests // 50, proxy=proxy)
        metrics = {"req/s": len(m.latencies) / m.wall, **latency_metrics(m.latencies), **m.common()}
        return Row("pythons", f"{requests} requests, c=50", "", metrics, "req/s")

    cases = [("single", single), ("parallel", parallel), ("setup", connections)]
    for _, case in cases:
        bench.add(replace(case(_route(bench, None), None), path="direct"))
    for python in bench.pythons:
        version = interpreter_version(python)
        settings = replace(bench.proxy, python=python)
        with bench.proxy_for(f"pythons-{version}", settings) as proxy:
            for _, case in cases:
                bench.add(replace(case(_route(bench, proxy), proxy), path=f"proxy on {version}"))


SCENARIOS: Final[dict[str, Callable[[Bench], None]]] = {
    "bulk": bulk,
    "concurrency": concurrency,
    "setup": setup,
    "first-byte": first_byte,
    "small-writes": small_writes,
    "idle": idle,
    "udp": udp,
    "logging": logging,
    "pythons": pythons,
}
