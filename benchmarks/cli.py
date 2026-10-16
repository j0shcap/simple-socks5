"""
python -m benchmarks <scenario>... runs scenarios and prints a results table; python -m benchmarks compare A B
compares two results.json files; python -m benchmarks chart A draws a results.json file as SVG charts. See
benchmarks/README.md.
"""

import argparse
import contextlib
import dataclasses
import datetime
import json
import multiprocessing
import os
import platform
import resource
import shutil
import subprocess
import sys
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Final

from . import charts
from .client import warm_up
from .processes import ROOT, Origins, ProxySettings, interpreter_version
from .scenarios import SCENARIOS, Bench, Row, format_value

PROFILERS: Final = ("cprofile", "cprofile-cpu", "sample", "py-spy")
LOG_LEVELS: Final = ("disabled", "debug", "info", "warning", "error", "critical")
DEFAULT_PYTHONS: Final = ("3.10", "3.11", "3.12", "3.13", "3.14")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks",
        description="Benchmark the proxy against direct connections to local origin servers.",
        epilog="python -m benchmarks compare A.json B.json compares two runs.",
    )
    parser.add_argument(
        "scenarios",
        nargs="+",
        choices=[*SCENARIOS, "all"],
        metavar="scenario",
        help=f"one or more of: {', '.join(SCENARIOS)}, all",
    )
    parser.add_argument("--quick", action="store_true", help="tiny sizes: checks the harness runs, measures nothing")
    parser.add_argument(
        "--candidates",
        action="store_true",
        help="also run each scenario's optimization candidates (see benchmarks/variants.py)",
    )
    parser.add_argument(
        "--variant",
        action="append",
        default=[],
        metavar="SPEC",
        help="also run the proxy with this variant, e.g. nodelay or pumps+buf=262144 (repeatable)",
    )
    parser.add_argument(
        "-L",
        "--logging-level",
        default="info",
        choices=LOG_LEVELS,
        help="the proxy's log level (default: info, as in the Docker image)",
    )
    parser.add_argument(
        "--env", action="append", default=[], metavar="NAME=VALUE", help="extra environment for the proxy (repeatable)"
    )
    parser.add_argument("--python", default=sys.executable, help="interpreter that runs the proxy")
    parser.add_argument(
        "--pythons",
        default=",".join(DEFAULT_PYTHONS),
        help="interpreters for the pythons scenario: paths or versions found on PATH or by uv",
    )
    parser.add_argument(
        "--installed",
        action="store_true",
        help="run the simple_socks5 installed for --python instead of this checkout's src/",
    )
    parser.add_argument(
        "--repeat", type=int, default=3, help="run each measurement this many times and keep the median (default: 3)"
    )
    parser.add_argument("--profile", choices=PROFILERS, help="profile every proxy the scenarios start")
    parser.add_argument("--tracemalloc", action="store_true", help="trace the proxy's allocations (idle scenario)")
    parser.add_argument(
        "--workers", type=int, default=min(4, os.cpu_count() or 1), help="load-generating processes (default: up to 4)"
    )
    parser.add_argument("--out", type=Path, help="directory for results.json, logs and profiles")
    parser.add_argument("--json", type=Path, help="also write the results to this file")
    return parser


def _find_python(spec: str) -> str | None:
    if os.sep in spec:
        return spec if Path(spec).exists() else None
    found = shutil.which(f"python{spec}")
    if found:
        return found
    uv = shutil.which("uv")
    if uv:
        result = subprocess.run([uv, "python", "find", spec], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return None


def _environment(settings: ProxySettings, workers: int, repeat: int) -> dict[str, object]:
    commit = None
    with contextlib.suppress(OSError, subprocess.CalledProcessError):
        commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    return {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "in_container": Path("/.dockerenv").exists(),
        "harness_python": platform.python_version(),
        "proxy_python": interpreter_version(settings.python),
        "proxy_log_level": settings.log_level,
        "proxy_env": settings.env,
        "workers": workers,
        "repeat": repeat,
        "commit": commit,
    }


def _raise_file_limit() -> None:
    """The idle scenario holds a thousand connections; the proxy and origins inherit the limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
    if soft != resource.RLIM_INFINITY and soft < want:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))


def run(argv: Sequence[str]) -> int:
    args = _parser().parse_args(argv)
    names = list(SCENARIOS) if "all" in args.scenarios else list(dict.fromkeys(args.scenarios))
    env = dict(item.split("=", 1) for item in args.env)
    settings = ProxySettings(
        python=args.python,
        log_level=args.logging_level,
        env=env,
        profile=args.profile or "",
        tracemalloc=args.tracemalloc,
        installed=args.installed,
    )
    pythons = []
    if "pythons" in names:
        for spec in args.pythons.split(","):
            found = _find_python(spec.strip())
            if found is None:
                print(f"skipping Python {spec}: not found", file=sys.stderr)
            else:
                pythons.append(found)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = args.out or ROOT / "benchmarks" / "results" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    _raise_file_limit()

    environment = _environment(settings, args.workers, args.repeat)
    print(_describe_environment(environment), flush=True)
    context = multiprocessing.get_context("spawn")
    with Origins() as origins, ProcessPoolExecutor(args.workers, mp_context=context) as pool:
        for future in [pool.submit(warm_up) for _ in range(args.workers)]:
            future.result()
        bench = Bench(
            settings,
            args.variant,
            args.candidates,
            args.quick,
            args.workers,
            out_dir,
            origins,
            pool,
            pythons,
            repeat=1 if args.quick else args.repeat,
        )
        for name in names:
            print(f"\n{name}: {_summary(name)}", flush=True)
            SCENARIOS[name](bench)

    results = {"environment": environment, "rows": [dataclasses.asdict(row) for row in bench.rows]}
    (out_dir / "results.json").write_text(json.dumps(results, indent=1))
    if args.json:
        args.json.write_text(json.dumps(results, indent=1))
    print()
    print(render_tables(bench.rows))
    print(f"\nResults, logs and profiles: {out_dir}")
    if args.profile:
        print(_profile_index(out_dir))
    errors = sum(int(row.metrics.get("errors", 0)) for row in bench.rows)
    if errors:
        print(f"\n{errors} operation(s) failed; see the proxy logs in {out_dir}", file=sys.stderr)
    return 1 if errors else 0


def _describe_environment(environment: dict[str, object]) -> str:
    return (
        f"{environment['platform']} ({environment['cpus']} CPUs{', container' if environment['in_container'] else ''})"
        f", proxy on Python {environment['proxy_python']} -L {environment['proxy_log_level']}"
        f", harness on Python {environment['harness_python']}, {environment['workers']} load processes"
    )


def _profile_index(out_dir: Path) -> str:
    lines = ["\nProfile summaries (share of time by category):"]
    for path in sorted(out_dir.glob("*.json")):
        if path.name == "results.json" or path.name.startswith("stats-"):
            continue
        summary = json.loads(path.read_text())
        categories = summary.get("categories", {})
        top = ", ".join(f"{name} {pct:.0f}%" for name, pct in list(categories.items())[:4])
        lines.append(f"  {path.stem}: {top}")
    return "\n".join(lines)


def render_tables(rows: list[Row]) -> str:
    """One Markdown table per scenario, with each proxy row's primary metric relative to the direct row."""
    blocks = []
    for scenario in dict.fromkeys(row.scenario for row in rows):
        group = [row for row in rows if row.scenario == scenario]
        columns = list(dict.fromkeys(name for row in group for name in row.metrics if name != "errors"))
        if any(row.metrics.get("errors") for row in group):
            columns.append("errors")
        direct = {row.case: row for row in group if row.path == "direct"}
        has_direct = bool(direct)
        header = ["case", "path", *columns] + (["vs direct"] if has_direct else [])
        lines = [f"### {scenario}", "", _md(header), _md(["---"] * 2 + ["--:"] * (len(header) - 2))]
        for row in group:
            cells = [row.case, row.path] + [format_value(row.metrics.get(c, float("nan"))) for c in columns]
            if has_direct:
                cells.append(_relative(row, direct.get(row.case)))
            lines.append(_md(cells))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _relative(row: Row, direct: Row | None) -> str:
    if direct is None or row is direct:
        return ""
    ours, theirs = row.metrics.get(row.primary), direct.metrics.get(row.primary)
    if not ours or not theirs:
        return ""
    return f"{ours / theirs:.2f}x"


def _md(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def compare(argv: Sequence[str]) -> int:
    """Prints each row's primary metric in two results files side by side, and optionally charts them."""
    parser = argparse.ArgumentParser(prog="python -m benchmarks compare")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--chart", type=Path, metavar="FILE.svg", help="also write a before/after chart")
    args = parser.parse_args(argv)
    baseline, candidate = _rows(args.baseline), _rows(args.candidate)
    before = {row.key: row for row in baseline}
    lines = [
        _md(["scenario", "case", "path", "metric", "baseline", "candidate", "change"]),
        _md(["---"] * 4 + ["--:"] * 3),
    ]
    for row in candidate:
        old_row = before.get(row.key)
        if old_row is None:
            continue
        metric = row.primary
        old, new = old_row.metrics.get(metric), row.metrics.get(metric)
        change = f"{100 * (new - old) / old:+.1f}%" if old and new is not None else ""
        lines.append(_md([row.scenario, row.case, row.path, metric, format_value(old), format_value(new), change]))
    print("\n".join(lines))
    if args.chart:
        names = (args.baseline.stem, args.candidate.stem)
        if names[0] == names[1]:
            names = ("baseline", "candidate")
        _write(args.chart, charts.before_after(baseline, candidate, names))
    return 0


def chart(argv: Sequence[str]) -> int:
    """Writes an SVG chart per scenario in a results file, plus the scaling curve of the concurrency scenario."""
    parser = argparse.ArgumentParser(prog="python -m benchmarks chart")
    parser.add_argument("results", type=Path)
    parser.add_argument("--out", type=Path, help="directory for the SVGs (default: the results file's)")
    args = parser.parse_args(argv)
    out_dir = args.out or args.results.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = _rows(args.results)
    for scenario in dict.fromkeys(row.scenario for row in rows):
        group = [row for row in rows if row.scenario == scenario]
        _write(out_dir / f"{scenario}.svg", charts.bars(group, f"{scenario}: {_summary(scenario)}"))
        if scenario == "concurrency":
            _write(out_dir / "concurrency-scaling.svg", charts.scaling(group))
    return 0


def _summary(scenario: str) -> str:
    return (SCENARIOS[scenario].__doc__ or "").strip().splitlines()[0]


def _rows(results: Path) -> list[Row]:
    return [Row(**row) for row in json.loads(results.read_text())["rows"]]


def _write(path: Path, svg: str) -> None:
    path.write_text(svg)
    print(path)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["compare"]:
        return compare(argv[1:])
    if argv[:1] == ["chart"]:
        return chart(argv[1:])
    return run(argv)
