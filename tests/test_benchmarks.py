"""
Checks that the benchmark harness in benchmarks/ still runs every scenario, variant and profiler. It measures
nothing: --quick sizes are too small to mean anything, and timings on CI runners are too noisy to assert on.

Deselected by default; run with pytest -m bench.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.bench


def _bench(out: Path, *args: str) -> dict[str, list[dict[str, object]]]:
    result = subprocess.run(  # noqa: S603 - fixed argv built by the test
        [sys.executable, "-m", "benchmarks", *args, "--quick", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    results: dict[str, list[dict[str, object]]] = json.loads((out / "results.json").read_text())
    return results


def test_every_scenario_runs(tmp_path: Path) -> None:
    results = _bench(tmp_path, "all", "--pythons", sys.executable)

    scenarios = {row["scenario"] for row in results["rows"]}
    assert scenarios == {
        "bulk",
        "concurrency",
        "setup",
        "first-byte",
        "small-writes",
        "idle",
        "udp",
        "logging",
        "pythons",
    }
    assert all(row["metrics"] for row in results["rows"])


def test_candidates_and_profilers_run(tmp_path: Path) -> None:
    results = _bench(tmp_path, "bulk", "small-writes", "idle", "--candidates", "--profile", "sample", "--tracemalloc")

    paths = {row["path"] for row in results["rows"]}
    assert {"proxy+nodelay", "proxy+pumps", "proxy+stack=262144", "proxy+buf=262144"} <= paths
    assert list(tmp_path.glob("*.sample.svg"))


def test_cprofile_runs(tmp_path: Path) -> None:
    _bench(tmp_path, "setup", "--profile", "cprofile")

    summary = json.loads((tmp_path / "setup-proxy.cprofile.json").read_text())
    assert summary["categories"]


def test_compare_prints_both_runs(tmp_path: Path) -> None:
    _bench(tmp_path, "first-byte")
    results = tmp_path / "results.json"

    output = subprocess.run(  # noqa: S603 - fixed argv built by the test
        [sys.executable, "-m", "benchmarks", "compare", str(results), str(results)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    assert "| first-byte |" in output
    assert "+0.0%" in output
