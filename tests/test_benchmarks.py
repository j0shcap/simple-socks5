"""
Checks that the benchmark harness in benchmarks/ still runs every scenario, variant and profiler. It measures
nothing: --quick sizes are too small to mean anything, and timings on CI runners are too noisy to assert on.

Deselected by default; run with pytest -m bench.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

import pytest

import simple_socks5.main
from benchmarks import profiles, variants
from simple_socks5.relays import tcp_relay
from simple_socks5.relays.tcp_relay import TCPRelay

ROOT = Path(__file__).resolve().parents[1]
SVG = "{http://www.w3.org/2000/svg}"

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
    assert {"proxy+recv_into", "proxy+stack=262144", "proxy+buf=65536"} <= paths
    assert list(tmp_path.glob("*.sample.svg"))


def test_buf_variant_fixes_the_relay_read_size() -> None:
    module = vars(tcp_relay)
    with patch.dict(module):
        variants.apply("buf=16384")

        assert (module["RELAY_INITIAL_BUFFER_SIZE"], module["RELAY_BUFFER_SIZE"]) == (16384, 16384)


def test_stack_variant_replaces_the_stack_size_main_sets() -> None:
    with patch.dict(vars(simple_socks5.main)):
        variants.apply("stack=262144")

        assert vars(simple_socks5.main)["THREAD_STACK_SIZE"] == 262144


def test_copy_variants_replace_only_how_the_relay_moves_a_chunk() -> None:
    for name in ("recv_into", "splice") if sys.platform == "linux" else ("recv_into",):
        with patch.object(TCPRelay, "_move", TCPRelay._move), patch.object(TCPRelay, "_cleanup", TCPRelay._cleanup):
            move, pump = TCPRelay._move, TCPRelay._pump
            variants.apply(name)

            assert TCPRelay._move is not move
            assert TCPRelay._pump is pump


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


def _benchmarks(*args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed argv built by the test
        [sys.executable, "-m", "benchmarks", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def _root(svg: Path) -> ElementTree.Element:
    return ElementTree.parse(svg).getroot()  # noqa: S314 - an SVG the harness just wrote


def _texts(svg: Path) -> list[str]:
    """The visible text of an SVG, after checking it parses and starts with an opaque background."""
    root = _root(svg)
    assert root.tag == f"{SVG}svg"
    background = root[0]
    assert background.tag == f"{SVG}rect"
    assert background.get("width") == "100%"
    return ["".join(element.itertext()) for element in root.iter(f"{SVG}text")]


@pytest.fixture(scope="module")
def quick_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("quick")
    _bench(out, "first-byte", "small-writes", "concurrency", "--variant", "buf=65536")
    return out / "results.json"


def test_chart_writes_an_svg_per_scenario(quick_run: Path, tmp_path: Path) -> None:
    _benchmarks("chart", str(quick_run), "--out", str(tmp_path))

    for scenario in ("first-byte", "small-writes", "concurrency"):
        texts = _texts(tmp_path / f"{scenario}.svg")
        assert texts[0] == scenario
        assert texts[1].endswith("."), "the subtitle is the docstring's whole first paragraph"
        assert {"direct", "proxy", "proxy+buf=65536"} <= set(texts)
        assert any(text.endswith((" ms", " MB/s")) for text in texts)


def test_chart_marks_lower_is_better(tmp_path: Path) -> None:
    rows = [
        {
            "scenario": "small-writes",
            "case": "300 x 512 B",
            "path": path,
            "metrics": {"p50 ms": p50},
            "primary": "p50 ms",
            "notes": [],
        }
        for path, p50 in (("direct", 1.43), ("proxy", 85.5), ("proxy+buf=65536", 1.9))
    ]
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"environment": {}, "rows": rows}))

    _benchmarks("chart", str(results), "--out", str(tmp_path))

    texts = _texts(tmp_path / "small-writes.svg")
    assert "\N{MULTIPLICATION SIGN}45.0 vs proxy" in texts
    assert "lower is better" in " ".join(texts)


def test_concurrency_scaling_chart(quick_run: Path, tmp_path: Path) -> None:
    _benchmarks("chart", str(quick_run), "--out", str(tmp_path))

    svg = tmp_path / "concurrency-scaling.svg"
    texts = _texts(svg)
    assert len(list(_root(svg).iter(f"{SVG}polyline"))) == 3
    assert {"1", "4"} <= set(texts)
    assert {"direct", "proxy", "proxy+buf=65536"} <= set(texts)


def test_compare_chart(quick_run: Path, tmp_path: Path) -> None:
    results = json.loads(quick_run.read_text())
    dropped = results["rows"].pop()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(results))
    chart = tmp_path / "before-after.svg"

    _benchmarks("compare", str(baseline), str(quick_run), "--chart", str(chart))

    texts = _texts(chart)
    assert texts.count("+0.0%") == len(results["rows"])
    assert f"{dropped['scenario']} · {dropped['case']} · {dropped['path']}" not in texts


def test_flamegraph_trims_and_has_legend(tmp_path: Path) -> None:
    counts = {
        "run (worker.py:1);sock_sendall (socket.py:2)": 600,
        "run (worker.py:1);emit (logging/__init__.py:3)": 399,
        "run (worker.py:1);rare (simple_socks5/relays.py:4)": 1,
    }
    svg = tmp_path / "flame.svg"

    profiles.render_flamegraph(counts, svg, "test")

    texts = _texts(svg)
    assert not any("rare" in text for text in texts)
    assert {"socket data I/O", "logging", "other"} <= set(texts)
    assert "relay loop (Python)" not in texts


def test_flamegraph_truncates_labels_before_escaping(tmp_path: Path) -> None:
    # At this width the <module> frame's label is cut where escaping first would split "&lt;" into "&l.."
    counts = {"<module> (main.py:1)": 1, "serve_forever (socketserver.py:2)": 1}
    svg = tmp_path / "flame.svg"

    profiles.render_flamegraph(counts, svg, "test", width=61)

    assert "<m.." in _texts(svg)


def test_read_collapsed_merges_threads_by_name(tmp_path: Path) -> None:
    collapsed = tmp_path / "stacks.collapsed"
    collapsed.write_text(
        "thread (11): Thread-1 (process_request_thread);handle (h.py:1) 3\n"
        "thread (12): Thread-2 (process_request_thread);handle (h.py:1) 4\n"
        "thread (10): MainThread;serve_forever (s.py:1) 5\n"
    )

    assert profiles.read_collapsed(collapsed) == {
        "thread: Thread-N (process_request_thread);handle (h.py:1)": 7,
        "thread: MainThread;serve_forever (s.py:1)": 5,
    }
