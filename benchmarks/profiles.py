"""
Profile collection and summaries, shared by the launcher (inside the proxy process) and the harness.

Three sources, all summarised the same way: top functions or frames, and the share of time per category.

- cProfile: call counts and own time per function. Python 3.10 and 3.11 get a profiler per thread, which is exact.
  From 3.12 cProfile is process-wide and keeps one call stack for all threads, so call counts and own times are
  right but cumulative times are not, and only own times are reported. Wall-clock time charges a call for the time
  its thread then waits for the GIL, so under contention it shows who waits, not who works; cprofile-cpu times
  each thread's CPU time instead (3.10 and 3.11 only).
- The stdlib sampler: wall-clock stacks of every thread from sys._current_frames(). It shows where threads are,
  including waiting in recv() or select(), not where CPU goes. Works everywhere without privileges.
- py-spy (dev extra): CPU samples of every thread, optionally with native frames. Needs root on macOS, or
  CAP_SYS_PTRACE in a container.
"""

import html
import linecache
import pstats
import re
import sys
import threading
from collections import Counter
from pathlib import Path
from types import FrameType
from typing import Final

# Matched in order against "<function> <file> <source line>"; the first match wins
CATEGORIES: Final = (
    (
        "socket data I/O",
        r"'(recv|recv_into|send|sendall|recvfrom|sendto)' of '_socket|\.(recv|recv_into|sendall|"
        r"sendto|recvfrom)\(|\b(sock_recv\w*|sock_send\w*|__libc_(recv|send)\w*|__(recv|send)\w*)\b|splice",
    ),
    (
        "readiness wait (select/poll)",
        r"'(select|poll|control)' of 'select|selectors\.py|\.select\(|\b(epoll_wait|"
        r"kevent|select_epoll_poll\w*)\b",
    ),
    ("connect / accept / DNS", r"'(connect|connect_ex|_accept)' of|getaddrinfo|resolver\.py|\.connect\(|accept"),
    ("logging", r"logging[/\\]"),
    ("thread start / locks", r"threading\.py|_thread|'(acquire|release)' of|socketserver\.py"),
    (
        "socket setup / teardown",
        r"'(setsockopt|settimeout|setblocking|getpeername|getsockname|shutdown|close|"
        r"detach)' of|socket\.py|\.(setsockopt|settimeout|getpeername|shutdown|close)\(",
    ),
    ("handshake parsing", r"simple_socks5[/\\]handlers"),
    ("relay loop (Python)", r"simple_socks5[/\\]relays|benchmarks[/\\]variants"),
    ("other simple_socks5", r"simple_socks5"),
)
_COMPILED: Final = tuple((name, re.compile(pattern)) for name, pattern in CATEGORIES)
_THREAD_ID: Final = re.compile(r"^thread \(\d+\): ")
_THREAD_NUMBER: Final = re.compile(r"(?<=^thread: )Thread-\d+")
_FRAME: Final = re.compile(r"^(?P<name>.*) \((?P<path>[^()]*?):(?P<line>\d+)\)$")


def categorize(text: str) -> str:
    for name, pattern in _COMPILED:
        if pattern.search(text):
            return name
    return "other"


def summarize_pstats(stats: pstats.Stats, kind: str, top: int = 25) -> dict[str, object]:
    """Own time per function and per category, with call counts."""
    rows = []
    categories: Counter[str] = Counter()
    raw = stats.stats  # type: ignore[attr-defined]  # pstats.Stats.stats isn't in typeshed
    total = sum(entry[2] for entry in raw.values()) or 1.0
    for (path, line, name), (_, ncalls, tottime, _, _) in raw.items():
        label = f"{name} ({_short(path)}:{line})" if path != "~" else name
        categories[categorize(f"{name} {path}")] += tottime
        rows.append({"function": label, "calls": ncalls, "own_s": tottime, "own_pct": 100 * tottime / total})
    rows.sort(key=lambda row: -float(str(row["own_s"])))
    return {
        "kind": kind,
        "total_s": total,
        "top": rows[:top],
        "categories": {name: 100 * value / total for name, value in categories.most_common()},
    }


def summarize_collapsed(counts: dict[str, int], kind: str, top: int = 25) -> dict[str, object]:
    """Share of samples per leaf frame, per function anywhere on the stack, and per category of the leaf."""
    total = sum(counts.values()) or 1
    leaves: Counter[str] = Counter()
    inclusive: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    for stack, n in counts.items():
        frames = stack.split(";")
        leaf = frames[-1]
        leaves[leaf] += n
        categories[categorize(_with_source(leaf))] += n
        for frame in set(frames):
            inclusive[_function(frame)] += n
    return {
        "kind": kind,
        "samples": total,
        "top_leaves": [{"frame": _with_source(f), "pct": 100 * n / total} for f, n in leaves.most_common(top)],
        "top_inclusive": [{"function": f, "pct": 100 * n / total} for f, n in inclusive.most_common(top)],
        "categories": {name: 100 * n / total for name, n in categories.most_common()},
    }


def read_collapsed(path: Path) -> dict[str, int]:
    """
    Reads py-spy's collapsed stacks, merging threads by name: its --threads root frame names every thread by id, so
    a run with thousands of short-lived handler threads would otherwise have thousands of tiny roots.
    """
    counts: Counter[str] = Counter()
    for line in path.read_text().splitlines():
        stack, _, n = line.rpartition(" ")
        if stack and n.isdigit():
            counts[_THREAD_NUMBER.sub("Thread-N", _THREAD_ID.sub("thread: ", stack, count=1), count=1)] += int(n)
    return dict(counts)


def write_collapsed(counts: dict[str, int], path: Path) -> None:
    path.write_text("".join(f"{stack} {n}\n" for stack, n in sorted(counts.items())))


def _short(path: str) -> str:
    for marker in ("simple_socks5/", "benchmarks/", "/lib/python"):
        index = path.find(marker)
        if index >= 0:
            return path[index + 1 :] if marker.startswith("/") else path[index:]
    return path


def _function(frame: str) -> str:
    match = _FRAME.match(frame)
    return f"{match['name']} ({_short(match['path'])})" if match else frame


def _with_source(frame: str) -> str:
    """The frame with its source line, so a frame blocked in sock.sendall() reads as such."""
    match = _FRAME.match(frame)
    if not match:
        return frame
    source = linecache.getline(match["path"], int(match["line"])).strip()
    label = f"{match['name']} ({_short(match['path'])}:{match['line']})"
    return f"{label} `{source}`" if source else label


class Sampler:
    """Samples every thread's Python stack rate times a second, on a daemon thread, until stopped."""

    def __init__(self, rate: float = 200.0) -> None:
        self.counts: Counter[str] = Counter()
        self._interval = 1.0 / rate
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="bench-sampler", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> dict[str, int]:
        self._stop.set()
        self._thread.join()
        return dict(self.counts)

    def _run(self) -> None:
        me = threading.get_ident()
        while not self._stop.wait(self._interval):
            for ident, frame in sys._current_frames().items():
                if ident != me:
                    self.counts[_stack(frame)] += 1


def _stack(frame: FrameType | None) -> str:
    frames = []
    while frame is not None:
        code = frame.f_code
        frames.append(f"{code.co_name} ({code.co_filename}:{frame.f_lineno})")
        frame = frame.f_back
    return ";".join(reversed(frames))


_COLOURS: Final = {
    "socket data I/O": "#e8a33d",
    "readiness wait (select/poll)": "#c8c8c8",
    "connect / accept / DNS": "#8fbf6a",
    "logging": "#d9534f",
    "thread start / locks": "#9b7fcf",
    "socket setup / teardown": "#5bc0de",
    "handshake parsing": "#f0c75e",
    "relay loop (Python)": "#f28f5c",
    "other simple_socks5": "#e3b37a",
    "other": "#b0b8c0",
}


def render_flamegraph(
    counts: dict[str, int], path: Path, title: str, width: int = 1600, min_share: float = 0.005
) -> None:
    """
    Writes an SVG icicle graph (root at the top) of collapsed stacks, coloured by category, with a legend of the
    categories drawn. Frames under min_share of the samples are left out, which keeps a committed graph small.
    """
    tree: dict[str, object] = {}
    for stack, n in counts.items():
        node = tree
        for frame in stack.split(";"):
            child = node.setdefault(frame, {"#": 0})
            assert isinstance(child, dict)
            child["#"] = int(child["#"]) + n
            node = child
    total = sum(counts.values()) or 1
    row, rects, drawn = 17, [], set()

    def draw(node: dict[str, object], x: float, depth: int) -> int:
        deepest = depth
        for frame, child in sorted(node.items()):
            if frame == "#" or not isinstance(child, dict):
                continue
            share = int(child["#"]) / total
            w = width * share
            if share >= min_share:
                category = categorize(_with_source(frame))
                drawn.add(category)
                label = _function(frame)
                # Cut before escaping, so a cut never splits an entity such as the &lt; of <module>
                text = label if len(label) * 7 < w else label[: max(0, int(w / 7) - 2)] + ".." if w > 30 else ""
                rects.append(
                    f"<g><title>{html.escape(_with_source(frame))} ({100 * share:.1f}%)</title>"
                    f'<rect x="{x:.1f}" y="{depth * row}" width="{w:.1f}" height="{row - 1}" '
                    f'fill="{_COLOURS[category]}"/><text x="{x + 3:.1f}" y="{depth * row + 12}">'
                    f"{html.escape(text)}</text></g>"
                )
                deepest = max(deepest, draw(child, x, depth + 1))
            x += w
        return deepest

    depth = draw(tree, 0.0, 0)
    legend, x, y = [], 4, 24
    for category, colour in _COLOURS.items():
        if category not in drawn:
            continue
        if x + 30 + len(category) * 7 > width:
            x, y = 4, y + 18
        legend.append(
            f'<rect x="{x}" y="{y}" width="12" height="12" fill="{colour}"/>'
            f'<text x="{x + 16}" y="{y + 10}">{html.escape(category)}</text>'
        )
        x += 30 + len(category) * 7
    top = y + 22
    height = top + 10 + (depth + 1) * row
    path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" font-family="monospace" '
        f'font-size="11"><rect width="100%" height="100%" fill="#ffffff"/>'
        f'<text x="4" y="13">{html.escape(title)} ({total} samples, frames under {100 * min_share:g}% left out)</text>'
        f'{"".join(legend)}<g transform="translate(0,{top})">{"".join(rects)}</g></svg>\n'
    )


def write_summary_text(summary: dict[str, object], path: Path) -> None:
    lines = [f"{summary['kind']}"]
    categories = summary.get("categories")
    if isinstance(categories, dict):
        lines += ["", "Share by category:"] + [f"  {pct:5.1f}%  {name}" for name, pct in categories.items()]
    for key in ("top", "top_leaves", "top_inclusive"):
        rows = summary.get(key)
        if isinstance(rows, list):
            lines += ["", f"{key}:"]
            for entry in rows:
                assert isinstance(entry, dict)
                pct = entry.get("own_pct", entry.get("pct"))
                calls = f"{entry['calls']:>9} calls  " if "calls" in entry else ""
                lines.append(f"  {pct:5.1f}%  {calls}{entry.get('function', entry.get('frame'))}")
    path.write_text("\n".join(lines) + "\n")
