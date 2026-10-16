"""
SVG charts of results rows, for the README and pull requests: bars per scenario, the concurrency scaling curve and
a baseline/candidate comparison.

GitHub shows a committed SVG as an image, so nothing here relies on hover: every value is printed, and every chart
has an opaque background so it stays readable on a dark theme.
"""

import html
import math
from typing import Final

from .scenarios import Row, format_value

WIDTH: Final = 760
FONT: Final = "system-ui, -apple-system, 'Segoe UI', sans-serif"
CHAR: Final = 6.6  # approximate width of a 12 px character, for laying out labels
SURFACE: Final = "#fcfcfb"
INK: Final = "#0b0b0b"
SECONDARY: Final = "#52514e"
MUTED: Final = "#898781"
GRID: Final = "#e1e0d9"
AXIS: Final = "#c3c2b7"
# Categorical slots in a fixed order, validated for colour-vision deficiency on adjacent pairs; never cycled
SERIES: Final = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948")
BAR: Final = 16
ROW: Final = 24
TIMES: Final = "\N{MULTIPLICATION SIGN}"


def lower_is_better(unit: str) -> bool:
    """Latencies and memory improve as they fall; throughput and rates as they rise."""
    return unit.endswith(" ms") or "KiB" in unit


def _direction(unit: str) -> str:
    return "lower is better" if lower_is_better(unit) else "higher is better"


def _gain(value: float, reference: float, unit: str) -> float:
    """How many times better value is than reference."""
    return reference / value if lower_is_better(unit) else value / reference


def _value(row: Row) -> float:
    return row.metrics.get(row.primary, float("nan"))


def _with_unit(value: float, unit: str) -> str:
    """The value with the last word of its metric's name: 85.5 ms, 4,247 MB/s, 28.9 KiB/conn."""
    return f"{format_value(value)} {unit.rsplit(maxsplit=1)[-1]}"


def _usable(value: float) -> bool:
    return value > 0  # also False for NaN


def _svg(height: float, body: list[str]) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height:.0f}" '
        f'viewBox="0 0 {WIDTH} {height:.0f}" font-family="{FONT}" font-size="12">'
        f'<rect width="100%" height="100%" fill="{SURFACE}"/>{"".join(body)}</svg>\n'
    )


def _text(x: float, y: float, text: str, fill: str = INK, extra: str = "") -> str:
    return f'<text x="{x:.1f}" y="{y:.1f}" fill="{fill}"{extra}>{html.escape(text)}</text>'


def _heading(title: str, subtitle: str) -> list[str]:
    return [
        _text(16, 26, title, extra=' font-size="15" font-weight="600"'),
        _text(16, 46, subtitle, SECONDARY),
    ]


def _bar(x: float, y: float, width: float, fill: str) -> str:
    """A horizontal bar, square at the baseline with a 4 px rounded end."""
    r = min(4.0, width / 2)
    return (
        f'<path d="M{x:.1f},{y:.1f}h{width - r:.1f}a{r:.1f},{r:.1f} 0 0 1 {r:.1f},{r:.1f}v{BAR - 2 * r:.1f}'
        f'a{r:.1f},{r:.1f} 0 0 1 -{r:.1f},{r:.1f}h-{width - r:.1f}z" fill="{fill}"/>'
    )


def _path_colour(path: str) -> str:
    """Direct is the reference, proxy the baseline, anything else a variant of the proxy."""
    return {"direct": MUTED, "proxy": SERIES[0]}.get(path, SERIES[1])


def bars(rows: list[Row], title: str, subtitle: str) -> str:
    """Horizontal bars of each row's primary metric, one group per case, each scaled to its own largest value."""
    label_width = max(120.0, max(len(row.path) for row in rows) * CHAR + 24)
    plot = WIDTH - label_width - 200
    body = _heading(title, subtitle)
    y = 64.0
    for case in dict.fromkeys(row.case for row in rows):
        group = [row for row in rows if row.case == case]
        unit = group[0].primary
        body.append(_text(16, y + 12, f"{case}: {unit}, {_direction(unit)}", extra=' font-weight="600"'))
        y += 22
        largest = max((v for v in map(_value, group) if _usable(v)), default=1.0)
        proxy = next((_value(row) for row in group if row.path == "proxy"), float("nan"))
        for row in group:
            value = _value(row)
            body.append(_text(label_width - 8, y + 12, row.path, extra=' text-anchor="end"'))
            width = plot * value / largest if _usable(value) else 0.0
            if width > 0:
                body.append(_bar(label_width, y, width, _path_colour(row.path)))
            label = _with_unit(value, row.primary)
            x = label_width + width + 6
            body.append(_text(x, y + 12, label))
            if row.path != "proxy" and _usable(value) and _usable(proxy):
                gain = _gain(value, proxy, row.primary)
                times = f"{TIMES}{gain:.2f}" if gain < 10 else f"{TIMES}{gain:.1f}"
                body.append(_text(x + len(label) * CHAR + 10, y + 12, f"{times} vs proxy", SECONDARY))
            y += ROW
        y += 10
    note = f"Bars are scaled per case. {TIMES}N is how many times better than the default proxy."
    body.append(_text(16, y + 8, note, MUTED))
    return _svg(y + 20, body)


def _nice_step(largest: float) -> float:
    """A 1, 2 or 5 times a power of ten step that splits 0..largest into about four gridlines."""
    raw = largest / 4
    power = 10.0 ** math.floor(math.log10(raw))
    return next(power * m for m in (1, 2, 5, 10) if power * m >= raw)


def scaling(rows: list[Row]) -> str:
    """The concurrency scenario's throughput against the connection count, one line per path."""
    levels = sorted({int(row.case.split(" x ")[0]) for row in rows})
    paths = list(dict.fromkeys(row.path for row in rows))
    variants = [path for path in paths if path != "direct"]
    if len(variants) > len(SERIES):
        raise ValueError(f"at most {len(SERIES)} proxy paths fit one chart, got {len(variants)}")
    colours = {"direct": MUTED} | dict(zip(variants, SERIES, strict=False))
    unit = rows[0].primary
    body = _heading("concurrency: the scaling curve", f"{unit} by number of connections, {_direction(unit)}")

    x, legend_y = 16.0, 60.0
    for path in paths:
        width = 18 + len(path) * CHAR + 20
        if x + width > WIDTH - 16:
            x, legend_y = 16.0, legend_y + 20
        body.append(f'<rect x="{x:.1f}" y="{legend_y:.0f}" width="12" height="12" rx="2" fill="{colours[path]}"/>')
        body.append(_text(x + 18, legend_y + 10, path))
        x += width

    left, right, top, height = 72.0, WIDTH - 96.0, legend_y + 36, 260.0
    values = {(int(row.case.split(" x ")[0]), row.path): _value(row) for row in rows}
    largest = max((v for v in values.values() if _usable(v)), default=1.0)
    step = _nice_step(largest)
    ceiling = step * math.ceil(largest / step)

    def at_x(level: int) -> float:
        return left + (right - left) * levels.index(level) / max(1, len(levels) - 1)

    def at_y(value: float) -> float:
        return top + height * (1 - value / ceiling)

    for tick in range(round(ceiling / step) + 1):
        y = at_y(tick * step)
        body.append(f'<line x1="{left}" x2="{right}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}"/>')
        body.append(_text(left - 8, y + 4, format_value(tick * step), MUTED, ' text-anchor="end"'))
    body.append(f'<line x1="{left}" x2="{right}" y1="{top + height}" y2="{top + height}" stroke="{AXIS}"/>')
    for level in levels:
        body.append(_text(at_x(level), top + height + 18, str(level), MUTED, ' text-anchor="middle"'))
    body.append(_text((left + right) / 2, top + height + 38, "connections", SECONDARY, ' text-anchor="middle"'))

    ends: list[tuple[float, str]] = []
    for path in paths:
        points = [
            (at_x(level), at_y(values[level, path])) for level in levels if _usable(values.get((level, path), 0.0))
        ]
        coords = " ".join(f"{px:.1f},{py:.1f}" for px, py in points)
        body.append(f'<polyline points="{coords}" fill="none" stroke="{colours[path]}" stroke-width="2"/>')
        body += [
            f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4" fill="{colours[path]}" stroke="{SURFACE}" stroke-width="2"/>'
            for px, py in points
        ]
        last = values.get((levels[-1], path), 0.0)
        if _usable(last):
            ends.append((at_y(last), format_value(last)))
    # The value at the last level of each line, pushed apart so the labels never overlap
    floor = 0.0
    for y, label in sorted(ends):
        floor = max(y, floor + 14)
        body.append(_text(right + 10, floor + 4, label, SECONDARY))
    return _svg(top + height + 52, body)


def before_after(baseline: list[Row], candidate: list[Row], names: tuple[str, str]) -> str:
    """Grouped baseline and candidate bars for each row in both runs, with the change in its primary metric."""
    before = {row.key: row for row in baseline}
    pairs = [(before[row.key], row) for row in candidate if row.key in before]
    label_width = max(len(name) for name in names) * CHAR + 24
    plot = WIDTH - label_width - 150
    body = _heading(f"{names[0]} vs {names[1]}", "The primary metric of each case. Bars are scaled per case.")
    y = 64.0
    for old, new in pairs:
        unit = new.primary
        body.append(_text(16, y + 12, " · ".join(new.key), extra=' font-weight="600"'))
        old_value, new_value = _value(old), _value(new)
        if _usable(old_value) and _usable(new_value):
            change = 100 * (new_value - old_value) / old_value
            verdict = ""
            if round(change, 1):
                verdict = "better" if (change < 0) == lower_is_better(unit) else "worse"
                body.append(_text(WIDTH - 16, y + 12, verdict, SECONDARY, ' text-anchor="end"'))
            x = WIDTH - 16 - (len(verdict) * CHAR + 6 if verdict else 0)
            body.append(_text(x, y + 12, f"{change:+.1f}%", extra=' text-anchor="end" font-weight="600"'))
        y += 22
        largest = max((v for v in (old_value, new_value) if _usable(v)), default=1.0)
        for name, value, colour in ((names[0], old_value, MUTED), (names[1], new_value, SERIES[0])):
            body.append(_text(label_width - 8, y + 12, name, SECONDARY, ' text-anchor="end"'))
            width = plot * value / largest if _usable(value) else 0.0
            if width > 0:
                body.append(_bar(label_width, y, width, colour))
            body.append(_text(label_width + width + 6, y + 12, _with_unit(value, unit)))
            y += BAR + 4
        y += 14
    return _svg(y + 6, body)
