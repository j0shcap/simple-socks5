# Benchmarks

A harness that measures the proxy against direct connections to local origin servers, plus profiles of where
its time goes. It is development tooling: stdlib only, not packaged, not in the image.

## Running

From a checkout with the dev extra installed (`pip install -e '.[dev]'`):

```bash
python -m benchmarks setup                        # one scenario
python -m benchmarks bulk concurrency --candidates  # also measure each scenario's optimization candidates
python -m benchmarks all                          # every scenario, about 4 minutes without --candidates
python -m benchmarks compare old.json new.json    # primary metric of two runs side by side
bash benchmarks/run-in-docker.sh all              # the same, on Linux, inside the image
```

Each run prints a Markdown table per scenario and writes `results.json`, the proxy's logs and any profiles to
`benchmarks/results/<timestamp>/` (git-ignored; `--out DIR` and `--json FILE` override). Every measurement runs
three times and the median is kept (`--repeat`). Each scenario takes under two minutes, including
`--candidates`. Useful options:

| Option | Effect |
|---|---|
| `--quick` | Tiny sizes: checks the harness runs. Measures nothing. |
| `--candidates` | Adds the scenario's candidate variants (below) as extra proxy rows. |
| `--variant SPEC` | Adds a proxy row with a variant, e.g. `nodelay` or `pumps+buf=262144`. |
| `-L LEVEL`, `--env NAME=VALUE` | The proxy's log level (default `info`, as in the image) and extra environment. |
| `--python PATH`, `--installed` | The interpreter running the proxy; use its installed `simple_socks5` instead of `src/`. |
| `--profile KIND` | `cprofile`, `cprofile-cpu`, `sample` or `py-spy`: see [Profiling](#profiling). |
| `--tracemalloc` | Traces the proxy's allocations; the idle scenario reports KiB per connection. |

The harness starts the origin servers and the proxy as subprocesses, and drives load from four worker processes
so the client side isn't limited by one GIL. The proxy runs from `src/` with `SOCKS5_ALLOW_LOOPBACK=true` (the
origins are on loopback) and `SOCKS5_MAX_CONNECTIONS=5000`. Its log goes to a file, as a container's stdout would.
Client sockets set `TCP_NODELAY`, as curl and browsers do. POSIX only.

## Scenarios

| Scenario | Measures |
|---|---|
| `bulk` | One stream, 1 GiB download and upload: MB/s and proxy CPU. |
| `concurrency` | 2 GiB of downloads split over 1, 10, 50 and 200 connections: the scaling curve. |
| `setup` | A fresh connection per 100-byte response, 500 at c=1 and 5,000 at c=50: req/s and p50/p95/p99, plain, with username/password auth, and by hostname (`localhost`, which adds the DNS lookup). |
| `first-byte` | 300 sequential connections: time to first byte, split into TCP connect, method reply and CONNECT reply. |
| `small-writes` | 300 request/response round trips of 512 B over one connection, each message written in two parts 0.5 ms apart: the case Nagle's algorithm delays. |
| `idle` | 100 and 1,000 established idle connections: RSS, virtual size and threads per connection. |
| `udp` | 64-byte datagram round trips through a UDP association: 1 and 8 associations. |
| `logging` | `setup` (c=50) and 10 parallel downloads at `-L disabled`, `info` and `debug`, with log bytes per connection. |
| `pythons` | One stream, 50 streams and connection setup on each interpreter in `--pythons` (3.10 to 3.14 if found). |

"proxy CPU %" is the proxy's user plus system CPU time over the run's wall time, so 100% is one core.

## Variants

To measure a candidate before anyone implements it, [`variants.py`](variants.py) patches the proxy's relay inside
the benchmark's proxy process only. These are sketches made to be measured, not reviewed code.

| Variant | Change |
|---|---|
| `nodelay` | `TCP_NODELAY` on both relay sockets |
| `buf=N` | `RELAY_BUFFER_SIZE` of N bytes instead of 64 KiB |
| `recv_into` | `recv_into()` a buffer reused for the whole relay instead of `recv()` allocating each chunk |
| `blocking` | Blocking sockets, with the write timeout as the kernel's `SO_SNDTIMEO` |
| `pumps` | Two threads per relay, one per direction, blocking in `recv()`; no selector |
| `splice` | `pumps` moving data with `os.splice()` through a pipe, so it never enters Python (Linux) |
| `stack=N` | `threading.stack_size(N)` for every thread the proxy starts |

## Profiling

`--profile` profiles every proxy a run starts and writes the profile, a summary (`*.txt`, `*.json`) and, for the
samplers, an SVG flame graph to the results directory.

- `cprofile`: call counts and own time per function. It measures wall-clock time, so under GIL contention a call
  is charged for the time its thread waits to get the GIL back: it shows who waits, not who works. From Python
  3.12 one profiler covers all threads and shares one call stack, so cumulative times are wrong there.
- `cprofile-cpu`: the same, timing each thread's CPU time. Exact, but needs the proxy on 3.10 or 3.11
  (`--python python3.11`) because it needs a profiler per thread.
- `sample`: a stdlib sampler of every thread's stack, 200 times a second. Wall clock: it shows where threads are,
  including blocked in `recv()`. Works anywhere without privileges.
- `py-spy`: CPU samples of every thread. Needs root on macOS, so use `run-in-docker.sh`, which grants
  `CAP_SYS_PTRACE`. `BENCH_PY_SPY_ARGS=--gil` samples only the thread holding the GIL; `--native` adds C frames.

The flame graphs and `.collapsed` stack files also load in [speedscope](https://www.speedscope.app/).

## Tests and coverage

`pytest -m bench` runs every scenario, the candidates and the profilers with `--quick`, in about a minute.
It is deselected by default and runs in CI as a non-blocking job, with no timing thresholds: runners are too noisy.
The harness is outside the coverage target (`--cov=simple_socks5`), because it is tooling, not the product, and
its quick run would only show that each line executes.
