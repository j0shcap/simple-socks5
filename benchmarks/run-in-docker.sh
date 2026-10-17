#!/usr/bin/env bash
# Runs the benchmarks on Linux inside the Docker image, with the proxy the image installed:
#   bash benchmarks/run-in-docker.sh <python -m benchmarks arguments>
# Builds the image from this checkout unless BENCH_IMAGE names one. Results land in benchmarks/results/docker-*.
# --profile py-spy installs py-spy in the throwaway container; BENCH_PY_SPY_ARGS adds flags such as --gil.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
out="$repo/benchmarks/results/docker-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"

image=${BENCH_IMAGE:-}
if [ -z "$image" ]; then
    image=simple-socks5:bench
    docker build -q -t "$image" "$repo" >/dev/null
fi

docker run --rm --user root --cap-add SYS_PTRACE --ulimit nofile=65536:65536 \
    -e BENCH_PY_SPY_ARGS -v "$repo:/bench:ro" -v "$out:/out" -w /bench --entrypoint sh "$image" -c '
        case " $* " in *" py-spy "*|*"=py-spy "*) pip install -q --root-user-action=ignore py-spy ;; esac
        exec python -m benchmarks --installed --out /out "$@"
    ' sh "$@"
echo "On the host: $out"
