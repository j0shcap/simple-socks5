# Releasing

Pushing a `vX.Y.Z` tag publishes the Docker images: the `publish` job in `.github/workflows/ci.yml` runs after the
tests and the container smoke test pass. Replace `X.Y.Z` below with the version.

## 1. Prepare the release PR

- Bump `version` in `pyproject.toml`, the only place it's written; `__version__` reads it from the installed
  package. Rerun `pip install -e .` afterwards, or `tests/test_version.py` fails on the stale version.
- In `CHANGELOG.md`, move the `[Unreleased]` entries into `## [X.Y.Z] - YYYY-MM-DD`, leave `## [Unreleased]`
  empty above it, and update the link references at the bottom. List every **Behaviour change** and its opt-out
  under "Upgrading". `tests/test_docs.py` fails without a dated section for the current version.
- If the relay, protocol handling, Dockerfile or workflow changed, rerun the release checks below on the branch
  and paste the output into the PR.
- Merge once CI is green. If you tag on a later day than the CHANGELOG date, fix the date first.

## 2. Tag

```bash
git fetch origin
MERGE_SHA=$(git rev-parse origin/main)
git tag -a vX.Y.Z -m "vX.Y.Z" "$MERGE_SHA"
git push origin vX.Y.Z
```

`.github/scripts/release-guard.sh` rejects anything that isn't `vX.Y.Z` or `vX.Y.Z-prerelease`, and any
version below 2.1.0, so the immutable `2.0.0`, `2.0` and `2.0.0-logging-disabled` images can't be overwritten.

| Tag | Publishes |
|-----|-----------|
| `vX.Y.Z` | `X.Y.Z`, `X.Y`, `X`, `latest`, `X.Y.Z-logging-disabled`, `logging-disabled` |
| `vX.Y.Z-rc.N` | `X.Y.Z-rc.N` and `X.Y.Z-rc.N-logging-disabled` only |

## 3. Watch the workflow

```bash
sleep 15   # let the run register
gh run watch "$(gh run list --workflow ci.yml --branch vX.Y.Z --limit 1 --json databaseId -q '.[0].databaseId')" \
    --exit-status
```

## 4. Verify the images

```bash
# Three platforms: linux/amd64, linux/arm/v7, linux/arm64
docker buildx imagetools inspect jcaponigro20/simple-socks5:X.Y.Z

# One line with a count of 4: latest, X, X.Y and X.Y.Z share a digest
for t in latest X X.Y X.Y.Z; do
    docker buildx imagetools inspect "jcaponigro20/simple-socks5:$t" --format '{{println .Manifest.Digest}}'
done | uniq -c

# One line with a count of 2
for t in logging-disabled X.Y.Z-logging-disabled; do
    docker buildx imagetools inspect "jcaponigro20/simple-socks5:$t" --format '{{println .Manifest.Digest}}'
done | uniq -c

# Unchanged: sha256:cb8d38d2260b852d5efd1edc6315d6bde3002892f921aea86e27c0c8bbc3f278
docker buildx imagetools inspect jcaponigro20/simple-socks5:2.0.0 --format '{{println .Manifest.Digest}}'
```

## 5. Create the GitHub Release

The release notes are the CHANGELOG section, extracted rather than retyped:

```bash
awk '/^## \[X.Y.Z\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md > /tmp/notes-X.Y.Z.md
gh release create vX.Y.Z --title vX.Y.Z --notes-file /tmp/notes-X.Y.Z.md --verify-tag
```

## 6. Smoke-test the published image

```bash
docker run --rm -d --name s5 -p 127.0.0.1:1080:1080 jcaponigro20/simple-socks5:X.Y.Z
sleep 2
curl -sS --socks5-hostname 127.0.0.1:1080 -o /dev/null -w '%{http_code}\n' https://example.com   # 200
docker logs s5   # startup lines, including the open-proxy WARNING
docker stop s5
```

## 7. Check a browser (manual)

Start a container without authentication, published on loopback only (Chromium can't do SOCKS5 authentication):

```bash
docker run --rm -d --name s5 -p 127.0.0.1:1080:1080 -e SOCKS5_AUTH_REQUIRED=false \
    jcaponigro20/simple-socks5:X.Y.Z
```

- **Firefox:** Settings → Network Settings → Manual proxy configuration: SOCKS Host `127.0.0.1`, Port `1080`,
  SOCKS v5, and tick "Proxy DNS when using SOCKS v5".
- **Chromium:** `chromium --user-data-dir="$(mktemp -d)" --proxy-server="socks5://127.0.0.1:1080"`

Load an HTTPS site in each and check that `docker logs s5` shows a `CLOSED` line for it. Then `docker stop s5`.

## Release checks

Run these against the branch when the relay, protocol handling, Dockerfile or workflow changed:

- a 100 MB download with `curl --limit-rate 1M` completes;
- 200 idle connections are closed within `SOCKS5_HANDSHAKE_TIMEOUT`, and a new client still connects;
- CONNECT to a blackholed address replies `0x04` within `SOCKS5_CONNECT_TIMEOUT`;
- a client that half-closes after sending `hello world` gets `GOT 11 BYTES` back;
- a malformed UDP datagram doesn't end the association, and closing the TCP connection does;
- `docker stop` exits 0 in under 6 seconds;
- a default `docker run` logs the open-proxy WARNING;
- CONNECT to `127.0.0.1` and `169.254.169.254` replies `0x02`;
- throughput on loopback (100 downloads of 10 MB, 50 at a time);
- the healthcheck adds no log lines;
- `curl --socks5`, `curl --socks5-hostname`, `requests[socks]` with `socks5h://` and proxychains4 reach a public
  host.

Most are covered by `tests/e2e/` with shortened timeouts. Repeat them at the defaults against an image built with
`docker build` (never `--push`).

## Rolling back

Never move a published version tag. Fix forward with `X.Y.(Z+1)`; users who need the previous behaviour pin the
previous version.
