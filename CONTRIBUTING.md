# Contributing

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

## Checks

CI runs the tests and mypy on Python 3.10 to 3.14, and Ruff on 3.13:

```bash
pytest --cov=simple_socks5 --cov-fail-under=85
ruff check .
ruff format --check .
mypy
```

`ruff format .` fixes formatting. Ruff and mypy are pinned in `pyproject.toml`, which also holds their config.
Run `git config blame.ignoreRevsFile .git-blame-ignore-revs` once so `git blame` skips formatting commits.

The end-to-end tests in `tests/e2e/` start a real proxy and origin servers on loopback. They run with the rest of
the suite, or on their own with `pytest tests/e2e`. CI also builds the image and smoke-tests it:

```bash
docker build -t simple-socks5:dev . && bash .github/scripts/smoke-test.sh simple-socks5:dev
```

## Rules

- The runtime is standard library only. Tools go in the `dev` extra.
- Python 3.10 or later.
- Every user-visible change gets a line under `[Unreleased]` in the CHANGELOG. Mark changed defaults
  **Behaviour change**.
- Keep commits small, with a short subject line. PRs are squash-merged, so the PR title becomes the commit on `main`.

## Releasing

1. In a PR, bump `version` in `pyproject.toml` (then rerun `pip install -e .`) and turn `[Unreleased]` in the
   CHANGELOG into `## [X.Y.Z] - YYYY-MM-DD`, with an empty `[Unreleased]` above it and the bottom links updated.
2. Merge once CI is green.
3. Tag the merge commit and push the tag:
   ```bash
   git fetch origin && git tag -a vX.Y.Z -m vX.Y.Z origin/main && git push origin vX.Y.Z
   ```
4. CI publishes the multi-arch images. `vX.Y.Z` moves `X.Y.Z`, `X.Y`, `X`, `latest`, `X.Y.Z-logging-disabled` and
   `logging-disabled`; a prerelease such as `vX.Y.Z-rc.N` publishes only its own two tags. `release-guard.sh`
   rejects tags of any other form and anything below 2.1.0.
5. Check that the tags share a digest (one line with a count of 4):
   ```bash
   for t in latest X X.Y X.Y.Z; do
       docker buildx imagetools inspect "jcaponigro20/simple-socks5:$t" --format '{{println .Manifest.Digest}}'
   done | uniq -c
   ```
6. Publish the CHANGELOG section as the release notes:
   ```bash
   awk '/^## \[X.Y.Z\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md > /tmp/notes.md
   gh release create vX.Y.Z --title vX.Y.Z --notes-file /tmp/notes.md --verify-tag
   ```

Never move a published version tag. Fix forward with `X.Y.(Z+1)`.
