#!/usr/bin/env bash
# Usage: release-guard.sh REF_NAME
# Validates a release tag and prints "prerelease=true|false" for $GITHUB_OUTPUT.
set -euo pipefail

ref_name=${1-}
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

if [[ ! $ref_name =~ $semver ]]; then
    echo "::error::Tag '$ref_name' is not a release tag of the form vX.Y.Z or vX.Y.Z-prerelease" >&2
    exit 1
fi

major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
prerelease_suffix=${BASH_REMATCH[4]}

# 2.0.0, 2.0 and 2.0.0-logging-disabled are immutable on Docker Hub; anything below 2.1 would retarget them
# or move latest backwards.
if (( major < 2 || (major == 2 && minor < 1) )); then
    echo "::error::Tag '$ref_name' is below v2.1.0 and would retarget the immutable image tags" \
        "2.0.0, 2.0 and 2.0.0-logging-disabled" >&2
    exit 1
fi

if [[ -n $prerelease_suffix ]]; then
    echo "prerelease=true"
else
    echo "prerelease=false"
fi
