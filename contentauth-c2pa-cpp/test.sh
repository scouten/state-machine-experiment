#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
./build.sh "$@" -DBUILD_TESTING=ON
ctest --test-dir build --verbose --output-on-failure