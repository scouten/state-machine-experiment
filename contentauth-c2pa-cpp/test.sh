#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
./build.sh "$@"
ctest --test-dir build --verbose --output-on-failure