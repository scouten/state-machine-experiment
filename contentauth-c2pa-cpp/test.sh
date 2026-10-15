#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
./build.sh "$@"
ctest --test-dir build --output-on-failure