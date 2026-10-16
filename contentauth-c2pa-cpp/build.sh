#!/usr/bin/env bash
# Configure and build into ./build. Extra arguments go to cmake's configure
# step, e.g. `./build.sh -DCMAKE_BUILD_TYPE=Release`.
set -euo pipefail

cd "$(dirname "$0")"
cmake -S . -B build "$@"
cmake --build build -j
