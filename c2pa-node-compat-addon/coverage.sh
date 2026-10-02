#!/usr/bin/env bash
# Coverage for both halves of the Node side, from one test run:
#   lcov.info       the JavaScript driver (node's built-in coverage)
#   lcov.rust.info  the Rust addon, instrumented by cargo-llvm-cov and
#                   exercised by loading it into Node
# Requires cargo-llvm-cov.
set -euo pipefail
cd "$(dirname "$0")"

cargo llvm-cov clean --workspace
# shellcheck disable=SC1090
source <(cargo llvm-cov show-env --export-prefix)

cargo build
node build.mjs debug
npm run --silent coverage

cargo llvm-cov report --lcov --output-path lcov.rust.info
cargo llvm-cov report

# Make every path in both reports relative to the repository root, so a
# coverage service maps them onto the checkout whatever machine ran this.
root="$(git rev-parse --show-toplevel)"
prefix="${PWD#"$root"/}"
sed -i "s|^SF:|SF:$prefix/|" lcov.info            # node reports paths relative to here
sed -i "s|^SF:$root/|SF:|" lcov.rust.info          # llvm-cov reports absolute paths
