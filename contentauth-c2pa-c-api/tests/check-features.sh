#!/bin/sh
# Copyright 2026 Adobe. Licensed under Apache-2.0 OR MIT.
# Run from the workspace root. No C++ crate is linked into these checks.
set -eu

crate=contentauth-c2pa-c-api
target=target/c-api-feature-smoke
header=contentauth-c2pa-c-api/include/contentauth_c2pa_c_api.h
initial_header=
for features in read,build read build none; do
    if [ "$features" = none ]; then
        cargo build -p "$crate" --no-default-features --target-dir "$target"
    else
        cargo build -p "$crate" --no-default-features --features "$features" --target-dir "$target"
    fi
    # Rust archives contain non-object metadata; nm may return nonzero for that
    # member while still reporting every object. Filter actual ABI definitions.
    symbols="$(nm -g "$target/debug/libcontentauth_c2pa_c_api.a" 2>/dev/null | grep -E ' [Tt] _?c2pa_sm_[[:alnum:]_]+$')"
    for symbol in c2pa_sm_version c2pa_sm_string_free c2pa_sm_error_free c2pa_sm_error_code; do
        printf '%s\n' "$symbols" | grep -Eq " [Tt] _?$symbol$"
    done
    for symbol in c2pa_sm_session_new c2pa_sm_session_advance c2pa_sm_reader_json; do
        if printf '%s\n' "$symbols" | grep -Eq " [Tt] _?$symbol$"; then
            case "$features" in read|read,build) ;; *) exit 1 ;; esac
        else
            case "$features" in read|read,build) exit 1 ;; esac
        fi
    done
    for symbol in c2pa_sm_build_session_new c2pa_sm_build_read_acquire c2pa_sm_build_write_acquire c2pa_sm_sign_report_view; do
        if printf '%s\n' "$symbols" | grep -Eq " [Tt] _?$symbol$"; then
            case "$features" in build|read,build) ;; *) exit 1 ;; esac
        else
            case "$features" in build|read,build) exit 1 ;; esac
        fi
    done
    # Old API must not accidentally survive as a compatibility shim.
    if printf '%s\n' "$symbols" | grep -Eq ' [Tt] _?c2pa_sm_(read_new|build_new|read_finish|build_finish)$'; then
        exit 1
    fi
    current_header="$(shasum "$header")"
    if [ -n "$initial_header" ]; then
        test "$current_header" = "$initial_header"
    fi
    initial_header="$current_header"
    cc -std=c11 -Wall -Wextra -Werror -fsyntax-only contentauth-c2pa-c-api/tests/header_smoke.c
    c++ -std=c++17 -Wall -Wextra -Werror -x c++ -fsyntax-only contentauth-c2pa-c-api/tests/header_smoke.c
    printf 'PASS %s: symbols, stable header, C11, C++17\n' "$features"
done
if cargo tree -p "$crate" --no-default-features -e normal --prefix none | grep -q contentauth-c2pa-session-bridge; then
    printf 'shared-only must not depend on the bridge\n' >&2
    exit 1
fi
