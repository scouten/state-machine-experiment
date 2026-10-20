// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#ifndef C2PA_SM_SCOPE_EXIT_HPP
#define C2PA_SM_SCOPE_EXIT_HPP

#include <type_traits>
#include <utility>

namespace c2pa::sm::detail {

/// Runs a non-throwing cleanup on scope exit, including exception unwinding.
template <typename F>
class ScopeExit {
    static_assert(std::is_nothrow_invocable_v<F &>, "scope-exit cleanup must be noexcept");

public:
    explicit ScopeExit(F action) noexcept(std::is_nothrow_move_constructible_v<F>)
        : action_(std::move(action)) {}

    ScopeExit(const ScopeExit &) = delete;
    ScopeExit &operator=(const ScopeExit &) = delete;
    ScopeExit(ScopeExit &&) = delete;
    ScopeExit &operator=(ScopeExit &&) = delete;

    ~ScopeExit() noexcept { action_(); }

private:
    F action_;
};

/// Stores the callable by value; C++17 copy elision keeps the guard in its scope.
template <typename F>
[[nodiscard]] ScopeExit<std::decay_t<F>> make_scope_exit(F &&action) {
    return ScopeExit<std::decay_t<F>>(std::forward<F>(action));
}

}  // namespace c2pa::sm::detail

#endif
