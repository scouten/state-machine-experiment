#ifndef CONTENTAUTH_C2PA_SM_SIGN_CORO_HPP
#define CONTENTAUTH_C2PA_SM_SIGN_CORO_HPP

#include "c2pa_sm_coro.hpp"
#include "c2pa_sm_sign_async.hpp"

namespace c2pa::sm {

/// Builds without blocking; replies resume the task on their delivery thread.
/// Link c2pa_sm_coro (C++20). The host must outlive all started work.
/// Destruction cancels suspended work and synchronizes with callback-driven
/// resume (including nested Tasks). It does not wait for host I/O to finish:
/// the host must still outlive its accepted requests. Task::get is blocking.
Task<SignReport> co_build_and_sign(BuildSession session, AsyncBuildHost &host);

}  // namespace c2pa::sm

#endif