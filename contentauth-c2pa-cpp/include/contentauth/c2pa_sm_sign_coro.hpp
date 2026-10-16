#ifndef CONTENTAUTH_C2PA_SM_SIGN_CORO_HPP
#define CONTENTAUTH_C2PA_SM_SIGN_CORO_HPP

#include "c2pa_sm_coro.hpp"
#include "c2pa_sm_sign_async.hpp"

namespace c2pa::sm {

/// Builds without blocking; replies resume the task on their delivery thread.
/// Link c2pa_sm_coro (C++20). The host must outlive all started work.
/// Destroying a suspended, quiescent task disarms its wakeup. Destruction must
/// be externally serialized with active execution and callback-driven resume,
/// including a wakeup already selected for delivery. Task::get is blocking.
Task<SignReport> co_build_and_sign(BuildSession session, AsyncBuildHost &host);

}  // namespace c2pa::sm

#endif