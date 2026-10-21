// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#include "contentauth/c2pa_sm.hpp"
#include "contentauth/c2pa_sm_async.hpp"
#include "contentauth/c2pa_sm_sign.hpp"
#include "contentauth/c2pa_sm_sign_async.hpp"
#include "contentauth/thread_pool.hpp"
#include "contentauth_c2pa_c_api.h"

static_assert(__cplusplus == 201703L, "The compatibility check must compile as C++17");

using namespace c2pa::sm;

void check_reading(SyncHost &blocking, AsyncHost &async, std::shared_ptr<AsyncHost> owner,
                   ThreadPool &pool) {
    auto reader = read(Session("image/jpeg"), blocking);
    if (reader) {
        (void)reader->json();
        (void)reader->validation_state();
    }
    Reading reading(Session("image/jpeg"), async);
    while (!reading.step()) reading.mailbox().wait();
    (void)std::move(reading).finish();
    PooledHost pooled(blocking, pool);
    (void)read_parallel(Session("image/jpeg"), pooled);
    (void)read_future(Session("image/jpeg"), std::move(owner)).get();
}

void check_signing(const BuildSettings &settings, SyncBuildHost &blocking,
                   AsyncBuildHost &async, std::shared_ptr<AsyncBuildHost> owner,
                   ThreadPool &pool) {
    (void)build_and_sign(BuildSession(settings), blocking);
    Building building(BuildSession(settings), async);
    while (!building.step()) building.mailbox().wait();
    building.wait();
    (void)std::move(building).finish();
    PooledBuildHost pooled(blocking, pool);
    (void)build_parallel(BuildSession(settings), pooled);
    (void)build_future(BuildSession(settings), std::move(owner)).get();
    auto simple_pool = make_simple_thread_pool(1);
    simple_pool->post([] {});
#if defined(__APPLE__)
    auto apple_pool = make_apple_thread_pool();
    apple_pool->post([] {});
#endif
}

int main() {}
