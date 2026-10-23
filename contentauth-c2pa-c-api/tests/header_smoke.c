/* Copyright 2026 Adobe. Licensed under Apache-2.0 OR MIT. */
#include "../include/contentauth_c2pa_c_api.h"
#include <stddef.h>

#ifdef __cplusplus
#define ABI_ASSERT static_assert
#else
#define ABI_ASSERT _Static_assert
#endif

ABI_ASSERT(C2PA_SM_OK == 0, "success");
ABI_ASSERT(C2PA_SM_ERR_BUILD == 6, "build error code");
ABI_ASSERT(C2PA_SM_BUILD_REQUEST_TIMESTAMP == 4, "timestamp request");
ABI_ASSERT(C2PA_SM_BUILD_REPLY_FAILED == 5, "failure reply");
ABI_ASSERT(C2PA_SM_BUILD_SOURCE == 0 && C2PA_SM_BUILD_OUTPUT == 1, "streams");
ABI_ASSERT(C2PA_SM_VALIDATION_UNAVAILABLE == -1, "missing reader");
ABI_ASSERT(offsetof(C2paSmRequest, kind) == 0, "read request discriminator");
ABI_ASSERT(offsetof(C2paSmBuildRequest, kind) == 0, "build request discriminator");
ABI_ASSERT(sizeof(((C2paSmRequest *)0)->id) == sizeof(uint64_t), "request IDs");
ABI_ASSERT(sizeof(((C2paSmBuildRequest *)0)->kind) == sizeof(int), "integer discriminators");
ABI_ASSERT(sizeof(C2paSmBuffer) == sizeof(C2paSmMutableBytes), "buffer views");

int header_smoke(void) {
    C2paSmSession *session = NULL;
    C2paSmBuildSession *build = NULL;
    C2paSmError *error = NULL;
    C2paSmBuffer cert = {NULL, 0};
    /* Deliberately refer to both workflows even for single-feature builds. */
    int read_status = c2pa_sm_session_new("jpeg", NULL, &session, &error);
    int build_status = c2pa_sm_build_session_new("{}", "tiff", "es256",
                                                &cert, 1, &build, &error);
    c2pa_sm_session_free(session);
    c2pa_sm_error_free(error);
    return read_status + build_status + c2pa_sm_build_session_free(build, NULL);
}
