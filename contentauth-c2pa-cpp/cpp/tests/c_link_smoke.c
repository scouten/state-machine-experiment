/* Copyright 2026 Adobe. Licensed under Apache-2.0 OR MIT. */

/* Links and runs a plain C11 client against the canonical contentauth-c2pa-c-api
 * header and static library, the same ones the C++ wrappers use. It drives a
 * read session by hand, as any host without C++ would. */
#include "contentauth_c2pa_c_api.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,    \
                    #condition);                                                \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

/* The smallest structurally valid JPEG: SOI, EOI. It carries no manifest. */
static const uint8_t ASSET[] = {0xff, 0xd8, 0xff, 0xd9};

static int answer(C2paSmSession *session, const C2paSmRequest *request) {
    C2paSmReply reply;
    C2paSmError *error = NULL;
    static const char failure[] = "unexpected request";
    memset(&reply, 0, sizeof reply);
    reply.id = request->id;
    switch (request->kind) {
    case C2PA_SM_REQUEST_LENGTH:
        reply.kind = C2PA_SM_REPLY_LENGTH;
        reply.value = (int64_t)sizeof ASSET;
        break;
    case C2PA_SM_REQUEST_READ:
        reply.kind = C2PA_SM_REPLY_BYTES;
        if (request->start > sizeof ASSET || request->len > sizeof ASSET - request->start) {
            reply.kind = C2PA_SM_REPLY_FAILED;
            reply.data = (const uint8_t *)failure;
            reply.data_len = sizeof failure - 1;
        } else {
            reply.data = ASSET + request->start;
            reply.data_len = (size_t)request->len;
        }
        break;
    default:
        reply.kind = C2PA_SM_REPLY_FAILED;
        reply.data = (const uint8_t *)failure;
        reply.data_len = sizeof failure - 1;
        break;
    }
    int status = c2pa_sm_session_fulfill(session, &reply, &error);
    c2pa_sm_error_free(error);
    return status;
}

static void reads_an_asset_without_a_manifest(void) {
    C2paSmSession *session = NULL;
    C2paSmReader *reader = NULL;
    C2paSmError *error = NULL;

    CHECK(c2pa_sm_session_new("jpeg", NULL, &session, &error) == C2PA_SM_OK);
    CHECK(session != NULL && error == NULL);
    for (int turn = 0; session != NULL && turn < 16; turn += 1) {
        int done = 0;
        CHECK(c2pa_sm_session_advance(session, &done, &error) == C2PA_SM_OK);
        if (done) {
            break;
        }
        size_t count = c2pa_sm_session_request_count(session);
        CHECK(count > 0);
        for (size_t index = 0; index < count; index += 1) {
            C2paSmRequest request;
            CHECK(c2pa_sm_session_request(session, index, &request));
            CHECK(answer(session, &request) == C2PA_SM_OK);
        }
    }
    CHECK(c2pa_sm_session_finish(session, &reader, &error) == C2PA_SM_OK);
    CHECK(reader == NULL && error == NULL);
    CHECK(c2pa_sm_reader_validation_state(reader) == C2PA_SM_VALIDATION_UNAVAILABLE);
}

static void reports_owned_errors(void) {
    C2paSmSession *session = NULL;
    C2paSmError *error = NULL;

    int status = c2pa_sm_session_new("png", NULL, &session, &error);
    CHECK(status == C2PA_SM_ERR_UNSUPPORTED_TYPE);
    CHECK(session == NULL && error != NULL);
    CHECK(c2pa_sm_error_code(error) == C2PA_SM_ERR_UNSUPPORTED_TYPE);
    CHECK(c2pa_sm_error_message(error) != NULL);
    CHECK(c2pa_sm_error_name(error) != NULL);
    c2pa_sm_error_free(error);
}

static void selects_registered_formats(void) {
    static const char *const formats[] = {"image/jpeg", "image/jpg", "tif", "image/tiff", "dng"};
    for (size_t index = 0; index < sizeof formats / sizeof formats[0]; index += 1) {
        C2paSmSession *session = NULL;
        C2paSmError *error = NULL;
        CHECK(c2pa_sm_session_new(formats[index], NULL, &session, &error) == C2PA_SM_OK);
        CHECK(session != NULL && error == NULL);
        c2pa_sm_session_free(session);
    }
}

static void rejects_a_bad_signing_definition(void) {
    C2paSmBuildSession *session = NULL;
    C2paSmError *error = NULL;
    C2paSmBuffer certificate = {(const uint8_t *)"x", 1};

    int status = c2pa_sm_build_session_new("not json", "jpeg", "es256", &certificate, 1,
                                           &session, &error);
    CHECK(status != C2PA_SM_OK);
    CHECK(session == NULL && error != NULL);
    c2pa_sm_error_free(error);
}

int main(void) {
    const char *version = c2pa_sm_version();
    CHECK(version != NULL && version[0] != '\0');
    reads_an_asset_without_a_manifest();
    reports_owned_errors();
    selects_registered_formats();
    rejects_a_bad_signing_definition();
    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("c2pa_sm C link smoke: ok");
    return 0;
}
