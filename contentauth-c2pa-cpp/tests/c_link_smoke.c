/* Copyright 2026 Adobe. Licensed under Apache-2.0 OR MIT. */

/* Links and runs a plain C11 client against the canonical contentauth-c2pa-c-api
 * header and static library, the same ones the C++ wrappers use. It drives a
 * read session by hand, as any host without C++ would. */
#include "contentauth_c2pa_c_api.h"

#include <stdio.h>
#include <stdlib.h>
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

static C2paSmBuildSession *new_build(void) {
    static const char definition[] =
        "{\"title\":\"lease.jpg\","
        "\"instance_id\":\"xmp:iid:00000000-0000-4000-8000-000000000001\","
        "\"label\":\"urn:uuid:00000000-0000-4000-8000-000000000002\","
        "\"claim_generator_info\":[{\"name\":\"c-link-smoke\",\"version\":\"0.1\"}]}";
    C2paSmBuffer certificate = {(const uint8_t *)"x", 1};
    C2paSmBuildSession *session = NULL;
    C2paSmError *error = NULL;
    CHECK(c2pa_sm_build_session_new(definition, "jpeg", "es256", &certificate, 1,
                                   &session, &error) == C2PA_SM_OK);
    CHECK(session != NULL && error == NULL);
    c2pa_sm_error_free(error);
    return session;
}

static int pending_build_request(C2paSmBuildSession *session, int kind,
                                 C2paSmBuildRequest *out) {
    for (int turn = 0; session != NULL && turn < 32; turn += 1) {
        int done = 0;
        size_t count = 0;
        C2paSmError *error = NULL;
        int status = c2pa_sm_build_session_advance(session, &done, &count, &error);
        CHECK(status == C2PA_SM_OK && error == NULL && !done && count > 0);
        c2pa_sm_error_free(error);
        if (status != C2PA_SM_OK || done || count == 0) return 0;
        C2paSmBuildRequest *requests = calloc(count, sizeof *requests);
        CHECK(requests != NULL);
        if (requests == NULL) return 0;
        for (size_t index = 0; index < count; index += 1) {
            error = NULL;
            status = c2pa_sm_build_session_request(session, index, &requests[index], &error);
            CHECK(status == C2PA_SM_OK && error == NULL);
            c2pa_sm_error_free(error);
            if (status != C2PA_SM_OK) {
                free(requests);
                return 0;
            }
            if (requests[index].kind == kind) {
                *out = requests[index];
                free(requests);
                return 1;
            }
        }
        for (size_t index = 0; index < count; index += 1) {
            C2paSmBuildRequest request = requests[index];
            C2paSmBuildReply reply = {0};
            reply.id = request.id;
            if (request.kind == C2PA_SM_BUILD_REQUEST_LENGTH) {
                reply.kind = C2PA_SM_BUILD_REPLY_LENGTH;
                reply.value = sizeof ASSET;
            } else if (request.kind == C2PA_SM_BUILD_REQUEST_READ) {
                CHECK(request.stream == C2PA_SM_BUILD_SOURCE);
                if (request.offset > sizeof ASSET || request.len > sizeof ASSET - request.offset) {
                    CHECK(0);
                    free(requests);
                    return 0;
                }
                reply.kind = C2PA_SM_BUILD_REPLY_BYTES;
                reply.data = (C2paSmBuffer){ASSET + request.offset, (size_t)request.len};
            } else {
                CHECK(0);
                free(requests);
                return 0;
            }
            error = NULL;
            status = c2pa_sm_build_session_fulfill(session, &reply, &error);
            CHECK(status == C2PA_SM_OK && error == NULL);
            c2pa_sm_error_free(error);
            if (status != C2PA_SM_OK) {
                free(requests);
                return 0;
            }
        }
        free(requests);
    }
    CHECK(0);
    return 0;
}

static void read_leases_have_explicit_ownership_transitions(void) {
    for (int cancel = 0; cancel < 3; cancel += 1) {
        C2paSmBuildSession *session = new_build();
        C2paSmBuildRequest request;
        C2paSmReadBuffer *buffer = NULL;
        C2paSmCompletedRead *completed = NULL;
        C2paSmMutableBytes bytes = {0};
        C2paSmError *error = NULL;
        if (!pending_build_request(session, C2PA_SM_BUILD_REQUEST_READ, &request)) {
            CHECK(c2pa_sm_build_session_free(session, NULL) == C2PA_SM_OK);
            continue;
        }
        int status = c2pa_sm_build_read_acquire(session, request.id, &buffer, &bytes, &error);
        CHECK(status == C2PA_SM_OK && error == NULL && buffer != NULL);
        c2pa_sm_error_free(error);
        if (status != C2PA_SM_OK) {
            CHECK(c2pa_sm_build_session_free(session, NULL) == C2PA_SM_OK);
            continue;
        }
        CHECK(bytes.len == request.len && bytes.len > 0 && bytes.data != NULL);
        memset(bytes.data, 42, bytes.len);
        C2paSmReadBuffer *original = buffer;
        error = NULL;
        CHECK(c2pa_sm_read_seal(&buffer, bytes.len + 1, &completed, &error) ==
              C2PA_SM_ERR_INVALID_ARGUMENT);
        CHECK(buffer == original && completed == NULL && error != NULL);
        c2pa_sm_error_free(error);
        if (cancel) {
            CHECK(c2pa_sm_build_session_free(session, NULL) == C2PA_SM_OK);
            CHECK(bytes.data[0] == 42);
        }
        if (cancel == 2) {
            CHECK(c2pa_sm_read_buffer_free(&buffer, NULL) == C2PA_SM_OK);
            CHECK(buffer == NULL);
            continue;
        }
        error = NULL;
        status = c2pa_sm_read_seal(&buffer, bytes.len, &completed, &error);
        CHECK(status == C2PA_SM_OK && buffer == NULL && completed != NULL && error == NULL);
        c2pa_sm_error_free(error);
        if (status == C2PA_SM_OK) {
            C2paSmCompletedRead *sealed = completed;
            error = NULL;
            CHECK(c2pa_sm_build_fulfill_read(session, UINT64_MAX, &completed, &error) ==
                  C2PA_SM_ERR_INVALID_ARGUMENT);
            CHECK(completed == sealed && error != NULL);
            c2pa_sm_error_free(error);
            if (!cancel) {
                error = NULL;
                CHECK(c2pa_sm_build_fulfill_read(session, request.id, &completed, &error) ==
                      C2PA_SM_OK);
                CHECK(completed == NULL && error == NULL);
                c2pa_sm_error_free(error);
            }
        }
        CHECK(c2pa_sm_read_buffer_free(&buffer, NULL) == C2PA_SM_OK);
        CHECK(c2pa_sm_completed_read_free(&completed, NULL) == C2PA_SM_OK);
        CHECK(completed == NULL);
        if (!cancel) CHECK(c2pa_sm_build_session_free(session, NULL) == C2PA_SM_OK);
    }
}

static void write_leases_outlive_acknowledgment_and_session_destruction(void) {
    C2paSmBuildSession *session = new_build();
    C2paSmBuildRequest request;
    if (pending_build_request(session, C2PA_SM_BUILD_REQUEST_WRITE, &request)) {
        CHECK(request.data.len > 0);
        uint8_t first = request.data.data[0];
        C2paSmWriteBuffer *buffer = NULL;
        C2paSmBuffer bytes = {0};
        C2paSmError *error = NULL;
        int status = c2pa_sm_build_write_acquire(session, request.id, &buffer, &bytes, &error);
        CHECK(status == C2PA_SM_OK && error == NULL && buffer != NULL);
        c2pa_sm_error_free(error);
        if (status == C2PA_SM_OK) {
            CHECK(bytes.data == request.data.data && bytes.len == request.data.len);
            CHECK(bytes.len > 0);
            CHECK(request.data.data[0] == first);
            C2paSmBuildReply reply = {0};
            reply.id = request.id;
            reply.kind = C2PA_SM_BUILD_REPLY_WRITTEN;
            error = NULL;
            CHECK(c2pa_sm_build_session_fulfill(session, &reply, &error) == C2PA_SM_OK);
            CHECK(error == NULL);
            c2pa_sm_error_free(error);
            CHECK(c2pa_sm_build_session_free(session, NULL) == C2PA_SM_OK);
            session = NULL;
            CHECK(bytes.data[0] == first);
        }
        CHECK(c2pa_sm_write_buffer_free(&buffer, NULL) == C2PA_SM_OK);
        CHECK(buffer == NULL);
    }
    CHECK(c2pa_sm_build_session_free(session, NULL) == C2PA_SM_OK);
}

int main(void) {
    const char *version = c2pa_sm_version();
    CHECK(version != NULL && version[0] != '\0');
    reads_an_asset_without_a_manifest();
    reports_owned_errors();
    selects_registered_formats();
    rejects_a_bad_signing_definition();
    read_leases_have_explicit_ownership_transitions();
    write_leases_outlive_acknowledgment_and_session_destruction();
    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("c2pa_sm C link smoke: ok");
    return 0;
}
