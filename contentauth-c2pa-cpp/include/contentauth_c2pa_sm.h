/* Copyright 2026 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License,
 * Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * or the MIT license (http://opensource.org/licenses/MIT),
 * at your option.
 *
 * Unless required by applicable law or agreed to in writing,
 * this software is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
 * implied. See the LICENSE-MIT and LICENSE-APACHE files for the
 * specific language governing permissions and limitations under
 * each license.
 */

/* C ABI of contentauth-c2pa-cpp: the sans-I/O C2PA reader session.
 *
 * Hand-written to match src/lib.rs (the documentation of every function
 * lives there). The C++ test suite links against the real library, so a
 * mismatch is a link or test failure rather than silent drift.
 *
 * Contract in one paragraph: no function here blocks, spawns, locks, or
 * calls back; a session is movable between threads but must not be used
 * from two at once; errors are values returned through an out-parameter,
 * never thread-local state.
 */

#ifndef CONTENTAUTH_C2PA_SM_H
#define CONTENTAUTH_C2PA_SM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct C2paSmSession C2paSmSession; /* a read in progress */
typedef struct C2paSmReader C2paSmReader;   /* a finished read, immutable */
typedef struct C2paSmError C2paSmError;     /* an error, by value */

enum {
    C2PA_SM_OK = 0,
    C2PA_SM_ERR_INVALID_ARGUMENT = 1,
    C2PA_SM_ERR_UNSUPPORTED_TYPE = 2,
    C2PA_SM_ERR_NOT_FOUND = 3,
    C2PA_SM_ERR_READ = 4,
    C2PA_SM_ERR_PANIC = 5
};

enum {
    C2PA_SM_REQUEST_READ = 0,   /* start, len        -> REPLY_BYTES  */
    C2PA_SM_REQUEST_LENGTH = 1, /*                   -> REPLY_LENGTH */
    C2PA_SM_REQUEST_TIME = 2,   /*                   -> REPLY_TIME   */
    C2PA_SM_REQUEST_OCSP = 3    /* url, body         -> REPLY_OCSP   */
};

enum {
    C2PA_SM_REPLY_BYTES = 0,
    C2PA_SM_REPLY_LENGTH = 1,
    C2PA_SM_REPLY_TIME = 2,
    C2PA_SM_REPLY_OCSP = 3,
    C2PA_SM_REPLY_FAILED = 4 /* valid for any request; data = UTF-8 message */
};

/* Pointers borrow from the session until the next call that takes it
 * mutably (advance, fulfill, finish, free). */
typedef struct C2paSmRequest {
    int kind;
    uint64_t id;
    uint64_t start;
    uint64_t len;
    const char *url; /* UTF-8, NOT NUL-terminated */
    size_t url_len;
    const uint8_t *body;
    size_t body_len;
} C2paSmRequest;

/* Copied by fulfill; the host may free `data` as soon as it returns. */
typedef struct C2paSmReply {
    int kind;
    uint64_t id;
    int64_t value;
    const uint8_t *data;
    size_t data_len;
} C2paSmReply;

const char *c2pa_sm_version(void);

int c2pa_sm_session_new(const char *format, const char *settings_json /* nullable */,
                        C2paSmSession **out_session, C2paSmError **out_error);
void c2pa_sm_session_free(C2paSmSession *session);
int c2pa_sm_session_advance(C2paSmSession *session, int *out_done, C2paSmError **out_error);
size_t c2pa_sm_session_request_count(const C2paSmSession *session);
bool c2pa_sm_session_request(const C2paSmSession *session, size_t index, C2paSmRequest *out);
int c2pa_sm_session_fulfill(C2paSmSession *session, const C2paSmReply *reply,
                            C2paSmError **out_error);
/* Always consumes `session`. *out_reader is NULL with C2PA_SM_OK if the
 * asset has no manifest store. */
int c2pa_sm_session_finish(C2paSmSession *session, C2paSmReader **out_reader,
                           C2paSmError **out_error);

void c2pa_sm_reader_free(C2paSmReader *reader);
char *c2pa_sm_reader_json(const C2paSmReader *reader);         /* free with string_free */
char *c2pa_sm_reader_active_label(const C2paSmReader *reader); /* NULL if none */
bool c2pa_sm_reader_is_embedded(const C2paSmReader *reader);
void c2pa_sm_string_free(char *s);

int c2pa_sm_error_code(const C2paSmError *error);
const char *c2pa_sm_error_message(const C2paSmError *error);
const char *c2pa_sm_error_name(const C2paSmError *error); /* e.g. "C2pa(JumbfNotFound)" */
void c2pa_sm_error_free(C2paSmError *error);

#ifdef __cplusplus
}
#endif

#endif /* CONTENTAUTH_C2PA_SM_H */
