// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

use super::*;

#[test]
fn c_api_constructor_scenarios_validate_each_string_with_valid_companion_fields() {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let certificate = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    for (definition, format, algorithm) in [
        (definition.as_ptr(), c"\xff".as_ptr(), c"es256".as_ptr()),
        (
            definition.as_ptr(),
            c"image/jpeg".as_ptr(),
            c"\xff".as_ptr(),
        ),
        (
            definition.as_ptr(),
            c"image/jpeg".as_ptr(),
            c"unsupported".as_ptr(),
        ),
    ] {
        let mut session = ptr::null_mut();
        let mut error = ptr::null_mut();
        let code = unsafe {
            c2pa_sm_build_session_new(
                definition,
                format,
                algorithm,
                &certificate,
                1,
                &mut session,
                &mut error,
            )
        };
        let (code, message) = result(code, error).unwrap_err();
        assert_eq!(code, crate::C2PA_SM_ERR_INVALID_ARGUMENT);
        assert!(!message.is_empty());
        assert!(session.is_null());
    }
}

#[test]
fn build_format_aliases_select_registered_handlers() {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let certificate = C2paSmBuffer::borrowed(TEST_SIGNER_CERT);
    for (format, supported) in [
        (c"image/jpeg", true),
        (c"jpeg", true),
        (c"jpg", true),
        (c"JPEG", true),
        (c"image/jpg", true),
        (c"image/tiff", true),
        (c"tiff", true),
        (c"dng", true),
        (c"image/png", false),
    ] {
        let mut session = ptr::null_mut();
        let mut error = ptr::null_mut();
        let code = unsafe {
            c2pa_sm_build_session_new(
                definition.as_ptr(),
                format.as_ptr(),
                c"es256".as_ptr(),
                &certificate,
                1,
                &mut session,
                &mut error,
            )
        };
        if supported {
            result(code, error).unwrap();
            assert!(!session.is_null());
            let mut error = ptr::null_mut();
            let code = unsafe { c2pa_sm_build_session_free(session, &mut error) };
            result(code, error).unwrap();
        } else {
            assert_eq!(
                result(code, error).unwrap_err().0,
                crate::C2PA_SM_ERR_UNSUPPORTED_TYPE
            );
            assert!(session.is_null());
        }
    }
}

#[test]
fn empty_certificate_chain_and_entries_are_not_rejected_at_construction() {
    let definition = CString::new(BASELINE_DEFINITION).unwrap();
    let empty = C2paSmBuffer::default();
    for count in [0, 1] {
        let mut session = ptr::null_mut();
        let mut error = ptr::null_mut();
        let code = unsafe {
            c2pa_sm_build_session_new(
                definition.as_ptr(),
                c"image/jpeg".as_ptr(),
                c"es256".as_ptr(),
                &empty,
                count,
                &mut session,
                &mut error,
            )
        };
        result(code, error).unwrap();
        assert!(!session.is_null());
        let mut error = ptr::null_mut();
        let code = unsafe { c2pa_sm_build_session_free(session, &mut error) };
        result(code, error).unwrap();
    }
}

#[test]
fn c_api_unknown_build_ids_are_rejected_for_every_reply_kind() {
    let mut build = Build::new(BASELINE_DEFINITION);
    for kind in 0..=5 {
        assert_eq!(
            build
                .fulfill(C2paSmBuildReply {
                    id: u64::MAX,
                    kind,
                    data: C2paSmBuffer::borrowed(b"host reply"),
                    ..Default::default()
                })
                .unwrap_err()
                .0,
            crate::C2PA_SM_ERR_INVALID_ARGUMENT,
            "reply kind {kind}",
        );
    }
    assert!(
        Host::default()
            .drive(&mut build)
            .unwrap()
            .view()
            .manifest
            .len
            > 0
    );
}

#[test]
fn c_api_malformed_payload_matrix_preserves_the_pending_build_request() {
    let mut build = Build::new(BASELINE_DEFINITION);
    assert_eq!(build.advance().unwrap(), (false, 1));
    let request = build.request(0).unwrap();
    for kind in [0, 3, 4, 5] {
        for data in [
            C2paSmBuffer {
                data: ptr::null(),
                len: 1,
            },
            C2paSmBuffer {
                data: TEST_SIGNER_CERT.as_ptr(),
                len: usize::MAX,
            },
        ] {
            assert_eq!(
                build
                    .fulfill(C2paSmBuildReply {
                        id: request.id,
                        kind,
                        data,
                        ..Default::default()
                    })
                    .unwrap_err()
                    .0,
                crate::C2PA_SM_ERR_INVALID_ARGUMENT,
                "reply kind {kind}",
            );
        }
    }
    assert_eq!(build.advance().unwrap(), (false, 0));
    build
        .fulfill(C2paSmBuildReply {
            id: request.id,
            kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_LENGTH as c_int,
            value: SOURCE_JPEG.len() as u64,
            ..Default::default()
        })
        .unwrap();
    assert!(
        Host::default()
            .drive(&mut build)
            .unwrap()
            .view()
            .manifest
            .len
            > 0
    );
}

#[test]
fn c_api_failed_build_remains_terminal_and_finish_returns_no_report() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    build
        .fulfill(C2paSmBuildReply {
            id: request.id,
            kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_FAILED as c_int,
            data: C2paSmBuffer::borrowed(b"build cancelled"),
            ..Default::default()
        })
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            build.advance().unwrap_err().0,
            C2paSmBuildErrorCode::C2PA_SM_ERR_BUILD as c_int,
        );
    }
    assert!(build.finish().is_err());
    assert!(build.0.is_null());
}

#[test]
fn empty_copying_read_reply_is_accepted_then_rejected_by_engine_length_validation() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    assert!(request.len > 0);
    build
        .fulfill(C2paSmBuildReply {
            id: request.id,
            kind: C2paSmBuildReplyKind::C2PA_SM_BUILD_REPLY_BYTES as c_int,
            data: C2paSmBuffer::default(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        build.advance().unwrap_err().0,
        C2paSmBuildErrorCode::C2PA_SM_ERR_BUILD as c_int,
    );
}

#[test]
fn c_api_short_form_timestamp_token_is_embedded_without_its_response_envelope() {
    let response = [
        0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x02, 0x01, 0x2a,
    ];
    let mut build = Build::new(&timestamp_definition());
    let mut host = Host {
        timestamp: response.to_vec(),
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = host.drive(&mut build).unwrap();
    assert_eq!(host.seen[4], 1);
    let view = report.view();
    let manifest = unsafe { view.manifest.bytes().unwrap() };
    assert!(manifest
        .windows(response[7..].len())
        .any(|bytes| bytes == &response[7..]));
    assert!(!manifest
        .windows(response.len())
        .any(|bytes| bytes == response));
}

#[test]
fn c_api_returned_manifest_is_embedded_and_every_exclusion_is_nonempty_and_in_bounds() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let mut host = Host {
        leased: true,
        leased_writes: true,
        ..Default::default()
    };
    let report = host.drive(&mut build).unwrap();
    let view = report.view();
    let manifest = unsafe { view.manifest.bytes().unwrap() };
    assert!(!manifest.is_empty());
    assert!(host
        .output
        .windows(manifest.len())
        .any(|bytes| bytes == manifest));
    let exclusions = unsafe { std::slice::from_raw_parts(view.exclusions, view.exclusion_count) };
    assert!(!exclusions.is_empty());
    for exclusion in exclusions {
        assert!(exclusion.len > 0);
        assert!(exclusion.start <= host.output.len() as u64);
        assert!(exclusion.len <= host.output.len() as u64 - exclusion.start);
    }
}

#[test]
fn all_build_session_exports_reject_null_and_wrong_type_handles_without_consuming_results() {
    let mut build = Build::new(BASELINE_DEFINITION);
    let report = Host::default().drive(&mut build).unwrap();
    for session in [ptr::null_mut(), report.0.cast::<C2paSmBuildSession>()] {
        unsafe {
            let mut done = 42;
            let mut count = 42;
            invalid(|error| c2pa_sm_build_session_advance(session, &mut done, &mut count, error));
            assert_eq!((done, count), (0, 0));
            let mut request = C2paSmBuildRequest {
                id: 42,
                ..Default::default()
            };
            invalid(|error| c2pa_sm_build_session_request(session, 0, &mut request, error));
            assert_eq!(request.id, 0);
            invalid(|error| {
                c2pa_sm_build_session_fulfill(session, &C2paSmBuildReply::default(), error)
            });
            let mut output = ptr::null_mut();
            invalid(|error| c2pa_sm_build_session_finish(session, &mut output, error));
            assert!(output.is_null());
            if !session.is_null() {
                invalid(|error| c2pa_sm_build_session_free(session, error));
            }

            let mut read = ptr::null_mut();
            let mut writable = C2paSmMutableBytes::default();
            invalid(|error| {
                c2pa_sm_build_read_acquire(session, 1, &mut read, &mut writable, error)
            });
            assert!(read.is_null());
            assert!(writable.data.is_null());
            assert_eq!(writable.len, 0);
            let mut write = ptr::null_mut();
            let mut bytes = C2paSmBuffer::default();
            invalid(|error| c2pa_sm_build_write_acquire(session, 1, &mut write, &mut bytes, error));
            assert!(write.is_null());
            assert!(bytes.data.is_null());
            assert_eq!(bytes.len, 0);
            let mut completed = ptr::null_mut();
            invalid(|error| c2pa_sm_build_fulfill_read(session, 1, &mut completed, error));
            assert!(completed.is_null());
        }
    }
    assert!(report.view().manifest.len > 0);
}

#[test]
fn read_lease_wrong_type_and_stale_handles_preserve_the_real_owners() {
    let build = Build::new(BASELINE_DEFINITION);
    let request = build.first_read();
    let checked = cimpl::checkout_exclusive(build.0).unwrap();
    assert!(build.acquire(request.id).is_err());
    drop(checked);

    let mut lease = build.acquire(request.id).unwrap();
    unsafe {
        let mut wrong = build.0.cast::<C2paSmReadBuffer>();
        let mut completed = ptr::null_mut();
        invalid(|error| c2pa_sm_read_seal(&mut wrong, 0, &mut completed, error));
        assert_eq!(wrong, build.0.cast());
        assert!(completed.is_null());
        let mut wrong = lease.raw.cast::<C2paSmCompletedRead>();
        invalid(|error| c2pa_sm_completed_read_free(&mut wrong, error));
        assert_eq!(wrong, lease.raw.cast());
        invalid(|error| c2pa_sm_build_fulfill_read(build.0, request.id, &mut wrong, error));
        assert_eq!(wrong, lease.raw.cast());
    }
    let stale = lease.raw;
    let mut completed = lease.seal(lease.view.len).unwrap();
    assert!(lease.raw.is_null());
    unsafe {
        let mut stale = stale;
        let mut output = ptr::null_mut();
        invalid(|error| c2pa_sm_read_seal(&mut stale, 0, &mut output, error));
        assert!(!stale.is_null());
        assert!(output.is_null());
        invalid(|error| c2pa_sm_read_buffer_free(&mut stale, error));
        assert!(!stale.is_null());

        let stale = completed.0;
        assert_eq!(
            c2pa_sm_completed_read_free(&mut completed.0, ptr::null_mut()),
            C2PA_SM_OK
        );
        assert!(completed.0.is_null());
        let mut stale_slot = stale;
        invalid(|error| c2pa_sm_completed_read_free(&mut stale_slot, error));
        assert_eq!(stale_slot, stale);
    }
}
