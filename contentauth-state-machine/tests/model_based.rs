// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Property-based (generative) tests of the session machinery.
//!
//! These run on every `cargo test` with `proptest`'s structured, shrinking
//! generators, and drive the same harnesses (`tests/support/model.rs`) that
//! the coverage-guided `cargo-fuzz` targets in `fuzz/` drive with raw bytes.
//! See the engine README's "Testing and fuzzing" section.

#![allow(clippy::unwrap_used)]

use proptest::prelude::*;

#[path = "support/model.rs"]
mod model;

use model::{
    decode_core, decode_session, run_core, run_session, CoreOp, Kind, Reply, SessionOp,
    SessionScript, Target,
};

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![Just(Kind::A), Just(Kind::B)]
}

fn reply() -> impl Strategy<Value = Reply> {
    prop_oneof![Just(Reply::A), Just(Reply::B), Just(Reply::Failed)]
}

/// Mostly IDs the session really issued, with a tail of arbitrary ones.
fn target() -> impl Strategy<Value = Target> {
    prop_oneof![
        4 => any::<u8>().prop_map(Target::Issued),
        1 => any::<u64>().prop_map(Target::Raw),
    ]
}

fn core_op() -> impl Strategy<Value = CoreOp> {
    prop_oneof![
        3 => kind().prop_map(CoreOp::Issue),
        4 => (target(), reply()).prop_map(|(t, r)| CoreOp::Fulfill(t, r)),
        2 => target().prop_map(CoreOp::TakeReply),
        1 => Just(CoreOp::MarkComplete),
        1 => Just(CoreOp::MarkFailed),
        1 => Just(CoreOp::FinishCheck),
        1 => Just(CoreOp::Inspect),
    ]
}

fn session_op() -> impl Strategy<Value = SessionOp> {
    prop_oneof![
        3 => Just(SessionOp::Advance),
        5 => (target(), reply()).prop_map(|(t, r)| SessionOp::Fulfill(t, r)),
        1 => Just(SessionOp::Inspect),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn session_core_matches_its_model(ops in prop::collection::vec(core_op(), 0..64)) {
        run_core(&ops);
    }

    #[test]
    fn fan_out_session_matches_its_model(
        n in 0u8..6,
        ops in prop::collection::vec(session_op(), 0..64),
    ) {
        run_session(&SessionScript { n, ops });
    }

    /// The byte decoders (the fuzz targets' entry points) accept anything.
    #[test]
    fn arbitrary_bytes_decode_and_run(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        run_core(&decode_core(&bytes));
        run_session(&decode_session(&bytes));
    }
}

/// A well-behaved host reaches `Complete` and `finish` succeeds, for every
/// fan-out width and every order of replies.
#[test]
fn happy_path_completes_for_any_reply_order() {
    use contentauth_state_machine::{RequestId, Session, Step};

    for n in 0..6u8 {
        for reverse in [false, true] {
            let mut session = model::FanOut::new(n as usize);
            let first = session.advance().unwrap();
            if n == 0 {
                assert_eq!(first, Step::Complete);
            } else {
                assert_eq!(first, Step::AwaitHost);
            }

            let mut ids: Vec<RequestId> = session
                .outstanding_requests()
                .iter()
                .map(|r| r.id)
                .collect();
            if reverse {
                ids.reverse();
            }
            for id in ids {
                let reply = match session
                    .outstanding_requests()
                    .iter()
                    .find(|r| r.id == id)
                    .unwrap()
                    .kind
                {
                    Kind::A => Reply::A,
                    Kind::B => Reply::B,
                };
                session.fulfill(id, reply).unwrap();
            }

            assert_eq!(session.advance().unwrap(), Step::Complete);
            assert_eq!(session.advance().unwrap(), Step::Complete);
            assert_eq!(session.finish().unwrap(), n as usize);
        }
    }
}

/// Hand-written seeds for illegal sequences, replayed verbatim so a
/// regression in any of them is named rather than found by chance.
#[test]
fn seed_scripts() {
    use CoreOp::*;

    run_core(&[
        Fulfill(Target::Raw(7), Reply::A),
        Issue(Kind::A),
        Fulfill(Target::Issued(0), Reply::B),
        Fulfill(Target::Issued(0), Reply::A),
        Fulfill(Target::Issued(0), Reply::A),
        TakeReply(Target::Issued(0)),
        TakeReply(Target::Issued(0)),
        MarkFailed,
        Fulfill(Target::Issued(0), Reply::A),
        MarkComplete,
        FinishCheck,
        Fulfill(Target::Issued(0), Reply::A),
    ]);

    run_session(&SessionScript {
        n: 3,
        ops: vec![
            SessionOp::Fulfill(Target::Issued(0), Reply::A),
            SessionOp::Advance,
            SessionOp::Fulfill(Target::Issued(1), Reply::Failed),
            SessionOp::Fulfill(Target::Issued(1), Reply::Failed),
            SessionOp::Advance,
            SessionOp::Advance,
            SessionOp::Fulfill(Target::Issued(2), Reply::A),
        ],
    });
}

/// The tracked fuzz seeds are hand-encoded; this pins each one to the
/// scenario its name promises, so a decoder change cannot silently turn a
/// seed into something else.
#[test]
fn fuzz_seeds_decode_to_their_named_scenarios() {
    use CoreOp::*;

    let a = Target::Issued(0);

    let seed = include_bytes!("../fuzz/corpus/session_core/issue-fulfill-finish");
    let expected = vec![
        Issue(Kind::A),
        Fulfill(a, Reply::A),
        MarkComplete,
        FinishCheck,
    ];
    assert_eq!(decode_core(seed), expected);
    run_core(&expected);

    let seed = include_bytes!("../fuzz/corpus/session_core/mismatch-then-take");
    let expected = vec![
        Issue(Kind::A),
        Fulfill(a, Reply::B),
        Fulfill(a, Reply::A),
        TakeReply(a),
        TakeReply(a),
    ];
    assert_eq!(decode_core(seed), expected);
    run_core(&expected);

    let seed = include_bytes!("../fuzz/corpus/fan_out_session/fan-out-3");
    let expected = SessionScript {
        n: 3,
        ops: vec![
            SessionOp::Advance,
            SessionOp::Fulfill(Target::Issued(0), Reply::A),
            SessionOp::Fulfill(Target::Issued(1), Reply::B),
            SessionOp::Fulfill(Target::Issued(2), Reply::A),
            SessionOp::Advance,
            SessionOp::Advance,
        ],
    };
    assert_eq!(decode_session(seed), expected);
    run_session(&expected);

    let seed = include_bytes!("../fuzz/corpus/fan_out_session/fail-then-advance");
    let expected = SessionScript {
        n: 2,
        ops: vec![
            SessionOp::Advance,
            SessionOp::Fulfill(Target::Issued(0), Reply::Failed),
            SessionOp::Advance,
            SessionOp::Advance,
            SessionOp::Fulfill(Target::Issued(1), Reply::B),
        ],
    };
    assert_eq!(decode_session(seed), expected);
    run_session(&expected);
}
