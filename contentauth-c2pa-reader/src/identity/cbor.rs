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

//! Locating a CBOR item's exact bytes inside an enclosing item, with
//! `c2pa_cbor` doing all the decoding.
//!
//! An identity assertion's signature covers the `signer_payload` *as the
//! signer encoded it*, so verification needs those bytes, not a decoded
//! and re-encoded equivalent: `c2pa_cbor::Value` keeps maps sorted, and a
//! signer that wrote its fields in another order (c2pa-rs writes
//! `referenced_assertions`, `sig_type`, `role`) would otherwise turn a good
//! signature into a mismatch. Decoding throws the original encoding away,
//! so the decoder is run over a reader that counts what it consumes, and
//! the offsets either side of the wanted value are read off it.

use std::{
    cell::Cell,
    fmt,
    io::{self, Read},
    rc::Rc,
};

use c2pa_cbor::{Decoder, Value};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

/// A reader over a slice that publishes how much has been consumed.
struct Counting<'a> {
    bytes: &'a [u8],
    consumed: Rc<Cell<usize>>,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.bytes.len().min(buf.len());
        let (head, rest) = self.bytes.split_at(n);
        buf[..n].copy_from_slice(head);
        self.bytes = rest;
        self.consumed.set(self.consumed.get() + n);
        Ok(n)
    }
}

/// Walks a map, noting the span of the value stored under `key`.
struct FindValue<'k> {
    key: &'k str,
    consumed: Rc<Cell<usize>>,
    span: Rc<Cell<Option<(usize, usize, Value)>>>,
}

impl<'de> Visitor<'de> for FindValue<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = false;
        while let Some(key) = map.next_key::<Value>()? {
            // A decoder reads a key and then the value that follows it, so
            // the count is at the start of the value here.
            if key.as_str() == Some(self.key) && !seen {
                seen = true;
                let start = self.consumed.get();
                let value: Value = map.next_value()?;
                self.span.set(Some((start, self.consumed.get(), value)));
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// Returns the exact bytes of the value stored under the text key `key` in
/// the CBOR map that is `bytes`.
///
/// `None` if `bytes` is not a map, is malformed, or has no such key. The
/// first of any duplicated keys wins.
///
/// The span is checked before it is returned: decoding it on its own must
/// succeed, consume it entirely, and give the value the walk saw. That
/// guards against the count being off — by a byte the decoder looked ahead
/// at, say — so a wrong span is refused instead of verified against.
pub(super) fn map_value<'a>(bytes: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let consumed = Rc::new(Cell::new(0));
    let span = Rc::new(Cell::new(None));

    let mut decoder = Decoder::new(Counting {
        bytes,
        consumed: Rc::clone(&consumed),
    });
    (&mut decoder)
        .deserialize_map(FindValue {
            key,
            consumed,
            span: Rc::clone(&span),
        })
        .ok()?;

    let (start, end, value) = span.take()?;
    let found = bytes.get(start..end)?;

    (c2pa_cbor::from_slice::<Value>(found).ok()? == value).then_some(found)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn encode(value: &Value) -> Vec<u8> {
        c2pa_cbor::to_vec(value).unwrap_or_default()
    }

    fn sample() -> Vec<u8> {
        encode(&Value::Map(
            [
                (
                    Value::Text("a".into()),
                    Value::Array(vec![Value::Integer(1), Value::Text("x".into())]),
                ),
                (Value::Text("b".into()), Value::Bytes(vec![9; 300])),
                (
                    Value::Text("c".into()),
                    Value::Tag(55799, Box::new(Value::Integer(-70_000))),
                ),
            ]
            .into_iter()
            .collect(),
        ))
    }

    #[test]
    fn finds_each_entry_exactly() {
        let bytes = sample();

        assert_eq!(
            map_value(&bytes, "a"),
            Some(
                &encode(&Value::Array(vec![
                    Value::Integer(1),
                    Value::Text("x".into())
                ]))[..]
            )
        );
        assert_eq!(
            map_value(&bytes, "b"),
            Some(&encode(&Value::Bytes(vec![9; 300]))[..])
        );
        assert_eq!(
            map_value(&bytes, "c"),
            Some(&encode(&Value::Tag(55799, Box::new(Value::Integer(-70_000))))[..])
        );
    }

    #[test]
    fn a_missing_key_is_none() {
        assert_eq!(map_value(&sample(), "z"), None);
    }

    #[test]
    fn something_other_than_a_map_is_none() {
        assert_eq!(map_value(&encode(&Value::Integer(1)), "a"), None);
        assert_eq!(map_value(&[], "a"), None);
    }

    #[test]
    fn the_encoders_key_order_is_preserved_not_sorted() {
        // `z` before `a`: a decode to `Value` and back would swap them.
        let bytes = [
            0xa2, 0x61, b'z', 0x01, 0x61, b'a', 0xa2, 0x62, b'y', b'y', 0x01, 0x62, b'x', b'x',
            0x02,
        ];
        let found = map_value(&bytes, "a").unwrap();
        assert_eq!(found, &bytes[6..]);
    }

    #[test]
    fn indefinite_length_items_are_located_exactly() {
        // {"k": {_ "b": 1, "a": 2}} with an indefinite-length inner map.
        let bytes = [
            0xa1, 0x61, b'k', 0xbf, 0x61, b'b', 0x01, 0x61, b'a', 0x02, 0xff,
        ];
        assert_eq!(map_value(&bytes, "k"), Some(&bytes[3..]));

        // And an indefinite-length outer map, with the wanted entry
        // followed by another.
        let bytes = [0xbf, 0x61, b'k', 0x82, 0x01, 0x02, 0x61, b'm', 0x03, 0xff];
        assert_eq!(map_value(&bytes, "k"), Some(&bytes[3..6]));
    }

    #[test]
    fn truncated_or_malformed_input_is_none() {
        // A value promised but missing.
        assert_eq!(map_value(&[0xa1, 0x61, b'a'], "a"), None);
        // A byte string longer than the input.
        assert_eq!(map_value(&[0xa1, 0x61, b'a', 0x45, 1, 2], "a"), None);
        // Reserved additional information.
        assert_eq!(map_value(&[0xa1, 0x61, b'a', 0x1c], "a"), None);
    }

    #[test]
    fn non_text_and_non_utf8_keys_never_match() {
        let mixed = [0xa2, 0x01, 0x02, 0x61, b'k', 0x03];
        assert_eq!(map_value(&mixed, "k"), Some(&[0x03][..]));

        let bad = [0xa1, 0x61, 0xff, 0x01];
        assert_eq!(map_value(&bad, "a"), None);
    }

    #[test]
    fn the_first_of_duplicate_keys_wins() {
        let bytes = [0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        assert_eq!(map_value(&bytes, "a"), Some(&[0x01][..]));
    }

    #[test]
    fn nesting_beyond_the_decoders_limit_is_none() {
        let mut deep = vec![0xa1, 0x61, b'a'];
        deep.extend(std::iter::repeat_n(0x81, 5_000));
        deep.push(0x00);
        assert_eq!(map_value(&deep, "a"), None);
    }

    #[test]
    fn the_reader_reports_a_short_read_as_end_of_input() {
        let consumed = Rc::new(Cell::new(0));
        let mut reader = Counting {
            bytes: &[1, 2, 3],
            consumed: Rc::clone(&consumed),
        };

        let mut buf = [0u8; 8];
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(consumed.get(), 3);
    }
}
