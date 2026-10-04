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

//! Locating a CBOR item's exact bytes inside an enclosing item.
//!
//! An identity assertion's signature covers the `signer_payload` *as the
//! signer encoded it*, so verification needs those bytes, not a decoded
//! and re-encoded equivalent: a different map order or integer width in
//! someone else's encoder would turn a good signature into a mismatch.
//! Decoding to a `Value` throws the original encoding away, so this module
//! finds where one entry's value starts and ends instead.

/// Deepest nesting this module will walk. Identity assertions are a few
/// levels deep; the bound exists because the input is untrusted.
const MAX_DEPTH: usize = 32;

/// Returns the length in bytes of the CBOR data item at the start of
/// `bytes`, or `None` if it is truncated, uses an indefinite length (which
/// deterministic encodings never do), or nests too deeply.
fn item_len(bytes: &[u8], depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }

    let first = *bytes.first()?;
    let major = first >> 5;
    let info = first & 0x1f;

    let (argument, head) = match info {
        0..=23 => (u64::from(info), 1),
        24 => (u64::from(*bytes.get(1)?), 2),
        25 => (
            u64::from(u16::from_be_bytes(bytes.get(1..3)?.try_into().ok()?)),
            3,
        ),
        26 => (
            u64::from(u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?)),
            5,
        ),
        27 => (u64::from_be_bytes(bytes.get(1..9)?.try_into().ok()?), 9),
        _ => return None,
    };

    match major {
        // Integers and simple values/floats: the head is everything.
        0 | 1 | 7 => Some(head),

        // Byte and text strings: the head, then `argument` bytes.
        2 | 3 => {
            let end = head.checked_add(usize::try_from(argument).ok()?)?;
            (end <= bytes.len()).then_some(end)
        }

        // Arrays and maps: the head, then that many items (two per map
        // entry).
        4 | 5 => {
            let items = if major == 5 {
                argument.checked_mul(2)?
            } else {
                argument
            };

            let mut offset = head;
            for _ in 0..items {
                offset += item_len(bytes.get(offset..)?, depth + 1)?;
            }
            Some(offset)
        }

        // A tag wraps one item.
        _ => Some(head + item_len(bytes.get(head..)?, depth + 1)?),
    }
}

/// Returns the exact bytes of the value stored under the text key `key` in
/// the CBOR map that is `bytes`.
///
/// `None` if `bytes` is not a definite-length map, is malformed, or has no
/// such key. The first of any duplicated keys wins.
pub(super) fn map_value<'a>(bytes: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let first = *bytes.first()?;
    if first >> 5 != 5 {
        return None;
    }

    // Reuse `item_len` to learn where the head ends: a map of zero
    // entries has length equal to its head.
    let (entries, head) = match first & 0x1f {
        info @ 0..=23 => (u64::from(info), 1),
        24 => (u64::from(*bytes.get(1)?), 2),
        25 => (
            u64::from(u16::from_be_bytes(bytes.get(1..3)?.try_into().ok()?)),
            3,
        ),
        26 => (
            u64::from(u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?)),
            5,
        ),
        27 => (u64::from_be_bytes(bytes.get(1..9)?.try_into().ok()?), 9),
        _ => return None,
    };

    let mut offset = head;
    for _ in 0..entries {
        let key_len = item_len(bytes.get(offset..)?, 1)?;
        let key_bytes = bytes.get(offset..offset + key_len)?;
        offset += key_len;

        let value_len = item_len(bytes.get(offset..)?, 1)?;
        let value_bytes = bytes.get(offset..offset + value_len)?;
        offset += value_len;

        if text_key(key_bytes) == Some(key) {
            return Some(value_bytes);
        }
    }

    None
}

/// Reads a definite-length CBOR text string's contents, without
/// allocating. `None` for any other item.
fn text_key(bytes: &[u8]) -> Option<&str> {
    let first = *bytes.first()?;
    if first >> 5 != 3 {
        return None;
    }

    let head = match first & 0x1f {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => return None,
    };

    core::str::from_utf8(bytes.get(head..)?).ok()
}

#[cfg(test)]
mod tests {
    use c2pa_cbor::Value;

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
        assert_eq!(map_value(&[0xbf, 0xff], "a"), None);
    }

    #[test]
    fn every_head_width_is_measured() {
        // Text lengths 23, 24, 256 and 65_536 exercise the one-, two-,
        // three- and five-byte heads; an eight-byte head is built by hand.
        for len in [23usize, 24, 256, 65_536] {
            let item = encode(&Value::Text("x".repeat(len)));
            assert_eq!(item_len(&item, 0), Some(item.len()));
        }

        let mut wide = vec![0x7b];
        wide.extend_from_slice(&2u64.to_be_bytes());
        wide.extend_from_slice(b"hi");
        assert_eq!(item_len(&wide, 0), Some(wide.len()));

        // Floats are heads of 3, 5 and 9 bytes.
        assert_eq!(item_len(&[0xf9, 0, 0], 0), Some(3));
        assert_eq!(item_len(&[0xfa, 0, 0, 0, 0], 0), Some(5));
        assert_eq!(item_len(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], 0), Some(9));
        assert_eq!(item_len(&[0xf4], 0), Some(1));
        assert_eq!(item_len(&[0xf8, 0x20], 0), Some(2));
    }

    #[test]
    fn truncation_and_indefinite_lengths_are_refused() {
        assert_eq!(item_len(&[], 0), None);
        // A byte string promising more than is there.
        assert_eq!(item_len(&[0x45, 1, 2], 0), None);
        // Heads cut short.
        assert_eq!(item_len(&[0x18], 0), None);
        assert_eq!(item_len(&[0x19, 0], 0), None);
        assert_eq!(item_len(&[0x1a, 0, 0, 0], 0), None);
        assert_eq!(item_len(&[0x1b, 0, 0, 0, 0], 0), None);
        // Indefinite-length and reserved additional information.
        assert_eq!(item_len(&[0x5f, 0xff], 0), None);
        assert_eq!(item_len(&[0x1c], 0), None);
        // An array promising items that are not there.
        assert_eq!(item_len(&[0x82, 0x01], 0), None);
        // A tag with nothing under it.
        assert_eq!(item_len(&[0xc1], 0), None);
        // A string length that cannot be addressed.
        let mut huge = vec![0x5b];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(item_len(&huge, 0), None);
    }

    #[test]
    fn nesting_is_bounded() {
        let mut deep = vec![0x81; MAX_DEPTH + 2];
        deep.push(0x00);
        assert_eq!(item_len(&deep, 0), None);

        let mut shallow = vec![0x81; 4];
        shallow.push(0x00);
        assert_eq!(item_len(&shallow, 0), Some(5));
    }

    #[test]
    fn map_walk_stops_at_malformed_entries() {
        // One entry claimed, key present, value missing.
        assert_eq!(map_value(&[0xa1, 0x61, b'a'], "a"), None);
        // A non-text key is skipped over rather than matched.
        let mixed = [0xa2, 0x01, 0x02, 0x61, b'k', 0x03];
        assert_eq!(map_value(&mixed, "k"), Some(&[0x03][..]));
        // A text key that is not UTF-8 never matches.
        let bad = [0xa1, 0x61, 0xff, 0x01];
        assert_eq!(map_value(&bad, "a"), None);
    }

    #[test]
    fn every_map_head_width_is_read() {
        // A map whose entry count needs a 1-, 2-, 4- and 8-byte argument,
        // each holding the single entry the argument claims is too many
        // for the bytes present — so the walk fails — except the first.
        let entry = [0x61, b'a', 0x01];
        let mut one = vec![0xb8, 1];
        one.extend_from_slice(&entry);
        assert_eq!(map_value(&one, "a"), Some(&[0x01][..]));

        let mut two = vec![0xb9, 0, 1];
        two.extend_from_slice(&entry);
        assert_eq!(map_value(&two, "a"), Some(&[0x01][..]));

        let mut four = vec![0xba, 0, 0, 0, 1];
        four.extend_from_slice(&entry);
        assert_eq!(map_value(&four, "a"), Some(&[0x01][..]));

        let mut eight = vec![0xbb, 0, 0, 0, 0, 0, 0, 0, 1];
        eight.extend_from_slice(&entry);
        assert_eq!(map_value(&eight, "a"), Some(&[0x01][..]));

        assert_eq!(map_value(&[0xbc], "a"), None);
    }

    #[test]
    fn text_keys_of_every_head_width_are_read() {
        assert_eq!(text_key(&[0x61, b'a']), Some("a"));
        assert_eq!(text_key(&[0x78, 1, b'a']), Some("a"));
        assert_eq!(text_key(&[0x79, 0, 1, b'a']), Some("a"));
        assert_eq!(text_key(&[0x7a, 0, 0, 0, 1, b'a']), Some("a"));
        assert_eq!(text_key(&[0x7b, 0, 0, 0, 0, 0, 0, 0, 1, b'a']), Some("a"));
        assert_eq!(text_key(&[0x7c]), None);
        assert_eq!(text_key(&[0x41, 1]), None);
        assert_eq!(text_key(&[]), None);
    }
}
