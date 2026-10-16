# TIFF — security fix porting status

Part of [Porting security fixes from c2pa-rs to the state-machine SDK](README.md).

Covers the TIFF / BigTIFF / DNG handler
([`contentauth-c2pa-format-tiff`](../../contentauth-c2pa-format-tiff)). All
regression tests live in
[`tests/tiff_handler.rs`](../../contentauth-c2pa-format-tiff/tests/tiff_handler.rs).

## Why most TIFF exploits don't reach this handler

Two design facts explain nearly every verdict below:

- **The reader is a minimal locator.** `scan.rs` walks the IFD chain only to
  find the single C2PA manifest-store entry (tag `0xCD41`); it `continue`s past
  every other tag without reading or sizing its data. It accepts the store
  entry only as `UNDEFINED`/`BYTE` (one byte per value — so a byte count is a
  count, never `count × type_size`), bounds that range with
  `value.checked_add(count) ≤ source_len`, caps IFD entry counts at
  `MAX_ENTRIES` (2^20) and IFD chain length at `MAX_IFDS` (2^16), tracks
  visited IFD offsets in a `seen` set, and — being sans-I/O — never allocates a
  read buffer itself (the host reads host-bounded ranges).
- **The writer splices.** `embed.rs` keeps the source bytes verbatim, appends a
  new trailing IFD plus the store, and rewrites exactly one next-IFD pointer
  ("nothing moves"). It never re-serializes strips, tiles or entries, so
  clone-time amplification has nothing to re-copy.

## Summary

| c2pa-rs PR | Vulnerability (TIFF) | Verdict | Regression test |
|---|---|---|---|
| [#2012](https://github.com/contentauth/c2pa-rs/pull/2012) | BigTIFF `value_count × type_size` integer-overflow panic | **Not applicable** | `a_bigtiff_store_entry_with_an_overflowing_value_count_is_refused_not_panicked` |
| [#2068](https://github.com/contentauth/c2pa-rs/pull/2068) | Cyclic IFD chain → infinite loop / OOM | **Already fixed** | `cyclic_ifd_self_loop_is_refused`, `cyclic_ifd_two_node_cycle_is_refused`, `a_self_referential_ifd_chain_is_refused_not_looped` |
| [#2059](https://github.com/contentauth/c2pa-rs/pull/2059) | Forged IFD entry count → multi-GB allocation / OOM | **Already fixed** | `a_bigtiff_byte_entry_claiming_billions_of_bytes_is_refused_not_allocated` |
| [#2282](https://github.com/contentauth/c2pa-rs/pull/2282) | Strip / tile / BigTable clone memory amplification | **Not applicable** | `embedding_copies_the_source_exactly_once_so_strips_cannot_amplify` |
| [#2669](https://github.com/contentauth/c2pa-rs/pull/2669) | Cumulative amplification across many aliasing IFD entries | **Not applicable** | `many_aliasing_entries_do_not_amplify_on_embed` |
| [#2610](https://github.com/contentauth/c2pa-rs/pull/2610) | Forged IFD count widens a recomputed data-hash exclusion (validation bypass) | **Latent** | — (tracked for update manifests) |
| [#628](https://github.com/contentauth/c2pa-rs/pull/628) | Unbounded buffer allocation from a length field | **Not applicable** | covered by #2059 + `refuses_what_is_malformed` |

Seven processed; none needs porting today. One (#2610) is latent, waiting on a
feature that isn't built yet.

## Details

### #2012 — integer-overflow panic in BigTIFF entry sizing · Not applicable

**Exploit.** An IFD entry declares a `type` (bytes-per-value, e.g. `Rational` =
8) and a `value_count`. Sizing the entry's data as `value_count × type_size`
overflows `u64` for a 64-bit BigTIFF count (`0x2000000000000001 × 8`) → panic in
debug (DoS, exit 101) or a wrapped small size in release.

**Why not applicable.** The handler never multiplies a count by a type size. It
reads data only for the store entry, which must be `UNDEFINED`/`BYTE` (size 1,
so the byte count *is* the count), and bounds it with `checked_add`. Non-store
entries are skipped unread. There is no `count × type_size` anywhere.

### #2068 — cyclic IFD chain → infinite loop / OOM · Already fixed

**Exploit.** An IFD's `next` pointer targets an already-visited offset (A→A, or
A→B→A), so the chain walk never terminates and allocates each iteration
(14 bytes → 2+ GB).

**Why already fixed.** `issue_ifd` — the one choke point every IFD pointer
passes through — rejects a pointer to an already-seen offset:

```rust
if !self.seen.insert(offset) {
    return Err(malformed(format!("the IFD chain loops back to offset {offset}")));
}
```

plus a `MAX_IFDS` cap and an offset-past-EOF check. The ported PoCs give each
IFD a dummy entry so the chain is actually followed and the *cycle* is what gets
refused.

### #2059 — forged entry count → giant allocation / OOM · Already fixed

**Exploit.** A buffer is sized from an attacker-controlled `count` without a
file-size check — a BigTIFF Byte entry claiming ~10 billion bytes drives a
multi-GB allocation (OOM, exit 137 on Linux).

**Why already fixed.** `check_entry` validates the store's range against the
source length before any read — exactly c2pa-rs's `check_ifd_data_size`:

```rust
if value.checked_add(count).is_none_or(|end| end > self.source_len) {
    return Err(malformed("the C2PA manifest store reaches past the end of the file"));
}
```

### #2282 — strip / tile / BigTable clone amplification · Not applicable

**Exploit.** c2pa-rs re-serializes a TIFF when signing, copying each strip/tile's
data with no cap on cumulative bytes; aliasing offsets with huge counts make it
re-copy the input until OOM (293 KB → 4.9 GB).

**Why not applicable.** The writer splices: it copies the source verbatim and
appends the store, never re-serializing strips. The regression test asserts the
cumulative `Edit::Copy` bytes never exceed the source length.

### #2669 — cumulative amplification across many aliasing entries · Not applicable

**Exploit.** Many private IFD tags whose offsets/counts all alias the same bytes;
each passes an individual size check but their *sum* dwarfs the file (536 tags ×
600 KB). The 8-byte element types had no size check at all.

**Why not applicable.** The reader reads no entry's data except the single store
entry (`continue`s past every other tag), and the writer splices, so neither the
number of entries nor their claimed sizes amplify anything. The 8-byte types are
never read; if one were the store tag, `check_entry` rejects it (only
`UNDEFINED`/`BYTE` accepted).

### #2610 — forged IFD count widens a recomputed exclusion · Latent

**Exploit.** When an active *update manifest* inherits a data hash, c2pa-rs
recomputes the signed `c2pa.hash.data` exclusion from the current asset and
over-measured it using the attacker-declared IFD `count` (tag `0xCD41`) — so
foreign, unhashed bytes sit inside the exclusion while the asset still validates
(spec 15.12.1 bypass).

**Why latent, not safe-by-design.** The vulnerable step is the *recomputation of
a signed exclusion from the asset*, which only exists for update manifests with
inherited data hashes — a feature this SDK does not implement. Today the reader
validates every hard binding against the manifest's own signed exclusions and
never derives them from the IFD count, so a forged count can't widen an unhashed
window (tampered bytes outside the signed exclusion get hashed → `Invalid`).
When update manifests land, the recomputation must be bounded — see the recorded
requirement in [09-future.md](../walkthrough/09-future.md) (bound the widening to
the measured delta, enforce spec 15.12.1, and bound the located store's `count`
to the JUMBF superbox length).

### #628 — unbounded buffer allocation from a length field · Not applicable

**Exploit.** The general form of #2059: `let mut data = vec![0u8; data_len];
reader.read_exact(&mut data)?` with `data_len` an attacker-controlled IFD
`value_count`/segment length → huge allocation. c2pa-rs introduced `safe_vec` to
cap it.

**Why not applicable.** Being sans-I/O, the handler never allocates a read
buffer — it requests a `ByteRange` and the host reads it — and every range is
bounded against `source_len` first. The only `vec![...]`s in the crate are a
fixed two-element exclusion list and 0–7 byte alignment padding. Already covered
by #2059's test and the "more entries than the file could hold" case in
`refuses_what_is_malformed`.
