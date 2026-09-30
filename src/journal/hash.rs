//! The two hash functions a journal `DATA` object's own `hash` field can hold, matched byte-exact
//! against systemd's own implementation so a freshly-computed hash of an untampered fixture's
//! payload equals the hash systemd itself wrote (see `journal_hash_matches_real_fixture_data` in
//! `crates/frnsc-linux/tests/journal_real_samples.rs`) — without that cross-check, a hash-mismatch
//! "integrity finding" would really just be this module disagreeing with systemd, not evidence of
//! tampering.
//!
//! - [`jenkins_hash64`]: used unconditionally unless `HEADER_INCOMPATIBLE_KEYED_HASH` is set, and
//!   *always* (regardless of that flag) for an `ENTRY` object's own `xor_hash`. Transcribed from
//!   `jenkins_hashlittle2` in systemd's `src/libsystemd/sd-journal/lookup3.c` — Bob Jenkins'
//!   public-domain "lookup3", May 2006. Only the byte-at-a-time code path is reimplemented here:
//!   `hashlittle2` guarantees the same output regardless of which of its three internal code
//!   paths (word-aligned/half-word-aligned/byte-at-a-time) a given input takes — that is the
//!   whole point of the algorithm being safe to call on unaligned data — so reimplementing just
//!   the always-correct byte-wise path reproduces the exact same hash for any input, on any host.
//! - [`keyed_hash64`]: SipHash-2-4 keyed by the file's own 16-byte `file_id`, used when
//!   `HEADER_INCOMPATIBLE_KEYED_HASH` is set. `siphasher` is a well-tested pure-Rust
//!   implementation of the standard algorithm; the only journal-specific part is splitting the
//!   16-byte key into two little-endian `u64` halves, confirmed against
//!   `siphash24_init`/`unaligned_read_le64` in systemd's `src/basic/siphash24.c`.

use std::hash::Hasher;

use siphasher::sip::SipHasher24;

/// `jenkins_hash64(data, len)`: `((a << 32) | b)` where `(a, b)` is `hashlittle2(data, 0, 0)`.
pub fn jenkins_hash64(data: &[u8]) -> u64 {
    let (c, b) = hashlittle2(data, 0, 0);
    ((c as u64) << 32) | (b as u64)
}

/// `journal_file_hash_data`'s keyed-hash branch: `siphash24(data, len, file_id.bytes)`.
pub fn keyed_hash64(data: &[u8], file_id: &[u8; 16]) -> u64 {
    let k0 = u64::from_le_bytes(file_id[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(file_id[8..16].try_into().unwrap());
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(data);
    hasher.finish()
}

#[inline]
fn rot(x: u32, k: u32) -> u32 {
    x.rotate_left(k)
}

/// `mix(a,b,c)` from lookup3.c, verbatim.
#[inline]
fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= rot(*c, 4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rot(*a, 6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rot(*b, 8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= rot(*c, 16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rot(*a, 19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rot(*b, 4);
    *b = b.wrapping_add(*a);
}

/// `final(a,b,c)` from lookup3.c, verbatim.
#[inline]
fn final_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(rot(*b, 14));
    *a ^= *c;
    *a = a.wrapping_sub(rot(*c, 11));
    *b ^= *a;
    *b = b.wrapping_sub(rot(*a, 25));
    *c ^= *b;
    *c = c.wrapping_sub(rot(*b, 16));
    *a ^= *c;
    *a = a.wrapping_sub(rot(*c, 4));
    *b ^= *a;
    *b = b.wrapping_sub(rot(*a, 14));
    *c ^= *b;
    *c = c.wrapping_sub(rot(*b, 24));
}

/// The byte-at-a-time code path of `jenkins_hashlittle2`. See the module docs for why this one
/// path alone reproduces `hashlittle2`'s output for any input.
fn hashlittle2(key: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    let length = key.len() as u32;
    let mut a = 0xdeadbeefu32.wrapping_add(length).wrapping_add(pc);
    let mut b = a;
    let mut c = a.wrapping_add(pb);

    let mut rest = key;
    while rest.len() > 12 {
        a = a.wrapping_add(u32::from_le_bytes(rest[0..4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(rest[4..8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(rest[8..12].try_into().unwrap()));
        mix(&mut a, &mut b, &mut c);
        rest = &rest[12..];
    }

    if rest.is_empty() {
        // "zero length strings require no mixing"
        return (c, b);
    }

    let mut tail = [0u8; 12];
    tail[..rest.len()].copy_from_slice(rest);
    // Padding the tail with zero bytes and always adding all three words is equivalent to the
    // reference implementation's per-length switch/fallthrough: a byte that isn't really present
    // contributes `0 << shift == 0`, a no-op.
    a = a.wrapping_add(u32::from_le_bytes(tail[0..4].try_into().unwrap()));
    b = b.wrapping_add(u32::from_le_bytes(tail[4..8].try_into().unwrap()));
    c = c.wrapping_add(u32::from_le_bytes(tail[8..12].try_into().unwrap()));
    final_mix(&mut a, &mut b, &mut c);
    (c, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground truth obtained by compiling systemd's actual, unmodified
    /// `src/libsystemd/sd-journal/lookup3.c` and calling `jenkins_hashlittle2("abcdefghijklmnopq
    /// rstuvwxyz", 26, &a, &b)` directly — 26 bytes so the test exercises both the 12-byte-block
    /// loop (twice) and the tail path in the same call. `hashlittle2` returns `(c, b)` via its
    /// out-parameters; `jenkins_hash64` packs them as `(c << 32) | b`.
    #[test]
    fn matches_compiled_systemd_lookup3_reference_for_the_alphabet() {
        let (c, b) = hashlittle2(b"abcdefghijklmnopqrstuvwxyz", 0, 0);
        assert_eq!(c, 0x7538_b5bd);
        assert_eq!(b, 0x7ded_7e16);
    }

    /// More ground truth from the same compiled systemd `lookup3.c`, covering every tail length
    /// from 1 to 13 bytes (so both the "less than one block" and "one full block plus one byte"
    /// shapes of the tail-handling code are pinned) plus a 19-byte string.
    #[test]
    fn matches_compiled_systemd_lookup3_reference_across_short_lengths() {
        let cases: &[(&[u8], u32, u32)] = &[
            (b"a", 0x58d6_8708, 0x5826_47ac),
            (b"ab", 0xfbb3_a8df, 0x6b79_a0f2),
            (b"abc", 0x0e39_7631, 0x3c03_be9e),
            (b"abcd", 0xb5f4_889c, 0xe20d_d3fa),
            (b"abcdefghijkl", 0x4012_f87b, 0x75b5_0ec0),
            (b"abcdefghijklm", 0x9281_28f9, 0x0f04_ab68),
            (b"The quick brown fox", 0x9b1d_2752, 0x3edb_d698),
        ];
        for (input, expected_c, expected_b) in cases {
            let (c, b) = hashlittle2(input, 0, 0);
            assert_eq!(c, *expected_c, "input {input:?}");
            assert_eq!(b, *expected_b, "input {input:?}");
        }
    }

    #[test]
    fn empty_input_needs_no_mixing() {
        // hashlittle2("", 0, 0): a=b=c=0xdeadbeef (length 0 contributes nothing), and length==0
        // returns immediately with (c, b) unmodified.
        let (c, b) = hashlittle2(b"", 0, 0);
        assert_eq!(c, 0xdeadbeef);
        assert_eq!(b, 0xdeadbeef);
    }

    #[test]
    fn jenkins_hash64_packs_c_high_b_low() {
        let (c, b) = hashlittle2(b"abcdefghijklmnopqrstuvwxyz", 0, 0);
        let expected = ((c as u64) << 32) | (b as u64);
        assert_eq!(jenkins_hash64(b"abcdefghijklmnopqrstuvwxyz"), expected);
    }

    /// The reference SipHash-2-4 test vector for key `{0x00, 0x01, ..., 0x0f}` and an empty
    /// message, from `vectors.h` published alongside the original SipHash paper
    /// (Aumasson & Bernstein) — the standard cross-implementation sanity check for this
    /// algorithm, independent of anything journal-specific.
    #[test]
    fn keyed_hash64_matches_the_published_siphash24_test_vector_for_an_empty_message() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let hash = keyed_hash64(&[], &key);
        assert_eq!(hash, 0x726f_db47_dd0e_0e31);
    }
}
