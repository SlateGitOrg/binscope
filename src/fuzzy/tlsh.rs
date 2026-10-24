//! TLSH (Trend Micro Locality Sensitive Hash), 128 buckets / 1-byte checksum,
//! the "T1" format produced by the reference `tlsh` 4.x tools.
//!
//! Implemented from Oliver, Cheng & Chen, "TLSH - A Locality Sensitive Hash"
//! (CTC 2013) with the constant tables copied from the reference
//! implementation (`tlsh_tables.rs`). Digests and distances are verified
//! byte-for-byte against trendmicro/tlsh 4.12.1 in `tests/reference_vectors.rs`.
//!
//! Algorithm sketch:
//! * Slide a 5-byte window; for six fixed byte triplets of the window, a
//!   salted Pearson hash picks one of 256 buckets (only the first 128 are
//!   used) and increments it.
//! * The quartiles q1 <= q2 <= q3 of the 128 bucket counts quantise every
//!   bucket to 2 bits -> a 32-byte body.
//! * Header: a 1-byte checksum (Pearson chain over the input), a log-scale
//!   length bucket, and q1/q3 and q2/q3 ratios mod 16.
//!
//! Hashing is O(n) time and O(1) space; the distance is O(1) (32 body bytes
//! via a 256x256 lookup table computed at compile time).

use std::fmt::{self, Write as _};
use std::str::FromStr;

use super::tlsh_tables::{TOPVAL, V_TABLE};
use crate::error::{Error, Result};

const WINDOW: usize = 5;
const EFF_BUCKETS: usize = 128;
const CODE_SIZE: usize = 32;
/// Minimum input length the reference implementation accepts.
pub const MIN_DATA_LENGTH: usize = 50;
const RANGE_LVALUE: u32 = 256;
const RANGE_QRATIO: u32 = 16;

#[inline]
fn b_mapping(salt: u8, i: u8, j: u8, k: u8) -> u8 {
    let mut h = V_TABLE[usize::from(salt)];
    h = V_TABLE[usize::from(h ^ i)];
    h = V_TABLE[usize::from(h ^ j)];
    V_TABLE[usize::from(h ^ k)]
}

/// Map a length to its log-scale bucket via binary search over `TOPVAL`
/// (bucket `i` covers `TOPVAL[i-1] < len <= TOPVAL[i]`).
fn l_capturing(len: u64) -> u8 {
    let idx = TOPVAL.partition_point(|&t| u64::from(t) < len);
    idx.min(TOPVAL.len() - 1) as u8
}

#[allow(clippy::manual_abs_diff)]
const fn pair_diff(left: u8, right: u8) -> u32 {
    let mut total = 0;
    let mut pair = 0;
    while pair < 4 {
        let lq = (left >> (2 * pair)) & 3;
        let rq = (right >> (2 * pair)) & 3;
        // Not `abs_diff`: this runs 2^18 times during const evaluation and
        // the plain comparison keeps that well under rustc's const-eval budget.
        let delta = if lq > rq { lq - rq } else { rq - lq };
        // A full quartile flip (0 <-> 3) is penalised more than linearly.
        total += if delta == 3 { 6 } else { delta as u32 };
        pair += 1;
    }
    total
}

#[allow(clippy::large_stack_arrays)] // const-evaluated at compile time, never on the stack
const fn build_pair_table() -> [[u8; 256]; 256] {
    let mut t = [[0u8; 256]; 256];
    let mut a = 0;
    while a < 256 {
        let mut b = 0;
        while b < 256 {
            t[a][b] = pair_diff(a as u8, b as u8) as u8;
            b += 1;
        }
        a += 1;
    }
    t
}

static BIT_PAIRS_DIFF: [[u8; 256]; 256] = build_pair_table();

fn mod_diff(x: u32, y: u32, range: u32) -> u32 {
    let (dl, dr) = if y > x { (y - x, x + range - y) } else { (x - y, y + range - x) };
    dl.min(dr)
}

/// Streaming TLSH builder.
#[derive(Clone, Debug)]
pub struct TlshBuilder {
    buckets: [u32; 256],
    window: [u8; WINDOW],
    checksum: u8,
    len: u64,
}

impl Default for TlshBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlshBuilder {
    /// Fresh builder.
    pub fn new() -> Self {
        Self { buckets: [0; 256], window: [0; WINDOW], checksum: 0, len: 0 }
    }

    /// Feed more input.
    pub fn update(&mut self, data: &[u8]) {
        let mut j = (self.len % WINDOW as u64) as usize;
        for &byte in data {
            self.window[j] = byte;
            if self.len >= 4 {
                // c0 is the newest byte, c4 the oldest in the 5-byte window.
                let win = &self.window;
                let c0 = win[j];
                let c1 = win[(j + 4) % WINDOW];
                let c2 = win[(j + 3) % WINDOW];
                let c3 = win[(j + 2) % WINDOW];
                let c4 = win[(j + 1) % WINDOW];
                self.checksum = b_mapping(0, c0, c1, self.checksum);
                for (salt, x, y) in [(2, c1, c2), (3, c1, c3), (5, c2, c3), (7, c2, c4), (11, c1, c4), (13, c3, c4)] {
                    self.buckets[usize::from(b_mapping(salt, c0, x, y))] += 1;
                }
            }
            self.len += 1;
            j = (j + 1) % WINDOW;
        }
    }

    /// Finish the digest. Fails for inputs shorter than 50 bytes, longer than
    /// 4 GiB, or without enough variety to fill half of the buckets (the
    /// reference implementation returns no hash in those cases too).
    pub fn finish(&self) -> Result<Tlsh> {
        let unavailable = |reason: String| Error::DigestUnavailable { kind: "tlsh", reason };
        if self.len < MIN_DATA_LENGTH as u64 {
            return Err(unavailable(format!("input is {} bytes; TLSH needs at least {MIN_DATA_LENGTH}", self.len)));
        }
        if self.len > u64::from(u32::MAX) {
            return Err(unavailable("input exceeds 4 GiB".into()));
        }
        let mut sorted = [0u32; EFF_BUCKETS];
        sorted.copy_from_slice(&self.buckets[..EFF_BUCKETS]);
        sorted.sort_unstable();
        let (q1, q2, q3) =
            (sorted[EFF_BUCKETS / 4 - 1], sorted[EFF_BUCKETS / 2 - 1], sorted[EFF_BUCKETS - EFF_BUCKETS / 4 - 1]);
        let nonzero = self.buckets[..EFF_BUCKETS].iter().filter(|&&c| c > 0).count();
        if nonzero <= 4 * CODE_SIZE / 2 {
            return Err(unavailable(
                "input lacks byte-pattern variety (more than half of the TLSH buckets are empty)".into(),
            ));
        }
        let mut code = [0u8; CODE_SIZE];
        for (i, slot) in code.iter_mut().enumerate() {
            let mut h = 0u8;
            for j in 0..4 {
                let k = self.buckets[4 * i + j];
                let v = if q3 < k {
                    3
                } else if q2 < k {
                    2
                } else {
                    u8::from(q1 < k)
                };
                h |= v << (2 * j);
            }
            *slot = h;
        }
        // The reference computes these ratios with a wrapping 32-bit multiply
        // followed by single-precision division; mirror both exactly.
        let q1_ratio = ((q1.wrapping_mul(100) as f32 / q3 as f32) as u32 % 16) as u8;
        let q2_ratio = ((q2.wrapping_mul(100) as f32 / q3 as f32) as u32 % 16) as u8;
        Ok(Tlsh { checksum: self.checksum, lvalue: l_capturing(self.len), q1_ratio, q2_ratio, code })
    }
}

/// Hash a complete buffer.
pub fn hash(data: &[u8]) -> Result<Tlsh> {
    let mut b = TlshBuilder::new();
    b.update(data);
    b.finish()
}

/// A TLSH digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tlsh {
    /// 1-byte rolling checksum.
    pub checksum: u8,
    /// Log-scale length bucket.
    pub lvalue: u8,
    /// `q1 * 100 / q3 mod 16`.
    pub q1_ratio: u8,
    /// `q2 * 100 / q3 mod 16`.
    pub q2_ratio: u8,
    /// 128 two-bit bucket codes, in internal (non-reversed) order.
    pub code: [u8; CODE_SIZE],
}

#[inline]
fn swap_nibbles(b: u8) -> u8 {
    b.rotate_left(4)
}

impl Tlsh {
    /// Distance between two digests (0 = identical; the score is unbounded
    /// above, values under ~100 usually indicate related files).
    /// `include_length` mirrors the reference `-xlen` switch when false.
    pub fn distance(&self, other: &Tlsh, include_length: bool) -> u32 {
        let mut diff = self.header_distance(other, include_length);
        for (a, b) in self.code.iter().zip(other.code.iter()) {
            diff += u32::from(BIT_PAIRS_DIFF[usize::from(*a)][usize::from(*b)]);
        }
        diff
    }

    /// Header-only part of [`Tlsh::distance`]; a lower bound of the full
    /// distance used by clustering to skip hopeless pairs.
    pub fn header_distance(&self, other: &Tlsh, include_length: bool) -> u32 {
        let mut diff = 0;
        if include_length {
            diff += Self::length_distance(self.lvalue, other.lvalue);
        }
        for (a, b) in [(self.q1_ratio, other.q1_ratio), (self.q2_ratio, other.q2_ratio)] {
            let q = mod_diff(u32::from(a), u32::from(b), RANGE_QRATIO);
            diff += if q <= 1 { q } else { (q - 1) * 12 };
        }
        if self.checksum != other.checksum {
            diff += 1;
        }
        diff
    }

    /// Length-term of the distance for two length buckets.
    pub fn length_distance(a: u8, b: u8) -> u32 {
        let l = mod_diff(u32::from(a), u32::from(b), RANGE_LVALUE);
        if l <= 1 {
            l
        } else {
            l * 12
        }
    }

    /// Serialise in the reference "T1" + 70 hex digits format.
    pub fn to_hex(&self) -> String {
        let mut bytes = Vec::with_capacity(3 + CODE_SIZE);
        bytes.push(swap_nibbles(self.checksum));
        bytes.push(swap_nibbles(self.lvalue));
        bytes.push(swap_nibbles(self.q1_ratio | (self.q2_ratio << 4)));
        bytes.extend(self.code.iter().rev());
        let mut s = String::with_capacity(72);
        s.push_str("T1");
        for b in bytes {
            let _ = write!(s, "{b:02X}");
        }
        s
    }
}

impl fmt::Display for Tlsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Tlsh {
    type Err = Error;

    /// Parse a `T1`-prefixed (or legacy unprefixed) 70-hex-digit digest.
    fn from_str(s: &str) -> Result<Self> {
        let bad = |reason: &str| Error::InvalidDigest {
            kind: "tlsh",
            digest: s.chars().take(200).collect(),
            reason: reason.to_string(),
        };
        let body = s.strip_prefix("T1").or_else(|| s.strip_prefix("t1")).unwrap_or(s);
        if body.len() != 2 * (3 + CODE_SIZE) {
            return Err(bad("expected 70 hex digits after the T1 prefix"));
        }
        let mut bytes = [0u8; 3 + CODE_SIZE];
        for (i, out) in bytes.iter_mut().enumerate() {
            *out = u8::from_str_radix(&body[2 * i..2 * i + 2], 16).map_err(|_| bad("not hexadecimal"))?;
        }
        let q = swap_nibbles(bytes[2]);
        let mut code = [0u8; CODE_SIZE];
        for (i, c) in code.iter_mut().enumerate() {
            *c = bytes[3 + CODE_SIZE - 1 - i];
        }
        Ok(Self {
            checksum: swap_nibbles(bytes[0]),
            lvalue: swap_nibbles(bytes[1]),
            q1_ratio: q & 0x0f,
            q2_ratio: q >> 4,
            code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 7) as u8
            })
            .collect()
    }

    #[test]
    fn too_short_or_uniform_inputs_have_no_digest() {
        assert!(hash(&[1u8; 49]).is_err());
        assert!(hash(&[0u8; 10_000]).is_err());
    }

    #[test]
    fn hex_round_trip() {
        let h = hash(&sample(4096, 7)).unwrap();
        let s = h.to_hex();
        assert_eq!(s.len(), 72);
        assert!(s.starts_with("T1"));
        assert_eq!(s.parse::<Tlsh>().unwrap(), h);
        assert_eq!(s[2..].parse::<Tlsh>().unwrap(), h);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!("T1abc".parse::<Tlsh>().is_err());
        assert!(format!("T1{}", "Z".repeat(70)).parse::<Tlsh>().is_err());
    }

    #[test]
    fn distance_is_a_symmetric_pseudo_metric() {
        let a = hash(&sample(8192, 1)).unwrap();
        let b = hash(&sample(8192, 2)).unwrap();
        assert_eq!(a.distance(&a, true), 0);
        assert_eq!(a.distance(&b, true), b.distance(&a, true));
        assert!(a.header_distance(&b, true) <= a.distance(&b, true));
    }

    #[test]
    fn streaming_equals_one_shot() {
        let data = sample(10_000, 3);
        let mut b = TlshBuilder::new();
        for c in data.chunks(3) {
            b.update(c);
        }
        assert_eq!(b.finish().unwrap(), hash(&data).unwrap());
    }

    #[test]
    fn length_buckets_follow_topval() {
        assert_eq!(l_capturing(1), 0);
        assert_eq!(l_capturing(2), 1);
        assert_eq!(l_capturing(3), 2);
        assert_eq!(l_capturing(4), 3);
        assert_eq!(l_capturing(656), 15);
        assert_eq!(l_capturing(657), 16);
    }

    #[test]
    fn pair_table_penalises_full_flips() {
        assert_eq!(pair_diff(0b00, 0b11), 6);
        assert_eq!(pair_diff(0b00, 0b10), 2);
        assert_eq!(pair_diff(0xff, 0x00), 24);
        assert_eq!(mod_diff(1, 255, 256), 2);
    }
}
