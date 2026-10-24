//! ssdeep (context-triggered piecewise hashing, CTPH).
//!
//! Implemented from Kornblum's CTPH description ("Identifying almost identical
//! files using context triggered piecewise hashing", DFRWS 2006) and the
//! behaviour of ssdeep 2.14.1, whose `fuzzy_hash_buf` / `fuzzy_compare`
//! outputs this module reproduces exactly (see `tests/reference_vectors.rs`).
//!
//! Algorithm sketch:
//! * A 7-byte rolling hash decides *trigger points*: position `p` triggers at
//!   block size `b` when `(roll(p) + 1) % b == 0`.
//! * Between triggers an FNV-style hash accumulates; at each trigger its low
//!   six bits become one base64 character of the digest for that block size.
//! * Block sizes `3 * 2^k` are tracked simultaneously in one pass; the final
//!   digest uses the smallest block size whose signature is at least 32
//!   characters (and at least `size / 64`), plus the next block size.
//!
//! Hashing is O(n) time with O(1) state (31 block contexts of 64 bytes).
//! Comparison is O(64 * 64) for the edit distance of two 64-char strings.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Maximum characters in each digest part.
pub const SPAMSUM_LENGTH: usize = 64;
const MIN_BLOCKSIZE: u64 = 3;
const ROLLING_WINDOW: usize = 7;
const HASH_PRIME: u32 = 0x0100_0193;
const HASH_INIT: u32 = 0x2802_1967;
const NUM_BLOCKHASHES: usize = 31;
/// Largest input ssdeep accepts: `3 * 2^30 * 64` bytes.
pub const MAX_INPUT: u64 = MIN_BLOCKSIZE << (NUM_BLOCKHASHES - 1) << 6;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[inline]
const fn block_size(index: usize) -> u64 {
    MIN_BLOCKSIZE << index
}

/// FNV-style piece hash. Only the low 6 bits are ever used, and the low 6 bits
/// of `h * PRIME ^ c` depend only on the low 6 bits of `h`, so the state is
/// kept reduced to 0..64 (the same trick ssdeep 2.13+ uses with `sum_table`).
#[inline]
fn sum_hash(c: u8, h: u8) -> u8 {
    ((u32::from(h).wrapping_mul(HASH_PRIME) ^ u32::from(c)) & 0x3f) as u8
}

const HASH_INIT_6: u8 = (HASH_INIT & 0x3f) as u8;

/// The 7-byte rolling hash (an Adler-32 variant plus a shift-xor term).
#[derive(Clone, Debug, Default)]
pub(crate) struct Roll {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl Roll {
    #[inline]
    pub(crate) fn push(&mut self, c: u8) {
        let c32 = u32::from(c);
        self.h2 = self.h2.wrapping_sub(self.h1);
        self.h2 = self.h2.wrapping_add(ROLLING_WINDOW as u32 * c32);
        self.h1 = self.h1.wrapping_add(c32);
        self.h1 = self.h1.wrapping_sub(u32::from(self.window[self.n]));
        self.window[self.n] = c;
        self.n = (self.n + 1) % ROLLING_WINDOW;
        self.h3 = (self.h3 << 5) ^ c32;
    }

    #[inline]
    pub(crate) fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

#[derive(Clone, Debug)]
struct BlockHash {
    h: u8,
    halfh: u8,
    digest: [u8; SPAMSUM_LENGTH],
    halfdigest: u8,
    dindex: usize,
}

impl BlockHash {
    const fn new() -> Self {
        Self {
            h: HASH_INIT_6,
            halfh: HASH_INIT_6,
            digest: [0; SPAMSUM_LENGTH],
            halfdigest: 0,
            dindex: 0,
        }
    }
}

/// Streaming ssdeep hasher.
///
/// For results identical to `ssdeep`/`fuzzy_hash_buf`, either use
/// [`hash`] or create the hasher with [`SsdeepHasher::with_total_size`]: like
/// libfuzzy, the block-size elimination heuristic depends on knowing the
/// final input length up front.
#[derive(Clone, Debug)]
pub struct SsdeepHasher {
    bh: Vec<BlockHash>,
    bhstart: usize,
    bhend: usize,
    bhendlimit: usize,
    roll: Roll,
    total_size: u64,
    fixed_size: Option<u64>,
    reduce_border: u64,
    lasth: u8,
    need_lasth: bool,
}

impl Default for SsdeepHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl SsdeepHasher {
    /// Hasher for input of unknown length.
    pub fn new() -> Self {
        Self {
            bh: vec![BlockHash::new(); NUM_BLOCKHASHES],
            bhstart: 0,
            bhend: 1,
            bhendlimit: NUM_BLOCKHASHES - 1,
            roll: Roll::default(),
            total_size: 0,
            fixed_size: None,
            reduce_border: MIN_BLOCKSIZE * SPAMSUM_LENGTH as u64,
            lasth: 0,
            need_lasth: false,
        }
    }

    /// Hasher that knows the input will be exactly `total` bytes long.
    pub fn with_total_size(total: u64) -> Result<Self> {
        if total > MAX_INPUT {
            return Err(Error::DigestUnavailable {
                kind: "ssdeep",
                reason: format!("input of {total} bytes exceeds the ssdeep maximum {MAX_INPUT}"),
            });
        }
        let mut s = Self::new();
        let mut bi = 0;
        while block_size(bi) * (SPAMSUM_LENGTH as u64) < total {
            bi += 1;
            if bi == NUM_BLOCKHASHES - 2 {
                break;
            }
        }
        s.bhendlimit = bi + 1;
        s.fixed_size = Some(total);
        Ok(s)
    }

    fn try_fork(&mut self) {
        let last = self.bhend - 1;
        if self.bhend <= self.bhendlimit {
            let (h, halfh) = (self.bh[last].h, self.bh[last].halfh);
            let nb = &mut self.bh[self.bhend];
            nb.h = h;
            nb.halfh = halfh;
            nb.digest[0] = 0;
            nb.halfdigest = 0;
            nb.dindex = 0;
            self.bhend += 1;
        } else if self.bhend == NUM_BLOCKHASHES && !self.need_lasth {
            self.need_lasth = true;
            self.lasth = self.bh[last].h;
        }
    }

    fn try_reduce(&mut self) {
        if self.bhend - self.bhstart < 2 {
            return;
        }
        let size = self.fixed_size.unwrap_or(self.total_size);
        if self.reduce_border >= size {
            return;
        }
        if self.bh[self.bhstart + 1].dindex < SPAMSUM_LENGTH / 2 {
            return;
        }
        self.bhstart += 1;
        self.reduce_border *= 2;
    }

    #[inline]
    fn step(&mut self, c: u8) {
        self.roll.push(c);
        let horg = u64::from(self.roll.sum().wrapping_add(1));
        for b in &mut self.bh[self.bhstart..self.bhend] {
            b.h = sum_hash(c, b.h);
            b.halfh = sum_hash(c, b.halfh);
        }
        if self.need_lasth {
            self.lasth = sum_hash(c, self.lasth);
        }
        // roll + 1 == 0 (mod 2^32) never triggers: 0xffffffff is not -1 (mod 3).
        if horg == 0 {
            return;
        }
        let mut i = self.bhstart;
        while i < self.bhend && horg % block_size(i) == 0 {
            if self.bh[i].dindex == 0 {
                self.try_fork();
            }
            let b = &mut self.bh[i];
            b.digest[b.dindex] = B64[usize::from(b.h)];
            b.halfdigest = B64[usize::from(b.halfh)];
            if b.dindex < SPAMSUM_LENGTH - 1 {
                b.dindex += 1;
                b.digest[b.dindex] = 0;
                b.h = HASH_INIT_6;
                if b.dindex < SPAMSUM_LENGTH / 2 {
                    b.halfh = HASH_INIT_6;
                    b.halfdigest = 0;
                }
            } else {
                self.try_reduce();
            }
            i += 1;
        }
    }

    /// Feed more input.
    pub fn update(&mut self, data: &[u8]) {
        self.total_size = self.total_size.saturating_add(data.len() as u64);
        for &c in data {
            self.step(c);
        }
    }

    /// Produce the digest for everything fed so far.
    pub fn digest(&self) -> Result<SsdeepHash> {
        if self.total_size > MAX_INPUT {
            return Err(Error::DigestUnavailable {
                kind: "ssdeep",
                reason: "input exceeds the ssdeep maximum size".into(),
            });
        }
        if let Some(fixed) = self.fixed_size {
            if fixed != self.total_size {
                return Err(Error::DigestUnavailable {
                    kind: "ssdeep",
                    reason: format!("declared {fixed} bytes but received {}", self.total_size),
                });
            }
        }
        let mut bi = self.bhstart;
        let h = self.roll.sum();
        while block_size(bi) * (SPAMSUM_LENGTH as u64) < self.total_size {
            bi += 1;
        }
        if bi >= self.bhend {
            bi = self.bhend - 1;
        }
        while bi > self.bhstart && self.bh[bi].dindex < SPAMSUM_LENGTH / 2 {
            bi -= 1;
        }

        let b = &self.bh[bi];
        let mut part1: Vec<u8> = b.digest[..b.dindex].to_vec();
        if h != 0 {
            part1.push(B64[usize::from(b.h)]);
        } else if b.digest[b.dindex] != 0 {
            part1.push(b.digest[b.dindex]);
        }

        let mut part2: Vec<u8> = Vec::new();
        if bi < self.bhend - 1 {
            let b2 = &self.bh[bi + 1];
            let n = b2.dindex.min(SPAMSUM_LENGTH / 2 - 1);
            part2.extend_from_slice(&b2.digest[..n]);
            if h != 0 {
                part2.push(B64[usize::from(b2.halfh)]);
            } else if b2.halfdigest != 0 {
                part2.push(b2.halfdigest);
            }
        } else if h != 0 {
            let c = if bi == 0 { b.h } else { self.lasth };
            part2.push(B64[usize::from(c)]);
        }

        Ok(SsdeepHash {
            block_size: block_size(bi),
            part1: String::from_utf8(part1).expect("base64 alphabet is ASCII"),
            part2: String::from_utf8(part2).expect("base64 alphabet is ASCII"),
        })
    }
}

/// Hash a complete buffer (equivalent to libfuzzy's `fuzzy_hash_buf`).
pub fn hash(data: &[u8]) -> Result<SsdeepHash> {
    let mut h = SsdeepHasher::with_total_size(data.len() as u64)?;
    h.update(data);
    h.digest()
}

/// A parsed ssdeep digest: `blocksize:part1:part2`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SsdeepHash {
    /// Block size of `part1` (`part2` uses twice this).
    pub block_size: u64,
    /// Signature at `block_size` (at most 64 characters).
    pub part1: String,
    /// Signature at `2 * block_size` (at most 32 characters when produced by
    /// [`hash`]; up to 64 accepted when parsing).
    pub part2: String,
}

impl fmt::Display for SsdeepHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.block_size, self.part1, self.part2)
    }
}

impl FromStr for SsdeepHash {
    type Err = Error;

    /// Parse `bs:part1:part2[,"filename"]` (the filename suffix written by the
    /// `ssdeep` tool is ignored).
    fn from_str(s: &str) -> Result<Self> {
        let bad = |reason: &str| Error::InvalidDigest {
            kind: "ssdeep",
            digest: s.chars().take(200).collect(),
            reason: reason.to_string(),
        };
        let mut it = s.splitn(3, ':');
        let bs = it.next().ok_or_else(|| bad("missing block size"))?;
        let p1 = it.next().ok_or_else(|| bad("missing first part"))?;
        let rest = it.next().ok_or_else(|| bad("missing second part"))?;
        let p2 = rest.split(',').next().unwrap_or("");
        let block_size: u64 = bs.trim().parse().map_err(|_| bad("block size is not a number"))?;
        if block_size < MIN_BLOCKSIZE || block_size % MIN_BLOCKSIZE != 0 || !(block_size / MIN_BLOCKSIZE).is_power_of_two() {
            return Err(bad("block size must be 3 * 2^k"));
        }
        for part in [p1, p2] {
            if part.len() > SPAMSUM_LENGTH {
                return Err(bad("part longer than 64 characters"));
            }
            if !part.bytes().all(|c| B64.contains(&c)) {
                return Err(bad("part contains non-base64 characters"));
            }
        }
        Ok(Self {
            block_size,
            part1: p1.to_string(),
            part2: p2.to_string(),
        })
    }
}

/// Collapse runs of more than three identical characters (as ssdeep does
/// before comparing).
pub fn eliminate_sequences(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    for (i, &c) in b.iter().enumerate() {
        if i >= 3 && c == b[i - 1] && c == b[i - 2] && c == b[i - 3] {
            continue;
        }
        out.push(c);
    }
    String::from_utf8(out).expect("input was valid UTF-8 and only whole bytes of ASCII are dropped")
}

/// True when `a` and `b` share a substring of `ROLLING_WINDOW` (7) characters.
pub fn has_common_substring(a: &[u8], b: &[u8]) -> bool {
    if a.len() < ROLLING_WINDOW || b.len() < ROLLING_WINDOW {
        return false;
    }
    a.windows(ROLLING_WINDOW)
        .any(|wa| b.windows(ROLLING_WINDOW).any(|wb| wa == wb))
}

/// Weighted edit distance used by ssdeep: insert 1, delete 1, replace 2.
pub fn edit_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut prev: Vec<u32> = (0..=b.len() as u32).collect();
    let mut cur = vec![0u32; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i as u32 + 1;
        for (j, &cb) in b.iter().enumerate() {
            let add = prev[j + 1] + 1;
            let del = cur[j] + 1;
            let rep = prev[j] + if ca == cb { 0 } else { 2 };
            cur[j + 1] = add.min(del).min(rep);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn score_strings(a: &[u8], b: &[u8], block_size: u64) -> u32 {
    if a.len() > SPAMSUM_LENGTH || b.len() > SPAMSUM_LENGTH || !has_common_substring(a, b) {
        return 0;
    }
    let mut score = edit_distance(a, b);
    score = score * SPAMSUM_LENGTH as u32 / (a.len() + b.len()) as u32;
    score = 100 * score / SPAMSUM_LENGTH as u32;
    if score >= 100 {
        return 0;
    }
    score = 100 - score;
    let unclamped_from = (99 + ROLLING_WINDOW as u64) / ROLLING_WINDOW as u64 * MIN_BLOCKSIZE;
    if block_size >= unclamped_from {
        return score;
    }
    let cap = block_size / MIN_BLOCKSIZE * a.len().min(b.len()) as u64;
    if u64::from(score) > cap {
        cap as u32
    } else {
        score
    }
}

/// Similarity score 0..=100 between two digests (ssdeep's `fuzzy_compare`).
pub fn compare(a: &SsdeepHash, b: &SsdeepHash) -> u32 {
    let (bs1, bs2) = (a.block_size, b.block_size);
    if bs1 != bs2 && bs1.checked_mul(2) != Some(bs2) && bs2.checked_mul(2) != Some(bs1) {
        return 0;
    }
    let a1 = eliminate_sequences(&a.part1);
    let a2 = eliminate_sequences(&a.part2);
    let b1 = eliminate_sequences(&b.part1);
    let b2 = eliminate_sequences(&b.part2);
    if bs1 == bs2 && a1 == b1 && a2 == b2 {
        return 100;
    }
    if bs1 == bs2 {
        let s1 = score_strings(a1.as_bytes(), b1.as_bytes(), bs1);
        let s2 = score_strings(a2.as_bytes(), b2.as_bytes(), bs1.saturating_mul(2));
        s1.max(s2)
    } else if bs1.checked_mul(2) == Some(bs2) {
        score_strings(b1.as_bytes(), a2.as_bytes(), bs2)
    } else {
        score_strings(a1.as_bytes(), b2.as_bytes(), bs1)
    }
}

/// Parse and compare two digest strings.
pub fn compare_str(a: &str, b: &str) -> Result<u32> {
    Ok(compare(&a.parse()?, &b.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert_eq!(hash(b"").unwrap().to_string(), "3::");
    }

    #[test]
    fn tiny_input_has_single_char_parts() {
        let h = hash(b"a").unwrap();
        assert_eq!(h.block_size, 3);
        assert_eq!(h.part1.len(), 1);
        assert_eq!(h.part2.len(), 1);
    }

    #[test]
    fn streaming_with_known_size_matches_one_shot() {
        let data: Vec<u8> = (0..50_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let mut h = SsdeepHasher::with_total_size(data.len() as u64).unwrap();
        for chunk in data.chunks(777) {
            h.update(chunk);
        }
        assert_eq!(h.digest().unwrap(), hash(&data).unwrap());
    }

    #[test]
    fn declared_size_mismatch_is_an_error() {
        let mut h = SsdeepHasher::with_total_size(10).unwrap();
        h.update(b"abc");
        assert!(h.digest().is_err());
        assert!(SsdeepHasher::with_total_size(MAX_INPUT + 1).is_err());
    }

    #[test]
    fn parse_round_trip_and_filename_suffix() {
        let s = "96:abcdefgh:xyz";
        let h: SsdeepHash = s.parse().unwrap();
        assert_eq!(h.to_string(), s);
        let with_name: SsdeepHash = "96:abcdefgh:xyz,\"/some/file\"".parse().unwrap();
        assert_eq!(with_name, h);
    }

    #[test]
    fn parse_rejects_garbage() {
        for bad in ["", "3", "3:a", "x:a:b", "5:a:b", "3:a!:b", &format!("3:{}:b", "A".repeat(65))] {
            assert!(bad.parse::<SsdeepHash>().is_err(), "{bad}");
        }
    }

    #[test]
    fn sequence_elimination() {
        assert_eq!(eliminate_sequences("AAAAAABBBC"), "AAABBBC");
        assert_eq!(eliminate_sequences("abc"), "abc");
    }

    #[test]
    fn edit_distance_costs() {
        assert_eq!(edit_distance(b"abc", b"abc"), 0);
        assert_eq!(edit_distance(b"abc", b"abd"), 2);
        assert_eq!(edit_distance(b"abc", b"ab"), 1);
        assert_eq!(edit_distance(b"", b"xyz"), 3);
    }

    #[test]
    fn compare_identity_and_incompatible_block_sizes() {
        let a: SsdeepHash = "48:abcdefghijk:abc".parse().unwrap();
        assert_eq!(compare(&a, &a), 100);
        let far: SsdeepHash = "384:abcdefghijk:abc".parse().unwrap();
        assert_eq!(compare(&a, &far), 0);
    }

    #[test]
    fn compare_short_identical_parts_are_identical() {
        let a: SsdeepHash = "3:ab:c".parse().unwrap();
        assert_eq!(compare(&a, &a.clone()), 100);
    }

    #[test]
    fn small_block_size_caps_score() {
        // Same 7-char run, one char different: capped by block_size/3 * minlen.
        let a: SsdeepHash = "3:abcdefgh:".parse().unwrap();
        let b: SsdeepHash = "3:abcdefgX:".parse().unwrap();
        assert_eq!(compare(&a, &b), 8);
    }
}
