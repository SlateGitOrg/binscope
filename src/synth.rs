//! Deterministic synthetic inputs for tests, benchmarks and the reference
//! vector generator.
//!
//! The same `(kind, size, seed)` triple always yields the same bytes on every
//! platform, so reference digests produced by the real `ssdeep`/`tlsh` tools
//! over files written by `examples/gen_synth.rs` can be re-derived in tests
//! without committing megabytes of data.

/// Small xorshift64* generator (not cryptographic; reproducible).
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Seeded generator (a zero seed is remapped to a fixed constant).
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

const WORDS: [&str; 32] = [
    "section",
    "import",
    "export",
    "entropy",
    "string",
    "symbol",
    "loader",
    "header",
    "binary",
    "digest",
    "rolling",
    "window",
    "bucket",
    "cluster",
    "triage",
    "sample",
    "capability",
    "library",
    "segment",
    "offset",
    "relocation",
    "archive",
    "module",
    "runtime",
    "linker",
    "object",
    "table",
    "signature",
    "checksum",
    "quartile",
    "report",
    "rule",
];

/// Kind of synthetic content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Uniform random bytes (entropy ~8).
    Random,
    /// Space-separated words from a 32-word vocabulary (entropy ~4).
    Text,
    /// 4 KiB blocks cycling through random, text, zeros and a counter ramp,
    /// which loosely imitates the layout of an executable.
    Mixed,
}

impl Kind {
    /// Name used in reference-vector files.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Random => "random",
            Kind::Text => "text",
            Kind::Mixed => "mixed",
        }
    }

    /// Parse a reference-vector kind name.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "random" => Some(Kind::Random),
            "text" => Some(Kind::Text),
            "mixed" => Some(Kind::Mixed),
            _ => None,
        }
    }
}

fn fill_text(rng: &mut Rng, out: &mut Vec<u8>, size: usize) {
    while out.len() < size {
        let w = WORDS[rng.below(WORDS.len() as u64) as usize];
        out.extend_from_slice(w.as_bytes());
        out.push(if rng.below(12) == 0 { b'\n' } else { b' ' });
    }
    out.truncate(size);
}

/// Generate `size` bytes of `kind` content from `seed`.
pub fn generate(kind: Kind, size: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::with_capacity(size);
    match kind {
        Kind::Random => {
            while out.len() < size {
                out.extend_from_slice(&rng.next_u64().to_le_bytes());
            }
            out.truncate(size);
        }
        Kind::Text => fill_text(&mut rng, &mut out, size),
        Kind::Mixed => {
            let mut block = 0usize;
            while out.len() < size {
                let end = (out.len() + 4096).min(size);
                match block % 4 {
                    0 => {
                        while out.len() < end {
                            out.push(rng.next_u64() as u8);
                        }
                    }
                    1 => fill_text(&mut rng, &mut out, end),
                    2 => out.resize(end, 0),
                    _ => {
                        let mut v = 0u8;
                        while out.len() < end {
                            out.push(v);
                            v = v.wrapping_add(3);
                        }
                    }
                }
                block += 1;
            }
        }
    }
    out
}

/// Copy of `data` with roughly `per_mille`/1000 of its bytes overwritten and a
/// few short insertions, simulating a lightly modified build.
pub fn mutate(data: &[u8], per_mille: u32, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed ^ 0xA5A5_5A5A);
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    let edits = (out.len() as u64 * u64::from(per_mille) / 1000).max(1);
    for _ in 0..edits {
        let at = rng.below(out.len() as u64) as usize;
        out[at] = rng.next_u64() as u8;
    }
    for _ in 0..(edits / 50).min(16) {
        let at = rng.below(out.len() as u64) as usize;
        let ins: Vec<u8> = (0..8).map(|_| rng.next_u64() as u8).collect();
        out.splice(at..at, ins);
    }
    out
}

/// Copy of `data` with one contiguous run of `len` bytes at `offset`
/// replaced by random bytes: a *localised* edit, like a rebuilt function.
pub fn patch(data: &[u8], offset: usize, len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed ^ 0x5EED);
    let mut out = data.to_vec();
    let start = offset.min(out.len());
    let end = offset.saturating_add(len).min(out.len());
    for b in &mut out[start..end] {
        *b = rng.next_u64() as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sized() {
        for kind in [Kind::Random, Kind::Text, Kind::Mixed] {
            let a = generate(kind, 10_000, 42);
            assert_eq!(a.len(), 10_000);
            assert_eq!(a, generate(kind, 10_000, 42));
            assert_ne!(a, generate(kind, 10_000, 43));
            assert_eq!(Kind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(generate(Kind::Text, 0, 1), Vec::<u8>::new());
        assert_eq!(Kind::from_name("bogus"), None);
    }

    #[test]
    fn zero_seed_is_usable() {
        let mut r = Rng::new(0);
        assert_ne!(r.next_u64(), 0);
    }

    #[test]
    fn mutation_changes_a_little() {
        let base = generate(Kind::Mixed, 20_000, 7);
        let m = mutate(&base, 10, 1);
        assert_ne!(m, base);
        assert!(m.len() >= base.len());
        assert_eq!(mutate(&[], 10, 1), Vec::<u8>::new());
    }

    #[test]
    fn patch_is_localised() {
        let base = generate(Kind::Text, 1000, 3);
        let p = patch(&base, 100, 50, 1);
        assert_eq!(p[..100], base[..100]);
        assert_eq!(p[150..], base[150..]);
        assert_ne!(p[100..150], base[100..150]);
        assert_eq!(patch(&base, 5000, 10, 1), base);
    }
}
