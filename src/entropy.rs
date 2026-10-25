//! Shannon entropy over byte buffers.
//!
//! Entropy is reported in bits per byte (0.0 ..= 8.0). Compressed or encrypted
//! data sits near 8.0, machine code typically 5.5-6.8, ASCII text 4-5 and
//! zero padding 0. All functions are single-pass, O(n) time and O(1) extra
//! space (a fixed 256-entry histogram).

/// Byte histogram (256 counters).
#[derive(Clone, Debug)]
pub struct Histogram {
    counts: [u64; 256],
    total: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self { counts: [0; 256], total: 0 }
    }
}

impl Histogram {
    /// Empty histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Histogram of `data`.
    pub fn of(data: &[u8]) -> Self {
        let mut h = Self::new();
        h.update(data);
        h
    }

    /// Add `data` to the counts.
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.counts[usize::from(b)] += 1;
        }
        self.total += data.len() as u64;
    }

    /// Number of bytes counted so far.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Number of distinct byte values seen.
    pub fn distinct(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// Shannon entropy in bits per byte; 0.0 for an empty histogram.
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        let mut e = 0.0;
        for &c in &self.counts {
            if c > 0 {
                let p = c as f64 / total;
                e -= p * p.log2();
            }
        }
        // Guard against -0.0 and tiny float overshoot above 8.
        e.clamp(0.0, 8.0)
    }
}

/// Shannon entropy of `data` in bits per byte.
pub fn shannon(data: &[u8]) -> f64 {
    Histogram::of(data).entropy()
}

/// Entropy of consecutive fixed-size windows (the last window may be shorter).
///
/// Useful for spotting an embedded compressed blob inside an otherwise
/// low-entropy section. Returns an empty vector for `window == 0`.
pub fn windowed(data: &[u8], window: usize) -> Vec<f64> {
    if window == 0 {
        return Vec::new();
    }
    data.chunks(window).map(shannon).collect()
}

/// Coarse interpretation of an entropy value, used by the human report.
pub fn classify(entropy: f64) -> &'static str {
    match entropy {
        e if e < 1.0 => "padding/sparse",
        e if e < 5.0 => "text/structured",
        e if e < 7.0 => "code/mixed",
        e if e < 7.5 => "dense",
        _ => "compressed/encrypted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_constant_are_zero() {
        assert!(shannon(&[]).abs() < f64::EPSILON);
        assert!(shannon(&[0x41; 1000]).abs() < f64::EPSILON);
    }

    #[test]
    fn uniform_bytes_are_eight_bits() {
        let data: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((shannon(&data) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn two_symbols_are_one_bit() {
        let data: Vec<u8> = [0u8, 1].iter().copied().cycle().take(1000).collect();
        assert!((shannon(&data) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn histogram_tracks_distinct_and_total() {
        let mut h = Histogram::new();
        h.update(b"abca");
        h.update(b"");
        assert_eq!(h.total(), 4);
        assert_eq!(h.distinct(), 3);
    }

    #[test]
    fn windows_cover_input() {
        let data = vec![7u8; 10];
        assert_eq!(windowed(&data, 4).len(), 3);
        assert_eq!(windowed(&data, 0), Vec::<f64>::new());
    }

    #[test]
    fn classify_bands() {
        assert_eq!(classify(0.2), "padding/sparse");
        assert_eq!(classify(4.5), "text/structured");
        assert_eq!(classify(6.0), "code/mixed");
        assert_eq!(classify(7.2), "dense");
        assert_eq!(classify(7.9), "compressed/encrypted");
    }
}
