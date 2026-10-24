//! Fuzzy (similarity-preserving) hashes: ssdeep and TLSH.
//!
//! Both are implemented from their published descriptions and verified
//! against the reference tools' output (see `tests/reference_vectors.rs`).

pub mod ssdeep;
pub mod tlsh;
mod tlsh_tables;

use serde::{Deserialize, Serialize};

pub use ssdeep::SsdeepHash;
pub use tlsh::Tlsh;

/// Both fuzzy digests for one input; either may be missing (TLSH needs at
/// least 50 bytes with some variety).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyDigests {
    /// ssdeep digest string.
    pub ssdeep: Option<String>,
    /// TLSH digest string (`T1...`).
    pub tlsh: Option<String>,
    /// Why TLSH is absent, if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsh_unavailable: Option<String>,
}

impl FuzzyDigests {
    /// Compute both digests of `data`.
    pub fn of(data: &[u8]) -> Self {
        let ssdeep = ssdeep::hash(data).ok().map(|h| h.to_string());
        let (tlsh, tlsh_unavailable) = match tlsh::hash(data) {
            Ok(h) => (Some(h.to_hex()), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self { ssdeep, tlsh, tlsh_unavailable }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_input_reports_missing_tlsh() {
        let d = FuzzyDigests::of(b"tiny");
        assert!(d.ssdeep.is_some());
        assert!(d.tlsh.is_none());
        assert!(d.tlsh_unavailable.unwrap().contains("50"));
    }
}
