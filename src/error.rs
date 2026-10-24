//! Error type shared by every binscope module.

use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while triaging, hashing or clustering.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading an input file or rule file failed.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The container format was recognised but its structures are malformed.
    #[error("malformed {format} binary: {message}")]
    Parse {
        /// Format being parsed (ELF, PE, Mach-O).
        format: &'static str,
        /// Human-readable cause.
        message: String,
    },
    /// A fuzzy-hash digest string could not be parsed.
    #[error("invalid {kind} digest {digest:?}: {reason}")]
    InvalidDigest {
        /// `ssdeep` or `tlsh`.
        kind: &'static str,
        /// The offending input (truncated by the caller if huge).
        digest: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A fuzzy hash cannot be computed for this input (too small, too uniform).
    #[error("{kind} digest unavailable: {reason}")]
    DigestUnavailable {
        /// `ssdeep` or `tlsh`.
        kind: &'static str,
        /// Why no digest exists.
        reason: String,
    },
    /// A capability rule file failed to load or validate.
    #[error("rule error in {origin}: {message}")]
    Rule {
        /// File name (or `builtin:<name>`) the rule came from.
        origin: String,
        /// What is wrong, including the rule id when known.
        message: String,
    },
    /// Invalid user-supplied configuration (thresholds, limits).
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl Error {
    /// Build an [`Error::Io`] for `path`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Build an [`Error::Parse`].
    pub fn parse(format: &'static str, message: impl Into<String>) -> Self {
        Self::Parse {
            format,
            message: message.into(),
        }
    }
}
