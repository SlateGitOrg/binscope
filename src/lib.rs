//! # binscope
//!
//! Static triage for ELF, Mach-O and PE binaries.
//!
//! * [`format`] parses the container (via `goblin`) into a format-neutral
//!   [`format::BinaryInfo`]: sections with per-section entropy, imports,
//!   exports, libraries and format-specific metadata.
//! * [`entropy`], [`strings`], [`hashes`] and [`fuzzy`] are the analysis
//!   primitives (Shannon entropy, ASCII/UTF-16 strings, MD5/SHA/imphash,
//!   ssdeep and TLSH).
//! * [`rules`] evaluates YAML capability rules (API sets, strings, section
//!   properties -> capability labels) with evidence.
//! * [`triage`] ties everything into a [`triage::TriageReport`]; [`report`]
//!   renders it for humans or JSON.
//! * [`cluster`] groups a sample set by fuzzy-hash similarity.
//!
//! binscope never executes, emulates or modifies its inputs.

pub mod entropy;
pub mod error;
pub mod format;
pub mod fuzzy;
pub mod hashes;
pub mod strings;
pub mod synth;

pub use error::{Error, Result};

