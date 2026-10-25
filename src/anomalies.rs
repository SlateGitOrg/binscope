//! Structural heuristics ("anomalies") over a parsed binary.
//!
//! Each check is a cheap, explainable rule of thumb that analysts use when
//! deciding whether a sample deserves a closer look. None of them is a
//! verdict: benign software trips several (installers carry overlays,
//! reproducible builds zero their timestamps).

use serde::{Deserialize, Serialize};

use crate::format::{BinaryInfo, BinaryKind, Format};
use crate::rules::Severity;

/// Entropy (bits/byte) at or above which data is treated as compressed or
/// encrypted. 7.2 is the conventional triage threshold (Lyda & Hamrock 2007
/// report packed/encrypted PE sections averaging ~7.2 and above).
pub const HIGH_ENTROPY: f64 = 7.2;

/// Sections smaller than this are too short for a meaningful entropy reading.
pub const MIN_ENTROPY_BYTES: u64 = 256;

/// Identifiers of every check, for rule validation (`anomaly:` leaves).
pub const ANOMALY_IDS: [&str; 11] = [
    "high-entropy-section",
    "high-entropy-file",
    "writable-executable-section",
    "entry-outside-sections",
    "entry-in-writable-section",
    "executable-section-without-file-data",
    "section-beyond-eof",
    "overlay",
    "no-imports",
    "nonstandard-pe-section-name",
    "pe-zero-timestamp",
];

/// One heuristic hit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Anomaly {
    /// Stable identifier (see [`ANOMALY_IDS`]).
    pub id: String,
    /// How much attention it deserves on its own.
    pub severity: Severity,
    /// Human-readable explanation with the concrete values.
    pub message: String,
}

fn push(out: &mut Vec<Anomaly>, id: &str, severity: Severity, message: String) {
    debug_assert!(ANOMALY_IDS.contains(&id), "unregistered anomaly id {id}");
    out.push(Anomaly { id: id.to_string(), severity, message });
}

const KNOWN_PE_SECTIONS: [&str; 20] = [
    ".text", ".rdata", ".data", ".pdata", ".xdata", ".rsrc", ".reloc", ".idata", ".edata", ".tls", ".bss", ".CRT",
    ".didat", ".gfids", ".giats", ".00cfg", ".debug", "INIT", "PAGE", ".retplne",
];

/// Run every check on `info` (recursing into universal-binary slices) plus
/// the whole-file entropy check.
pub fn detect(info: &BinaryInfo, file_len: u64, file_entropy: f64) -> Vec<Anomaly> {
    let mut out = Vec::new();
    if file_entropy >= HIGH_ENTROPY && file_len >= 1024 {
        push(
            &mut out,
            "high-entropy-file",
            Severity::Medium,
            format!("whole-file entropy {file_entropy:.2} bits/byte suggests compressed or encrypted content"),
        );
    }
    detect_image(info, file_len, &mut out);
    for slice in &info.slices {
        detect_image(slice, file_len, &mut out);
    }
    out
}

fn detect_image(info: &BinaryInfo, file_len: u64, out: &mut Vec<Anomaly>) {
    let tag = if info.format == Format::MachO && info.arch != "universal" {
        format!("[{}] ", info.arch)
    } else {
        String::new()
    };
    for s in &info.sections {
        if s.file_size >= MIN_ENTROPY_BYTES && s.entropy >= HIGH_ENTROPY {
            push(
                out,
                "high-entropy-section",
                Severity::Medium,
                format!("{tag}section {} has entropy {:.2} over {} bytes", s.name, s.entropy, s.file_size),
            );
        }
        if s.write && s.execute {
            push(
                out,
                "writable-executable-section",
                Severity::High,
                format!("{tag}section {} is mapped writable and executable ({})", s.name, s.perms()),
            );
        }
        if s.execute && s.file_size == 0 && s.virtual_size > 0 {
            push(
                out,
                "executable-section-without-file-data",
                Severity::Medium,
                format!(
                    "{tag}executable section {} has {} bytes in memory but none on disk (typical of unpacking stubs)",
                    s.name, s.virtual_size
                ),
            );
        }
        if s.file_size > 0 && s.file_offset.saturating_add(s.file_size) > file_len {
            push(
                out,
                "section-beyond-eof",
                Severity::Medium,
                format!(
                    "{tag}section {} claims bytes {:#x}..{:#x} but the file is {file_len} bytes",
                    s.name,
                    s.file_offset,
                    s.file_offset.saturating_add(s.file_size)
                ),
            );
        }
        if info.format == Format::Pe && !KNOWN_PE_SECTIONS.contains(&s.name.as_str()) {
            push(
                out,
                "nonstandard-pe-section-name",
                Severity::Info,
                format!("section name {:?} is not one the common toolchains emit", s.name),
            );
        }
    }
    if let Some(entry) = info.entry_point {
        if !info.sections.is_empty() {
            match info.section_at_va(entry) {
                None => push(
                    out,
                    "entry-outside-sections",
                    Severity::Medium,
                    format!("{tag}entry point {entry:#x} is not inside any section"),
                ),
                Some(s) if s.write => push(
                    out,
                    "entry-in-writable-section",
                    Severity::High,
                    format!("{tag}entry point {entry:#x} lies in writable section {}", s.name),
                ),
                Some(_) => {}
            }
        }
    }
    if let Some(o) = &info.overlay {
        let severity = if o.entropy >= HIGH_ENTROPY { Severity::Medium } else { Severity::Low };
        push(
            out,
            "overlay",
            severity,
            format!("{} bytes appended after the image at {:#x} (entropy {:.2})", o.size, o.offset, o.entropy),
        );
    }
    if info.imports.is_empty()
        && info.slices.is_empty()
        && matches!(info.kind, BinaryKind::Executable | BinaryKind::SharedLibrary)
    {
        push(
            out,
            "no-imports",
            Severity::Low,
            format!("{tag}{:?} image imports nothing (static, packed, or resolves APIs at run time)", info.kind)
                .to_lowercase(),
        );
    }
    if let Some(pe) = &info.pe {
        if pe.timestamp == 0 {
            push(
                out,
                "pe-zero-timestamp",
                Severity::Info,
                "COFF TimeDateStamp is zero (stripped or reproducible build)".into(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{Overlay, PeDetails, Section};

    #[allow(clippy::too_many_arguments)] // test fixture builder
    fn section(name: &str, entropy: f64, w: bool, x: bool, off: u64, size: u64, va: u64, vsize: u64) -> Section {
        Section {
            name: name.into(),
            file_offset: off,
            file_size: size,
            virtual_address: va,
            virtual_size: vsize,
            read: true,
            write: w,
            execute: x,
            entropy,
            raw_flags: 0,
        }
    }

    fn info(format: Format, sections: Vec<Section>, entry: Option<u64>) -> BinaryInfo {
        BinaryInfo {
            format,
            arch: "x86_64".into(),
            bits: 64,
            endian: "little".into(),
            kind: BinaryKind::Executable,
            entry_point: entry,
            sections,
            imports: Vec::new(),
            exports: Vec::new(),
            libraries: Vec::new(),
            mitigations: Vec::new(),
            overlay: None,
            pe: None,
            elf: None,
            macho: None,
            slices: Vec::new(),
        }
    }

    fn ids(v: &[Anomaly]) -> Vec<&str> {
        v.iter().map(|a| a.id.as_str()).collect()
    }

    #[test]
    fn packed_like_layout_trips_the_expected_checks() {
        let mut i = info(
            Format::Pe,
            vec![
                section("UPX0", 0.0, true, true, 0x400, 0, 0x1000, 0x8000),
                section("UPX1", 7.9, true, true, 0x400, 0x3000, 0x9000, 0x3000),
            ],
            Some(0x9100),
        );
        i.overlay = Some(Overlay { offset: 0x3400, size: 100, entropy: 7.5 });
        i.pe = Some(PeDetails {
            machine: 0x8664,
            timestamp: 0,
            image_base: 0,
            subsystem: "windows-console".into(),
            linker_version: "14.0".into(),
            dll_characteristics: Vec::new(),
            ordinal_imports: 0,
            signed: false,
            pdb_path: None,
        });
        let found = detect(&i, 0x3000, 7.6);
        let got = ids(&found);
        for want in [
            "high-entropy-file",
            "high-entropy-section",
            "writable-executable-section",
            "executable-section-without-file-data",
            "section-beyond-eof",
            "nonstandard-pe-section-name",
            "entry-in-writable-section",
            "overlay",
            "no-imports",
            "pe-zero-timestamp",
        ] {
            assert!(got.contains(&want), "missing {want} in {got:?}");
        }
        let overlay = found.iter().find(|a| a.id == "overlay").unwrap();
        assert_eq!(overlay.severity, Severity::Medium);
        for a in &found {
            assert!(ANOMALY_IDS.contains(&a.id.as_str()));
        }
    }

    #[test]
    fn clean_image_has_no_anomalies() {
        let mut i =
            info(Format::Elf, vec![section(".text", 6.0, false, true, 0x100, 0x400, 0x1100, 0x400)], Some(0x1100));
        i.imports.push(crate::format::Import { library: None, name: "puts".into(), ordinal: None, weak: false });
        assert_eq!(detect(&i, 0x1000, 5.0), Vec::<Anomaly>::new());
    }

    #[test]
    fn entry_outside_sections_and_slice_recursion() {
        let mut fat = info(Format::MachOFat, Vec::new(), None);
        fat.arch = "universal".into();
        let mut slice =
            info(Format::MachO, vec![section("__TEXT,__text", 5.0, false, true, 0, 16, 0x1000, 16)], Some(0x5000));
        slice.arch = "aarch64".into();
        fat.slices.push(slice);
        let found = detect(&fat, 100, 3.0);
        assert_eq!(ids(&found), vec!["entry-outside-sections", "no-imports"]);
        assert!(found[0].message.starts_with("[aarch64]"));
    }
}
