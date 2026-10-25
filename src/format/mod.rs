//! Container parsing: ELF, PE and Mach-O (including universal binaries) into
//! one format-neutral model.
//!
//! Parsing is delegated to `goblin`; this module normalises the result,
//! computes per-section entropy over the section's file bytes, and fills in
//! what goblin does not provide (Mach-O chained-fixup imports, ELF symbol to
//! library attribution through version-needs, security mitigations, overlay
//! detection).

mod elf;
mod macho;
mod pe;

pub use pe::import_refs as pe_import_refs;

use serde::{Deserialize, Serialize};

use crate::entropy;
use crate::error::{Error, Result};

/// Container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Executable and Linkable Format.
    Elf,
    /// Portable Executable (PE32 / PE32+).
    Pe,
    /// Single-architecture Mach-O.
    #[serde(rename = "macho")]
    MachO,
    /// Universal ("fat") Mach-O holding several architecture slices.
    #[serde(rename = "macho-fat")]
    MachOFat,
}

impl Format {
    /// Stable short name, as used in rule files (`elf`, `pe`, `macho`).
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Elf => "elf",
            Format::Pe => "pe",
            Format::MachO => "macho",
            Format::MachOFat => "macho-fat",
        }
    }

    /// Parse a rule-file format name. `macho` also matches universal files.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "elf" => Some(Format::Elf),
            "pe" => Some(Format::Pe),
            "macho" | "mach-o" => Some(Format::MachO),
            "macho-fat" | "fat" | "universal" => Some(Format::MachOFat),
            _ => None,
        }
    }
}

/// Coarse kind of image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinaryKind {
    /// Program image.
    Executable,
    /// Shared library / DLL / dylib.
    SharedLibrary,
    /// Relocatable object.
    Object,
    /// Core dump.
    Core,
    /// Anything else (bundles, kernel extensions, ...).
    Other,
}

/// One section (or, when a file has no section table, one loadable segment).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Section {
    /// Section name (`.text`, `__TEXT,__text`, `PT_LOAD[0]` ...).
    pub name: String,
    /// Offset of the section's bytes in the file.
    pub file_offset: u64,
    /// Number of bytes the section occupies in the file (0 for `.bss`-like).
    pub file_size: u64,
    /// Virtual address when loaded.
    pub virtual_address: u64,
    /// Size in memory.
    pub virtual_size: u64,
    /// Readable when mapped.
    pub read: bool,
    /// Writable when mapped.
    pub write: bool,
    /// Executable when mapped.
    pub execute: bool,
    /// Shannon entropy (bits/byte) of the section's file bytes.
    pub entropy: f64,
    /// Format-specific flags word (ELF `sh_flags`, PE characteristics,
    /// Mach-O section flags).
    pub raw_flags: u64,
}

impl Section {
    /// `rwx`-style permission string.
    pub fn perms(&self) -> String {
        format!(
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' }
        )
    }

    /// True when `addr` lies inside the section's virtual range.
    pub fn contains_va(&self, addr: u64) -> bool {
        let size = self.virtual_size.max(self.file_size);
        addr >= self.virtual_address && addr - self.virtual_address < size
    }
}

/// An imported symbol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Import {
    /// Providing library, when the format records it.
    pub library: Option<String>,
    /// Symbol name as stored (Mach-O names keep their leading underscore).
    /// Ordinal-only PE imports are named `ord<N>` (or the well-known name
    /// for `ws2_32`/`wsock32`/`oleaut32`, as pefile does).
    pub name: String,
    /// PE import ordinal when imported by ordinal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u16>,
    /// Weak import (ELF weak binding, Mach-O weak import).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub weak: bool,
}

impl Import {
    /// Name with the Mach-O C-symbol underscore removed, for rule matching.
    pub fn normalized_name(&self, format: Format) -> &str {
        match format {
            Format::MachO | Format::MachOFat => self.name.strip_prefix('_').unwrap_or(&self.name),
            _ => &self.name,
        }
    }
}

/// An exported symbol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    /// Symbol name (`ord<N>` for nameless PE exports).
    pub name: String,
    /// Address / RVA of the export (0 for forwarders).
    pub address: u64,
    /// PE forwarder target (`OTHER.dll!Name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_to: Option<String>,
}

/// A hardening feature and whether the binary has it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mitigation {
    /// Short name (`aslr`, `nx`, `pie`, `relro`, `canary`, ...).
    pub name: String,
    /// Present / enabled.
    pub enabled: bool,
    /// Extra detail (`partial` RELRO, the flag that was checked, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Mitigation {
    pub(crate) fn new(name: &str, enabled: bool, detail: Option<String>) -> Self {
        Self { name: name.to_string(), enabled, detail }
    }
}

/// Bytes appended after the end of the last mapped section/segment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Overlay {
    /// File offset where the overlay starts.
    pub offset: u64,
    /// Overlay length in bytes.
    pub size: u64,
    /// Shannon entropy of the overlay.
    pub entropy: f64,
}

/// PE-specific header fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeDetails {
    /// COFF machine value.
    pub machine: u16,
    /// COFF `TimeDateStamp` (with `/Brepro` builds this is a hash, not a time).
    pub timestamp: u32,
    /// Preferred image base.
    pub image_base: u64,
    /// Subsystem name (`console`, `gui`, ...).
    pub subsystem: String,
    /// Linker version `major.minor`.
    pub linker_version: String,
    /// Set `DllCharacteristics` flag names.
    pub dll_characteristics: Vec<String>,
    /// Number of imports done by ordinal only.
    pub ordinal_imports: usize,
    /// Authenticode certificate table present.
    pub signed: bool,
    /// `CodeView` PDB path from the debug directory, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb_path: Option<String>,
}

/// ELF-specific fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfDetails {
    /// `e_type` name.
    pub elf_type: String,
    /// OS/ABI byte name.
    pub os_abi: String,
    /// `PT_INTERP` program interpreter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    /// `DT_SONAME`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soname: Option<String>,
    /// `DT_RPATH` + `DT_RUNPATH` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpaths: Vec<String>,
    /// A static `.symtab` is present (binary not stripped).
    pub has_symtab: bool,
    /// Number of program headers.
    pub program_headers: usize,
}

/// Mach-O-specific fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachODetails {
    /// File type name (`execute`, `dylib`, ...).
    pub filetype: String,
    /// Set header flag names.
    pub flags: Vec<String>,
    /// `LC_UUID`, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Minimum OS version from `LC_BUILD_VERSION` / `LC_VERSION_MIN_*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_os: Option<String>,
    /// `LC_CODE_SIGNATURE` present.
    pub code_signature: bool,
    /// Imports were recovered from `LC_DYLD_CHAINED_FIXUPS`.
    pub chained_fixups: bool,
    /// `LC_RPATH` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpaths: Vec<String>,
}

/// Everything binscope extracts from the container structure of one image.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// Container format.
    pub format: Format,
    /// Architecture name (`x86_64`, `aarch64`, `i386`, `universal` ...).
    pub arch: String,
    /// Pointer width in bits.
    pub bits: u8,
    /// `little` or `big`.
    pub endian: String,
    /// Image kind.
    pub kind: BinaryKind,
    /// Entry point virtual address, when defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<u64>,
    /// Sections in file order.
    pub sections: Vec<Section>,
    /// Imported symbols (PE: import-directory order).
    pub imports: Vec<Import>,
    /// Exported symbols.
    pub exports: Vec<Export>,
    /// Needed libraries / imported DLLs, in load order.
    pub libraries: Vec<String>,
    /// Hardening features.
    pub mitigations: Vec<Mitigation>,
    /// Trailing data beyond the mapped image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<Overlay>,
    /// PE header details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeDetails>,
    /// ELF header details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf: Option<ElfDetails>,
    /// Mach-O header details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macho: Option<MachODetails>,
    /// Per-architecture slices of a universal Mach-O.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slices: Vec<BinaryInfo>,
}

impl BinaryInfo {
    /// Imports of this image and all of its slices.
    pub fn all_imports(&self) -> Vec<&Import> {
        let mut v: Vec<&Import> = self.imports.iter().collect();
        for s in &self.slices {
            v.extend(s.all_imports());
        }
        v
    }

    /// Sections of this image and all of its slices.
    pub fn all_sections(&self) -> Vec<&Section> {
        let mut v: Vec<&Section> = self.sections.iter().collect();
        for s in &self.slices {
            v.extend(s.all_sections());
        }
        v
    }

    /// Section whose virtual range contains `addr`.
    pub fn section_at_va(&self, addr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_va(addr))
    }
}

/// Result of format detection on raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detected {
    /// One of the supported formats.
    Supported(Format),
    /// A container goblin recognises that binscope does not analyse
    /// (COFF object, TE image, `ar` archive).
    Unsupported(&'static str),
    /// Not a recognised executable container.
    Unknown,
}

/// Cheap magic-number detection (no full parse).
pub fn detect(data: &[u8]) -> Detected {
    match data {
        [0x7f, b'E', b'L', b'F', ..] => Detected::Supported(Format::Elf),
        [b'M', b'Z', ..] => Detected::Supported(Format::Pe),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..] | [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..] => Detected::Supported(Format::MachO),
        // 0xcafebabe is shared with Java class files; goblin disambiguates
        // by the slice count, so treat it as a fat Mach-O candidate.
        [0xca, 0xfe, 0xba, 0xbe | 0xbf, ..] => Detected::Supported(Format::MachOFat),
        [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n', ..] => Detected::Unsupported("ar archive"),
        [b'V', b'Z', ..] => Detected::Unsupported("TE image"),
        _ => Detected::Unknown,
    }
}

/// Parse `data` into a [`BinaryInfo`].
///
/// Returns `Ok(None)` when the bytes are not a supported container (the
/// caller can still hash and string-scan them) and `Err` when the container
/// is recognised but malformed.
pub fn parse(data: &[u8]) -> Result<Option<BinaryInfo>> {
    // Triage inputs are hostile by definition. A panic inside the parser on a
    // malformed file must become a parse error for that file, not take down
    // a whole batch run.
    match std::panic::catch_unwind(|| parse_inner(data)) {
        Ok(r) => r,
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "parser panicked".into());
            let label = match detect(data) {
                Detected::Supported(f) => format_label(f),
                _ => "binary",
            };
            Err(Error::parse(label, format!("parser panic: {msg}")))
        }
    }
}

fn parse_inner(data: &[u8]) -> Result<Option<BinaryInfo>> {
    use goblin::Object;
    let obj = match Object::parse(data) {
        Ok(o) => o,
        Err(e) => {
            return match detect(data) {
                Detected::Supported(f) => Err(Error::parse(format_label(f), e.to_string())),
                _ => Ok(None),
            }
        }
    };
    match obj {
        Object::Elf(e) => Ok(Some(elf::analyze(&e, data))),
        Object::PE(p) => Ok(Some(pe::analyze(&p, data))),
        Object::Mach(m) => macho::analyze(m, data).map(Some),
        _ => Ok(None),
    }
}

fn format_label(f: Format) -> &'static str {
    match f {
        Format::Elf => "ELF",
        Format::Pe => "PE",
        Format::MachO | Format::MachOFat => "Mach-O",
    }
}

/// Bytes of `[offset, offset+size)` clamped to the file.
pub(crate) fn file_slice(data: &[u8], offset: u64, size: u64) -> &[u8] {
    let len = data.len() as u64;
    let start = offset.min(len);
    let end = offset.saturating_add(size).min(len);
    &data[start as usize..end as usize]
}

/// Entropy of a section's file bytes.
pub(crate) fn section_entropy(data: &[u8], offset: u64, size: u64) -> f64 {
    entropy::shannon(file_slice(data, offset, size))
}

/// Overlay from the end of the furthest file-backed range to EOF, if any.
pub(crate) fn overlay_after(data: &[u8], image_end: u64) -> Option<Overlay> {
    let len = data.len() as u64;
    if image_end == 0 || image_end >= len {
        return None;
    }
    let tail = file_slice(data, image_end, len - image_end);
    Some(Overlay { offset: image_end, size: len - image_end, entropy: entropy::shannon(tail) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_magics() {
        assert_eq!(detect(b"\x7fELF...."), Detected::Supported(Format::Elf));
        assert_eq!(detect(b"MZ\x90\x00"), Detected::Supported(Format::Pe));
        assert_eq!(detect(&[0xcf, 0xfa, 0xed, 0xfe]), Detected::Supported(Format::MachO));
        assert_eq!(detect(&[0xca, 0xfe, 0xba, 0xbe]), Detected::Supported(Format::MachOFat));
        assert_eq!(detect(b"!<arch>\nxxxx"), Detected::Unsupported("ar archive"));
        assert_eq!(detect(b"VZ.."), Detected::Unsupported("TE image"));
        assert_eq!(detect(b"hello"), Detected::Unknown);
    }

    #[test]
    fn unknown_bytes_parse_to_none() {
        assert!(parse(b"just some text, not a binary").unwrap().is_none());
    }

    #[test]
    fn truncated_elf_is_a_parse_error() {
        let err = parse(b"\x7fELF\x02\x01\x01").unwrap_err();
        assert!(err.to_string().contains("ELF"), "{err}");
    }

    #[test]
    fn slices_are_clamped() {
        let data = [1u8, 2, 3, 4];
        assert_eq!(file_slice(&data, 2, 10), &[3, 4]);
        assert_eq!(file_slice(&data, 10, 10), []);
        assert_eq!(file_slice(&data, u64::MAX, u64::MAX), []);
    }

    #[test]
    fn overlay_only_when_bytes_follow_the_image() {
        let data = vec![0u8; 100];
        assert!(overlay_after(&data, 100).is_none());
        assert!(overlay_after(&data, 0).is_none());
        let o = overlay_after(&data, 60).unwrap();
        assert_eq!((o.offset, o.size), (60, 40));
    }

    #[test]
    fn format_names_round_trip() {
        for f in [Format::Elf, Format::Pe, Format::MachO, Format::MachOFat] {
            assert_eq!(Format::from_name(f.as_str()), Some(f));
        }
        assert_eq!(Format::from_name("coff"), None);
    }

    #[test]
    fn section_helpers() {
        let s = Section {
            name: ".text".into(),
            file_offset: 0,
            file_size: 0x10,
            virtual_address: 0x1000,
            virtual_size: 0x20,
            read: true,
            write: false,
            execute: true,
            entropy: 0.0,
            raw_flags: 0,
        };
        assert_eq!(s.perms(), "r-x");
        assert!(s.contains_va(0x101f));
        assert!(!s.contains_va(0x1020));
        assert!(!s.contains_va(0xfff));
    }
}
