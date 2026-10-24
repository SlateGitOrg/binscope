//! PE32 / PE32+ normalisation.

use goblin::pe::import::SyntheticImportLookupTableEntry;
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use goblin::pe::PE;

use super::{
    overlay_after, section_entropy, BinaryInfo, BinaryKind, Export, Format, Import, Mitigation, PeDetails, Section,
};
use crate::hashes::ImportRef;

const IMAGE_FILE_DLL: u16 = 0x2000;

const DLL_CHARACTERISTICS: [(u16, &str); 11] = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
];

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "i386",
        0x8664 => "x86_64",
        0xaa64 => "aarch64",
        0x01c0 | 0x01c4 => "arm",
        0x0200 => "ia64",
        _ => "unknown",
    }
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-console",
        9 => "windows-ce-gui",
        10..=13 => "efi",
        16 => "windows-boot-application",
        _ => "other",
    }
}

/// Imports as `(dll, reference)` pairs in import-directory order: the exact
/// sequence pefile's imphash walks.
pub fn import_refs<'a>(pe: &'a PE<'a>) -> Vec<(&'a str, ImportRef<'a>)> {
    let mut out = Vec::new();
    if let Some(data) = &pe.import_data {
        for entry in &data.import_data {
            let Some(table) = &entry.import_lookup_table else { continue };
            for item in table {
                let r = match item {
                    SyntheticImportLookupTableEntry::OrdinalNumber(o) => ImportRef::Ordinal(*o),
                    SyntheticImportLookupTableEntry::HintNameTableRVA((_, hint)) => ImportRef::Name(hint.name),
                };
                out.push((entry.name, r));
            }
        }
    }
    out
}

pub(super) fn analyze(pe: &PE<'_>, data: &[u8]) -> BinaryInfo {
    let coff = &pe.header.coff_header;
    let opt = pe.header.optional_header.as_ref();
    let image_base = pe.image_base;

    let mut sections = Vec::with_capacity(pe.sections.len());
    let mut image_end = u64::from(pe.header.dos_header.pe_pointer);
    for s in &pe.sections {
        let name = match &s.real_name {
            Some(n) => n.clone(),
            None => s.name().unwrap_or("").to_string(),
        };
        let offset = u64::from(s.pointer_to_raw_data);
        let size = u64::from(s.size_of_raw_data);
        if size > 0 {
            image_end = image_end.max(offset + size);
        }
        sections.push(Section {
            name,
            file_offset: offset,
            file_size: size,
            virtual_address: image_base + u64::from(s.virtual_address),
            virtual_size: u64::from(s.virtual_size),
            read: s.characteristics & IMAGE_SCN_MEM_READ != 0,
            write: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
            execute: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            entropy: section_entropy(data, offset, size),
            raw_flags: u64::from(s.characteristics),
        });
    }
    if let Some(h) = opt {
        image_end = image_end.max(u64::from(h.windows_fields.size_of_headers));
    }
    // An Authenticode blob at the end of the file is part of the image, not an overlay.
    let mut signed = false;
    if let Some(cert) = opt.and_then(|h| h.data_directories.get_certificate_table().copied()) {
        if cert.size > 0 {
            signed = true;
            let end = u64::from(cert.virtual_address) + u64::from(cert.size);
            if end <= data.len() as u64 && u64::from(cert.virtual_address) >= image_end {
                image_end = end;
            }
        }
    }

    let refs = import_refs(pe);
    let ordinal_imports = refs.iter().filter(|(_, r)| matches!(r, ImportRef::Ordinal(_))).count();
    let imports = refs
        .iter()
        .map(|(dll, r)| match r {
            ImportRef::Name(n) => {
                Import { library: Some((*dll).to_string()), name: (*n).to_string(), ordinal: None, weak: false }
            }
            ImportRef::Ordinal(o) => {
                // Same name pefile would use for this ordinal.
                let token = crate::hashes::imphash_input([(*dll, ImportRef::Ordinal(*o))]);
                let name = token.rsplit_once('.').map_or(token.as_str(), |(_, f)| f).to_string();
                Import { library: Some((*dll).to_string()), name, ordinal: Some(*o), weak: false }
            }
        })
        .collect();

    let exports = pe
        .exports
        .iter()
        .map(|e| {
            let forwarded_to = e.reexport.as_ref().map(|r| match r {
                goblin::pe::export::Reexport::DLLName { export, lib } => format!("{lib}!{export}"),
                goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}!#{ordinal}"),
            });
            Export {
                name: e.name.map_or_else(|| format!("rva_{:x}", e.rva), str::to_string),
                address: if forwarded_to.is_some() { 0 } else { image_base + e.rva as u64 },
                forwarded_to,
            }
        })
        .collect();

    let dll_chars = opt.map_or(0, |h| h.windows_fields.dll_characteristics);
    let has = |flag: u16| dll_chars & flag != 0;
    let mut mitigations = vec![
        Mitigation::new("aslr", has(0x0040), Some("DYNAMIC_BASE".into())),
        Mitigation::new("nx", has(0x0100), Some("NX_COMPAT".into())),
        Mitigation::new("cfg", has(0x4000), Some("GUARD_CF".into())),
        Mitigation::new("signed", signed, Some("certificate table present (not verified)".into())),
    ];
    if pe.is_64 {
        mitigations.insert(1, Mitigation::new("high-entropy-va", has(0x0020), Some("HIGH_ENTROPY_VA".into())));
    }

    let pdb_path = pe
        .debug_data
        .as_ref()
        .and_then(|d| d.codeview_pdb70_debug_info.as_ref())
        .map(|cv| String::from_utf8_lossy(cv.filename).trim_end_matches('\0').to_string());

    let details = PeDetails {
        machine: coff.machine,
        timestamp: coff.time_date_stamp,
        image_base,
        subsystem: opt.map_or("other", |h| subsystem_name(h.windows_fields.subsystem)).to_string(),
        linker_version: opt.map_or_else(String::new, |h| {
            format!("{}.{}", h.standard_fields.major_linker_version, h.standard_fields.minor_linker_version)
        }),
        dll_characteristics: DLL_CHARACTERISTICS
            .iter()
            .filter(|(f, _)| has(*f))
            .map(|(_, n)| (*n).to_string())
            .collect(),
        ordinal_imports,
        signed,
        pdb_path,
    };

    BinaryInfo {
        format: Format::Pe,
        arch: machine_name(coff.machine).to_string(),
        bits: if pe.is_64 { 64 } else { 32 },
        endian: "little".into(),
        kind: if coff.characteristics & IMAGE_FILE_DLL != 0 {
            BinaryKind::SharedLibrary
        } else {
            BinaryKind::Executable
        },
        entry_point: (pe.entry != 0).then(|| image_base + u64::from(pe.entry)),
        sections,
        imports,
        exports,
        libraries: pe.libraries.iter().map(|s| (*s).to_string()).collect(),
        mitigations,
        overlay: overlay_after(data, image_end),
        pe: Some(details),
        elf: None,
        macho: None,
        slices: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(machine_name(0x8664), "x86_64");
        assert_eq!(machine_name(0x14c), "i386");
        assert_eq!(machine_name(0xaa64), "aarch64");
        assert_eq!(machine_name(0x1c4), "arm");
        assert_eq!(machine_name(0x200), "ia64");
        assert_eq!(machine_name(0x1234), "unknown");
        assert_eq!(subsystem_name(3), "windows-console");
        assert_eq!(subsystem_name(2), "windows-gui");
        assert_eq!(subsystem_name(1), "native");
        assert_eq!(subsystem_name(9), "windows-ce-gui");
        assert_eq!(subsystem_name(11), "efi");
        assert_eq!(subsystem_name(16), "windows-boot-application");
        assert_eq!(subsystem_name(99), "other");
    }
}
