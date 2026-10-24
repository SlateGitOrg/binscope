//! Mach-O normalisation, including universal binaries and imports recovered
//! from `LC_DYLD_CHAINED_FIXUPS` (which goblin does not decode; every arm64
//! binary linked for macOS 11+ stores its imports this way).

use goblin::mach::header::{filetype_to_str, MH_ALLOW_STACK_EXECUTION, MH_NO_HEAP_EXECUTION, MH_PIE};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::symbols::{N_EXT, N_STAB, N_TYPE, N_UNDF};
use goblin::mach::{Mach, MachO, SingleArch};

use super::{
    file_slice, overlay_after, section_entropy, BinaryInfo, BinaryKind, Export, Format, Import, MachODetails,
    Mitigation, Section,
};
use crate::error::{Error, Result};

const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;
const SECTION_TYPE_MASK: u32 = 0xff;
const ZEROFILL_TYPES: [u32; 3] = [0x01, 0x0c, 0x12];

const HEADER_FLAGS: [(u32, &str); 8] = [
    (0x1, "NOUNDEFS"),
    (0x4, "DYLDLINK"),
    (0x80, "TWOLEVEL"),
    (0x8000, "WEAK_DEFINES"),
    (0x10000, "BINDS_TO_WEAK"),
    (MH_ALLOW_STACK_EXECUTION, "ALLOW_STACK_EXECUTION"),
    (MH_PIE, "PIE"),
    (MH_NO_HEAP_EXECUTION, "NO_HEAP_EXECUTION"),
];

fn cpu_name(cputype: u32) -> &'static str {
    match cputype {
        7 => "i386",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000c => "aarch64",
        0x0200_000c => "arm64_32",
        18 => "powerpc",
        0x0100_0012 => "powerpc64",
        _ => "unknown",
    }
}

fn cstr(name: &[u8; 16]) -> String {
    let end = name.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&name[..end]).into_owned()
}

fn version_string(v: u32) -> String {
    let (major, minor, patch) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

fn uuid_string(u: &[u8; 16]) -> String {
    let h = crate::hashes::hex(u).to_ascii_uppercase();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// One import from a chained-fixups imports table.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChainedImport {
    pub lib_ordinal: i32,
    pub weak: bool,
    pub name: String,
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_le_bytes(a)
    })
}

/// Decode the imports table of a `dyld_chained_fixups_header` blob.
pub(crate) fn parse_chained_imports(blob: &[u8]) -> Result<Vec<ChainedImport>> {
    let bad = |m: &str| Error::parse("Mach-O", format!("chained fixups: {m}"));
    let version = rd_u32(blob, 0).ok_or_else(|| bad("truncated header"))?;
    if version != 0 {
        return Err(bad("unknown fixups_version"));
    }
    let imports_offset = rd_u32(blob, 8).ok_or_else(|| bad("truncated header"))? as usize;
    let symbols_offset = rd_u32(blob, 12).ok_or_else(|| bad("truncated header"))? as usize;
    let count = rd_u32(blob, 16).ok_or_else(|| bad("truncated header"))? as usize;
    let format = rd_u32(blob, 20).ok_or_else(|| bad("truncated header"))?;
    let symbols_format = rd_u32(blob, 24).ok_or_else(|| bad("truncated header"))?;
    if symbols_format != 0 {
        return Err(bad("compressed symbol pool is not supported"));
    }
    let stride = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => return Err(bad("unknown imports_format")),
    };
    if count.saturating_mul(stride) > blob.len() {
        return Err(bad("imports table larger than the blob"));
    }
    let name_at = |off: usize| -> Result<String> {
        let start = symbols_offset.checked_add(off).ok_or_else(|| bad("name offset overflow"))?;
        let tail = blob.get(start..).ok_or_else(|| bad("name offset out of range"))?;
        let end = tail.iter().position(|&b| b == 0).ok_or_else(|| bad("unterminated name"))?;
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = imports_offset + i * stride;
        let (lib_ordinal, weak, name_off) = if format == 3 {
            let raw = rd_u64(blob, at).ok_or_else(|| bad("truncated import"))?;
            // lib_ordinal:16 (signed), weak_import:1, reserved:15, name_offset:32
            (i32::from((raw & 0xffff) as u16 as i16), raw & 0x1_0000 != 0, (raw >> 32) as usize)
        } else {
            let raw = rd_u32(blob, at).ok_or_else(|| bad("truncated import"))?;
            // lib_ordinal:8 (signed), weak_import:1, name_offset:23
            (i32::from((raw & 0xff) as u8 as i8), raw & 0x100 != 0, (raw >> 9) as usize)
        };
        out.push(ChainedImport { lib_ordinal, weak, name: name_at(name_off)? });
    }
    Ok(out)
}

fn library_for(libs: &[&str], ordinal: i32) -> Option<String> {
    // Ordinal 0 = this image, negative = special lookups (main executable,
    // flat namespace, weak lookup); 1..=n index the LC_LOAD_DYLIB list.
    usize::try_from(ordinal).ok().filter(|&o| o >= 1).and_then(|o| libs.get(o)).map(|s| (*s).to_string())
}

fn symtab_imports(m: &MachO<'_>) -> Vec<Import> {
    let mut out = Vec::new();
    for (name, nlist) in m.symbols().flatten() {
        if nlist.n_type & N_STAB != 0 || nlist.n_type & N_EXT == 0 || nlist.n_type & N_TYPE != N_UNDF {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        let ordinal = i32::from((nlist.n_desc >> 8) & 0xff);
        let ordinal = if ordinal >= 0xfd { ordinal - 0x100 } else { ordinal };
        out.push(Import {
            library: library_for(&m.libs, ordinal),
            name: name.to_string(),
            ordinal: None,
            weak: nlist.n_desc & 0x40 != 0, // N_WEAK_REF
        });
    }
    out
}

fn imports(m: &MachO<'_>, data: &[u8], base: u64) -> (Vec<Import>, bool) {
    for lc in &m.load_commands {
        if let CommandVariant::DyldChainedFixups(cmd) = &lc.command {
            let blob = file_slice(data, base + u64::from(cmd.dataoff), u64::from(cmd.datasize));
            match parse_chained_imports(blob) {
                Ok(list) => {
                    let v = list
                        .into_iter()
                        .map(|ci| Import {
                            library: library_for(&m.libs, ci.lib_ordinal),
                            name: ci.name,
                            ordinal: None,
                            weak: ci.weak,
                        })
                        .collect();
                    return (v, true);
                }
                Err(e) => log::warn!("{e}; falling back to the symbol table"),
            }
        }
    }
    if let Ok(list) = m.imports() {
        if !list.is_empty() {
            let mut v: Vec<Import> = list
                .iter()
                .map(|i| Import {
                    library: Some(i.dylib.to_string()).filter(|d| !d.is_empty()),
                    name: i.name.to_string(),
                    ordinal: None,
                    weak: i.is_weak,
                })
                .collect();
            // Lazy and non-lazy bindings can name the same symbol twice.
            let mut seen = std::collections::HashSet::new();
            v.retain(|i| seen.insert((i.library.clone(), i.name.clone())));
            return (v, false);
        }
    }
    (symtab_imports(m), false)
}

fn analyze_single(m: &MachO<'_>, data: &[u8], base: u64) -> Result<BinaryInfo> {
    let mut sections = Vec::new();
    let mut image_end = base;
    for seg in &m.segments {
        if seg.filesize > 0 {
            image_end = image_end.max(base + seg.fileoff + seg.filesize);
        }
        let read = seg.initprot & VM_PROT_READ != 0;
        let write = seg.initprot & VM_PROT_WRITE != 0;
        let execute = seg.initprot & VM_PROT_EXECUTE != 0;
        let secs = seg.sections().map_err(|e| Error::parse("Mach-O", e.to_string()))?;
        for (sec, _) in secs {
            let zerofill = ZEROFILL_TYPES.contains(&(sec.flags & SECTION_TYPE_MASK));
            let file_size = if zerofill || sec.offset == 0 { 0 } else { sec.size };
            let file_offset = base + u64::from(sec.offset);
            sections.push(Section {
                name: format!("{},{}", cstr(&sec.segname), cstr(&sec.sectname)),
                file_offset,
                file_size,
                virtual_address: sec.addr,
                virtual_size: sec.size,
                read,
                write,
                execute,
                entropy: section_entropy(data, file_offset, file_size),
                raw_flags: u64::from(sec.flags),
            });
        }
    }

    let (imports, chained) = imports(m, data, base);
    let exports = m
        .exports()
        .unwrap_or_default()
        .into_iter()
        .map(|e| Export { name: e.name, address: e.offset, forwarded_to: None })
        .collect();

    let mut uuid = None;
    let mut min_os = None;
    let mut code_signature = false;
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::Uuid(u) => uuid = Some(uuid_string(&u.uuid)),
            CommandVariant::BuildVersion(b) => min_os = Some(version_string(b.minos)),
            CommandVariant::VersionMinMacosx(v) | CommandVariant::VersionMinIphoneos(v) => {
                min_os = Some(version_string(v.version));
            }
            CommandVariant::CodeSignature(_) => code_signature = true,
            _ => {}
        }
    }

    let flags = m.header.flags;
    let canary = imports.iter().any(|i| i.name == "___stack_chk_fail" || i.name == "___stack_chk_guard");
    let mitigations = vec![
        Mitigation::new("pie", flags & MH_PIE != 0, Some("MH_PIE".into())),
        Mitigation::new("nx-stack", flags & MH_ALLOW_STACK_EXECUTION == 0, Some("no MH_ALLOW_STACK_EXECUTION".into())),
        Mitigation::new("canary", canary, Some("imports ___stack_chk_fail".into())),
        Mitigation::new("code-signature", code_signature, Some("LC_CODE_SIGNATURE present (not verified)".into())),
    ];
    let kind = match m.header.filetype {
        2 => BinaryKind::Executable,
        6 | 9 => BinaryKind::SharedLibrary,
        1 => BinaryKind::Object,
        4 => BinaryKind::Core,
        _ => BinaryKind::Other,
    };

    Ok(BinaryInfo {
        format: Format::MachO,
        arch: cpu_name(m.header.cputype).to_string(),
        bits: if m.is_64 { 64 } else { 32 },
        endian: if m.little_endian { "little" } else { "big" }.into(),
        kind,
        // goblin already maps LC_MAIN's file offset through __TEXT to a VA.
        entry_point: (m.entry != 0).then_some(m.entry),
        sections,
        imports,
        exports,
        libraries: m.libs.iter().skip(1).map(|s| (*s).to_string()).collect(),
        mitigations,
        overlay: if base == 0 { overlay_after(data, image_end) } else { None },
        pe: None,
        elf: None,
        macho: Some(MachODetails {
            filetype: filetype_to_str(m.header.filetype).to_ascii_lowercase(),
            flags: HEADER_FLAGS.iter().filter(|(f, _)| flags & f != 0).map(|(_, n)| (*n).to_string()).collect(),
            uuid,
            min_os,
            code_signature,
            chained_fixups: chained,
            rpaths: m.rpaths.iter().map(|s| (*s).to_string()).collect(),
        }),
        slices: Vec::new(),
    })
}

pub(super) fn analyze(mach: Mach<'_>, data: &[u8]) -> Result<BinaryInfo> {
    match mach {
        Mach::Binary(m) => analyze_single(&m, data, 0),
        Mach::Fat(multi) => {
            let arches = multi.arches().map_err(|e| Error::parse("Mach-O", e.to_string()))?;
            let mut slices = Vec::new();
            let mut end = 0u64;
            for (i, arch) in arches.iter().enumerate() {
                end = end.max(u64::from(arch.offset) + u64::from(arch.size));
                match multi.get(i).map_err(|e| Error::parse("Mach-O", e.to_string()))? {
                    SingleArch::MachO(m) => slices.push(analyze_single(&m, data, u64::from(arch.offset))?),
                    SingleArch::Archive(_) => log::info!("skipping static-archive slice {i} in universal binary"),
                }
            }
            let mut libraries: Vec<String> = Vec::new();
            for s in &slices {
                for l in &s.libraries {
                    if !libraries.contains(l) {
                        libraries.push(l.clone());
                    }
                }
            }
            Ok(BinaryInfo {
                format: Format::MachOFat,
                arch: "universal".into(),
                bits: slices.iter().map(|s| s.bits).max().unwrap_or(0),
                endian: "big".into(), // the fat header itself is big-endian
                kind: slices.first().map_or(BinaryKind::Other, |s| s.kind),
                entry_point: None,
                sections: Vec::new(),
                imports: Vec::new(),
                exports: Vec::new(),
                libraries,
                mitigations: Vec::new(),
                overlay: overlay_after(data, end),
                pe: None,
                elf: None,
                macho: None,
                slices,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(format: u32, entries: &[u64], names: &[&str], symbols_format: u32) -> Vec<u8> {
        let imports_offset = 28u32;
        let stride = match format {
            1 => 4,
            2 => 8,
            _ => 16,
        };
        let symbols_offset = imports_offset + (entries.len() * stride) as u32;
        let mut b = Vec::new();
        for v in [0, 0, imports_offset, symbols_offset, entries.len() as u32, format, symbols_format] {
            b.extend(v.to_le_bytes());
        }
        for &e in entries {
            if format == 3 {
                b.extend(e.to_le_bytes());
                b.extend(0u64.to_le_bytes());
            } else {
                b.extend((e as u32).to_le_bytes());
                if format == 2 {
                    b.extend(0u32.to_le_bytes());
                }
            }
        }
        for n in names {
            b.extend(n.as_bytes());
            b.push(0);
        }
        b
    }

    #[test]
    fn chained_imports_format_1_and_2() {
        // "_puts" at name offset 0, "_exit" at 6; second one weak, ordinal 2.
        let e1 = 1u64;
        let e2 = 2u64 | 0x100 | (6 << 9);
        for fmt in [1, 2] {
            let got = parse_chained_imports(&blob(fmt, &[e1, e2], &["_puts", "_exit"], 0)).unwrap();
            assert_eq!(
                got,
                vec![
                    ChainedImport { lib_ordinal: 1, weak: false, name: "_puts".into() },
                    ChainedImport { lib_ordinal: 2, weak: true, name: "_exit".into() },
                ]
            );
        }
    }

    #[test]
    fn chained_imports_format_3_and_special_ordinals() {
        let e = 0xfffe_u64; // ordinal -2 (flat lookup), name offset 0
        let got = parse_chained_imports(&blob(3, &[e], &["_dyn"], 0)).unwrap();
        assert_eq!(got[0].lib_ordinal, -2);
        let e8 = 0xffu64; // ordinal -1 in the 8-bit format
        assert_eq!(parse_chained_imports(&blob(1, &[e8], &["_m"], 0)).unwrap()[0].lib_ordinal, -1);
    }

    #[test]
    fn chained_imports_reject_malformed() {
        assert!(parse_chained_imports(&[0u8; 8]).is_err());
        assert!(parse_chained_imports(&blob(9, &[1], &["_x"], 0)).is_err());
        assert!(parse_chained_imports(&blob(1, &[1], &["_x"], 1)).is_err());
        let mut b = blob(1, &[1u64 | (100 << 9)], &["_x"], 0);
        assert!(parse_chained_imports(&b).is_err());
        b = blob(1, &[1], &["_x"], 0);
        b.pop(); // drop the terminating NUL
        assert!(parse_chained_imports(&b).is_err());
        let mut v = blob(1, &[1], &["_x"], 0);
        v[0] = 1; // fixups_version
        assert!(parse_chained_imports(&v).is_err());
        let mut huge = blob(1, &[1], &["_x"], 0);
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_chained_imports(&huge).is_err());
    }

    #[test]
    fn ordinal_to_library() {
        let libs = ["self", "/usr/lib/libSystem.B.dylib"];
        assert_eq!(library_for(&libs, 1).as_deref(), Some("/usr/lib/libSystem.B.dylib"));
        assert_eq!(library_for(&libs, 0), None);
        assert_eq!(library_for(&libs, -1), None);
        assert_eq!(library_for(&libs, 5), None);
    }

    #[test]
    fn helpers() {
        assert_eq!(cpu_name(0x0100_000c), "aarch64");
        assert_eq!(cpu_name(0x0100_0007), "x86_64");
        assert_eq!(cpu_name(7), "i386");
        assert_eq!(cpu_name(12), "arm");
        assert_eq!(cpu_name(0x0200_000c), "arm64_32");
        assert_eq!(cpu_name(18), "powerpc");
        assert_eq!(cpu_name(0x0100_0012), "powerpc64");
        assert_eq!(cpu_name(99), "unknown");
        assert_eq!(version_string(0x000b_0000), "11.0");
        assert_eq!(version_string(0x000a_0f02), "10.15.2");
        assert_eq!(uuid_string(&[0xab; 16]), "ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB");
        let mut n = [0u8; 16];
        n[..6].copy_from_slice(b"__TEXT");
        assert_eq!(cstr(&n), "__TEXT");
    }
}
