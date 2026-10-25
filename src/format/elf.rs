//! ELF normalisation.

use std::collections::HashMap;

use goblin::elf::dynamic::{DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1};
use goblin::elf::header::{EI_OSABI, ET_CORE, ET_DYN, ET_EXEC, ET_REL};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC, STT_GNU_IFUNC, STT_OBJECT};
use goblin::elf::Elf;

use super::{
    overlay_after, section_entropy, BinaryInfo, BinaryKind, ElfDetails, Export, Format, Import, Mitigation, Section,
};

fn machine_name(machine: u16) -> String {
    match machine {
        3 => "i386".into(),
        40 => "arm".into(),
        62 => "x86_64".into(),
        183 => "aarch64".into(),
        243 => "riscv".into(),
        8 => "mips".into(),
        20 => "powerpc".into(),
        21 => "powerpc64".into(),
        other => goblin::elf::header::machine_to_str(other).to_ascii_lowercase(),
    }
}

fn os_abi_name(abi: u8) -> &'static str {
    match abi {
        0 => "sysv",
        3 => "gnu/linux",
        6 => "solaris",
        9 => "freebsd",
        12 => "openbsd",
        2 => "netbsd",
        97 => "arm",
        255 => "standalone",
        _ => "other",
    }
}

/// Map dynamic-symbol version index -> needed library file, from
/// `.gnu.version_r`. Lets binscope say `puts` comes from `libc.so.6` the same
/// way `objdump -T` does.
fn version_libraries(elf: &Elf<'_>) -> HashMap<u16, String> {
    let mut map = HashMap::new();
    if let Some(verneed) = &elf.verneed {
        for need in verneed {
            let Some(file) = elf.dynstrtab.get_at(need.vn_file) else { continue };
            for aux in &need {
                map.insert(aux.vna_other & 0x7fff, file.to_string());
            }
        }
    }
    map
}

fn imports_and_exports(elf: &Elf<'_>) -> (Vec<Import>, Vec<Export>) {
    let versions = version_libraries(elf);
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for (i, sym) in elf.dynsyms.iter().enumerate() {
        let bind = sym.st_bind();
        if sym.st_name == 0 || !(bind == STB_GLOBAL || bind == STB_WEAK) {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else { continue };
        if name.is_empty() {
            continue;
        }
        if sym.st_shndx == 0 {
            let library =
                elf.versym.as_ref().and_then(|v| v.get_at(i)).and_then(|v| versions.get(&v.version()).cloned());
            imports.push(Import { library, name: name.to_string(), ordinal: None, weak: bind == STB_WEAK });
        } else if matches!(sym.st_type(), STT_FUNC | STT_OBJECT | STT_GNU_IFUNC) {
            exports.push(Export { name: name.to_string(), address: sym.st_value, forwarded_to: None });
        }
    }
    (imports, exports)
}

fn mitigations(elf: &Elf<'_>, imports: &[Import]) -> Vec<Mitigation> {
    let mut flags = 0u64;
    let mut flags_1 = 0u64;
    let mut bind_now_tag = false;
    if let Some(d) = &elf.dynamic {
        for dynent in &d.dyns {
            match dynent.d_tag {
                DT_FLAGS => flags |= dynent.d_val,
                DT_FLAGS_1 => flags_1 |= dynent.d_val,
                DT_BIND_NOW => bind_now_tag = true,
                _ => {}
            }
        }
    }
    let bind_now = bind_now_tag || flags & DF_BIND_NOW != 0 || flags_1 & DF_1_NOW != 0;
    let relro_seg = elf.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO);
    let relro = match (relro_seg, bind_now) {
        (true, true) => Some("full"),
        (true, false) => Some("partial"),
        _ => None,
    };
    let stack = elf.program_headers.iter().find(|p| p.p_type == PT_GNU_STACK);
    let nx = stack.is_some_and(|p| p.p_flags & PF_X == 0);
    let pie = elf.header.e_type == ET_DYN && (elf.interpreter.is_some() || flags_1 & DF_1_PIE != 0);
    let canary = imports.iter().any(|i| i.name == "__stack_chk_fail" || i.name == "__stack_chk_guard");
    let fortify =
        imports.iter().any(|i| i.name.starts_with("__") && i.name.ends_with("_chk") && i.name != "__stack_chk_fail");
    vec![
        Mitigation::new("pie", pie, None),
        Mitigation::new(
            "nx",
            nx,
            Some(if stack.is_some() { "PT_GNU_STACK" } else { "no PT_GNU_STACK (executable stack by default)" }.into()),
        ),
        Mitigation::new("relro", relro.is_some(), relro.map(str::to_string)),
        Mitigation::new("canary", canary, Some("imports __stack_chk_fail".into())),
        Mitigation::new("fortify", fortify, Some("imports __*_chk".into())),
    ]
}

pub(super) fn analyze(elf: &Elf<'_>, data: &[u8]) -> BinaryInfo {
    let mut sections = Vec::new();
    let mut image_end = 0u64;
    for sh in &elf.section_headers {
        if sh.sh_type == 0 {
            continue; // SHT_NULL
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let file_size = if sh.sh_type == SHT_NOBITS { 0 } else { sh.sh_size };
        if file_size > 0 {
            image_end = image_end.max(sh.sh_offset.saturating_add(file_size));
        }
        sections.push(Section {
            name,
            file_offset: sh.sh_offset,
            file_size,
            virtual_address: sh.sh_addr,
            virtual_size: sh.sh_size,
            read: sh.sh_flags & u64::from(SHF_ALLOC) != 0,
            write: sh.sh_flags & u64::from(SHF_WRITE) != 0,
            execute: sh.sh_flags & u64::from(SHF_EXECINSTR) != 0,
            entropy: section_entropy(data, sh.sh_offset, file_size),
            raw_flags: sh.sh_flags,
        });
    }
    let load_segments: Vec<_> = elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD).collect();
    if sections.is_empty() {
        // Section headers stripped (or never written): fall back to segments.
        for (i, p) in load_segments.iter().enumerate() {
            sections.push(Section {
                name: format!("PT_LOAD[{i}]"),
                file_offset: p.p_offset,
                file_size: p.p_filesz,
                virtual_address: p.p_vaddr,
                virtual_size: p.p_memsz,
                read: p.p_flags & PF_R != 0,
                write: p.p_flags & PF_W != 0,
                execute: p.p_flags & PF_X != 0,
                entropy: section_entropy(data, p.p_offset, p.p_filesz),
                raw_flags: u64::from(p.p_flags),
            });
        }
    }
    for p in &elf.program_headers {
        image_end = image_end.max(p.p_offset.saturating_add(p.p_filesz));
    }
    let h = &elf.header;
    image_end = image_end
        .max(h.e_shoff.saturating_add(u64::from(h.e_shnum) * u64::from(h.e_shentsize)))
        .max(h.e_phoff.saturating_add(u64::from(h.e_phnum) * u64::from(h.e_phentsize)));

    let (imports, exports) = imports_and_exports(elf);
    let mitigations = mitigations(elf, &imports);
    let kind = match h.e_type {
        ET_EXEC => BinaryKind::Executable,
        ET_DYN if elf.interpreter.is_some() => BinaryKind::Executable,
        ET_DYN => BinaryKind::SharedLibrary,
        ET_REL => BinaryKind::Object,
        ET_CORE => BinaryKind::Core,
        _ => BinaryKind::Other,
    };
    let mut rpaths: Vec<String> = elf.rpaths.iter().map(|s| (*s).to_string()).collect();
    rpaths.extend(elf.runpaths.iter().map(|s| (*s).to_string()));

    BinaryInfo {
        format: Format::Elf,
        arch: machine_name(h.e_machine),
        bits: if elf.is_64 { 64 } else { 32 },
        endian: if elf.little_endian { "little" } else { "big" }.into(),
        kind,
        entry_point: (elf.entry != 0).then_some(elf.entry),
        sections,
        imports,
        exports,
        libraries: elf.libraries.iter().map(|s| (*s).to_string()).collect(),
        mitigations,
        overlay: overlay_after(data, image_end),
        pe: None,
        elf: Some(ElfDetails {
            elf_type: goblin::elf::header::et_to_str(h.e_type).to_string(),
            os_abi: os_abi_name(h.e_ident[EI_OSABI]).to_string(),
            interpreter: elf.interpreter.map(str::to_string),
            soname: elf.soname.map(str::to_string),
            rpaths,
            has_symtab: !elf.syms.is_empty(),
            program_headers: elf.program_headers.len(),
        }),
        macho: None,
        slices: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_and_abi_names() {
        assert_eq!(machine_name(62), "x86_64");
        assert_eq!(machine_name(183), "aarch64");
        assert_eq!(machine_name(3), "i386");
        assert_eq!(machine_name(40), "arm");
        assert_eq!(machine_name(243), "riscv");
        assert_eq!(machine_name(8), "mips");
        assert_eq!(machine_name(20), "powerpc");
        assert_eq!(machine_name(21), "powerpc64");
        assert_ne!(machine_name(2), "");
        for (abi, name) in [
            (0, "sysv"),
            (3, "gnu/linux"),
            (6, "solaris"),
            (9, "freebsd"),
            (12, "openbsd"),
            (2, "netbsd"),
            (97, "arm"),
            (255, "standalone"),
            (50, "other"),
        ] {
            assert_eq!(os_abi_name(abi), name);
        }
    }
}
