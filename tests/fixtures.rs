//! Integration tests over the committed fixture corpus (fixtures/MANIFEST.tsv).

use std::path::PathBuf;

use binscope::format::{BinaryInfo, Format};
use binscope::rules::RuleSet;
use binscope::triage::{analyze_path, TriageOptions, TriageReport};

struct Entry {
    target: String,
    family: String,
    variant: u32,
    path: PathBuf,
    sha256: String,
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn manifest() -> Vec<Entry> {
    let text = std::fs::read_to_string(repo().join("fixtures/MANIFEST.tsv")).unwrap();
    text.lines()
        .skip(1)
        .map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            Entry {
                sha256: c[0].into(),
                target: c[2].into(),
                family: c[3].into(),
                variant: c[4].parse().unwrap(),
                path: repo().join("fixtures").join(c[5]),
            }
        })
        .collect()
}

fn triage(e: &Entry, rules: &RuleSet) -> TriageReport {
    analyze_path(&e.path, &TriageOptions::default(), rules).unwrap()
}

fn import_names(b: &BinaryInfo) -> Vec<String> {
    b.all_imports()
        .iter()
        .map(|i| {
            i.normalized_name(if b.format == Format::Pe || b.format == Format::Elf { b.format } else { Format::MachO })
                .to_ascii_lowercase()
        })
        .collect()
}

#[test]
fn manifest_hashes_match_committed_files() {
    let m = manifest();
    assert_eq!(m.len(), 121);
    for e in &m {
        let data = std::fs::read(&e.path).unwrap();
        assert_eq!(binscope::hashes::FileDigests::of(&data).sha256, e.sha256, "{}", e.path.display());
    }
}

#[test]
fn every_fixture_parses_with_the_expected_format_and_arch() {
    let rules = RuleSet::empty();
    for e in manifest() {
        let r = triage(&e, &rules);
        let b =
            r.binary.as_ref().unwrap_or_else(|| panic!("{} did not parse: {:?}", e.path.display(), r.unparsed_reason));
        let (format, arch, bits) = match e.target.as_str() {
            "elf-x86_64" => (Format::Elf, "x86_64", 64),
            "elf-aarch64" => (Format::Elf, "aarch64", 64),
            "pe-x86_64" => (Format::Pe, "x86_64", 64),
            "pe-i686" => (Format::Pe, "i386", 32),
            "macho-arm64" => (Format::MachO, "aarch64", 64),
            "macho-x86_64" => (Format::MachO, "x86_64", 64),
            "macho-universal" => (Format::MachOFat, "universal", 64),
            other => panic!("unknown target {other}"),
        };
        assert_eq!((b.format, b.arch.as_str(), b.bits), (format, arch, bits), "{}", e.path.display());
        if format != Format::MachOFat {
            assert!(!b.sections.is_empty(), "{}", e.path.display());
            let entry = b.entry_point.expect("executables have an entry point");
            let sec =
                b.section_at_va(entry).unwrap_or_else(|| panic!("entry outside sections in {}", e.path.display()));
            assert!(sec.execute, "{}: entry in non-executable {}", e.path.display(), sec.name);
        }
        for s in b.all_sections() {
            assert!((0.0..=8.0).contains(&s.entropy));
        }
    }
}

#[test]
fn imports_reflect_what_each_program_calls() {
    let rules = RuleSet::empty();
    for e in manifest() {
        let r = triage(&e, &rules);
        let b = r.binary.unwrap();
        let names = import_names(&b);
        let want: &[&str] = match (e.family.as_str(), e.target.starts_with("pe-")) {
            ("hello", true) => &["getstdhandle", "writefile", "writeconsolew", "exitprocess"],
            ("files", true) => &["createfilew", "readfile", "writefile", "deletefilew", "gettemppathw"],
            ("files", false) => &["fopen", "fwrite", "fread", "fclose", "remove"],
            ("net", true) => &["wsastartup", "socket", "connect", "send", "closesocket", "htons"],
            ("net", false) => &["socket", "connect", "send", "close", "htons"],
            (_, true) => &["getstdhandle", "writefile"],
            (_, false) => &["puts"],
        };
        for w in want {
            assert!(names.iter().any(|n| n == w), "{} lacks import {w}: {names:?}", e.path.display());
        }
        if e.target.starts_with("pe-") && e.family == "net" {
            let pe = b.pe.as_ref().unwrap();
            assert_eq!(pe.ordinal_imports, 4, "connect/htons/send/socket are by ordinal");
            assert!(b.imports.iter().any(|i| i.name == "connect" && i.ordinal == Some(4)));
        }
        if e.target.starts_with("elf-") {
            assert_eq!(b.libraries, vec!["libc.so.6"]);
            assert!(b.elf.as_ref().unwrap().interpreter.is_some());
        }
    }
}

#[test]
fn macho_import_encodings_both_decode() {
    let rules = RuleSet::empty();
    for e in manifest().iter().filter(|e| e.target.starts_with("macho-") && e.target != "macho-universal") {
        let b = triage(e, &rules).binary.unwrap();
        let m = b.macho.as_ref().unwrap();
        // arm64 is built for macOS 12 (chained fixups), x86_64 for 10.15 (bind opcodes).
        assert_eq!(m.chained_fixups, e.target == "macho-arm64", "{}", e.path.display());
        assert!(b
            .imports
            .iter()
            .all(|i| i.library.as_deref() == Some("/usr/lib/libSystem.B.dylib") || i.name == "dyld_stub_binder"));
        assert!(m.flags.contains(&"PIE".to_string()));
        assert!(m.uuid.is_some() && m.min_os.is_some());
    }
}

#[test]
fn universal_binary_reports_both_slices() {
    let e = manifest().into_iter().find(|e| e.target == "macho-universal").unwrap();
    let b = triage(&e, &RuleSet::empty()).binary.unwrap();
    let arches: Vec<&str> = b.slices.iter().map(|s| s.arch.as_str()).collect();
    assert_eq!(arches, vec!["x86_64", "aarch64"]);
    assert_eq!(b.libraries, vec!["/usr/lib/libSystem.B.dylib"]);
    assert!(b.slices.iter().all(|s| s.sections.iter().any(|x| x.name == "__TEXT,__text")));
    // Slice section offsets are absolute file offsets.
    let x = &b.slices[1].sections[0];
    assert!(x.file_offset > 0x4000);
}

fn blob_section(b: &BinaryInfo) -> &binscope::format::Section {
    b.sections
        .iter()
        .find(|s| s.name.ends_with("blob"))
        .unwrap_or_else(|| panic!("no blob section in {:?}", b.sections.iter().map(|s| &s.name).collect::<Vec<_>>()))
}

#[test]
fn compressed_variant_shows_the_entropy_contrast() {
    let rules = RuleSet::builtin().unwrap();
    for e in manifest().iter().filter(|e| e.family == "packed" || e.family == "plainblob") {
        let r = triage(e, &rules);
        let b = r.binary.as_ref().unwrap();
        let s = blob_section(b);
        let packed_rule = r.capabilities.iter().any(|c| c.id == "executable.packed-or-compressed-section");
        let anomaly = r.anomalies.iter().any(|a| a.id == "high-entropy-section");
        if e.family == "packed" {
            // PE raw sections are zero-padded to the 512-byte file alignment,
            // which pulls the measured entropy down a little.
            assert!(s.entropy > 7.5, "{} blob entropy {}", e.path.display(), s.entropy);
            assert!(packed_rule && anomaly, "{}", e.path.display());
        } else {
            assert!(s.entropy < 4.6, "{} blob entropy {}", e.path.display(), s.entropy);
            assert!(!packed_rule && !anomaly, "{}", e.path.display());
        }
    }
}

#[test]
fn capabilities_match_program_behaviour() {
    let rules = RuleSet::builtin().unwrap();
    for e in manifest() {
        let r = triage(&e, &rules);
        let ids: Vec<&str> = r.capabilities.iter().map(|c| c.id.as_str()).collect();
        let has = |id: &str| ids.contains(&id);
        assert!(has("host.console.output"), "{} {ids:?}", e.path.display());
        assert_eq!(has("communication.socket.tcp-client"), e.family == "net", "{} {ids:?}", e.path.display());
        assert_eq!(has("host.file.read-write"), e.family == "files", "{} {ids:?}", e.path.display());
        assert_eq!(has("host.file.delete"), e.family == "files", "{} {ids:?}", e.path.display());
        assert_eq!(
            has("communication.socket.winsock-init"),
            e.family == "net" && e.target.starts_with("pe-"),
            "{} {ids:?}",
            e.path.display()
        );
        // Nothing in the corpus creates processes, injects or checks for debuggers.
        for absent in ["host.process.create", "load-code.cross-process-write", "anti-analysis.debugger-check"] {
            assert!(!has(absent), "{} unexpectedly matched {absent}", e.path.display());
        }
        assert!(e.variant <= 3);
    }
}

#[test]
fn pe_wide_strings_are_extracted() {
    let rules = RuleSet::empty();
    for e in manifest().iter().filter(|e| e.family == "hello" && e.target.starts_with("pe-")) {
        let r = analyze_path(&e.path, &TriageOptions { max_listed_strings: 500, ..TriageOptions::default() }, &rules)
            .unwrap();
        let wide = r
            .strings
            .listed
            .iter()
            .find(|s| s.string.value == "binscope wide banner: hello")
            .unwrap_or_else(|| panic!("no wide banner in {}", e.path.display()));
        assert_eq!(wide.string.encoding, binscope::strings::Encoding::Utf16Le);
        assert_eq!(wide.section.as_deref(), Some(".rdata"));
    }
}

#[test]
fn import_hashes_by_format() {
    let rules = RuleSet::empty();
    for e in manifest() {
        let r = triage(&e, &rules);
        if e.target.starts_with("pe-") {
            assert!(r.import_hashes.imphash.is_some() && r.import_hashes.symhash.is_none());
        } else {
            assert!(r.import_hashes.symhash.is_some() && r.import_hashes.imphash.is_none());
        }
    }
}

#[test]
fn reports_round_trip_through_json() {
    let rules = RuleSet::builtin().unwrap();
    for e in manifest().iter().step_by(7) {
        let r = triage(e, &rules);
        let text = serde_json::to_string(&r).unwrap();
        let back: TriageReport = serde_json::from_str(&text).unwrap();
        assert_eq!(back, r, "{}", e.path.display());
    }
}

#[test]
fn mutated_fixtures_never_panic_and_always_report() {
    // Deterministic "fuzz" pass: truncations and byte flips of real binaries.
    let rules = RuleSet::builtin().unwrap();
    let mut rng = binscope::synth::Rng::new(2024);
    for e in manifest().iter().step_by(3) {
        let data = std::fs::read(&e.path).unwrap();
        for round in 0..12 {
            let mut d = data.clone();
            if round % 3 == 0 {
                d.truncate(rng.below(d.len() as u64) as usize);
            } else {
                for _ in 0..=rng.below(64) {
                    let at = rng.below(d.len() as u64) as usize;
                    d[at] = rng.next_u64() as u8;
                }
            }
            let r = binscope::analyze_bytes("mutant", &d, &TriageOptions::default(), &rules);
            assert_eq!(r.file.size, d.len() as u64);
            assert!(r.binary.is_some() || r.unparsed_reason.is_some());
        }
    }
}
