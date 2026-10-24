//! Byte-exact agreement with the reference tools.
//!
//! The TSV files in `tests/reference/` were produced by
//! `scripts/reference/gen_reference.py` with ssdeep 2.14.1, TLSH 4.12.1 and
//! pefile 2024.8.26 over (a) every fixture binary and (b) synthetic inputs
//! that `binscope::synth` regenerates here from their file names.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use binscope::fuzzy::{ssdeep, tlsh};
use binscope::synth::{generate, mutate, Kind};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rows(name: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(repo().join("tests/reference").join(name)).expect("reference file");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// Bytes for a reference-vector name: `synth/<kind>-<size>-<seed>[-m<pm>]`
/// or a repo-relative fixture path.
fn input(name: &str) -> Vec<u8> {
    if let Some(rest) = name.strip_prefix("synth/") {
        let parts: Vec<&str> = rest.split('-').collect();
        let kind = Kind::from_name(parts[0]).expect("kind");
        let size: usize = parts[1].parse().expect("size");
        let seed: u64 = parts[2].parse().expect("seed");
        let base = generate(kind, size, seed);
        match parts.get(3) {
            Some(m) => mutate(&base, m.trim_start_matches('m').parse().expect("per-mille"), seed),
            None => base,
        }
    } else {
        std::fs::read(repo().join(Path::new(name))).expect("fixture")
    }
}

struct Inputs(HashMap<String, Vec<u8>>);

impl Inputs {
    fn get(&mut self, name: &str) -> &[u8] {
        self.0.entry(name.to_string()).or_insert_with(|| input(name))
    }
}

#[test]
fn ssdeep_digests_match_ssdeep_2_14_1() {
    let table = rows("ssdeep_hashes.tsv");
    assert!(table.len() > 250, "expected the full vector set");
    let mut inputs = Inputs(HashMap::new());
    for row in &table {
        let ours = ssdeep::hash(inputs.get(&row[0])).unwrap().to_string();
        assert_eq!(ours, row[1], "ssdeep mismatch for {}", row[0]);
    }
}

#[test]
fn tlsh_digests_match_tlsh_4_12_1() {
    let table = rows("tlsh_hashes.tsv");
    let mut inputs = Inputs(HashMap::new());
    let mut with_digest = 0;
    for row in &table {
        let ours = tlsh::hash(inputs.get(&row[0])).map(|h| h.to_hex());
        if row[1] == "TNULL" {
            assert!(ours.is_err(), "reference has no TLSH for {} but we produced {ours:?}", row[0]);
        } else {
            assert_eq!(ours.unwrap(), row[1], "TLSH mismatch for {}", row[0]);
            with_digest += 1;
        }
    }
    assert!(with_digest > 200);
}

fn digest_map(file: &str) -> HashMap<String, String> {
    rows(file).into_iter().map(|r| (r[0].clone(), r[1].clone())).collect()
}

#[test]
fn ssdeep_compare_matches_fuzzy_compare() {
    let digests = digest_map("ssdeep_hashes.tsv");
    let table = rows("ssdeep_compare.tsv");
    let mut nonzero = 0;
    for row in &table {
        let (a, b) = (&digests[&row[0]], &digests[&row[1]]);
        let expected: u32 = row[2].parse().unwrap();
        assert_eq!(ssdeep::compare_str(a, b).unwrap(), expected, "{} vs {}", row[0], row[1]);
        assert_eq!(ssdeep::compare_str(b, a).unwrap(), expected, "symmetry {} vs {}", row[0], row[1]);
        nonzero += usize::from(expected > 0);
    }
    assert!(table.len() > 1000 && nonzero > 100, "vector set too weak: {nonzero}/{}", table.len());
}

#[test]
fn tlsh_distance_matches_total_diff() {
    let digests = digest_map("tlsh_hashes.tsv");
    for row in rows("tlsh_diff.tsv") {
        let a: tlsh::Tlsh = digests[&row[0]].parse().unwrap();
        let b: tlsh::Tlsh = digests[&row[1]].parse().unwrap();
        assert_eq!(a.distance(&b, true), row[2].parse::<u32>().unwrap(), "{} vs {}", row[0], row[1]);
        assert_eq!(a.distance(&b, false), row[3].parse::<u32>().unwrap(), "xlen {} vs {}", row[0], row[1]);
    }
}

#[test]
fn pe_imphash_and_section_entropy_match_pefile() {
    let table = rows("pefile.tsv");
    let mut checked_sections = 0;
    let mut by_file: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for row in table {
        by_file.entry(row[0].clone()).or_default().push(row);
    }
    assert_eq!(by_file.len(), 40, "every PE fixture has pefile output");
    for (name, sections) in &by_file {
        let data = input(name);
        let report = binscope::analyze_bytes(
            name,
            &data,
            &binscope::TriageOptions::default(),
            &binscope::rules::RuleSet::empty(),
        );
        assert_eq!(report.import_hashes.imphash.as_deref(), Some(sections[0][1].as_str()), "imphash {name}");
        let ours = report.binary.expect("PE parses").sections;
        assert_eq!(ours.len(), sections.len(), "section count {name}");
        for (s, row) in ours.iter().zip(sections) {
            assert_eq!(s.name, row[2], "{name}");
            assert_eq!(s.file_size, row[3].parse::<u64>().unwrap(), "{name} {}", s.name);
            let expected: f64 = row[4].parse().unwrap();
            assert!((s.entropy - expected).abs() < 1e-9, "{name} {}: {} vs {expected}", s.name, s.entropy);
            checked_sections += 1;
        }
    }
    assert!(checked_sections > 100);
}

fn parse_native(name: &str) -> binscope::format::BinaryInfo {
    binscope::format::parse(&input(name)).unwrap().expect("supported format")
}

#[test]
fn elf_and_macho_sections_match_llvm_readobj() {
    let mut by_file: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for row in rows("sections.tsv") {
        by_file.entry(row[0].clone()).or_default().push(row);
    }
    assert_eq!(by_file.len(), 80, "40 ELF + 40 single-arch Mach-O fixtures");
    for (name, expected) in &by_file {
        let ours = parse_native(name).sections;
        let got: Vec<(String, u64, u64, u64)> =
            ours.iter().map(|s| (s.name.clone(), s.file_offset, s.file_size, s.virtual_address)).collect();
        let want: Vec<(String, u64, u64, u64)> = expected
            .iter()
            .map(|r| (r[1].clone(), r[2].parse().unwrap(), r[3].parse().unwrap(), r[4].parse().unwrap()))
            .collect();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn elf_and_macho_imports_match_llvm_nm() {
    let table = rows("imports.tsv");
    assert_eq!(table.len(), 80);
    for row in table {
        let mut ours: Vec<String> = parse_native(&row[0]).imports.into_iter().map(|i| i.name).collect();
        ours.sort();
        ours.dedup();
        let want: Vec<String> = row.get(1).map(|s| s.split(',').map(str::to_string).collect()).unwrap_or_default();
        assert_eq!(ours, want, "{}", row[0]);
    }
}
