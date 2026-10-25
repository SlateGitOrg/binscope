//! One-file triage: everything binscope knows about a sample in one report.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::anomalies::{self, Anomaly};
use crate::entropy;
use crate::error::{Error, Result};
use crate::format::{self, BinaryInfo, Detected, Format, Section};
use crate::fuzzy::FuzzyDigests;
use crate::hashes::{self, FileDigests};
use crate::rules::{CapabilityMatch, RuleSet, Subject};
use crate::strings::{self, Encoding, ExtractedString, StringOptions};

/// JSON schema version of [`TriageReport`]; bumped on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Knobs for [`analyze_bytes`].
#[derive(Clone, Debug)]
pub struct TriageOptions {
    /// String extraction settings.
    pub strings: StringOptions,
    /// Maximum strings listed in the report (tagged strings first). All
    /// extracted strings are still used for rule matching and counts.
    pub max_listed_strings: usize,
}

impl Default for TriageOptions {
    fn default() -> Self {
        Self { strings: StringOptions::default(), max_listed_strings: 60 }
    }
}

/// Basic facts about the file itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileFacts {
    /// Name or path as given by the caller.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Cryptographic digests.
    #[serde(flatten)]
    pub digests: FileDigests,
    /// Whole-file Shannon entropy.
    pub entropy: f64,
}

/// Import-table hashes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportHashes {
    /// pefile-compatible imphash (PE only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    /// Sorted-symbol MD5 (ELF and Mach-O).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symhash: Option<String>,
}

/// A listed string with the section it falls in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListedString {
    /// The string.
    #[serde(flatten)]
    pub string: ExtractedString,
    /// Section containing the string's offset, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

/// String statistics plus a capped listing.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StringSummary {
    /// ASCII strings found.
    pub ascii: usize,
    /// UTF-16LE strings found.
    pub utf16le: usize,
    /// Count per indicator tag.
    pub tags: BTreeMap<String, usize>,
    /// Up to `max_listed_strings` strings, tagged ones first, then in offset order.
    pub listed: Vec<ListedString>,
    /// True when `listed` omits strings.
    pub truncated: bool,
}

/// Full triage result for one sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TriageReport {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// `binscope <version>`.
    pub tool: String,
    /// File facts.
    pub file: FileFacts,
    /// Parsed container, when the format is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<BinaryInfo>,
    /// Why `binary` is absent (unsupported or malformed container).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unparsed_reason: Option<String>,
    /// Import hashes.
    pub import_hashes: ImportHashes,
    /// ssdeep and TLSH.
    pub fuzzy: FuzzyDigests,
    /// Strings.
    pub strings: StringSummary,
    /// Structural heuristics.
    pub anomalies: Vec<Anomaly>,
    /// Capability-rule matches.
    pub capabilities: Vec<CapabilityMatch>,
}

impl TriageReport {
    /// Highest severity among anomalies and capabilities.
    pub fn max_severity(&self) -> Option<crate::rules::Severity> {
        self.anomalies.iter().map(|a| a.severity).chain(self.capabilities.iter().map(|c| c.severity)).max()
    }
}

fn import_hashes(info: &BinaryInfo, data: &[u8]) -> ImportHashes {
    match info.format {
        Format::Pe => {
            // Re-walk the import directory so ordinal entries feed the hash
            // exactly as pefile sees them.
            let imphash = goblin::pe::PE::parse(data).ok().and_then(|pe| hashes::imphash(format::pe_import_refs(&pe)));
            ImportHashes { imphash, symhash: None }
        }
        Format::Elf | Format::MachO | Format::MachOFat => ImportHashes {
            imphash: None,
            symhash: hashes::symhash(info.all_imports().into_iter().map(|i| i.name.as_str())),
        },
    }
}

/// Section containing each file offset, via binary search over sorted
/// file ranges: O((s + k) log s) for s sections and k strings.
fn section_lookup(sections: &[&Section]) -> impl Fn(u64) -> Option<String> {
    let mut ranges: Vec<(u64, u64, String)> = sections
        .iter()
        .filter(|s| s.file_size > 0)
        .map(|s| (s.file_offset, s.file_offset.saturating_add(s.file_size), s.name.clone()))
        .collect();
    ranges.sort_by_key(|r| r.0);
    move |off| {
        let idx = ranges.partition_point(|r| r.0 <= off);
        ranges[..idx]
            .iter()
            .rev()
            .take(4) // overlapping ranges are rare; check a few predecessors
            .find(|r| off < r.1)
            .map(|r| r.2.clone())
    }
}

fn summarise_strings(all: &[ExtractedString], sections: &[&Section], max: usize) -> StringSummary {
    let mut summary = StringSummary {
        ascii: all.iter().filter(|s| s.encoding == Encoding::Ascii).count(),
        utf16le: all.iter().filter(|s| s.encoding == Encoding::Utf16Le).count(),
        ..StringSummary::default()
    };
    for s in all {
        for t in &s.tags {
            *summary.tags.entry(t.as_str().to_string()).or_default() += 1;
        }
    }
    let lookup = section_lookup(sections);
    let mut order: Vec<&ExtractedString> = all.iter().filter(|s| !s.tags.is_empty()).collect();
    order.extend(all.iter().filter(|s| s.tags.is_empty()));
    summary.truncated = order.len() > max;
    summary.listed =
        order.into_iter().take(max).map(|s| ListedString { string: s.clone(), section: lookup(s.offset) }).collect();
    summary
}

/// Inputs at least this large run the independent whole-file passes
/// (digests, ssdeep, TLSH, strings) on scoped threads.
pub const PARALLEL_THRESHOLD: usize = 1 << 20;

/// Propagate a worker panic to the caller unchanged.
fn join<T>(r: std::thread::Result<T>) -> T {
    r.unwrap_or_else(|p| std::panic::resume_unwind(p))
}

/// Results of the passes that only need the raw bytes.
struct ContentPasses {
    digests: FileDigests,
    fuzzy: FuzzyDigests,
    strings: Vec<ExtractedString>,
}

fn content_passes(data: &[u8], opts: &StringOptions) -> ContentPasses {
    if data.len() < PARALLEL_THRESHOLD {
        return ContentPasses {
            digests: FileDigests::of(data),
            fuzzy: FuzzyDigests::of(data),
            strings: strings::extract(data, opts),
        };
    }
    std::thread::scope(|s| {
        let digests = s.spawn(|| FileDigests::of(data));
        let ss = s.spawn(|| crate::fuzzy::ssdeep::hash(data));
        let tl = s.spawn(|| crate::fuzzy::tlsh::hash(data));
        let found = strings::extract(data, opts);
        ContentPasses {
            digests: join(digests.join()),
            fuzzy: FuzzyDigests::from_results(join(ss.join()), join(tl.join())),
            strings: found,
        }
    })
}

/// Triage an in-memory sample. Never fails: unsupported or malformed
/// containers still get hashes, strings and content-based rule matches,
/// with `unparsed_reason` explaining what was skipped.
pub fn analyze_bytes(name: &str, data: &[u8], opts: &TriageOptions, rules: &RuleSet) -> TriageReport {
    let file_entropy = entropy::shannon(data);
    let (binary, unparsed_reason) = match format::parse(data) {
        Ok(Some(info)) => (Some(info), None),
        Ok(None) => {
            let why = match format::detect(data) {
                Detected::Unsupported(kind) => format!("unsupported container: {kind}"),
                _ => "not an ELF, PE or Mach-O file".to_string(),
            };
            (None, Some(why))
        }
        Err(e) => {
            log::warn!("{name}: {e}");
            (None, Some(e.to_string()))
        }
    };
    let ContentPasses { digests, fuzzy, strings: all_strings } = content_passes(data, &opts.strings);
    let sections: Vec<&Section> = binary.as_ref().map(BinaryInfo::all_sections).unwrap_or_default();
    let string_summary = summarise_strings(&all_strings, &sections, opts.max_listed_strings);
    let anomalies = binary.as_ref().map(|b| anomalies::detect(b, data.len() as u64, file_entropy)).unwrap_or_default();
    let capabilities = rules.evaluate(&Subject::new(binary.as_ref(), &all_strings, &anomalies));
    let import_hashes = binary.as_ref().map(|b| import_hashes(b, data)).unwrap_or_default();

    TriageReport {
        schema_version: SCHEMA_VERSION,
        tool: format!("binscope {}", env!("CARGO_PKG_VERSION")),
        file: FileFacts { name: name.to_string(), size: data.len() as u64, digests, entropy: file_entropy },
        binary,
        unparsed_reason,
        import_hashes,
        fuzzy,
        strings: string_summary,
        anomalies,
        capabilities,
    }
}

/// Read and triage a file.
pub fn analyze_path(path: &Path, opts: &TriageOptions, rules: &RuleSet) -> Result<TriageReport> {
    let data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    Ok(analyze_bytes(&path.display().to_string(), &data, opts, rules))
}

/// Expand `paths` into a sorted, de-duplicated list of regular files,
/// recursing into directories. Symbolic links are not followed (avoids loops
/// and escaping the requested tree).
pub fn collect_files(paths: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>> {
    fn walk(p: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
        let meta = std::fs::symlink_metadata(p).map_err(|e| Error::io(p, e))?;
        if meta.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(p)
                .map_err(|e| Error::io(p, e))?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .collect();
            entries.sort();
            for e in entries {
                walk(&e, out)?;
            }
        } else if meta.is_file() {
            out.push(p.to_path_buf());
        } else {
            log::info!("skipping {} (not a regular file)", p.display());
        }
        Ok(())
    }
    let mut out = Vec::new();
    for p in paths {
        walk(p, &mut out)?;
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    Ok(out)
}

/// The comma-joined `library.function` string imphash digests, for a PE
/// file (useful when comparing against other tools).
pub fn pe_imphash_input(data: &[u8]) -> Result<String> {
    let pe = goblin::pe::PE::parse(data).map_err(|e| Error::parse("PE", e.to_string()))?;
    Ok(hashes::imphash_input(format::pe_import_refs(&pe)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strings::StringTag;

    #[test]
    fn non_binary_input_still_gets_hashes_and_strings() {
        let data = b"plain text with a URL http://example.test/path and more words to pass fifty bytes".repeat(4);
        let r = analyze_bytes("note.txt", &data, &TriageOptions::default(), &RuleSet::builtin().unwrap());
        assert!(r.binary.is_none());
        assert_eq!(r.unparsed_reason.as_deref(), Some("not an ELF, PE or Mach-O file"));
        assert!(r.fuzzy.tlsh.is_some());
        assert_eq!(r.strings.tags.get("url"), Some(&1)); // one long printable run
        assert!(r.capabilities.iter().any(|c| c.id == "communication.url.embedded"));
        assert_eq!(r.anomalies, Vec::<Anomaly>::new());
        assert_eq!(r.max_severity(), Some(crate::rules::Severity::Info));
    }

    #[test]
    fn unsupported_and_malformed_containers_are_explained() {
        let r = analyze_bytes("a.a", b"!<arch>\nrest", &TriageOptions::default(), &RuleSet::empty());
        assert_eq!(r.unparsed_reason.as_deref(), Some("unsupported container: ar archive"));
        let r = analyze_bytes("bad", b"\x7fELF\x02\x01\x01", &TriageOptions::default(), &RuleSet::empty());
        assert!(r.unparsed_reason.as_deref().unwrap().contains("malformed ELF"));
        assert!(r.max_severity().is_none());
    }

    #[test]
    fn string_listing_prioritises_tagged_and_caps() {
        let s = |off: u64, v: &str, tags: Vec<StringTag>| ExtractedString {
            offset: off,
            encoding: Encoding::Ascii,
            value: v.into(),
            length: v.len(),
            tags,
        };
        let all = vec![s(0, "aaaa", vec![]), s(10, "http://x.test", vec![StringTag::Url]), s(30, "bbbb", vec![])];
        let sec = Section {
            name: ".rodata".into(),
            file_offset: 8,
            file_size: 16,
            virtual_address: 0,
            virtual_size: 16,
            read: true,
            write: false,
            execute: false,
            entropy: 0.0,
            raw_flags: 0,
        };
        let sum = summarise_strings(&all, &[&sec], 2);
        assert!(sum.truncated);
        assert_eq!(sum.listed[0].string.value, "http://x.test");
        assert_eq!(sum.listed[0].section.as_deref(), Some(".rodata"));
        assert_eq!(sum.listed[1].section, None);
        assert_eq!(sum.ascii, 3);
    }

    #[test]
    fn parallel_and_serial_passes_agree() {
        let data = crate::synth::generate(crate::synth::Kind::Mixed, PARALLEL_THRESHOLD + 4096, 9);
        let rules = RuleSet::builtin().unwrap();
        let big = analyze_bytes("big", &data, &TriageOptions::default(), &rules);
        assert_eq!(big.file.digests, FileDigests::of(&data));
        assert_eq!(big.fuzzy, FuzzyDigests::of(&data));
        assert_eq!(big.strings.ascii, strings::extract_ascii(&data, &StringOptions::default()).len());
    }

    #[test]
    fn collect_files_walks_sorted_and_dedups() {
        let dir = std::env::temp_dir().join(format!("binscope-walk-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("b"), b"x").unwrap();
        std::fs::write(dir.join("sub/a"), b"y").unwrap();
        let got = collect_files(&[dir.clone(), dir.join("b")]).unwrap();
        assert_eq!(got, vec![dir.join("b"), dir.join("sub/a")]);
        assert!(collect_files(&[dir.join("missing")]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn analyze_path_reports_io_errors() {
        let e = analyze_path(Path::new("/nonexistent/binscope"), &TriageOptions::default(), &RuleSet::empty());
        assert!(e.unwrap_err().to_string().contains("/nonexistent/binscope"));
    }
}
