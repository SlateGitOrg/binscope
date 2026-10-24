//! Rule evaluation with evidence collection.
//!
//! Cost per rule is linear in the number of imports / strings / sections a
//! leaf inspects; the subject pre-computes lower-cased strings and library
//! stems once, so evaluating the whole rule pack is
//! O(rules x (imports + strings + sections)).

use serde::{Deserialize, Serialize};

use super::{library_stem, Expr, Rule, SectionTest, Severity};
use crate::anomalies::Anomaly;
use crate::format::{BinaryInfo, Format, Section};
use crate::strings::ExtractedString;

/// Evidence lines kept per leaf before summarising the rest.
const EVIDENCE_PER_LEAF: usize = 3;

/// One import as rules see it.
#[derive(Clone, Debug)]
struct SubjectImport {
    library_stem: Option<String>,
    name: String,
    display: String,
}

/// Everything rules can match against, prepared once per sample.
#[derive(Clone, Debug, Default)]
pub struct Subject<'a> {
    format: Option<Format>,
    imports: Vec<SubjectImport>,
    libraries: Vec<(String, String)>,
    exports: Vec<&'a str>,
    strings: &'a [ExtractedString],
    lower_strings: Vec<String>,
    sections: Vec<&'a Section>,
    anomalies: Vec<&'a str>,
}

impl<'a> Subject<'a> {
    /// Build the subject from triage results. `info` is `None` for files
    /// that are not a supported executable format (only string and anomaly
    /// leaves can then match).
    pub fn new(info: Option<&'a BinaryInfo>, strings: &'a [ExtractedString], anomalies: &'a [Anomaly]) -> Self {
        let mut s = Subject {
            strings,
            lower_strings: strings.iter().map(|x| x.value.to_lowercase()).collect(),
            anomalies: anomalies.iter().map(|a| a.id.as_str()).collect(),
            ..Subject::default()
        };
        if let Some(info) = info {
            s.format = Some(info.format);
            for imp in info.all_imports() {
                let fmt = if info.format == Format::MachOFat { Format::MachO } else { info.format };
                let name = imp.normalized_name(fmt).to_string();
                let display = match &imp.library {
                    Some(l) => format!("{l}!{}", imp.name),
                    None => imp.name.clone(),
                };
                s.imports.push(SubjectImport {
                    library_stem: imp.library.as_deref().map(library_stem),
                    name,
                    display,
                });
            }
            let mut libs: Vec<&String> = info.libraries.iter().collect();
            for slice in &info.slices {
                libs.extend(slice.libraries.iter());
            }
            s.libraries = libs.into_iter().map(|l| (library_stem(l), l.clone())).collect();
            s.exports = info.exports.iter().map(|e| e.name.as_str()).collect();
            for slice in &info.slices {
                s.exports.extend(slice.exports.iter().map(|e| e.name.as_str()));
            }
            s.sections = info.all_sections();
        }
        s
    }
}

/// A rule that matched, with the facts that made it match.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityMatch {
    /// Rule id.
    pub id: String,
    /// Capability label.
    pub name: String,
    /// Rule namespace.
    pub namespace: String,
    /// Rule severity.
    pub severity: Severity,
    /// Rule description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// ATT&CK technique ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
    /// Matched facts (imports, strings, sections...).
    pub evidence: Vec<String>,
}

fn summarise(mut hits: Vec<String>) -> Vec<String> {
    if hits.len() > EVIDENCE_PER_LEAF {
        let extra = hits.len() - EVIDENCE_PER_LEAF;
        hits.truncate(EVIDENCE_PER_LEAF);
        hits.push(format!("(+{extra} more)"));
    }
    hits
}

fn section_matches(t: &SectionTest, s: &Section) -> bool {
    t.name.as_ref().is_none_or(|p| p.matches(&s.name))
        && t.min_entropy.is_none_or(|e| s.file_size > 0 && s.entropy >= e)
        && t.max_entropy.is_none_or(|e| s.entropy <= e)
        && t.min_size.is_none_or(|m| s.file_size >= m)
        && t.writable.is_none_or(|w| s.write == w)
        && t.executable.is_none_or(|x| s.execute == x)
}

fn leaf_hits(expr: &Expr, sub: &Subject<'_>) -> Vec<String> {
    match expr {
        Expr::Import { library, name } => sub
            .imports
            .iter()
            .filter(|i| {
                name.matches(&i.name)
                    && library
                        .as_ref()
                        .is_none_or(|l| i.library_stem.as_deref().is_some_and(|s| l.matches(s)))
            })
            .map(|i| format!("import {}", i.display))
            .collect(),
        Expr::Library(p) => sub
            .libraries
            .iter()
            .filter(|(stem, _)| p.matches(stem))
            .map(|(_, l)| format!("library {l}"))
            .collect(),
        Expr::Export(p) => sub
            .exports
            .iter()
            .filter(|e| p.matches(e))
            .map(|e| format!("export {e}"))
            .collect(),
        Expr::Substring(needle) => sub
            .lower_strings
            .iter()
            .zip(sub.strings)
            .filter(|(l, _)| l.contains(needle.as_str()))
            .map(|(_, s)| format!("string @{:#x} {:?}", s.offset, s.value))
            .collect(),
        Expr::StringRegex(re) => sub
            .strings
            .iter()
            .filter(|s| re.is_match(&s.value))
            .map(|s| format!("string @{:#x} {:?}", s.offset, s.value))
            .collect(),
        Expr::StringTag(tag) => sub
            .strings
            .iter()
            .filter(|s| s.tags.contains(tag))
            .map(|s| format!("{} string @{:#x} {:?}", tag.as_str(), s.offset, s.value))
            .collect(),
        Expr::Section(t) => sub
            .sections
            .iter()
            .filter(|s| section_matches(t, s))
            .map(|s| format!("section {} ({}, {} bytes, entropy {:.2})", s.name, s.perms(), s.file_size, s.entropy))
            .collect(),
        Expr::Anomaly(id) => sub
            .anomalies
            .iter()
            .filter(|a| *a == id)
            .map(|a| format!("anomaly {a}"))
            .collect(),
        Expr::Format(f) => {
            let ok = match (f, sub.format) {
                (Format::MachO, Some(Format::MachO | Format::MachOFat)) => true,
                (want, Some(have)) => *want == have,
                (_, None) => false,
            };
            if ok {
                vec![format!("format {}", f.as_str())]
            } else {
                Vec::new()
            }
        }
        Expr::All(_) | Expr::Any(_) | Expr::Not(_) | Expr::AtLeast(..) => unreachable!("combinators handled by eval"),
    }
}

/// Evaluate `expr`; on success return the supporting evidence.
fn eval(expr: &Expr, sub: &Subject<'_>) -> Option<Vec<String>> {
    match expr {
        Expr::All(children) => {
            let mut ev = Vec::new();
            for c in children {
                ev.extend(eval(c, sub)?);
            }
            Some(ev)
        }
        Expr::Any(children) => {
            let mut matched = false;
            let mut ev = Vec::new();
            for c in children {
                if let Some(e) = eval(c, sub) {
                    matched = true;
                    ev.extend(e);
                }
            }
            matched.then_some(ev)
        }
        Expr::Not(child) => match eval(child, sub) {
            Some(_) => None,
            None => Some(Vec::new()),
        },
        Expr::AtLeast(n, children) => {
            let mut count = 0;
            let mut ev = Vec::new();
            for c in children {
                if let Some(e) = eval(c, sub) {
                    count += 1;
                    ev.extend(e);
                }
            }
            (count >= *n).then_some(ev)
        }
        leaf => {
            let hits = leaf_hits(leaf, sub);
            (!hits.is_empty()).then(|| summarise(hits))
        }
    }
}

fn applies(rule: &Rule, sub: &Subject<'_>) -> bool {
    rule.formats.is_empty()
        || sub.format.is_some_and(|have| {
            rule.formats
                .iter()
                .any(|f| *f == have || (*f == Format::MachO && have == Format::MachOFat))
        })
}

pub(super) fn evaluate(rules: &[Rule], sub: &Subject<'_>) -> Vec<CapabilityMatch> {
    let mut out: Vec<CapabilityMatch> = rules
        .iter()
        .filter(|r| applies(r, sub))
        .filter_map(|r| {
            eval(&r.expr, sub).map(|mut evidence| {
                evidence.dedup();
                CapabilityMatch {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    namespace: r.namespace.clone(),
                    severity: r.severity,
                    description: r.description.clone(),
                    attack: r.attack.clone(),
                    evidence,
                }
            })
        })
        .collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.namespace.cmp(&b.namespace)).then_with(|| a.id.cmp(&b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::super::RuleSet;
    use super::*;
    use crate::format::{BinaryKind, Export, Import};
    use crate::strings::{Encoding, StringTag};

    fn info(format: Format, imports: &[(&str, &str)]) -> BinaryInfo {
        BinaryInfo {
            format,
            arch: "x86_64".into(),
            bits: 64,
            endian: "little".into(),
            kind: BinaryKind::Executable,
            entry_point: None,
            sections: vec![Section {
                name: ".blob".into(),
                file_offset: 0,
                file_size: 4096,
                virtual_address: 0,
                virtual_size: 4096,
                read: true,
                write: false,
                execute: false,
                entropy: 7.9,
                raw_flags: 0,
            }],
            imports: imports
                .iter()
                .map(|(l, n)| Import {
                    library: (!l.is_empty()).then(|| (*l).to_string()),
                    name: (*n).to_string(),
                    ordinal: None,
                    weak: false,
                })
                .collect(),
            exports: vec![Export {
                name: "ServiceMain".into(),
                address: 0x1000,
                forwarded_to: None,
            }],
            libraries: imports.iter().filter(|(l, _)| !l.is_empty()).map(|(l, _)| (*l).to_string()).collect(),
            mitigations: Vec::new(),
            overlay: None,
            pe: None,
            elf: None,
            macho: None,
            slices: Vec::new(),
        }
    }

    fn string(value: &str, tags: Vec<StringTag>) -> ExtractedString {
        ExtractedString {
            offset: 0x40,
            encoding: Encoding::Ascii,
            value: value.into(),
            length: value.len(),
            tags,
        }
    }

    fn run(yaml: &str, info: Option<&BinaryInfo>, strings: &[ExtractedString], anomalies: &[Anomaly]) -> Vec<CapabilityMatch> {
        let set = RuleSet::from_yaml("t", yaml).unwrap();
        set.evaluate(&Subject::new(info, strings, anomalies))
    }

    #[test]
    fn all_any_not_at_least() {
        let bin = info(Format::Pe, &[("WS2_32.dll", "socket"), ("WS2_32.dll", "connect"), ("KERNEL32.dll", "Sleep")]);
        let yaml = r"
rules:
  - id: all
    name: n
    namespace: x
    match: {all: [{import: socket}, {import: 'ws2_32!connect'}]}
  - id: any
    name: n
    namespace: x
    match: {any: [{import: nope}, {import: 'sleep'}]}
  - id: not
    name: n
    namespace: x
    match: {all: [{import: socket}, {not: {import: bind}}]}
  - id: atleast
    name: n
    namespace: x
    match: {at_least: {count: 2, of: [{import: socket}, {import: bind}, {import: listen}]}}
  - id: libqual-miss
    name: n
    namespace: x
    match: {import: 'kernel32!connect'}
";
        let got: Vec<String> = run(yaml, Some(&bin), &[], &[]).into_iter().map(|m| m.id).collect();
        assert_eq!(got, vec!["all", "any", "not"]);
    }

    #[test]
    fn evidence_is_collected_and_summarised() {
        let imports: Vec<(&str, &str)> = (0..6).map(|_| ("advapi32.dll", "RegSetValueExW")).collect();
        let bin = info(Format::Pe, &imports);
        let m = run(
            "rules: [{id: r, name: n, namespace: x, severity: medium, match: {import: 'Reg*'}}]",
            Some(&bin),
            &[],
            &[],
        );
        assert_eq!(m[0].severity, Severity::Medium);
        assert_eq!(m[0].evidence.len(), 2, "{:?}", m[0].evidence); // deduped + summary line
        assert!(m[0].evidence[1].starts_with("(+"));
    }

    #[test]
    fn macho_underscore_and_format_filters() {
        let bin = info(Format::MachO, &[("/usr/lib/libSystem.B.dylib", "_socket")]);
        let yaml = r"
rules:
  - id: mac
    name: n
    namespace: x
    formats: [macho]
    match: {all: [{import: socket}, {library: libSystem.B.dylib}, {format: macho}]}
  - id: pe-only
    name: n
    namespace: x
    formats: [pe]
    match: {import: socket}
";
        let got = run(yaml, Some(&bin), &[], &[]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "mac");
        let mut fat = info(Format::MachOFat, &[]);
        fat.slices.push(bin.clone());
        assert_eq!(run(yaml, Some(&fat), &[], &[]).len(), 1);
    }

    #[test]
    fn strings_sections_exports_anomalies() {
        let bin = info(Format::Elf, &[]);
        let strings = vec![
            string("GET http://example.test/x", vec![StringTag::Url]),
            string("User-Agent: probe", vec![]),
        ];
        let anomalies = vec![Anomaly {
            id: "overlay".into(),
            severity: Severity::Low,
            message: String::new(),
        }];
        let yaml = r"
rules:
  - id: s1
    name: n
    namespace: a
    match: {string: 'user-agent'}
  - id: s2
    name: n
    namespace: a
    match: {string_regex: '^GET '}
  - id: s3
    name: n
    namespace: a
    match: {string_tag: url}
  - id: sec
    name: n
    namespace: b
    match: {section: {name: '.bl*', min_entropy: 7.5, min_size: 1024, writable: false, executable: false}}
  - id: sec-miss
    name: n
    namespace: b
    match: {section: {max_entropy: 1.0}}
  - id: exp
    name: n
    namespace: c
    match: {export: servicemain}
  - id: an
    name: n
    namespace: d
    match: {anomaly: overlay}
  - id: fmt-miss
    name: n
    namespace: d
    match: {format: pe}
";
        let got: Vec<String> = run(yaml, Some(&bin), &strings, &anomalies).into_iter().map(|m| m.id).collect();
        assert_eq!(got, vec!["s1", "s2", "s3", "sec", "exp", "an"]);
    }

    #[test]
    fn non_binary_subject_only_matches_content_leaves() {
        let strings = vec![string("http://example.test", vec![StringTag::Url])];
        let yaml = r"
rules:
  - id: url
    name: n
    namespace: a
    match: {string_tag: url}
  - id: imp
    name: n
    namespace: a
    match: {import: socket}
  - id: fmt
    name: n
    namespace: a
    formats: [elf]
    match: {string_tag: url}
  - id: fmt-leaf
    name: n
    namespace: a
    match: {format: elf}
";
        let got: Vec<String> = run(yaml, None, &strings, &[]).into_iter().map(|m| m.id).collect();
        assert_eq!(got, vec!["url"]);
    }

    #[test]
    fn results_sorted_by_severity() {
        let bin = info(Format::Pe, &[("k.dll", "A"), ("k.dll", "B")]);
        let yaml = r"
rules:
  - {id: low, name: n, namespace: z, severity: low, match: {import: a}}
  - {id: high, name: n, namespace: z, severity: high, match: {import: b}}
";
        let got: Vec<String> = run(yaml, Some(&bin), &[], &[]).into_iter().map(|m| m.id).collect();
        assert_eq!(got, vec!["high", "low"]);
    }
}
