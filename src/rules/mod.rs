//! YAML capability rules: sets of APIs, strings and structural facts mapped
//! to capability labels.
//!
//! ```yaml
//! rules:
//!   - id: communication.tcp-client
//!     name: connect to a TCP endpoint
//!     namespace: communication/socket
//!     severity: low
//!     attack: [T1071]
//!     match:
//!       all:
//!         - import: socket
//!         - any: [ {import: connect}, {import: WSAConnect} ]
//! ```
//!
//! Leaves: `import`, `library`, `export`, `string`, `string_regex`,
//! `string_tag`, `section`, `anomaly`, `format`. Combinators: `all`, `any`,
//! `not`, `at_least: {count, of}`. Import patterns accept `*`/`?` globs and
//! an optional `library!` qualifier; names compare case-insensitively and a
//! Mach-O symbol's leading underscore is ignored. Rule files are validated
//! strictly on load (unknown keys, bad regexes, unknown tags or anomaly ids
//! and duplicate rule ids are errors).

mod eval;

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::anomalies::ANOMALY_IDS;
use crate::error::{Error, Result};
use crate::format::Format;
use crate::strings::StringTag;

pub use eval::{CapabilityMatch, Subject};

/// How much attention a finding deserves on its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Context only.
    #[default]
    Info,
    /// Worth noting.
    Low,
    /// Worth a look.
    Medium,
    /// Look first.
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    id: String,
    name: String,
    namespace: String,
    #[serde(default)]
    severity: Severity,
    #[serde(default)]
    description: String,
    #[serde(default)]
    attack: Vec<String>,
    #[serde(default)]
    formats: Vec<String>,
    // Rule files write leaves as single-key maps (`import: socket`), not
    // YAML tags, so map externally-tagged enums at every nesting level.
    #[serde(rename = "match", with = "serde_norway::with::singleton_map_recursive")]
    expr: ExprDef,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ExprDef {
    All(Vec<ExprDef>),
    Any(Vec<ExprDef>),
    Not(Box<ExprDef>),
    AtLeast { count: usize, of: Vec<ExprDef> },
    Import(String),
    Library(String),
    Export(String),
    String(String),
    StringRegex(String),
    StringTag(String),
    Section(SectionDef),
    Anomaly(String),
    Format(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SectionDef {
    name: Option<String>,
    min_entropy: Option<f64>,
    max_entropy: Option<f64>,
    min_size: Option<u64>,
    writable: Option<bool>,
    executable: Option<bool>,
}

/// Case-insensitive name pattern: exact string or `*`/`?` glob.
#[derive(Clone, Debug)]
pub(crate) enum NamePattern {
    Exact(String),
    Glob(Regex),
}

impl NamePattern {
    fn compile(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("empty name pattern".into());
        }
        if !pattern.contains(['*', '?']) {
            return Ok(Self::Exact(pattern.to_ascii_lowercase()));
        }
        let mut re = String::from("(?i)^");
        for c in pattern.chars() {
            match c {
                '*' => re.push_str(".*"),
                '?' => re.push('.'),
                c => re.push_str(&regex::escape(&c.to_string())),
            }
        }
        re.push('$');
        Regex::new(&re).map(Self::Glob).map_err(|e| e.to_string())
    }

    pub(crate) fn matches(&self, candidate: &str) -> bool {
        match self {
            Self::Exact(s) => candidate.eq_ignore_ascii_case(s),
            Self::Glob(r) => r.is_match(candidate),
        }
    }
}

/// Library name reduced for comparison: basename, lower-case, without a
/// `.dll`/`.so[.N]`/`.dylib` suffix (`/usr/lib/libSystem.B.dylib` ->
/// `libsystem.b`, `KERNEL32.dll` -> `kernel32`, `libc.so.6` -> `libc`).
pub fn library_stem(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase();
    if let Some(i) = base.find(".so") {
        let rest = &base[i + 3..];
        if rest.is_empty() || rest.starts_with('.') {
            return base[..i].to_string();
        }
    }
    for ext in [".dll", ".dylib", ".exe", ".sys", ".ocx", ".drv"] {
        if let Some(s) = base.strip_suffix(ext) {
            return s.to_string();
        }
    }
    base
}

/// Compiled section constraint.
#[derive(Clone, Debug, Default)]
pub(crate) struct SectionTest {
    pub name: Option<NamePattern>,
    pub min_entropy: Option<f64>,
    pub max_entropy: Option<f64>,
    pub min_size: Option<u64>,
    pub writable: Option<bool>,
    pub executable: Option<bool>,
}

/// Compiled rule expression.
#[derive(Clone, Debug)]
pub(crate) enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    AtLeast(usize, Vec<Expr>),
    Import { library: Option<NamePattern>, name: NamePattern },
    Library(NamePattern),
    Export(NamePattern),
    Substring(String),
    StringRegex(Regex),
    StringTag(StringTag),
    Section(SectionTest),
    Anomaly(String),
    Format(Format),
}

/// A validated, compiled rule.
#[derive(Clone, Debug)]
pub struct Rule {
    /// Unique identifier.
    pub id: String,
    /// Capability label shown to analysts.
    pub name: String,
    /// Slash-separated grouping (`communication/socket`).
    pub namespace: String,
    /// Severity of a match.
    pub severity: Severity,
    /// Longer explanation.
    pub description: String,
    /// MITRE ATT&CK technique ids the capability relates to.
    pub attack: Vec<String>,
    /// Formats the rule applies to (empty = all).
    pub formats: Vec<Format>,
    /// File the rule came from.
    pub origin: String,
    pub(crate) expr: Expr,
}

fn compile_expr(def: ExprDef, depth: usize) -> Result<Expr, String> {
    if depth > 32 {
        return Err("expression nested deeper than 32 levels".into());
    }
    let list = |v: Vec<ExprDef>, what: &str| -> Result<Vec<Expr>, String> {
        if v.is_empty() {
            return Err(format!("`{what}` needs at least one child"));
        }
        v.into_iter().map(|d| compile_expr(d, depth + 1)).collect()
    };
    Ok(match def {
        ExprDef::All(v) => Expr::All(list(v, "all")?),
        ExprDef::Any(v) => Expr::Any(list(v, "any")?),
        ExprDef::Not(d) => Expr::Not(Box::new(compile_expr(*d, depth + 1)?)),
        ExprDef::AtLeast { count, of } => {
            let children = list(of, "at_least.of")?;
            if count == 0 || count > children.len() {
                return Err(format!("at_least.count must be between 1 and {}", children.len()));
            }
            Expr::AtLeast(count, children)
        }
        ExprDef::Import(p) => match p.split_once('!') {
            Some((lib, name)) => Expr::Import {
                library: Some(NamePattern::compile(&library_stem(lib))?),
                name: NamePattern::compile(name)?,
            },
            None => Expr::Import {
                library: None,
                name: NamePattern::compile(&p)?,
            },
        },
        ExprDef::Library(p) => Expr::Library(NamePattern::compile(&library_stem(&p))?),
        ExprDef::Export(p) => Expr::Export(NamePattern::compile(&p)?),
        ExprDef::String(s) => {
            if s.is_empty() {
                return Err("empty `string`".into());
            }
            Expr::Substring(s.to_lowercase())
        }
        ExprDef::StringRegex(r) => Expr::StringRegex(Regex::new(&r).map_err(|e| format!("bad string_regex: {e}"))?),
        ExprDef::StringTag(t) => Expr::StringTag(StringTag::from_name(&t).ok_or_else(|| {
            let names: Vec<&str> = StringTag::ALL.iter().map(|t| t.as_str()).collect();
            format!("unknown string_tag {t:?} (known: {})", names.join(", "))
        })?),
        ExprDef::Section(s) => {
            if s.name.is_none()
                && s.min_entropy.is_none()
                && s.max_entropy.is_none()
                && s.min_size.is_none()
                && s.writable.is_none()
                && s.executable.is_none()
            {
                return Err("`section` needs at least one constraint".into());
            }
            for e in [s.min_entropy, s.max_entropy].into_iter().flatten() {
                if !(0.0..=8.0).contains(&e) {
                    return Err(format!("entropy bound {e} outside 0..=8"));
                }
            }
            Expr::Section(SectionTest {
                name: s.name.as_deref().map(NamePattern::compile).transpose()?,
                min_entropy: s.min_entropy,
                max_entropy: s.max_entropy,
                min_size: s.min_size,
                writable: s.writable,
                executable: s.executable,
            })
        }
        ExprDef::Anomaly(a) => {
            if !ANOMALY_IDS.contains(&a.as_str()) {
                return Err(format!("unknown anomaly id {a:?}"));
            }
            Expr::Anomaly(a)
        }
        ExprDef::Format(f) => Expr::Format(Format::from_name(&f).ok_or_else(|| format!("unknown format {f:?}"))?),
    })
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_' | '/'))
}

/// An ordered collection of compiled rules.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

/// The rule files compiled into the binary (`rules/*.yaml`).
pub const BUILTIN_RULE_FILES: [(&str, &str); 6] = [
    ("builtin:communication.yaml", include_str!("../../rules/communication.yaml")),
    ("builtin:host-interaction.yaml", include_str!("../../rules/host-interaction.yaml")),
    ("builtin:load-code.yaml", include_str!("../../rules/load-code.yaml")),
    ("builtin:data-manipulation.yaml", include_str!("../../rules/data-manipulation.yaml")),
    ("builtin:anti-analysis.yaml", include_str!("../../rules/anti-analysis.yaml")),
    ("builtin:executable.yaml", include_str!("../../rules/executable.yaml")),
];

impl RuleSet {
    /// No rules.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The default rule pack shipped with binscope.
    pub fn builtin() -> Result<Self> {
        let mut set = Self::empty();
        for (origin, text) in BUILTIN_RULE_FILES {
            set.extend(Self::from_yaml(origin, text)?)?;
        }
        Ok(set)
    }

    /// Parse and validate one YAML document.
    pub fn from_yaml(origin: &str, text: &str) -> Result<Self> {
        let err = |message: String| Error::Rule {
            origin: origin.to_string(),
            message,
        };
        let file: RuleFile = serde_norway::from_str(text).map_err(|e| err(e.to_string()))?;
        let mut rules = Vec::with_capacity(file.rules.len());
        let mut seen = HashSet::new();
        for def in file.rules {
            let id = def.id.clone();
            if !valid_id(&id) {
                return Err(err(format!("rule id {id:?} must be non-empty [a-z0-9._/-]")));
            }
            if !seen.insert(id.clone()) {
                return Err(err(format!("duplicate rule id {id:?}")));
            }
            if def.name.trim().is_empty() || def.namespace.trim().is_empty() {
                return Err(err(format!("rule {id:?}: name and namespace must be non-empty")));
            }
            let formats = def
                .formats
                .iter()
                .map(|f| Format::from_name(f).ok_or_else(|| err(format!("rule {id:?}: unknown format {f:?}"))))
                .collect::<Result<Vec<_>>>()?;
            let expr = compile_expr(def.expr, 0).map_err(|m| err(format!("rule {id:?}: {m}")))?;
            rules.push(Rule {
                id,
                name: def.name,
                namespace: def.namespace,
                severity: def.severity,
                description: def.description,
                attack: def.attack,
                formats,
                origin: origin.to_string(),
                expr,
            });
        }
        Ok(Self { rules })
    }

    /// Load a rule file, or every `*.yml`/`*.yaml` file of a directory in
    /// name order.
    pub fn load_path(path: &Path) -> Result<Self> {
        let mut set = Self::empty();
        if path.is_dir() {
            let mut files: Vec<_> = std::fs::read_dir(path)
                .map_err(|e| Error::io(path, e))?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
                .collect();
            files.sort();
            for f in files {
                set.extend(Self::load_file(&f)?)?;
            }
        } else {
            set = Self::load_file(path)?;
        }
        Ok(set)
    }

    fn load_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        Self::from_yaml(&path.display().to_string(), &text)
    }

    /// Append `other`, rejecting duplicate ids across files.
    pub fn extend(&mut self, other: RuleSet) -> Result<()> {
        for r in other.rules {
            if let Some(prev) = self.rules.iter().find(|p| p.id == r.id) {
                return Err(Error::Rule {
                    origin: r.origin.clone(),
                    message: format!("rule id {:?} already defined in {}", r.id, prev.origin),
                });
            }
            self.rules.push(r);
        }
        Ok(())
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate the rules in load order.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    /// Evaluate every applicable rule against `subject`.
    pub fn evaluate(&self, subject: &Subject<'_>) -> Vec<CapabilityMatch> {
        eval::evaluate(&self.rules, subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(yaml: &str) -> Result<RuleSet> {
        RuleSet::from_yaml("test", yaml)
    }

    #[test]
    fn builtin_pack_loads() {
        let set = RuleSet::builtin().unwrap();
        assert!(set.len() >= 25, "only {} builtin rules", set.len());
        assert!(!set.is_empty());
        assert!(set.iter().all(|r| r.origin.starts_with("builtin:")));
    }

    #[test]
    fn library_stems() {
        assert_eq!(library_stem("KERNEL32.dll"), "kernel32");
        assert_eq!(library_stem("/usr/lib/libSystem.B.dylib"), "libsystem.b");
        assert_eq!(library_stem("libc.so.6"), "libc");
        assert_eq!(library_stem("libssl.so"), "libssl");
        assert_eq!(library_stem("libsomething.sox"), "libsomething.sox");
        assert_eq!(library_stem(r"C:\x\WS2_32.DLL"), "ws2_32");
        assert_eq!(library_stem("custom"), "custom");
    }

    #[test]
    fn glob_patterns() {
        let p = NamePattern::compile("CreateFile*").unwrap();
        assert!(p.matches("createfilew"));
        assert!(!p.matches("XCreateFileW"));
        let q = NamePattern::compile("Reg?penKey*").unwrap();
        assert!(q.matches("RegOpenKeyExW"));
        assert!(NamePattern::compile("").is_err());
        let e = NamePattern::compile("a.b").unwrap();
        assert!(e.matches("A.B"));
        assert!(!e.matches("axb"));
    }

    #[test]
    fn validation_errors_name_the_problem() {
        let cases = [
            ("rules: [{id: a, name: n, namespace: x, match: {import: ''}}]", "empty name pattern"),
            ("rules: [{id: a, name: n, namespace: x, match: {bogus: 1}}]", "unknown variant"),
            ("rules: [{id: a, name: n, namespace: x, extra: 1, match: {import: x}}]", "unknown field"),
            ("rules: [{id: A!, name: n, namespace: x, match: {import: x}}]", "must be non-empty"),
            ("rules: [{id: a, name: '', namespace: x, match: {import: x}}]", "name and namespace"),
            ("rules: [{id: a, name: n, namespace: x, formats: [coff], match: {import: x}}]", "unknown format"),
            ("rules: [{id: a, name: n, namespace: x, match: {all: []}}]", "at least one child"),
            ("rules: [{id: a, name: n, namespace: x, match: {at_least: {count: 3, of: [{import: x}]}}}]", "between 1 and 1"),
            ("rules: [{id: a, name: n, namespace: x, match: {string_regex: '('}}]", "bad string_regex"),
            ("rules: [{id: a, name: n, namespace: x, match: {string_tag: nope}}]", "unknown string_tag"),
            ("rules: [{id: a, name: n, namespace: x, match: {section: {}}}]", "at least one constraint"),
            ("rules: [{id: a, name: n, namespace: x, match: {section: {min_entropy: 9}}}]", "outside 0..=8"),
            ("rules: [{id: a, name: n, namespace: x, match: {anomaly: weird}}]", "unknown anomaly"),
            ("rules: [{id: a, name: n, namespace: x, match: {format: coff}}]", "unknown format"),
            ("rules: [{id: a, name: n, namespace: x, match: {string: ''}}]", "empty `string`"),
            (
                "rules: [{id: a, name: n, namespace: x, match: {import: x}}, {id: a, name: n, namespace: x, match: {import: y}}]",
                "duplicate rule id",
            ),
        ];
        for (yaml, want) in cases {
            let e = load(yaml).unwrap_err().to_string();
            assert!(e.contains(want), "{yaml}\n -> {e}");
            assert!(e.contains("test"), "origin missing: {e}");
        }
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let mut expr = String::from("{import: x}");
        for _ in 0..40 {
            expr = format!("{{not: {expr}}}");
        }
        let yaml = format!("rules: [{{id: a, name: n, namespace: x, match: {expr}}}]");
        assert!(load(&yaml).unwrap_err().to_string().contains("nested deeper"));
    }

    #[test]
    fn extend_rejects_cross_file_duplicates() {
        let mut a = load("rules: [{id: a, name: n, namespace: x, match: {import: x}}]").unwrap();
        let b = RuleSet::from_yaml("other", "rules: [{id: a, name: n, namespace: x, match: {import: y}}]").unwrap();
        let e = a.extend(b).unwrap_err().to_string();
        assert!(e.contains("already defined in test"), "{e}");
    }

    #[test]
    fn load_path_reads_files_and_directories() {
        let dir = std::env::temp_dir().join(format!("binscope-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.yaml"), "rules: [{id: b, name: n, namespace: x, match: {import: y}}]").unwrap();
        std::fs::write(dir.join("a.yml"), "rules: [{id: a, name: n, namespace: x, match: {import: x}}]").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let set = RuleSet::load_path(&dir).unwrap();
        let ids: Vec<&str> = set.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(RuleSet::load_path(&dir.join("b.yaml")).unwrap().len(), 1);
        assert!(RuleSet::load_path(&dir.join("missing.yaml")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn severity_display_and_order() {
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert!(Severity::High > Severity::Medium && Severity::Low > Severity::Info);
    }
}
