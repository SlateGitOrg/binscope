//! Rendering of triage reports, comparisons and clusterings for humans.
//!
//! JSON output is plain `serde_json` over the report types; this module
//! only formats the terminal view.

use std::fmt::Write as _;

use crate::cluster::{Clustering, Method};
use crate::entropy;
use crate::format::{BinaryInfo, Format};
use crate::rules::Severity;
use crate::triage::TriageReport;

/// Terminal styling.
#[derive(Clone, Copy, Debug, Default)]
pub struct Style {
    /// Emit ANSI colours.
    pub color: bool,
}

impl Style {
    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(self, text: &str) -> String {
        self.paint("2", text)
    }

    fn severity(self, s: Severity) -> String {
        let label = format!("[{s}]");
        let code = match s {
            Severity::High => "1;31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.paint(code, &format!("{label:<8}"))
    }
}

/// Neutralise control characters (ANSI escapes, carriage returns, ...) in
/// text that came from the sample, so a hostile file cannot rewrite the
/// analyst's terminal. JSON output needs no such step: serde escapes them.
pub fn clean(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if c.is_control() {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Ten-cell entropy bar (`#` per 0.8 bits).
pub fn entropy_bar(e: f64) -> String {
    let filled = ((e / 8.0) * 10.0).round().clamp(0.0, 10.0) as usize;
    format!("{}{}", "#".repeat(filled), ".".repeat(10 - filled))
}

fn format_name(f: Format) -> &'static str {
    match f {
        Format::Elf => "ELF",
        Format::Pe => "PE",
        Format::MachO => "Mach-O",
        Format::MachOFat => "Mach-O universal",
    }
}

fn kv(out: &mut String, style: Style, key: &str, value: &str) {
    let _ = writeln!(out, "  {} {value}", style.dim(&format!("{key:<10}")));
}

fn render_image(out: &mut String, b: &BinaryInfo, style: Style, indent: &str) {
    if b.format == Format::MachOFat {
        let arches: Vec<&str> = b.slices.iter().map(|s| s.arch.as_str()).collect();
        let _ = writeln!(
            out,
            "{indent}{} with {} slices: {}",
            style.bold(format_name(b.format)),
            b.slices.len(),
            arches.join(", ")
        );
    } else {
        let _ = writeln!(
            out,
            "{indent}{} {}  {}-bit {}-endian {}",
            style.bold(format_name(b.format)),
            b.arch,
            b.bits,
            b.endian,
            format!("{:?}", b.kind).to_lowercase()
        );
    }
    if let Some(e) = b.entry_point {
        let sec = b.section_at_va(e).map_or("no section", |s| s.name.as_str());
        let _ = writeln!(out, "{indent}  entry {e:#x} ({sec})");
    }
    if !b.sections.is_empty() {
        let _ = writeln!(out, "\n{indent}{}", style.bold(&format!("Sections ({})", b.sections.len())));
        let width = b.sections.iter().map(|s| clean(&s.name).len()).max().unwrap_or(4).clamp(4, 28);
        let _ = writeln!(
            out,
            "{indent}  {}",
            style.dim(&format!(
                "{:<width$} {:>10} {:>8} {:>18} {:<4} {:>7}",
                "name", "offset", "size", "vaddr", "perm", "entropy"
            ))
        );
        for s in &b.sections {
            let _ = writeln!(
                out,
                "{indent}  {:<width$} {:>#10x} {:>8} {:>#18x} {:<4} {:>7.3} {} {}",
                clean(&s.name),
                s.file_offset,
                s.file_size,
                s.virtual_address,
                s.perms(),
                s.entropy,
                entropy_bar(s.entropy),
                style.dim(if s.file_size == 0 { "(no file data)" } else { entropy::classify(s.entropy) })
            );
        }
    }
    if !b.imports.is_empty() {
        let mut libs: Vec<(String, Vec<String>)> = Vec::new();
        for i in &b.imports {
            let lib = i.library.as_deref().map_or_else(|| "(unattributed)".into(), |l| clean(l).into_owned());
            let name = match i.ordinal {
                Some(o) => format!("{} (#{o})", clean(&i.name)),
                None => clean(&i.name).into_owned(),
            };
            match libs.iter_mut().find(|(l, _)| *l == lib) {
                Some((_, v)) => v.push(name),
                None => libs.push((lib, vec![name])),
            }
        }
        let _ = writeln!(
            out,
            "\n{indent}{}",
            style.bold(&format!("Imports ({} from {} libraries)", b.imports.len(), b.libraries.len()))
        );
        for (lib, names) in libs {
            let _ = writeln!(out, "{indent}  {lib}: {}", names.join(", "));
        }
    } else if !b.libraries.is_empty() && b.slices.is_empty() {
        let _ = writeln!(out, "\n{indent}{} {}", style.bold("Libraries:"), clean(&b.libraries.join(", ")));
    }
    if !b.exports.is_empty() {
        let shown: Vec<&str> = b.exports.iter().take(20).map(|e| e.name.as_str()).collect();
        let more = b.exports.len().saturating_sub(shown.len());
        let _ = writeln!(
            out,
            "\n{indent}{} {}{}",
            style.bold(&format!("Exports ({}):", b.exports.len())),
            clean(&shown.join(", ")),
            if more > 0 { format!(" (+{more} more)") } else { String::new() }
        );
    }
    if !b.mitigations.is_empty() {
        let items: Vec<String> =
            b.mitigations.iter().map(|m| format!("{} {}", m.name, if m.enabled { "yes" } else { "no" })).collect();
        let _ = writeln!(out, "\n{indent}{} {}", style.bold("Mitigations:"), items.join(" | "));
    }
    if let Some(o) = &b.overlay {
        let _ = writeln!(
            out,
            "{indent}{} {} bytes at {:#x}, entropy {:.3}",
            style.bold("Overlay:"),
            o.size,
            o.offset,
            o.entropy
        );
    }
    for slice in &b.slices {
        let _ = writeln!(out);
        render_image(out, slice, style, &format!("{indent}  | "));
    }
}

/// Human-readable triage report.
pub fn render_triage(r: &TriageReport, style: Style) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", style.bold(&format!("== {} ==", clean(&r.file.name))));
    kv(
        &mut out,
        style,
        "size",
        &format!("{} bytes, entropy {:.3} ({})", r.file.size, r.file.entropy, entropy::classify(r.file.entropy)),
    );
    kv(&mut out, style, "md5", &r.file.digests.md5);
    kv(&mut out, style, "sha256", &r.file.digests.sha256);
    if let Some(h) = &r.import_hashes.imphash {
        kv(&mut out, style, "imphash", h);
    }
    if let Some(h) = &r.import_hashes.symhash {
        kv(&mut out, style, "symhash", h);
    }
    kv(&mut out, style, "ssdeep", r.fuzzy.ssdeep.as_deref().unwrap_or("-"));
    kv(&mut out, style, "tlsh", r.fuzzy.tlsh.as_deref().or(r.fuzzy.tlsh_unavailable.as_deref()).unwrap_or("-"));
    let _ = writeln!(out);
    match (&r.binary, &r.unparsed_reason) {
        (Some(b), _) => render_image(&mut out, b, style, ""),
        (None, Some(why)) => {
            let _ = writeln!(out, "{} {why}", style.bold("Format:"));
        }
        (None, None) => {}
    }

    let _ = writeln!(out, "\n{}", style.bold(&format!("Anomalies ({})", r.anomalies.len())));
    for a in &r.anomalies {
        let _ = writeln!(out, "  {} {:<36} {}", style.severity(a.severity), a.id, clean(&a.message));
    }
    let _ = writeln!(out, "\n{}", style.bold(&format!("Capabilities ({})", r.capabilities.len())));
    for c in &r.capabilities {
        let attack = if c.attack.is_empty() { String::new() } else { format!(" [{}]", c.attack.join(", ")) };
        let _ = writeln!(
            out,
            "  {} {} {}{}",
            style.severity(c.severity),
            c.name,
            style.dim(&format!("({})", c.namespace)),
            attack
        );
        let _ = writeln!(out, "           {}", style.dim(&clean(&c.evidence.join("; "))));
    }

    let s = &r.strings;
    let tags: Vec<String> = s.tags.iter().map(|(k, v)| format!("{k} {v}")).collect();
    let _ = writeln!(
        out,
        "\n{} {} ASCII, {} UTF-16LE{}",
        style.bold("Strings:"),
        s.ascii,
        s.utf16le,
        if tags.is_empty() { String::new() } else { format!("; tagged: {}", tags.join(", ")) }
    );
    for l in &s.listed {
        let enc = match l.string.encoding {
            crate::strings::Encoding::Ascii => "a",
            crate::strings::Encoding::Utf16Le => "u",
        };
        let tag = if l.string.tags.is_empty() {
            String::new()
        } else {
            let t: Vec<&str> = l.string.tags.iter().map(|t| t.as_str()).collect();
            format!(" [{}]", t.join(","))
        };
        let _ = writeln!(
            out,
            "  {:>#8x} {enc} {:<16} {:?}{}",
            l.string.offset,
            l.section.as_deref().unwrap_or("-"),
            l.string.value,
            style.dim(&tag)
        );
    }
    if s.truncated {
        let _ = writeln!(out, "  {}", style.dim("(listing truncated; use --max-strings or the strings command)"));
    }
    out
}

/// Side-by-side comparison of two samples.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Comparison {
    /// First input (path or digest).
    pub a: String,
    /// Second input.
    pub b: String,
    /// ssdeep similarity 0..=100, when both digests exist.
    pub ssdeep_score: Option<u32>,
    /// TLSH distance (0 = identical), when both digests exist.
    pub tlsh_distance: Option<u32>,
    /// Both files have the same imphash (PE only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_imphash: Option<bool>,
}

/// Plain-text rendering of a [`Comparison`].
pub fn render_comparison(c: &Comparison, style: Style) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}  {}", style.dim("a"), c.a);
    let _ = writeln!(out, "{}  {}", style.dim("b"), c.b);
    let fmt = |v: Option<u32>| v.map_or_else(|| "n/a".to_string(), |x| x.to_string());
    let _ = writeln!(out, "ssdeep score   {} / 100 (higher = more similar)", fmt(c.ssdeep_score));
    let _ = writeln!(out, "tlsh distance  {} (lower = more similar)", fmt(c.tlsh_distance));
    if let Some(same) = c.same_imphash {
        let _ = writeln!(out, "imphash        {}", if same { "identical" } else { "different" });
    }
    out
}

/// Plain-text rendering of a clustering.
pub fn render_clustering(c: &Clustering, style: Style) -> String {
    let mut out = String::new();
    let rule = match c.method {
        Method::Tlsh => format!("TLSH distance <= {}", c.threshold),
        Method::Ssdeep => format!("ssdeep score >= {}", c.threshold),
    };
    let _ = writeln!(
        out,
        "{} {} samples, {} clusters, {} singletons, {} without a digest ({rule}; single linkage)",
        style.bold("Clustering:"),
        c.names.len(),
        c.clusters.len(),
        c.singletons.len(),
        c.unhashable.len()
    );
    let _ = writeln!(
        out,
        "{}",
        style.dim(&format!("compared {} of {} pairs after exact pruning", c.stats.pairs_compared, c.stats.pairs_total))
    );
    for (i, cl) in c.clusters.iter().enumerate() {
        let _ = writeln!(
            out,
            "\n{} ({} members, medoid {})",
            style.bold(&format!("cluster {}", i + 1)),
            cl.members.len(),
            clean(&c.names[cl.medoid])
        );
        for &m in &cl.members {
            let _ = writeln!(out, "  {}{}", if m == cl.medoid { "* " } else { "  " }, clean(&c.names[m]));
        }
    }
    if !c.singletons.is_empty() {
        let _ = writeln!(out, "\n{}", style.bold("singletons"));
        for &s in &c.singletons {
            let _ = writeln!(out, "    {}", clean(&c.names[s]));
        }
    }
    if !c.unhashable.is_empty() {
        let _ = writeln!(out, "\n{}", style.bold("no digest"));
        for &s in &c.unhashable {
            let _ = writeln!(out, "    {}", clean(&c.names[s]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bars_and_styles() {
        assert_eq!(entropy_bar(0.0), "..........");
        assert_eq!(entropy_bar(8.0), "##########");
        assert_eq!(entropy_bar(4.0), "#####.....");
        let plain = Style { color: false };
        let color = Style { color: true };
        assert_eq!(plain.bold("x"), "x");
        assert_eq!(color.bold("x"), "\x1b[1mx\x1b[0m");
        for s in [Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
            assert!(color.severity(s).contains(&s.to_string()));
        }
    }

    #[test]
    fn control_characters_are_neutralised() {
        assert_eq!(clean(".text"), ".text");
        assert_eq!(clean("\u{1b}[31mred\r"), "\\u{1b}[31mred\\u{d}");
        assert!(matches!(clean("plain"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn comparison_rendering() {
        let c = Comparison {
            a: "x".into(),
            b: "y".into(),
            ssdeep_score: Some(88),
            tlsh_distance: None,
            same_imphash: Some(true),
        };
        let text = render_comparison(&c, Style::default());
        assert!(text.contains("88 / 100"));
        assert!(text.contains("n/a"));
        assert!(text.contains("identical"));
    }
}
