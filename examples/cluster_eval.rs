//! Clustering evaluation on the fixture corpus:
//! `cargo run --release --example cluster_eval`.
//!
//! Ground truth comes from fixtures/MANIFEST.tsv. Two labelings are scored:
//! * **program+target**: same source family built for the same target
//!   (e.g. all four `net` variants for `pe-x86_64`) - what byte-level fuzzy
//!   hashes can reasonably be expected to recover;
//! * **program only**: same family across all targets - included to show
//!   the limit of byte-level similarity across compilers/architectures.
//!
//! The default thresholds (TLSH <= 70, ssdeep >= 40) were fixed before this
//! evaluation was run (DECISIONS.md); the sweep below is a sensitivity
//! analysis on the same corpus, not a tuning step.

use std::collections::HashMap;
use std::path::PathBuf;

use binscope::cluster::{adjusted_rand_index, cluster, pair_confusion, Item, Method};
use binscope::fuzzy::{ssdeep, tlsh};
use binscope::synth::{generate, mutate, patch, Kind};

type Edit = Box<dyn Fn(&[u8], u64) -> Vec<u8>>;

struct Scores {
    clusters: usize,
    precision: f64,
    recall: f64,
    f1: f64,
    ari: f64,
}

fn score(items: &[Item], truth: &[usize], method: Method, t: u32) -> Scores {
    let c = cluster(items, method, t).expect("valid threshold");
    let pred = c.assignment();
    let (tp, fp, fneg, _) = pair_confusion(&pred, truth);
    let precision = if tp + fp == 0 { 1.0 } else { tp as f64 / (tp + fp) as f64 };
    let recall = if tp + fneg == 0 { 1.0 } else { tp as f64 / (tp + fneg) as f64 };
    let f1 = if precision + recall == 0.0 { 0.0 } else { 2.0 * precision * recall / (precision + recall) };
    Scores { clusters: c.clusters.len(), precision, recall, f1, ari: adjusted_rand_index(&pred, truth) }
}

fn labels(keys: &[String]) -> Vec<usize> {
    let mut ids: HashMap<&str, usize> = HashMap::new();
    keys.iter()
        .map(|k| {
            let n = ids.len();
            *ids.entry(k.as_str()).or_insert(n)
        })
        .collect()
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let manifest = std::fs::read_to_string(root.join("MANIFEST.tsv")).expect("manifest");
    let mut items = Vec::new();
    let mut by_target = Vec::new();
    let mut by_family = Vec::new();
    for line in manifest.lines().skip(1) {
        let c: Vec<&str> = line.split('\t').collect();
        let data = std::fs::read(root.join(c[5])).expect("fixture");
        items.push(Item::from_bytes(c[5], &data));
        by_target.push(format!("{}/{}", c[3], c[2]));
        by_family.push(c[3].to_string());
    }
    let truth_target = labels(&by_target);
    let truth_family = labels(&by_family);
    println!(
        "# clustering evaluation: {} fixtures, {} program+target groups, {} program families\n",
        items.len(),
        truth_target.iter().max().map_or(0, |m| m + 1),
        truth_family.iter().max().map_or(0, |m| m + 1)
    );

    println!("## default thresholds\n");
    println!("| method | truth | clusters | pair precision | pair recall | pair F1 | ARI |");
    println!("|---|---|---:|---:|---:|---:|---:|");
    for method in [Method::Tlsh, Method::Ssdeep] {
        for (name, truth) in [("program+target", &truth_target), ("program only", &truth_family)] {
            let s = score(&items, truth, method, method.default_threshold());
            println!(
                "| {method:?} {} | {name} | {} | {:.3} | {:.3} | {:.3} | {:.3} |",
                method.default_threshold(),
                s.clusters,
                s.precision,
                s.recall,
                s.f1,
                s.ari
            );
        }
    }

    println!("\n## sensitivity (truth = program+target)\n");
    println!("| method | threshold | clusters | precision | recall | F1 | ARI |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for (method, sweep) in [
        (Method::Tlsh, vec![10u32, 20, 30, 50, 70, 100, 150, 200]),
        (Method::Ssdeep, vec![1u32, 10, 20, 30, 40, 60, 80]),
    ] {
        for t in sweep {
            let s = score(&items, &truth_target, method, t);
            println!(
                "| {method:?} | {t} | {} | {:.3} | {:.3} | {:.3} | {:.3} |",
                s.clusters, s.precision, s.recall, s.f1, s.ari
            );
        }
    }
    edit_robustness();
}

/// How often each hash links a file to an edited copy of itself (and how
/// often it links unrelated files), on synthetic 64 KiB inputs.
fn edit_robustness() {
    const BASES: u64 = 60;
    let size = 64 * 1024;
    let bases: Vec<Vec<u8>> = (0..BASES)
        .map(|i| generate([Kind::Random, Kind::Mixed, Kind::Text][(i % 3) as usize], size, 50_000 + i))
        .collect();
    let digests = |d: &[u8]| (ssdeep::hash(d).expect("ssdeep"), tlsh::hash(d).expect("tlsh"));
    let base_digests: Vec<_> = bases.iter().map(|b| digests(b)).collect();
    let (t_thr, s_thr) = (Method::Tlsh.default_threshold(), Method::Ssdeep.default_threshold());

    println!("\n## edit robustness (synthetic, {BASES} x 64 KiB bases: random, mixed, text)\n");
    println!("Share of (original, edited copy) pairs each hash links at its default threshold.\n");
    println!("| edit | bytes rewritten | TLSH <= {t_thr} | ssdeep >= {s_thr} | median TLSH | median ssdeep |");
    println!("|---|---:|---:|---:|---:|---:|");
    // Dispersed edits: `mutate` overwrites size*pm/1000 random positions and
    // inserts min(edits/50, 16) runs of 8 bytes.
    let dispersed = |pm: usize| {
        let edits = size * pm / 1000;
        edits + 8 * (edits / 50).min(16)
    };
    let cases: Vec<(&str, usize, Edit)> = vec![
        (
            "contiguous 1%",
            size / 100,
            Box::new(|b: &[u8], s| patch(b, (s as usize * 977) % (b.len() / 2), b.len() / 100, s)),
        ),
        (
            "contiguous 5%",
            size / 20,
            Box::new(|b: &[u8], s| patch(b, (s as usize * 977) % (b.len() / 2), b.len() / 20, s)),
        ),
        (
            "contiguous 20%",
            size / 5,
            Box::new(|b: &[u8], s| patch(b, (s as usize * 977) % (b.len() / 2), b.len() / 5, s)),
        ),
        ("dispersed 0.1%", dispersed(1), Box::new(|b: &[u8], s| mutate(b, 1, s))),
        ("dispersed 1%", dispersed(10), Box::new(|b: &[u8], s| mutate(b, 10, s))),
        ("dispersed 5%", dispersed(50), Box::new(|b: &[u8], s| mutate(b, 50, s))),
    ];
    for (name, changed, edit) in &cases {
        let mut tl = Vec::new();
        let mut ss = Vec::new();
        for (i, b) in bases.iter().enumerate() {
            let e = edit(b, i as u64 + 1);
            let (s, t) = digests(&e);
            tl.push(base_digests[i].1.distance(&t, true));
            ss.push(ssdeep::compare(&base_digests[i].0, &s));
        }
        let share = |hits: usize| 100.0 * hits as f64 / tl.len() as f64;
        let median = |v: &mut Vec<u32>| {
            v.sort_unstable();
            v[v.len() / 2]
        };
        let (t_hits, s_hits) = (tl.iter().filter(|&&d| d <= t_thr).count(), ss.iter().filter(|&&s| s >= s_thr).count());
        println!(
            "| {name} | {changed} | {:.0}% | {:.0}% | {} | {} |",
            share(t_hits),
            share(s_hits),
            median(&mut tl),
            median(&mut ss)
        );
    }
    // Unrelated pairs (different bases), split by content kind: same-kind
    // text/mixed bases share a vocabulary and layout, so they are "similar"
    // in a way TLSH is designed to notice.
    println!("\nLinks between *different* bases (false links at the default thresholds):\n");
    println!("| base kinds | pairs | TLSH <= {t_thr} | ssdeep >= {s_thr} |");
    println!("|---|---:|---:|---:|");
    let kind_name = |i: usize| ["random", "mixed", "text"][i % 3];
    let mut groups: Vec<(String, usize, usize, usize)> = Vec::new();
    for i in 0..bases.len() {
        for j in i + 1..bases.len() {
            let key = if i % 3 == j % 3 { format!("{0} vs {0}", kind_name(i)) } else { "different kinds".to_string() };
            let t = usize::from(base_digests[i].1.distance(&base_digests[j].1, true) <= t_thr);
            let s = usize::from(ssdeep::compare(&base_digests[i].0, &base_digests[j].0) >= s_thr);
            match groups.iter_mut().find(|g| g.0 == key) {
                Some(g) => {
                    g.1 += 1;
                    g.2 += t;
                    g.3 += s;
                }
                None => groups.push((key, 1, t, s)),
            }
        }
    }
    groups.sort();
    for (k, n, t, s) in groups {
        println!("| {k} | {n} | {t} | {s} |");
    }
}
