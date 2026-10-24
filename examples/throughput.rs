//! Throughput benchmark: `cargo run --release --example throughput [-- --quick]`.
//!
//! Measures each analysis primitive on a deterministic synthetic buffer
//! (`binscope::synth`, "mixed" content), full triage over the fixture corpus,
//! and clustering cost with and without exact candidate pruning. Each timing
//! is the best of several runs; numbers depend on the machine and on
//! concurrent load, so treat them as indicative.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use binscope::cluster::{cluster_with, Item, Method};
use binscope::fuzzy::{ssdeep, tlsh};
use binscope::hashes::FileDigests;
use binscope::rules::RuleSet;
use binscope::strings::{extract, StringOptions};
use binscope::synth::{generate, patch, Kind};
use binscope::triage::{analyze_bytes, analyze_path, collect_files, TriageOptions};

fn best_of<T>(runs: usize, mut f: impl FnMut() -> T) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..runs {
        let t = Instant::now();
        std::hint::black_box(f());
        best = best.min(t.elapsed());
    }
    best
}

fn mbps(bytes: usize, d: Duration) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / d.as_secs_f64()
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let size = if quick { 4 << 20 } else { 32 << 20 };
    let runs = if quick { 2 } else { 5 };
    let data = generate(Kind::Mixed, size, 7);
    let rules = RuleSet::builtin().expect("builtin rules");
    let opts = TriageOptions::default();

    println!("# binscope throughput ({} MiB mixed synthetic buffer, best of {runs})\n", size >> 20);
    println!("| operation | time (ms) | MiB/s |");
    println!("|---|---:|---:|");
    let rows: Vec<(&str, Duration)> = vec![
        ("entropy (Shannon)", best_of(runs, || binscope::entropy::shannon(&data))),
        ("strings (ASCII + UTF-16LE)", best_of(runs, || extract(&data, &StringOptions::default()).len())),
        ("md5 + sha1 + sha256", best_of(runs, || FileDigests::of(&data))),
        ("ssdeep digest", best_of(runs, || ssdeep::hash(&data).ok())),
        ("tlsh digest", best_of(runs, || tlsh::hash(&data).ok())),
        ("full triage (non-executable input)", best_of(runs, || analyze_bytes("bench", &data, &opts, &rules))),
    ];
    for (name, d) in rows {
        println!("| {name} | {:.1} | {:.1} |", d.as_secs_f64() * 1e3, mbps(size, d));
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/bin");
    let files = collect_files(&[root]).expect("fixtures present");
    let total: usize = files.iter().map(|f| std::fs::metadata(f).map_or(0, |m| m.len() as usize)).sum();
    let d = best_of(runs, || {
        for f in &files {
            std::hint::black_box(analyze_path(f, &opts, &rules).expect("triage"));
        }
    });
    println!(
        "\nfixture corpus: {} files, {:.2} MiB, full triage in {:.1} ms ({:.0} files/s, {:.1} MiB/s)",
        files.len(),
        total as f64 / 1_048_576.0,
        d.as_secs_f64() * 1e3,
        files.len() as f64 / d.as_secs_f64(),
        mbps(total, d)
    );

    // Clustering scale: families of localised edits over distinct bases.
    let n_items = if quick { 400 } else { 2000 };
    let mut items = Vec::with_capacity(n_items);
    let mut i = 0u64;
    while items.len() < n_items {
        let kind = [Kind::Random, Kind::Mixed][(i % 2) as usize];
        let base = generate(kind, 16_384 + (i as usize % 7) * 4_096, 10_000 + i);
        for v in 0..8u64 {
            if items.len() == n_items {
                break;
            }
            let edited = patch(&base, (v as usize * 1_931) % 12_000, 256, i * 100 + v);
            items.push(Item::from_bytes(format!("{i}-{v}"), &edited));
        }
        i += 1;
    }
    println!("\n| clustering {n_items} samples | pruned: pairs scored | pruned: ms | brute force: pairs | brute force: ms | clusters |");
    println!("|---|---:|---:|---:|---:|---:|");
    for (method, t) in
        [(Method::Tlsh, Method::Tlsh.default_threshold()), (Method::Ssdeep, Method::Ssdeep.default_threshold())]
    {
        let mut fast = None;
        let df = best_of(runs.min(3), || fast = Some(cluster_with(&items, method, t, false).expect("cluster")));
        let mut slow = None;
        let ds = best_of(1, || slow = Some(cluster_with(&items, method, t, true).expect("cluster")));
        let (fast, slow) = (fast.expect("ran"), slow.expect("ran"));
        assert_eq!(fast.clusters, slow.clusters, "pruning must not change the result");
        println!(
            "| {method:?} (threshold {t}) | {} | {:.1} | {} | {:.1} | {} |",
            fast.stats.pairs_compared,
            df.as_secs_f64() * 1e3,
            slow.stats.pairs_compared,
            ds.as_secs_f64() * 1e3,
            fast.clusters.len()
        );
    }
}
