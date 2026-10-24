//! Similarity clustering of a sample set by fuzzy hash.
//!
//! Samples become graph nodes; an edge joins two samples whose TLSH distance
//! is at most `threshold` (or whose ssdeep score is at least `threshold`).
//! Clusters are the connected components (single-linkage), found with a
//! union-find. Each cluster reports a medoid: the member with the smallest
//! total distance to the others.
//!
//! **Candidate pruning (exact).** Comparing all n(n-1)/2 pairs is avoided
//! without changing the result:
//! * ssdeep scores a pair 0 unless two digest parts at the same effective
//!   block size share a 7-character substring (or the digests are equal), so
//!   an inverted index over `(block size, 7-gram)` yields every pair that can
//!   score above 0.
//! * TLSH's length term alone adds `12 * |dL|` once `|dL| > 1`, a lower bound
//!   on the full distance, so only samples whose length buckets differ by at
//!   most `max(1, threshold / 12)` (cyclically) can be within `threshold`.
//!
//! Both prunings are property-tested against brute force.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fuzzy::ssdeep::{self, SsdeepHash};
use crate::fuzzy::tlsh::Tlsh;

/// Default TLSH distance cut-off (see DECISIONS.md: fixed a priori, not tuned).
pub const DEFAULT_TLSH_THRESHOLD: u32 = 70;
/// Default ssdeep score cut-off (see DECISIONS.md: fixed a priori, not tuned).
pub const DEFAULT_SSDEEP_THRESHOLD: u32 = 40;

/// Which similarity measure links samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// TLSH distance <= threshold.
    Tlsh,
    /// ssdeep score >= threshold.
    Ssdeep,
}

impl Method {
    /// Default threshold for this method.
    pub fn default_threshold(self) -> u32 {
        match self {
            Method::Tlsh => DEFAULT_TLSH_THRESHOLD,
            Method::Ssdeep => DEFAULT_SSDEEP_THRESHOLD,
        }
    }
}

/// One sample to cluster.
#[derive(Clone, Debug)]
pub struct Item {
    /// Display name (usually the path).
    pub name: String,
    /// ssdeep digest, if available.
    pub ssdeep: Option<SsdeepHash>,
    /// TLSH digest, if available (inputs under 50 bytes have none).
    pub tlsh: Option<Tlsh>,
}

impl Item {
    /// Hash `data` with both algorithms.
    pub fn from_bytes(name: impl Into<String>, data: &[u8]) -> Self {
        Self { name: name.into(), ssdeep: ssdeep::hash(data).ok(), tlsh: crate::fuzzy::tlsh::hash(data).ok() }
    }

    fn has(&self, method: Method) -> bool {
        match method {
            Method::Tlsh => self.tlsh.is_some(),
            Method::Ssdeep => self.ssdeep.is_some(),
        }
    }
}

/// An edge between two linked samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    /// Index of the first sample.
    pub a: usize,
    /// Index of the second sample.
    pub b: usize,
    /// TLSH distance or ssdeep score.
    pub value: u32,
}

/// One cluster of two or more samples.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cluster {
    /// Member indices, ascending.
    pub members: Vec<usize>,
    /// Member with the smallest summed distance to the others.
    pub medoid: usize,
}

/// Work counters (for the complexity claims in the docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterStats {
    /// n(n-1)/2 over hashable samples.
    pub pairs_total: u64,
    /// Pairs actually scored after pruning.
    pub pairs_compared: u64,
}

/// Clustering result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Clustering {
    /// Linking method.
    pub method: Method,
    /// Threshold used.
    pub threshold: u32,
    /// Sample names, indexable by the indices below.
    pub names: Vec<String>,
    /// Clusters with at least two members, largest first.
    pub clusters: Vec<Cluster>,
    /// Hashable samples that joined no cluster.
    pub singletons: Vec<usize>,
    /// Samples without a digest for the chosen method.
    pub unhashable: Vec<usize>,
    /// All linking edges.
    pub edges: Vec<Edge>,
    /// Work counters.
    pub stats: ClusterStats,
}

impl Clustering {
    /// Cluster label per sample (singletons and unhashable samples get their
    /// own unique labels), for scoring against ground truth.
    pub fn assignment(&self) -> Vec<usize> {
        let mut labels: Vec<usize> = (0..self.names.len()).map(|i| self.clusters.len() + i).collect();
        for (c, cl) in self.clusters.iter().enumerate() {
            for &m in &cl.members {
                labels[m] = c;
            }
        }
        labels
    }
}

/// Disjoint-set forest with path halving and union by size.
#[derive(Clone, Debug)]
pub struct UnionFind {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl UnionFind {
    /// `n` singleton sets.
    pub fn new(n: usize) -> Self {
        Self { parent: (0..n).collect(), size: vec![1; n] }
    }

    /// Representative of `x`'s set.
    pub fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    /// Merge the sets of `a` and `b`; returns true if they were distinct.
    pub fn union(&mut self, a: usize, b: usize) -> bool {
        let (mut ra, mut rb) = (self.find(a), self.find(b));
        if ra == rb {
            return false;
        }
        if self.size[ra] < self.size[rb] {
            std::mem::swap(&mut ra, &mut rb);
        }
        self.parent[rb] = ra;
        self.size[ra] += self.size[rb];
        true
    }
}

fn pair(a: usize, b: usize) -> (usize, usize) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

/// ssdeep candidate pairs: every pair that can score above zero.
pub fn ssdeep_candidates(items: &[Item]) -> HashSet<(usize, usize)> {
    let mut grams: HashMap<(u64, [u8; 7]), Vec<usize>> = HashMap::new();
    let mut exact: HashMap<(u64, String, String), Vec<usize>> = HashMap::new();
    for (i, it) in items.iter().enumerate() {
        let Some(h) = &it.ssdeep else { continue };
        let p1 = ssdeep::eliminate_sequences(&h.part1);
        let p2 = ssdeep::eliminate_sequences(&h.part2);
        for (bs, part) in [(h.block_size, &p1), (h.block_size.saturating_mul(2), &p2)] {
            let mut seen = HashSet::new();
            for w in part.as_bytes().windows(7) {
                let mut key = [0u8; 7];
                key.copy_from_slice(w);
                if seen.insert(key) {
                    grams.entry((bs, key)).or_default().push(i);
                }
            }
        }
        exact.entry((h.block_size, p1, p2)).or_default().push(i);
    }
    let mut out = HashSet::new();
    for list in grams.values().chain(exact.values()) {
        for (x, &a) in list.iter().enumerate() {
            for &b in &list[x + 1..] {
                if a != b {
                    out.insert(pair(a, b));
                }
            }
        }
    }
    out
}

/// TLSH candidate pairs: every pair whose length-term lower bound does not
/// already exceed `max_distance`. Bucket pairs are visited once each, so the
/// result has no duplicates and needs no hash set.
pub fn tlsh_candidates(items: &[Item], max_distance: u32) -> Vec<(usize, usize)> {
    let mut by_l: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (i, it) in items.iter().enumerate() {
        if let Some(t) = &it.tlsh {
            by_l.entry(t.lvalue).or_default().push(i);
        }
    }
    let buckets: Vec<(u8, &Vec<usize>)> = by_l.iter().map(|(k, v)| (*k, v)).collect();
    let mut out = Vec::new();
    for (x, &(la, ia)) in buckets.iter().enumerate() {
        // Same bucket: each unordered pair once.
        for (k, &a) in ia.iter().enumerate() {
            for &b in &ia[k + 1..] {
                out.push(pair(a, b));
            }
        }
        for &(lb, ib) in &buckets[x + 1..] {
            // Lower bound of the full distance: skip hopeless bucket pairs.
            if Tlsh::length_distance(la, lb) > max_distance {
                continue;
            }
            for &a in ia {
                for &b in ib {
                    out.push(pair(a, b));
                }
            }
        }
    }
    out
}

fn score(items: &[Item], method: Method, a: usize, b: usize) -> u32 {
    match method {
        Method::Tlsh => {
            items[a].tlsh.as_ref().zip(items[b].tlsh.as_ref()).map_or(u32::MAX, |(x, y)| x.distance(y, true))
        }
        Method::Ssdeep => {
            items[a].ssdeep.as_ref().zip(items[b].ssdeep.as_ref()).map_or(0, |(x, y)| ssdeep::compare(x, y))
        }
    }
}

fn linked(method: Method, value: u32, threshold: u32) -> bool {
    match method {
        Method::Tlsh => value <= threshold,
        Method::Ssdeep => value >= threshold,
    }
}

/// As a "distance" for medoid selection (lower is closer).
fn as_distance(method: Method, value: u32) -> u64 {
    match method {
        Method::Tlsh => u64::from(value),
        Method::Ssdeep => u64::from(100u32.saturating_sub(value)),
    }
}

/// Cluster `items` with `method` at `threshold`, using exact candidate
/// pruning. `brute_force` disables pruning (for testing/benchmarks).
pub fn cluster_with(items: &[Item], method: Method, threshold: u32, brute_force: bool) -> Result<Clustering> {
    if method == Method::Ssdeep && threshold > 100 {
        return Err(Error::Config(format!("ssdeep threshold {threshold} is above 100")));
    }
    let hashable: Vec<usize> = (0..items.len()).filter(|&i| items[i].has(method)).collect();
    let n = hashable.len() as u64;
    let candidates: Vec<(usize, usize)> = if brute_force {
        let mut v = Vec::new();
        for (x, &a) in hashable.iter().enumerate() {
            for &b in &hashable[x + 1..] {
                v.push((a, b));
            }
        }
        v
    } else {
        match method {
            Method::Tlsh => tlsh_candidates(items, threshold),
            Method::Ssdeep if threshold == 0 => {
                return cluster_with(items, method, threshold, true);
            }
            Method::Ssdeep => ssdeep_candidates(items).into_iter().collect(),
        }
    };

    let mut uf = UnionFind::new(items.len());
    let mut edges = Vec::new();
    for &(a, b) in &candidates {
        let v = score(items, method, a, b);
        if linked(method, v, threshold) {
            uf.union(a, b);
            edges.push(Edge { a, b, value: v });
        }
    }
    // Candidate order is unspecified; report edges deterministically.
    edges.sort_unstable_by_key(|e| (e.a, e.b));

    // Medoid selection re-uses the scores of linking edges; only intra-cluster
    // pairs that were not linked directly are scored again.
    let edge_value: HashMap<(usize, usize), u32> = edges.iter().map(|e| ((e.a, e.b), e.value)).collect();
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &i in &hashable {
        let root = uf.find(i);
        groups.entry(root).or_default().push(i);
    }
    let mut clusters = Vec::new();
    let mut singletons = Vec::new();
    for members in groups.into_values() {
        if members.len() == 1 {
            singletons.push(members[0]);
            continue;
        }
        let medoid = *members
            .iter()
            .min_by_key(|&&m| {
                members
                    .iter()
                    .filter(|&&o| o != m)
                    .map(|&o| {
                        let key = pair(m, o);
                        let v = edge_value.get(&key).copied().unwrap_or_else(|| score(items, method, key.0, key.1));
                        as_distance(method, v)
                    })
                    .sum::<u64>()
            })
            .expect("cluster has members");
        clusters.push(Cluster { members, medoid });
    }
    clusters.sort_by(|a, b| b.members.len().cmp(&a.members.len()).then(a.members[0].cmp(&b.members[0])));

    Ok(Clustering {
        method,
        threshold,
        names: items.iter().map(|i| i.name.clone()).collect(),
        clusters,
        singletons,
        unhashable: (0..items.len()).filter(|&i| !items[i].has(method)).collect(),
        edges,
        stats: ClusterStats { pairs_total: n * n.saturating_sub(1) / 2, pairs_compared: candidates.len() as u64 },
    })
}

/// Cluster with pruning enabled.
pub fn cluster(items: &[Item], method: Method, threshold: u32) -> Result<Clustering> {
    cluster_with(items, method, threshold, false)
}

/// Pairwise confusion counts of a predicted assignment against true labels:
/// `(true positive, false positive, false negative, true negative)` pairs.
pub fn pair_confusion(predicted: &[usize], truth: &[usize]) -> (u64, u64, u64, u64) {
    assert_eq!(predicted.len(), truth.len());
    let (mut tp, mut fp, mut fneg, mut tn) = (0, 0, 0, 0);
    for i in 0..predicted.len() {
        for j in i + 1..predicted.len() {
            match (predicted[i] == predicted[j], truth[i] == truth[j]) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => fneg += 1,
                (false, false) => tn += 1,
            }
        }
    }
    (tp, fp, fneg, tn)
}

/// Adjusted Rand index (Hubert & Arabie 1985) of two labelings.
pub fn adjusted_rand_index(predicted: &[usize], truth: &[usize]) -> f64 {
    let n = predicted.len() as f64;
    if predicted.len() < 2 {
        return 1.0;
    }
    let comb2 = |x: f64| x * (x - 1.0) / 2.0;
    let mut table: HashMap<(usize, usize), f64> = HashMap::new();
    let mut rows: HashMap<usize, f64> = HashMap::new();
    let mut cols: HashMap<usize, f64> = HashMap::new();
    for (&p, &t) in predicted.iter().zip(truth) {
        *table.entry((p, t)).or_default() += 1.0;
        *rows.entry(p).or_default() += 1.0;
        *cols.entry(t).or_default() += 1.0;
    }
    let index: f64 = table.values().map(|&v| comb2(v)).sum();
    let a: f64 = rows.values().map(|&v| comb2(v)).sum();
    let b: f64 = cols.values().map(|&v| comb2(v)).sum();
    let expected = a * b / comb2(n);
    let max = f64::midpoint(a, b);
    if (max - expected).abs() < f64::EPSILON {
        return 1.0;
    }
    (index - expected) / (max - expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{generate, patch, Kind};

    fn corpus() -> Vec<Item> {
        let mut items = Vec::new();
        for fam in 0..4u64 {
            // Distinct content per family; Mixed/Text share structure across
            // seeds, so only one family uses each of them.
            let kind = [Kind::Random, Kind::Random, Kind::Text, Kind::Mixed][fam as usize];
            let base = generate(kind, 30_000 + fam as usize * 7_000, fam + 1);
            items.push(Item::from_bytes(format!("f{fam}-base"), &base));
            for v in 0..3u64 {
                let m = patch(&base, 2_000 + v as usize * 9_000, 300, fam * 10 + v);
                items.push(Item::from_bytes(format!("f{fam}-v{v}"), &m));
            }
        }
        items.push(Item::from_bytes("tiny", b"abc"));
        items
    }

    #[test]
    fn union_find_basics() {
        let mut uf = UnionFind::new(5);
        assert!(uf.union(0, 1));
        assert!(uf.union(3, 4));
        assert!(!uf.union(1, 0));
        assert!(uf.union(1, 4));
        assert_eq!(uf.find(0), uf.find(3));
        assert_ne!(uf.find(2), uf.find(0));
    }

    #[test]
    fn families_are_recovered_by_both_methods() {
        let items = corpus();
        let truth: Vec<usize> = items.iter().map(|i| i.name.as_bytes()[1] as usize).collect();
        for method in [Method::Tlsh, Method::Ssdeep] {
            let c = cluster(&items, method, method.default_threshold()).unwrap();
            assert_eq!(c.clusters.len(), 4, "{method:?}: {:?}", c.clusters);
            let ari = adjusted_rand_index(&c.assignment()[..16], &truth[..16]);
            assert!((ari - 1.0).abs() < 1e-9, "{method:?} ari {ari}");
            assert!(c.stats.pairs_compared <= c.stats.pairs_total);
            for cl in &c.clusters {
                assert!(cl.members.contains(&cl.medoid));
            }
        }
        let t = cluster(&items, Method::Tlsh, 70).unwrap();
        assert_eq!(t.unhashable, vec![16]); // "tiny" has no TLSH
    }

    #[test]
    fn pruning_matches_brute_force() {
        let items = corpus();
        for (method, thresholds) in [(Method::Tlsh, vec![0, 30, 70, 150, 400]), (Method::Ssdeep, vec![0, 1, 40, 90])] {
            for t in thresholds {
                let fast = cluster_with(&items, method, t, false).unwrap();
                let slow = cluster_with(&items, method, t, true).unwrap();
                assert_eq!(fast.clusters, slow.clusters, "{method:?} t={t}");
                assert_eq!(fast.edges, slow.edges, "{method:?} t={t}");
            }
        }
    }

    #[test]
    fn rejects_bad_ssdeep_threshold() {
        assert!(cluster(&corpus(), Method::Ssdeep, 101).is_err());
    }

    #[test]
    fn metrics() {
        assert_eq!(pair_confusion(&[0, 0, 1], &[0, 0, 1]), (1, 0, 0, 2));
        assert_eq!(pair_confusion(&[0, 0, 0], &[0, 0, 1]), (1, 2, 0, 0));
        assert!((adjusted_rand_index(&[0, 0, 1, 1], &[5, 5, 7, 7]) - 1.0).abs() < 1e-12);
        assert!(adjusted_rand_index(&[0, 1, 0, 1], &[0, 0, 1, 1]) < 0.0);
        assert!((adjusted_rand_index(&[0], &[0]) - 1.0).abs() < 1e-12);
        assert!((adjusted_rand_index(&[0, 0], &[1, 1]) - 1.0).abs() < 1e-12);
    }
}
