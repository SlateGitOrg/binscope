//! Property-based tests (proptest) for the core algorithms.

use proptest::prelude::*;

use binscope::cluster::{cluster_with, Item, Method};
use binscope::entropy;
use binscope::fuzzy::{ssdeep, tlsh};
use binscope::strings::{extract, Encoding, StringOptions};
use binscope::synth::{generate, patch, Kind};

fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

/// Text-like bytes so string extraction has something to find.
fn arb_texty(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop_oneof![3 => 0x20u8..0x7f, 1 => Just(0u8), 1 => any::<u8>()], 0..max)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn entropy_is_bounded(data in arb_bytes(4096)) {
        let e = entropy::shannon(&data);
        prop_assert!((0.0..=8.0).contains(&e));
    }

    #[test]
    fn extracted_strings_are_faithful(data in arb_texty(2048), min in 1usize..8) {
        let opts = StringOptions { min_len: min, max_len: 10_000, utf16: true };
        for s in extract(&data, &opts) {
            prop_assert!(s.length >= min);
            prop_assert_eq!(s.value.len(), s.length);
            let off = s.offset as usize;
            match s.encoding {
                Encoding::Ascii => prop_assert_eq!(&data[off..off + s.length], s.value.as_bytes()),
                Encoding::Utf16Le => {
                    for (i, c) in s.value.bytes().enumerate() {
                        prop_assert_eq!(data[off + 2 * i], c);
                        prop_assert_eq!(data[off + 2 * i + 1], 0);
                    }
                }
            }
        }
    }

    #[test]
    fn ssdeep_streaming_equals_one_shot(data in arb_bytes(20_000), chunk in 1usize..997) {
        let mut h = ssdeep::SsdeepHasher::with_total_size(data.len() as u64).unwrap();
        for c in data.chunks(chunk) {
            h.update(c);
        }
        prop_assert_eq!(h.digest().unwrap(), ssdeep::hash(&data).unwrap());
    }

    #[test]
    fn ssdeep_digest_round_trips_and_self_compares(data in arb_bytes(20_000)) {
        let h = ssdeep::hash(&data).unwrap();
        let text = h.to_string();
        let parsed: ssdeep::SsdeepHash = text.parse().unwrap();
        prop_assert_eq!(&parsed, &h);
        prop_assert!(h.part1.len() <= 64 && h.part2.len() <= 32);
        prop_assert_eq!(ssdeep::compare(&h, &parsed), 100);
    }

    #[test]
    fn ssdeep_compare_is_symmetric_and_bounded(a in arb_bytes(8_000), b in arb_bytes(8_000)) {
        let (ha, hb) = (ssdeep::hash(&a).unwrap(), ssdeep::hash(&b).unwrap());
        let s = ssdeep::compare(&ha, &hb);
        prop_assert!(s <= 100);
        prop_assert_eq!(s, ssdeep::compare(&hb, &ha));
    }

    #[test]
    fn tlsh_streaming_and_metric_properties(a in arb_bytes(6_000), b in arb_bytes(6_000), chunk in 1usize..513) {
        if let (Ok(ha), Ok(hb)) = (tlsh::hash(&a), tlsh::hash(&b)) {
            let mut builder = tlsh::TlshBuilder::new();
            for c in a.chunks(chunk) {
                builder.update(c);
            }
            prop_assert_eq!(builder.finish().unwrap(), ha);
            prop_assert_eq!(ha.distance(&ha, true), 0);
            prop_assert_eq!(ha.distance(&hb, true), hb.distance(&ha, true));
            prop_assert!(ha.header_distance(&hb, true) <= ha.distance(&hb, true));
            prop_assert!(ha.distance(&hb, false) <= ha.distance(&hb, true));
            prop_assert_eq!(ha.to_hex().parse::<tlsh::Tlsh>().unwrap(), ha);
        }
    }

    #[test]
    fn tlsh_parse_never_panics(s in "[0-9A-Fa-fT]{0,80}") {
        let _ = s.parse::<tlsh::Tlsh>();
    }

    #[test]
    fn ssdeep_parse_never_panics(s in "[0-9]{0,4}:[A-Za-z0-9+/]{0,70}:[A-Za-z0-9+/,]{0,70}") {
        if let Ok(h) = s.parse::<ssdeep::SsdeepHash>() {
            prop_assert_eq!(ssdeep::compare(&h, &h), 100);
        }
    }

    #[test]
    fn format_parser_never_panics_on_garbage(data in arb_bytes(4096), magic in 0usize..5) {
        let mut d = data;
        let prefix: &[u8] = [&b"\x7fELF\x02\x01\x01"[..], b"MZ", &[0xcf, 0xfa, 0xed, 0xfe], &[0xca, 0xfe, 0xba, 0xbe], b""][magic];
        d.splice(0..0, prefix.iter().copied());
        let _ = binscope::format::parse(&d);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn clustering_pruning_is_exact(
        seeds in prop::collection::vec(1u64..1_000, 3..7),
        patches in prop::collection::vec((0usize..20_000, 1usize..2_000), 0..10),
        tlsh_t in 0u32..300,
        ssdeep_t in 1u32..100,
    ) {
        let mut items = Vec::new();
        for (i, &s) in seeds.iter().enumerate() {
            let kind = [Kind::Random, Kind::Text, Kind::Mixed][i % 3];
            let base = generate(kind, 4_000 + (s as usize % 20_000), s);
            items.push(Item::from_bytes(format!("b{i}"), &base));
            for (j, &(off, len)) in patches.iter().enumerate().filter(|(j, _)| j % seeds.len() == i) {
                items.push(Item::from_bytes(format!("b{i}p{j}"), &patch(&base, off, len, j as u64)));
            }
        }
        for (method, t) in [(Method::Tlsh, tlsh_t), (Method::Ssdeep, ssdeep_t)] {
            let fast = cluster_with(&items, method, t, false).unwrap();
            let slow = cluster_with(&items, method, t, true).unwrap();
            prop_assert_eq!(&fast.clusters, &slow.clusters);
            prop_assert_eq!(&fast.edges, &slow.edges);
            prop_assert!(fast.stats.pairs_compared <= slow.stats.pairs_compared);
        }
    }
}
