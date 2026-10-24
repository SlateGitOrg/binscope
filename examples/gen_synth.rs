//! Write the synthetic reference-vector inputs to a directory.
//!
//! `cargo run --example gen_synth -- OUT_DIR` writes one file per entry of
//! `binscope::synth`-based corpus below, named `<kind>-<size>-<seed>[-m<permille>]`.
//! `scripts/reference/gen_reference.py` then hashes them with the real ssdeep
//! and TLSH tools; the tests regenerate the same bytes from the file names.

use std::path::PathBuf;

use binscope::synth::{generate, mutate, Kind};

/// Sizes chosen to straddle ssdeep block-size boundaries (3*2^k*64) and the
/// TLSH 50-byte minimum.
const SIZES: [usize; 16] =
    [0, 1, 7, 49, 50, 64, 191, 192, 193, 1000, 4096, 12_289, 65_536, 200_000, 1_048_576, 3_500_000];

fn main() -> std::io::Result<()> {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: gen_synth OUT_DIR"));
    std::fs::create_dir_all(&out)?;
    let mut n = 0;
    for kind in [Kind::Random, Kind::Text, Kind::Mixed] {
        for (i, &size) in SIZES.iter().enumerate() {
            let seed = 1000 + i as u64;
            let base = generate(kind, size, seed);
            std::fs::write(out.join(format!("{}-{size}-{seed}", kind.as_str())), &base)?;
            n += 1;
            if size >= 1000 {
                for pm in [1u32, 10, 50, 200] {
                    let m = mutate(&base, pm, seed);
                    std::fs::write(out.join(format!("{}-{size}-{seed}-m{pm}", kind.as_str())), m)?;
                    n += 1;
                }
            }
        }
    }
    println!("wrote {n} files to {}", out.display());
    Ok(())
}
