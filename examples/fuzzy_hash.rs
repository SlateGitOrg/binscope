//! Print `ssdeep<TAB>tlsh<TAB>path` for each file argument (debug helper used
//! while validating against the reference tools).

fn main() -> std::io::Result<()> {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path)?;
        let d = binscope::fuzzy::FuzzyDigests::of(&data);
        println!("{}\t{}\t{path}", d.ssdeep.unwrap_or_default(), d.tlsh.unwrap_or_else(|| "TNULL".into()));
    }
    Ok(())
}
