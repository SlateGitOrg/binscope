//! `binscope` command-line interface.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use binscope::cluster::{self, Item, Method};
use binscope::fuzzy::{ssdeep, tlsh};
use binscope::report::{self, Comparison, Style};
use binscope::rules::{RuleSet, Severity};
use binscope::strings::{self, Encoding, StringOptions};
use binscope::triage::{self, TriageOptions, TriageReport};
use binscope::{Error, Result};

/// Static triage for ELF, Mach-O and PE binaries.
#[derive(Debug, Parser)]
#[command(name = "binscope", version, about, long_about = None)]
struct Cli {
    /// Increase log verbosity (-v info, -vv debug).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Colour output.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true)]
    color: ColorChoice,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Full triage report: format, sections, imports, hashes, strings, anomalies, capabilities.
    Triage(TriageArgs),
    /// Print digests (MD5, SHA-256, imphash/symhash, ssdeep, TLSH).
    Hash(HashArgs),
    /// Compare two files or two digests with ssdeep and TLSH.
    Compare(CompareArgs),
    /// Cluster samples by fuzzy-hash similarity.
    Cluster(ClusterArgs),
    /// Extract printable strings.
    Strings(StringsArgs),
    /// List or validate capability rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
}

#[derive(Debug, Args)]
struct RuleArgs {
    /// Extra rule file or directory (repeatable).
    #[arg(long = "rules", value_name = "PATH")]
    rules: Vec<PathBuf>,
    /// Do not load the built-in rule pack.
    #[arg(long)]
    no_builtin_rules: bool,
}

impl RuleArgs {
    fn load(&self) -> Result<RuleSet> {
        let mut set = if self.no_builtin_rules { RuleSet::empty() } else { RuleSet::builtin()? };
        for p in &self.rules {
            set.extend(RuleSet::load_path(p)?)?;
        }
        Ok(set)
    }
}

#[derive(Debug, Args)]
struct TriageArgs {
    /// Files or directories (recursed).
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// JSON output (an object for one file, an array for several).
    #[arg(long, conflicts_with = "jsonl")]
    json: bool,
    /// One JSON object per line.
    #[arg(long)]
    jsonl: bool,
    #[command(flatten)]
    rules: RuleArgs,
    /// Minimum string length.
    #[arg(long, default_value_t = 4)]
    min_len: usize,
    /// Skip UTF-16LE string extraction.
    #[arg(long)]
    no_utf16: bool,
    /// Strings listed per report.
    #[arg(long, default_value_t = 60)]
    max_strings: usize,
    /// Exit with status 3 when any finding reaches this severity.
    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
        }
    }
}

#[derive(Debug, Args)]
struct HashArgs {
    /// Files or directories (recursed).
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CompareArgs {
    /// File path, ssdeep digest (`bs:p1:p2`) or TLSH digest (`T1...`).
    a: String,
    /// File path, ssdeep digest or TLSH digest.
    b: String,
    /// JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MethodArg {
    Tlsh,
    Ssdeep,
}

#[derive(Debug, Args)]
struct ClusterArgs {
    /// Files or directories (recursed).
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Similarity measure.
    #[arg(long, value_enum, default_value_t = MethodArg::Tlsh)]
    method: MethodArg,
    /// TLSH: maximum distance (default 70). ssdeep: minimum score (default 40).
    #[arg(long)]
    threshold: Option<u32>,
    /// JSON output (includes every linking edge).
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EncodingArg {
    All,
    Ascii,
    Utf16,
}

#[derive(Debug, Args)]
struct StringsArgs {
    /// File to scan.
    path: PathBuf,
    /// Minimum string length.
    #[arg(long, default_value_t = 4)]
    min_len: usize,
    /// Which encodings to extract.
    #[arg(long, value_enum, default_value_t = EncodingArg::All)]
    encoding: EncodingArg,
    /// Only strings with an indicator tag (URL, IP, path, ...).
    #[arg(long)]
    tagged_only: bool,
    /// JSON output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// List the loaded rules.
    List(RuleArgs),
    /// Validate rule files or directories without the built-in pack.
    Check {
        /// Rule files or directories.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

fn style(choice: ColorChoice) -> Style {
    let color = match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };
    Style { color }
}

fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("report types serialise to JSON")
}

fn run_triage(args: &TriageArgs, style: Style, out: &mut impl Write) -> Result<ExitCode> {
    let rules = args.rules.load()?;
    let opts = TriageOptions {
        strings: StringOptions {
            min_len: args.min_len,
            utf16: !args.no_utf16,
            ..StringOptions::default()
        },
        max_listed_strings: args.max_strings,
    };
    let files = triage::collect_files(&args.paths)?;
    let mut reports: Vec<TriageReport> = Vec::with_capacity(files.len());
    for f in &files {
        let r = triage::analyze_path(f, &opts, &rules)?;
        if args.jsonl {
            writeln!(out, "{}", serde_json::to_string(&r).expect("serialisable")).map_err(io_err)?;
        } else if !args.json {
            writeln!(out, "{}", report::render_triage(&r, style)).map_err(io_err)?;
        }
        reports.push(r);
    }
    if args.json {
        let text = if reports.len() == 1 { to_json(&reports[0]) } else { to_json(&reports) };
        writeln!(out, "{text}").map_err(io_err)?;
    }
    if let Some(level) = args.fail_on {
        let level = Severity::from(level);
        if reports.iter().filter_map(TriageReport::max_severity).any(|s| s >= level) {
            return Ok(ExitCode::from(3));
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(serde::Serialize)]
struct HashLine {
    path: String,
    size: u64,
    md5: String,
    sha256: String,
    imphash: Option<String>,
    symhash: Option<String>,
    ssdeep: Option<String>,
    tlsh: Option<String>,
}

fn run_hash(args: &HashArgs, out: &mut impl Write) -> Result<ExitCode> {
    let rules = RuleSet::empty();
    let opts = TriageOptions {
        max_listed_strings: 0,
        ..TriageOptions::default()
    };
    let mut lines = Vec::new();
    for f in triage::collect_files(&args.paths)? {
        let r = triage::analyze_path(&f, &opts, &rules)?;
        lines.push(HashLine {
            path: r.file.name,
            size: r.file.size,
            md5: r.file.digests.md5,
            sha256: r.file.digests.sha256,
            imphash: r.import_hashes.imphash,
            symhash: r.import_hashes.symhash,
            ssdeep: r.fuzzy.ssdeep,
            tlsh: r.fuzzy.tlsh,
        });
    }
    if args.json {
        writeln!(out, "{}", to_json(&lines)).map_err(io_err)?;
    } else {
        writeln!(out, "# path\tmd5\tsha256\timphash|symhash\tssdeep\ttlsh").map_err(io_err)?;
        for l in lines {
            writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}\t{}",
                l.path,
                l.md5,
                l.sha256,
                l.imphash.or(l.symhash).unwrap_or_else(|| "-".into()),
                l.ssdeep.unwrap_or_else(|| "-".into()),
                l.tlsh.unwrap_or_else(|| "-".into())
            )
            .map_err(io_err)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Digests (and PE imphash) for one `compare` operand.
struct Operand {
    ssdeep: Option<ssdeep::SsdeepHash>,
    tlsh: Option<tlsh::Tlsh>,
    imphash: Option<String>,
    is_file: bool,
}

fn operand(arg: &str) -> Result<Operand> {
    let path = Path::new(arg);
    if path.is_file() {
        let data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        let imphash = triage::pe_imphash_input(&data)
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| binscope::hashes::md5_hex(s.as_bytes()));
        return Ok(Operand {
            ssdeep: ssdeep::hash(&data).ok(),
            tlsh: tlsh::hash(&data).ok(),
            imphash,
            is_file: true,
        });
    }
    if arg.starts_with("T1") || arg.starts_with("t1") {
        return Ok(Operand {
            ssdeep: None,
            tlsh: Some(arg.parse()?),
            imphash: None,
            is_file: false,
        });
    }
    if arg.contains(':') {
        return Ok(Operand {
            ssdeep: Some(arg.parse()?),
            tlsh: None,
            imphash: None,
            is_file: false,
        });
    }
    Err(Error::Config(format!("{arg:?} is neither a file nor an ssdeep/TLSH digest")))
}

fn run_compare(args: &CompareArgs, style: Style, out: &mut impl Write) -> Result<ExitCode> {
    let (a, b) = (operand(&args.a)?, operand(&args.b)?);
    let c = Comparison {
        a: args.a.clone(),
        b: args.b.clone(),
        ssdeep_score: a.ssdeep.as_ref().zip(b.ssdeep.as_ref()).map(|(x, y)| ssdeep::compare(x, y)),
        tlsh_distance: a.tlsh.as_ref().zip(b.tlsh.as_ref()).map(|(x, y)| x.distance(y, true)),
        same_imphash: (a.is_file && b.is_file && (a.imphash.is_some() || b.imphash.is_some()))
            .then(|| a.imphash == b.imphash),
    };
    if c.ssdeep_score.is_none() && c.tlsh_distance.is_none() {
        return Err(Error::Config("the two operands share no comparable digest".into()));
    }
    let text = if args.json { to_json(&c) } else { report::render_comparison(&c, style) };
    writeln!(out, "{}", text.trim_end()).map_err(io_err)?;
    Ok(ExitCode::SUCCESS)
}

fn run_cluster(args: &ClusterArgs, style: Style, out: &mut impl Write) -> Result<ExitCode> {
    let method = match args.method {
        MethodArg::Tlsh => Method::Tlsh,
        MethodArg::Ssdeep => Method::Ssdeep,
    };
    let threshold = args.threshold.unwrap_or_else(|| method.default_threshold());
    let mut items = Vec::new();
    for f in triage::collect_files(&args.paths)? {
        let data = std::fs::read(&f).map_err(|e| Error::io(&f, e))?;
        items.push(Item::from_bytes(f.display().to_string(), &data));
    }
    let c = cluster::cluster(&items, method, threshold)?;
    let text = if args.json { to_json(&c) } else { report::render_clustering(&c, style) };
    writeln!(out, "{}", text.trim_end()).map_err(io_err)?;
    Ok(ExitCode::SUCCESS)
}

fn run_strings(args: &StringsArgs, out: &mut impl Write) -> Result<ExitCode> {
    let data = std::fs::read(&args.path).map_err(|e| Error::io(&args.path, e))?;
    let opts = StringOptions {
        min_len: args.min_len,
        utf16: !matches!(args.encoding, EncodingArg::Ascii),
        ..StringOptions::default()
    };
    let mut found = strings::extract(&data, &opts);
    if matches!(args.encoding, EncodingArg::Utf16) {
        found.retain(|s| s.encoding == Encoding::Utf16Le);
    }
    if args.tagged_only {
        found.retain(|s| !s.tags.is_empty());
    }
    if args.json {
        writeln!(out, "{}", to_json(&found)).map_err(io_err)?;
    } else {
        for s in found {
            let enc = if s.encoding == Encoding::Ascii { "a" } else { "u" };
            writeln!(out, "{:#010x} {enc} {}", s.offset, s.value).map_err(io_err)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_rules(cmd: &RulesCommand, out: &mut impl Write) -> Result<ExitCode> {
    match cmd {
        RulesCommand::List(args) => {
            let set = args.load()?;
            for r in set.iter() {
                writeln!(out, "{:<8} {:<48} {:<34} {}", r.severity, r.id, r.namespace, r.name).map_err(io_err)?;
            }
            writeln!(out, "{} rules", set.len()).map_err(io_err)?;
        }
        RulesCommand::Check { paths } => {
            let mut total = RuleSet::empty();
            for p in paths {
                total.extend(RuleSet::load_path(p)?)?;
            }
            writeln!(out, "ok: {} rules valid", total.len()).map_err(io_err)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn io_err(e: std::io::Error) -> Error {
    Error::io("<stdout>", e)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    env_logger::Builder::new().filter_level(level).format_timestamp(None).init();
    let style = style(cli.color);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let result = match &cli.command {
        Command::Triage(a) => run_triage(a, style, &mut out),
        Command::Hash(a) => run_hash(a, &mut out),
        Command::Compare(a) => run_compare(a, style, &mut out),
        Command::Cluster(a) => run_cluster(a, style, &mut out),
        Command::Strings(a) => run_strings(a, &mut out),
        Command::Rules { command } => run_rules(command, &mut out),
    };
    match result {
        Ok(code) => code,
        Err(Error::Io { ref path, ref source }) if path.as_os_str() == "<stdout>" && source.kind() == std::io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = out.flush();
            eprintln!("binscope: error: {e}");
            ExitCode::FAILURE
        }
    }
}
