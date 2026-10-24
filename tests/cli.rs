//! End-to-end tests of the `binscope` binary.

use std::path::PathBuf;
use std::process::{Command, Output};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(rel: &str) -> String {
    repo().join("fixtures/bin").join(rel).display().to_string()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binscope")).args(args).env("NO_COLOR", "1").output().expect("binscope runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn triage_human_output() {
    let o = run(&["triage", &fixture("pe-x86_64/net-v0.exe")]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    for want in
        ["imphash", "Sections (2)", "ws2_32.dll", "connect (#4)", "connect to a network endpoint", "Mitigations:"]
    {
        assert!(out.contains(want), "missing {want:?} in\n{out}");
    }
    assert!(!out.contains("\x1b["), "NO_COLOR must disable ANSI");
}

#[test]
fn triage_color_always() {
    let o = run(&["--color", "always", "triage", &fixture("elf-x86_64/packed-v0")]);
    assert!(stdout(&o).contains("\x1b[33m"), "medium severity is yellow");
}

#[test]
fn triage_json_single_and_many() {
    let o = run(&["triage", "--json", &fixture("macho-arm64/hello-v0")]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["binary"]["format"], "macho");
    assert_eq!(v["binary"]["macho"]["chained_fixups"], true);

    let o = run(&[
        "triage",
        "--json",
        &repo().join("fixtures/bin/macho-universal").display().to_string(),
        &fixture("pe-i686/files-v2.exe"),
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[0]["binary"]["format"], "macho-fat");
}

#[test]
fn triage_jsonl_streams_one_object_per_line() {
    let dir = repo().join("fixtures/bin/elf-aarch64").display().to_string();
    let o = run(&["triage", "--jsonl", "--max-strings", "0", &dir]);
    let text = stdout(&o);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 20);
    for l in lines {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["binary"]["arch"], "aarch64");
        assert_eq!(v["strings"]["listed"].as_array().unwrap().len(), 0);
    }
}

#[test]
fn fail_on_gates_exit_code() {
    let packed = fixture("pe-x86_64/packed-v0.exe");
    assert_eq!(run(&["triage", "--fail-on", "medium", &packed]).status.code(), Some(3));
    assert_eq!(run(&["triage", "--fail-on", "high", &packed]).status.code(), Some(0));
    assert_eq!(run(&["triage", "--fail-on", "low", &fixture("pe-x86_64/hello-v0.exe")]).status.code(), Some(0));
    assert_eq!(run(&["triage", "--fail-on", "info", &fixture("pe-x86_64/hello-v0.exe")]).status.code(), Some(3));
}

#[test]
fn extra_rules_and_no_builtin() {
    let dir = std::env::temp_dir().join(format!("binscope-cli-rules-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rule = dir.join("custom.yaml");
    std::fs::write(
        &rule,
        "rules:\n  - id: custom.greeting\n    name: greets the world\n    namespace: demo\n    match: {string: 'hello from the binscope'}\n",
    )
    .unwrap();
    let r = rule.display().to_string();
    let o = run(&["triage", "--json", "--no-builtin-rules", "--rules", &r, &fixture("elf-x86_64/hello-v0")]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let caps = v["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0]["id"], "custom.greeting");

    let o = run(&["rules", "check", &r]);
    assert!(stdout(&o).contains("ok: 1 rules valid"));
    let o = run(&["rules", "list", "--rules", &r]);
    assert!(stdout(&o).contains("35 rules"));

    std::fs::write(dir.join("bad.yaml"), "rules:\n  - id: x\n    name: n\n    namespace: y\n    match: {import: ''}\n")
        .unwrap();
    let o = run(&["rules", "check", &dir.display().to_string()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("bad.yaml"), "{}", stderr(&o));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn hash_command_text_and_json() {
    let f = fixture("pe-x86_64/hello-v0.exe");
    let o = run(&["hash", &f]);
    let line = stdout(&o).lines().nth(1).unwrap().to_string();
    let cols: Vec<&str> = line.split('\t').collect();
    assert_eq!(cols.len(), 6);
    assert_eq!(cols[3].len(), 32, "imphash column");
    assert!(cols[5].starts_with("T1"));
    let o = run(&["hash", "--json", &f]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v[0]["size"], 2048);
}

#[test]
fn compare_files_and_digests() {
    let o = run(&["compare", &fixture("macho-x86_64/hello-v0"), &fixture("macho-x86_64/hello-v1")]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("tlsh distance"));

    let o = run(&["compare", "--json", &fixture("pe-x86_64/net-v0.exe"), &fixture("pe-x86_64/net-v1.exe")]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["same_imphash"], true);
    assert!(v["tlsh_distance"].as_u64().is_some());

    let o = run(&["compare", "--json", "96:abcdefghijk:abc", "96:abcdefghijx:abc"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(v["ssdeep_score"].as_u64().unwrap() > 0);
    assert!(v["tlsh_distance"].is_null());

    let t = "T1B941CC03F27469EEC0094B77D3872EC17679231443A61ADF5B3448696D613FF68B8B40";
    let o = run(&["compare", "--json", t, t]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["tlsh_distance"], 0);

    let o = run(&["compare", t, "96:abc:d"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("no comparable digest"));
    let o = run(&["compare", "not-a-file", "neither"]);
    assert!(stderr(&o).contains("neither a file nor"));
}

#[test]
fn cluster_command() {
    let dir = repo().join("fixtures/bin/pe-x86_64").display().to_string();
    let o = run(&["cluster", &dir]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("Clustering: 20 samples"));
    let o = run(&["cluster", "--json", "--method", "ssdeep", "--threshold", "1", &dir]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["method"], "ssdeep");
    assert_eq!(v["threshold"], 1);
    let o = run(&["cluster", "--method", "ssdeep", "--threshold", "101", &dir]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn strings_command_filters() {
    let f = fixture("pe-x86_64/hello-v0.exe");
    let o = run(&["strings", "--encoding", "utf16", &f]);
    assert!(stdout(&o).contains("binscope wide banner: hello"));
    assert!(stdout(&o).lines().all(|l| l.contains(" u ")));
    let o = run(&["strings", "--tagged-only", "--json", &f]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(v.as_array().unwrap().iter().all(|s| s["tags"].as_array().is_some_and(|t| !t.is_empty())));
    let o = run(&["strings", "--encoding", "ascii", "--min-len", "12", &f]);
    assert!(stdout(&o).lines().all(|l| l.contains(" a ")));
}

#[test]
fn missing_input_is_an_error() {
    let o = run(&["triage", "/definitely/not/here"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("cannot read /definitely/not/here"));
    let o = run(&["-v", "strings", "/definitely/not/here"]);
    assert_eq!(o.status.code(), Some(1));
}
