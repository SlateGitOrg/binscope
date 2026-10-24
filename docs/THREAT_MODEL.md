# Threat model

binscope is a **defensive, static** triage tool. It reads files and reports on
them. It never executes, emulates, patches, unpacks or uploads its inputs and
has no network code.

## Assets

1. The analyst's workstation (binscope runs on files that may be hostile).
2. The integrity of the report: analysts act on it (escalate, ignore, cluster).
3. Batch throughput: one bad file should not stop a run over thousands.

## Trust boundaries

| input | trust | notes |
|---|---|---|
| sample files | **untrusted** | possibly crafted to attack parsers or mislead analysts |
| rule files (`--rules`) | trusted-ish | written by the analyst/team; still validated strictly |
| command-line arguments | trusted | the operator |

## Threats and mitigations

| # | threat | mitigation | residual risk |
|---|---|---|---|
| T1 | Memory corruption via malformed headers | binscope's own code forbids `unsafe` (`unsafe_code = "forbid"` in the Cargo lint table); parsing uses goblin's bounds-checked readers; every offset/size derived from the file is clamped (`format::file_slice`) | bugs in dependencies; goblin itself is not fuzzed by this project beyond the mutation tests |
| T2 | Parser panic aborting a batch | `format::parse` wraps goblin in `catch_unwind` and turns a panic into a per-file parse error; triage still hashes and string-scans the file | an abort (e.g. allocator OOM) cannot be caught |
| T3 | Resource exhaustion (CPU/memory) | all per-file passes are O(n) with O(1) extra state except string extraction (O(strings)); ssdeep compare is bounded (64x64); rule nesting depth capped at 32; directories are walked without following symlinks (no loops) | files are read fully into memory (no size cap); clustering is O(n^2) in the worst case |
| T4 | Terminal escape injection via section/import/export names | human output escapes every control character from sample-derived text (`report::clean`); JSON escapes via serde | none known for the shipped renderers |
| T5 | Misleading the analyst (false negatives) | report shows evidence for every capability; anomalies are explained with values | see "evasion" below; static analysis is inherently evadable |
| T6 | Path traversal / overwrites | binscope writes nothing except to stdout; it never extracts embedded files | n/a |
| T7 | Malicious rule files | strict schema (`deny_unknown_fields`), regex compile errors reported, `regex` crate has linear-time matching (no catastrophic backtracking) | a rule author can still write rules that match everything |

## Evasion (out of scope, documented)

* **Dynamic API resolution** (hash-based `GetProcAddress`, `dlsym` with
  computed names) hides capabilities from import-based rules.
* **Fuzzy-hash attacks**: both ssdeep and TLSH can be pushed apart by an
  adversary who controls the bytes (Oliver et al., "Attacking LSH and
  Similarity Digests"); the evaluation in the README shows ssdeep collapses
  under dispersed edits even without an adversary.
* **Entropy games**: padding compressed data with low-entropy filler lowers
  section entropy below the 7.2 threshold.
* **Format confusion**: polyglots or containers binscope does not parse
  (COFF objects, archives, .NET metadata, installers) are reported as
  unsupported or parsed only at the outer layer.

binscope's output is a starting point for an analyst, not a verdict.

## Ethics and safety of the project itself

* The test corpus is built from the benign C sources in `fixtures/src`;
  nothing is downloaded. The `net` programs only contact 127.0.0.1, `files`
  only touches its own temp file, and the `packed` family has no unpacking
  stub (it is an entropy contrast, not a packer).
* The rule pack labels capabilities (including injection-related API sets and
  debugger checks) so analysts can spot them; binscope contains no code that
  performs those behaviours.
