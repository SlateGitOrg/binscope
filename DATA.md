# Data and third-party material

Everything committed is small (fixtures 2.0 MB, reference vectors ~0.4 MB) and
either built in this repository or derived from the reference tools listed
here. No dataset is downloaded at test time.

## 1. Fixture corpus (`fixtures/`)

* **Source:** built in-repo from the C sources in `fixtures/src` by
  `fixtures/build.sh` (clang + rust-lld from the Rust toolchain + lipo).
* **Licence:** MIT, same as this repository.
* **Contents:** 121 binaries (5 benign program families x 4 variants x 6
  targets + 1 universal Mach-O), listed with sha256 in `fixtures/MANIFEST.tsv`.
  See `fixtures/README.md`.
* **Synthetic?** The programs are real, compilable C; they are tiny and
  freestanding, so they are *not* representative of real-world binary sizes
  or toolchain boilerplate (see README "Limitations").

## 2. Reference vectors (`tests/reference/*.tsv`)

Produced by `scripts/reference/gen_reference.py` (driven by `make reference`)
from the outputs of the reference tools below, run over the fixture corpus and
over 132 synthetic inputs that `binscope::synth` regenerates deterministically
in the tests (`examples/gen_synth.rs`).

| file | produced by | tool licence |
|---|---|---|
| `ssdeep_hashes.tsv`, `ssdeep_compare.tsv` | ssdeep 2.14.1 (`ssdeep -s -c`, libfuzzy `fuzzy_compare`), source tarball sha256 `ff2eabc7...1313` from github.com/ssdeep-project/ssdeep | GPL-2.0 (tool output only; no ssdeep code is included) |
| `tlsh_hashes.tsv`, `tlsh_diff.tsv` | TLSH 4.12.1 (`Tlsh::final`, `totalDiff`), source tarball sha256 `6a811ca3...d9b1` from github.com/trendmicro/tlsh | Apache-2.0 OR BSD-3-Clause |
| `pefile.tsv` | pefile 2024.8.26 (`get_imphash`, `SectionStructure.get_entropy`) | MIT |
| `sections.tsv` | `llvm-readobj` 22.1.6 from the Rust 1.97.1 `llvm-tools` component | Apache-2.0 WITH LLVM-exception |
| `imports.tsv` | `llvm-nm` 22.1.6 from the same component | Apache-2.0 WITH LLVM-exception |

The tool sources are fetched by `scripts/reference/build_tools.sh` into a
temporary directory with sha256 verification and deleted afterwards; nothing
is installed system-wide.

## 3. Constant tables compiled into binscope

| file | content | source | licence |
|---|---|---|---|
| `src/fuzzy/tlsh_tables.rs` | TLSH Pearson permutation `v_table` (256 bytes) and `topval` length buckets (170 values) | trendmicro/tlsh 4.12.1 `src/tlsh_impl.cpp`, `src/tlsh_util.cpp`, extracted by `scripts/gen_tlsh_tables.py` | Apache-2.0 OR BSD-3-Clause (used under Apache-2.0; attribution here) |
| `src/hashes/ordinals.rs` | ordinal -> export-name tables for `ws2_32.dll`, `wsock32.dll`, `oleaut32.dll` | pefile 2024.8.26 `ordlookup/`, extracted by `scripts/gen_ordinals.py` | MIT (pefile, Copyright (c) Ero Carrera) |

The TLSH and ssdeep algorithms themselves are implemented from their published
descriptions (Kornblum, DFRWS 2006; Oliver, Cheng & Chen, CTC 2013); only the
two TLSH constant tables above are copied, because bit-exact digests require
identical constants.

## 4. Built-in rules (`rules/*.yaml`)

Written for this project (MIT). ATT&CK technique ids are references to the
public MITRE ATT&CK knowledge base and are coarse labels, not coverage claims.
