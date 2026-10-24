#!/usr/bin/env bash
# Offline end-to-end demo against the bundled fixture corpus (no network,
# nothing executed: binscope only reads the files).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --locked --quiet
BIN="${CARGO_TARGET_DIR:-target}/release/binscope"
F=fixtures/bin
step() { printf '\n$ %s\n' "$*"; }
run() { step "binscope $*"; "$BIN" --color never "$@"; }

run triage --max-strings 8 "$F/pe-x86_64/net-v0.exe"

step "entropy contrast: same program, blob stored plain vs zlib-compressed"
for f in "$F/elf-x86_64/plainblob-v0" "$F/elf-x86_64/packed-v0"; do
    "$BIN" --color never triage --max-strings 0 "$f" | grep -E '^== |  \.blob |\[medium\]' || true
done

run triage --max-strings 4 "$F/macho-universal/hello-v0"

step "binscope triage --json fixtures/bin/macho-arm64/net-v0 (excerpt: imports + capabilities)"
"$BIN" triage --json "$F/macho-arm64/net-v0" | python3 -c '
import json, sys
r = json.load(sys.stdin)
print(json.dumps({"format": r["binary"]["format"], "arch": r["binary"]["arch"],
                  "chained_fixups": r["binary"]["macho"]["chained_fixups"],
                  "imports": [i["name"] for i in r["binary"]["imports"]],
                  "symhash": r["import_hashes"]["symhash"], "tlsh": r["fuzzy"]["tlsh"],
                  "capabilities": [c["id"] for c in r["capabilities"]]}, indent=2))'

run hash "$F/pe-i686"
run compare "$F/pe-x86_64/net-v0.exe" "$F/pe-x86_64/net-v1.exe"
run compare "$F/pe-x86_64/net-v0.exe" "$F/pe-x86_64/packed-v0.exe"
run cluster "$F/elf-x86_64"

step "binscope triage --fail-on medium (CI gate) on a packed sample"
set +e
"$BIN" triage --fail-on medium --max-strings 0 "$F/pe-x86_64/packed-v0.exe" >/dev/null
echo "exit status: $?"
set -e
run rules list
