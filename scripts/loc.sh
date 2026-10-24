#!/usr/bin/env bash
# Count non-blank, non-comment source lines outside #[cfg(test)] modules.
# Generated tables (hashes/ordinals.rs, fuzzy/tlsh_tables.rs) are reported
# separately. Usage: scripts/loc.sh
set -euo pipefail
cd "$(dirname "$0")/.."
count() { # file -> lines of code before the first #[cfg(test)]
    awk '/^#\[cfg\(test\)\]/{exit} {line=$0; sub(/^[ \t]+/, "", line); if (line != "" && line !~ /^\/\//) n++} END{print n+0}' "$1"
}
total=0
printf '%-32s %6s\n' file lines
for f in $(find src -name '*.rs' | sort); do
    case "$f" in src/hashes/ordinals.rs|src/fuzzy/tlsh_tables.rs) continue ;; esac
    n=$(count "$f"); total=$((total + n)); printf '%-32s %6d\n' "$f" "$n"
done
gen=$(( $(count src/hashes/ordinals.rs) + $(count src/fuzzy/tlsh_tables.rs) ))
tests=$(cat tests/*.rs | grep -cv '^\s*$' || true)
inline=$(for f in $(find src -name '*.rs'); do awk '/^#\[cfg\(test\)\]/{t=1} t && $0 !~ /^[ \t]*$/ {n++} END{print n+0}' "$f"; done | awk '{s+=$1} END{print s+0}')
examples=$(cat examples/*.rs | grep -cv '^\s*$' || true)
printf '%-32s %6d\n' "TOTAL non-test source" "$total"
printf '%-32s %6d\n' "generated tables (excluded)" "$gen"
printf '%-32s %6d\n' "unit tests (inline modules)" "$inline"
printf '%-32s %6d\n' "integration tests (tests/)" "$tests"
printf '%-32s %6d\n' "examples" "$examples"
