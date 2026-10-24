#!/usr/bin/env bash
# Build the reference tools binscope is validated against, into DEST (default:
# a fresh temp dir). Nothing is installed system-wide.
#
#   ssdeep 2.14.1  (libfuzzy, GPL-2.0)            -> DEST/ssdeep, DEST/fuzzyref
#   TLSH 4.12.1    (trendmicro, Apache-2.0/BSD)   -> DEST/tlshref
#   pefile 2024.8.26 (MIT, in a uv venv)          -> DEST/venv
#
# Prints DEST on success. Requires: curl, cc/c++, make, uv.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$(mktemp -d "${TMPDIR:-/tmp}/binscope-ref.XXXXXX")}"
mkdir -p "$DEST" && cd "$DEST"

SSDEEP_URL=https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
SSDEEP_SHA=ff2eabc78106f009b4fb2def2d76fb0ca9e12acf624cbbfad9b3eb390d931313
TLSH_URL=https://github.com/trendmicro/tlsh/archive/refs/tags/4.12.1.tar.gz
TLSH_SHA=6a811ca31a36333fa3077a8765408449c0ecf9b37275d3722d511227f16ed9b1

fetch() { # url sha out
    [ -f "$3" ] || curl -sSL -o "$3" "$1"
    echo "$2  $3" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch for $3" >&2; exit 1; }
}

fetch "$SSDEEP_URL" "$SSDEEP_SHA" ssdeep.tar.gz
fetch "$TLSH_URL" "$TLSH_SHA" tlsh.tar.gz
tar xzf ssdeep.tar.gz && tar xzf tlsh.tar.gz

(cd ssdeep-2.14.1 && ./configure --disable-shared --prefix="$DEST/inst" >/dev/null && make -j3 >/dev/null && make install >/dev/null)
cp inst/bin/ssdeep "$DEST/ssdeep"
cc -O2 -I inst/include "$HERE/fuzzyref.c" inst/lib/libfuzzy.a -o "$DEST/fuzzyref"

cat > tlsh_version.h <<'H'
#define VERSION_MAJOR 4
#define VERSION_MINOR 12
#define VERSION_PATCH 1
#define TLSH_HASH "tlsh"
#define TLSH_CHECKSUM "1 byte checksum"
H
c++ -O2 -std=c++11 -DBUCKETS_128 -DCHECKSUM_1B -I. -I tlsh-4.12.1/include "$HERE/tlshref.cpp" \
    tlsh-4.12.1/src/tlsh.cpp tlsh-4.12.1/src/tlsh_impl.cpp tlsh-4.12.1/src/tlsh_util.cpp -o "$DEST/tlshref"

uv venv -q -p 3.12 venv
VIRTUAL_ENV="$DEST/venv" uv pip install -q pefile==2024.8.26
echo "$DEST"
