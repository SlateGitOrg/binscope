#!/usr/bin/env bash
# Rebuild the binscope test corpus from fixtures/src.
#
# Requirements (macOS host, as used to produce the committed corpus):
#   - clang with the x86/AArch64 backends (Apple clang works)
#   - rust-lld from the Rust toolchain (ld.lld / lld-link flavours)
#   - lipo (Xcode command line tools) for the universal Mach-O
#   - python3 (stdlib only) for gen_blob.py
#
# Output: fixtures/bin/<target>/<family>-v<variant>[.exe] and fixtures/MANIFEST.tsv
# The corpus is committed, so `make check` never needs this script.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
OUT="$HERE/bin"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/binscope-fixtures.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

RUST_LLD="${RUST_LLD:-$(ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/rust-lld | head -1)}"
[ -x "$RUST_LLD" ] || { echo "rust-lld not found; set RUST_LLD" >&2; exit 1; }

FAMILIES=(hello files net plainblob packed)
VARIANTS=(0 1 2 3)
CFLAGS=(-O2 -ffreestanding -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables -fno-ident -Wall -Werror)

source_for() { case "$1" in plainblob|packed) echo blob.c ;; *) echo "$1.c" ;; esac; }

blob_header() { # family variant -> writes $WORK/inc/blob_data.h
    mkdir -p "$WORK/inc"
    case "$1" in
        plainblob) python3 "$HERE/gen_blob.py" "$2" plain "$WORK/inc/blob_data.h" ;;
        packed) python3 "$HERE/gen_blob.py" "$2" packed "$WORK/inc/blob_data.h" ;;
        *) : > "$WORK/inc/blob_data.h" ;;
    esac
}

# ---- import stubs -----------------------------------------------------------
build_stubs() {
    for arch in x86_64 aarch64; do
        clang -target "$arch-unknown-linux-gnu" "${CFLAGS[@]}" -fPIC -c "$SRC/stubs/libc_stub.c" -o "$WORK/libc_stub-$arch.o"
        "$RUST_LLD" -flavor gnu -shared -soname libc.so.6 --hash-style=gnu --build-id=none \
            -o "$WORK/libc-$arch.so.6" "$WORK/libc_stub-$arch.o"
        clang -target "$arch-unknown-linux-gnu" "${CFLAGS[@]}" -fno-pic -c "$SRC/stubs/crt0_linux.c" -o "$WORK/crt0-$arch.o" \
            $( [ "$arch" = x86_64 ] && echo "" || echo "-Wno-unknown-attributes" )
    done
    for m in x64 x86; do
        for lib in kernel32 ws2_32; do
            local def="$SRC/stubs/$lib.def"
            [ "$m" = x86 ] && def="$SRC/stubs/$lib-x86.def"
            "$RUST_LLD" -flavor link /lib /machine:$m /def:"$def" /out:"$WORK/$lib-$m.lib" >/dev/null
        done
    done
    clang -target x86_64-pc-windows-msvc "${CFLAGS[@]}" -mno-incremental-linker-compatible -c "$SRC/stubs/crt0_windows.c" -o "$WORK/crt0-win-x64.obj"
    clang -target i686-pc-windows-msvc "${CFLAGS[@]}" -mno-incremental-linker-compatible -c "$SRC/stubs/crt0_windows.c" -o "$WORK/crt0-win-x86.obj"
}

# ---- per-target builders ----------------------------------------------------
build_elf() { # arch family variant out
    local arch=$1 fam=$2 var=$3 out=$4 obj="$WORK/$fam-$var-$arch.o" interp
    clang -target "$arch-unknown-linux-gnu" "${CFLAGS[@]}" -fno-pic -DBS_LINUX -DVARIANT="$var" \
        -I"$SRC" -I"$WORK/inc" -c "$SRC/$(source_for "$fam")" -o "$obj"
    if [ "$arch" = x86_64 ]; then interp=/lib64/ld-linux-x86-64.so.2; else interp=/lib/ld-linux-aarch64.so.1; fi
    "$RUST_LLD" -flavor gnu --dynamic-linker "$interp" -e _start --build-id=none --hash-style=gnu \
        -z noexecstack -o "$out" "$WORK/crt0-$arch.o" "$obj" "$WORK/libc-$arch.so.6"
}

build_pe() { # machine(x64|x86) family variant out
    local m=$1 fam=$2 var=$3 out=$4 triple obj entry
    if [ "$m" = x64 ]; then triple=x86_64-pc-windows-msvc; entry=mainCRTStartup; else triple=i686-pc-windows-msvc; entry=mainCRTStartup; fi
    obj="$WORK/$fam-$var-win-$m.obj"
    clang -target "$triple" "${CFLAGS[@]}" -mno-incremental-linker-compatible -DBS_WINDOWS -DVARIANT="$var" \
        -I"$SRC" -I"$WORK/inc" -c "$SRC/$(source_for "$fam")" -o "$obj"
    "$RUST_LLD" -flavor link /nologo /brepro /nodefaultlib /subsystem:console /entry:"$entry" /machine:$m \
        /out:"$out" "$WORK/crt0-win-$m.obj" "$obj" "$WORK/kernel32-$m.lib" "$WORK/ws2_32-$m.lib" >/dev/null
}

build_macho() { # arch family variant out
    local arch=$1 fam=$2 var=$3 out=$4 minos
    # arm64 targets macOS 12, where ld emits LC_DYLD_CHAINED_FIXUPS; x86_64
    # targets 10.15 and keeps classic dyld-info bind opcodes. The corpus thus
    # covers both import encodings.
    if [ "$arch" = arm64 ]; then minos=12.0; else minos=10.15; fi
    clang -arch "$arch" -mmacosx-version-min="$minos" "${CFLAGS[@]}" -DBS_DARWIN -DVARIANT="$var" \
        -I"$SRC" -I"$WORK/inc" "$SRC/$(source_for "$fam")" -o "$out"
}

# ---- driver ------------------------------------------------------------------
rm -rf "$OUT"
mkdir -p "$OUT"
build_stubs
printf 'sha256\tsize\ttarget\tfamily\tvariant\tpath\n' > "$WORK/manifest"
emit() { # target family variant path
    local sum size
    sum=$(shasum -a 256 "$4" | cut -d' ' -f1)
    size=$(wc -c < "$4" | tr -d ' ')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$sum" "$size" "$1" "$2" "$3" "${4#"$HERE"/}" >> "$WORK/manifest"
}

for fam in "${FAMILIES[@]}"; do
    for var in "${VARIANTS[@]}"; do
        blob_header "$fam" "$var"
        for t in elf-x86_64 elf-aarch64 pe-x86_64 pe-i686 macho-arm64 macho-x86_64; do
            mkdir -p "$OUT/$t"
            case "$t" in
                elf-*) f="$OUT/$t/$fam-v$var"; build_elf "${t#elf-}" "$fam" "$var" "$f" ;;
                pe-x86_64) f="$OUT/$t/$fam-v$var.exe"; build_pe x64 "$fam" "$var" "$f" ;;
                pe-i686) f="$OUT/$t/$fam-v$var.exe"; build_pe x86 "$fam" "$var" "$f" ;;
                macho-*) f="$OUT/$t/$fam-v$var"; build_macho "${t#macho-}" "$fam" "$var" "$f" ;;
            esac
            emit "$t" "$fam" "$var" "$f"
        done
    done
done

# One universal (fat) Mach-O so the multi-architecture path is covered.
mkdir -p "$OUT/macho-universal"
lipo -create "$OUT/macho-arm64/hello-v0" "$OUT/macho-x86_64/hello-v0" -output "$OUT/macho-universal/hello-v0"
emit macho-universal hello 0 "$OUT/macho-universal/hello-v0"

mv "$WORK/manifest" "$HERE/MANIFEST.tsv"
echo "built $(($(wc -l < "$HERE/MANIFEST.tsv") - 1)) binaries into $OUT"
